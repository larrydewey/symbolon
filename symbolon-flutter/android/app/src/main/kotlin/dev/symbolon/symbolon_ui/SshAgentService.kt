package dev.symbolon.symbolon_ui

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

// Symbolon's SSH agent for other apps on the phone (SPEC 16.1.1): the
// agent protocol's messages, unchanged, over Binder, for apps whose signing
// certificate Symbolon lists (res/values/ssh_agent_callers.xml; Pylon's).
//
// Each (calling app, connection) gets its own `libsymbolon.so
// ssh-agent-stdio DEVICE RUNDIR PEER` process, so a session-bind holds
// for the signature that follows it. Identities and binds are answered at
// once. A signature needs the principal: the agent announces a consent
// request, and the call returns a PendingIntent for SshConsentActivity,
// which the calling app (in front, as the principal is using it) starts;
// the app then waits for the answer (WAIT). A background service cannot
// open an activity itself on current Android, and should not.
//
// Every call checks the caller again: its package's single signer must be
// one of the listed certificates. The permission (signature|knownSigner
// with the same list) keeps other apps from binding at all on Android 12+.
//
// Transactions (interface "dev.symbolon.ISshAgent"):
//   CALL  (FIRST_CALL_TRANSACTION)     long conn, byte[] request
//         -> int 0, byte[] reply  |  int 1, PendingIntent (consent first; then WAIT)
//   WAIT  (FIRST_CALL_TRANSACTION + 1) long conn -> int 0, byte[] reply (up to 6 minutes)
//   CLOSE (FIRST_CALL_TRANSACTION + 2) long conn -> nothing
// A reply of int -1 means refused or failed (the client treats it as the
// agent's failure message).
class SshAgentService : Service() {
    companion object {
        const val DESCRIPTOR = "dev.symbolon.ISshAgent"
        const val CALL = IBinder.FIRST_CALL_TRANSACTION
        const val WAIT = IBinder.FIRST_CALL_TRANSACTION + 1
        const val CLOSE = IBinder.FIRST_CALL_TRANSACTION + 2
        const val TAG = "SymbolonSshAgent"
    }

    private class Conn(val proc: Process, val peer: String) {
        val replies = LinkedBlockingQueue<ByteArray>()
        val consents = LinkedBlockingQueue<String>()
        @Volatile var lastUse = System.currentTimeMillis()
        // A consent sheet is open for this connection: not idle.
        @Volatile var pending = false
    }

    private val conns = ConcurrentHashMap<String, Conn>()

    override fun onBind(intent: Intent): IBinder = binder

    override fun onDestroy() {
        conns.values.forEach { it.proc.destroy() }
        conns.clear()
        super.onDestroy()
    }

    private fun sha256Hex(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    // The caller as "Label (package)" when its sole signer is listed, else null.
    private fun verifiedCaller(uid: Int): String? {
        val allowed = resources.getStringArray(R.array.ssh_agent_callers).map { it.replace(":", "").lowercase() }.filter { it.isNotEmpty() }.toSet()
        if (allowed.isEmpty()) return null
        val pm = packageManager
        for (pkg in pm.getPackagesForUid(uid) ?: emptyArray()) {
            val info = try { pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES) } catch (e: Exception) { continue }
            val si = info.signingInfo ?: continue
            if (si.hasMultipleSigners()) continue
            val signer = si.apkContentsSigners.firstOrNull() ?: continue
            if (sha256Hex(signer.toByteArray()) !in allowed) continue
            val label = info.applicationInfo?.loadLabel(pm)?.toString() ?: pkg
            return "${label.replace("\n", " ").take(80)} ($pkg)"
        }
        return null
    }

    private fun deviceDir(): String {
        val f = File(filesDir, "settings.json")
        if (f.exists()) {
            try {
                val d = JSONObject(f.readText()).optString("deviceDir", "")
                if (d.isNotEmpty()) return d
            } catch (_: Exception) {
            }
        }
        return File(filesDir, "device").absolutePath
    }

    private fun runDir(): File {
        val r = File(filesDir, "sshrun")
        File(r, "symbolon").mkdirs()
        r.setReadable(false, false); r.setReadable(true, true)
        r.setWritable(false, false); r.setWritable(true, true)
        r.setExecutable(false, false); r.setExecutable(true, true)
        return r
    }

    private fun readFully(i: InputStream, n: Int): ByteArray? {
        val b = ByteArray(n)
        var at = 0
        while (at < n) {
            val k = i.read(b, at, n - at)
            if (k < 0) return null
            at += k
        }
        return b
    }

    private fun open(key: String, peer: String): Conn {
        conns[key]?.let { if (it.proc.isAlive) return it }
        val bin = File(applicationInfo.nativeLibraryDir, "libsymbolon.so").absolutePath
        val p = ProcessBuilder(bin, "ssh-agent-stdio", deviceDir(), runDir().absolutePath, peer).start()
        val c = Conn(p, peer)
        // Closing a connection destroys its process under these readers:
        // the read then fails, which ends the thread. Uncaught, it would
        // end the whole app and every other connection with it.
        Thread {
            try {
                val i = p.inputStream
                while (true) {
                    val h = readFully(i, 4) ?: break
                    val n = ((h[0].toInt() and 255) shl 24) or ((h[1].toInt() and 255) shl 16) or ((h[2].toInt() and 255) shl 8) or (h[3].toInt() and 255)
                    if (n < 1 || n > 262144) break
                    val body = readFully(i, n) ?: break
                    c.replies.put(h + body)
                }
            } catch (_: IOException) {
            }
        }.apply { isDaemon = true }.start()
        // The agent's other lines say why a request failed: logcat has them.
        Thread {
            try {
                p.errorStream.bufferedReader().forEachLine { l ->
                    if (l.startsWith("consent ")) c.consents.put(l.substring(8)) else Log.w(TAG, l.take(500))
                }
            } catch (_: IOException) {
            }
        }.apply { isDaemon = true }.start()
        conns[key] = c
        return c
    }

    private fun close(key: String) {
        conns.remove(key)?.let { it.proc.outputStream.close(); it.proc.destroy() }
    }

    // Connections idle for 30 seconds end; with a consent open, after the
    // longest WAIT (an abandoned sheet does not keep a process forever).
    private fun sweep() {
        val now = System.currentTimeMillis()
        for ((k, c) in conns) if (now - c.lastUse > (if (c.pending) 400_000 else 30_000)) close(k)
    }

    private fun consentIntent(c: Conn, request: String): PendingIntent {
        val i = Intent(this, SshConsentActivity::class.java)
            .putExtra("request", request)
            .putExtra("peer", c.peer)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return PendingIntent.getActivity(this, request.hashCode(), i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_ONE_SHOT)
    }

    private val binder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code == INTERFACE_TRANSACTION) { reply?.writeString(DESCRIPTOR); return true }
            if (code != CALL && code != WAIT && code != CLOSE) return super.onTransact(code, data, reply, flags)
            data.enforceInterface(DESCRIPTOR)
            val uid = Binder.getCallingUid()
            val peer = verifiedCaller(uid)
            reply?.writeNoException()
            if (peer == null) { reply?.writeInt(-1); return true }
            val key = "$uid:${data.readLong()}"
            sweep()
            when (code) {
                CLOSE -> close(key)
                CALL -> {
                    val req = data.createByteArray()
                    if (req == null || req.size < 5 || req.size > 262148) { reply?.writeInt(-1); return true }
                    val c = try { open(key, peer) } catch (e: Exception) { reply?.writeInt(-1); return true }
                    c.lastUse = System.currentTimeMillis()
                    c.consents.clear()
                    c.pending = false
                    try {
                        c.proc.outputStream.write(req)
                        c.proc.outputStream.flush()
                    } catch (e: Exception) { close(key); reply?.writeInt(-1); return true }
                    // An immediate answer, or a consent request.
                    val deadline = System.currentTimeMillis() + 30_000
                    while (System.currentTimeMillis() < deadline) {
                        c.replies.poll(50, TimeUnit.MILLISECONDS)?.let { reply?.writeInt(0); reply?.writeByteArray(it); return true }
                        c.consents.poll()?.let { path ->
                            c.pending = true
                            reply?.writeInt(1)
                            PendingIntent.writePendingIntentOrNullToParcel(consentIntent(c, path), reply!!)
                            return true
                        }
                        if (!c.proc.isAlive) break
                    }
                    reply?.writeInt(-1)
                }
                WAIT -> {
                    val c = conns[key]
                    val r = c?.replies?.poll(360, TimeUnit.SECONDS)
                    c?.pending = false
                    c?.lastUse = System.currentTimeMillis()
                    if (r == null) { reply?.writeInt(-1) } else { reply?.writeInt(0); reply?.writeByteArray(r) }
                }
            }
            return true
        }
    }
}
