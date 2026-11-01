package dev.symbolon.symbolon_ui

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import androidx.fragment.app.FragmentActivity
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.io.BufferedInputStream
import java.io.InputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import kotlin.concurrent.thread

// The Android Keystore for the agent (symbolon-resid src/agent/keystore.resid,
// SPEC 9.1): the agent runs as a separate process and cannot reach the
// Keystore, so the app serves it on loopback, behind a token that is new at
// every start and handed to the agent in SYMBOLON_KEYSTORE. Keys are
// non-exportable, in StrongBox where the phone has it (else the TEE), and
// usable only while the phone is unlocked.
//   POST /create-hmac?t=TOKEN&k=ALIAS        an HMAC-SHA256 key
//   POST /hmac?...           body: data      the HMAC
//   POST /create-ec?...                      a P-256 signing key; its point (65 bytes)
//   POST /sign?...           body: digest    r || s
//   POST /delete?...
object KeystoreServer {
    private val token: String = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
    private var port = 0
    private var strongBox = false

    @Synchronized
    fun start(c: Context): String {
        if (port == 0) {
            strongBox = Build.VERSION.SDK_INT >= 28 && c.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            // 127.0.0.1, where the agent connects (Android's loopback address is ::1).
            val server = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
            port = server.localPort
            thread(isDaemon = true, name = "symbolon-keystore") {
                while (true) {
                    val s = server.accept()
                    thread(isDaemon = true) { s.use { serve(it) } }
                }
            }
        }
        return "$port $token"
    }

    fun info(c: Context): Map<String, Any> {
        bindAuth(c)
        return mapOf("endpoint" to start(c), "available" to (Build.VERSION.SDK_INT >= 28), "strongbox" to strongBox, "authBound" to authBound)
    }

    private fun line(i: InputStream): String {
        val b = StringBuilder()
        while (true) {
            val c = i.read()
            if (c < 0 || c == '\n'.code) break
            if (c != '\r'.code) b.append(c.toChar())
            if (b.length > 4096) break
        }
        return b.toString()
    }

    private fun serve(s: Socket) {
        val i = BufferedInputStream(s.getInputStream())
        val request = line(i).split(" ")
        var length = 0
        while (true) {
            val h = line(i)
            if (h.isEmpty()) break
            if (h.lowercase().startsWith("content-length:")) length = h.substring(15).trim().toIntOrNull() ?: 0
        }
        if (length < 0 || length > 4096) return reply(s, 400, "too long".toByteArray())
        val body = ByteArray(length)
        var got = 0
        while (got < length) {
            val n = i.read(body, got, length - got)
            if (n < 0) break
            got += n
        }
        if (request.size < 2 || request[0] != "POST") return reply(s, 400, "bad request".toByteArray())
        val path = request[1].substringBefore('?')
        val q = request[1].substringAfter('?', "").split('&').associate { it.substringBefore('=') to URLDecoder.decode(it.substringAfter('=', ""), "UTF-8") }
        if (!MessageDigest.isEqual((q["t"] ?: "").toByteArray(), token.toByteArray())) return reply(s, 403, "wrong token".toByteArray())
        val alias = q["k"] ?: ""
        if (!alias.matches(Regex("symbolon-[0-9a-f]{1,64}-(unlock_a|unlock_b|dk)"))) return reply(s, 400, "bad key name".toByteArray())
        try {
            reply(s, 200, when (path) {
                "/create-hmac" -> { makeHmac(alias); ByteArray(0) }
                "/hmac" -> withCheck { Mac.getInstance("HmacSHA256").run { init(store().getKey(alias, null) as SecretKey); doFinal(body) } }
                "/create-ec" -> makeEc(alias)
                "/sign" -> {
                    if (body.size != 32) throw IllegalArgumentException("a digest is 32 bytes")
                    val sig = withCheck { Signature.getInstance("NONEwithECDSA").run { initSign(store().getKey(alias, null) as PrivateKey); update(body); sign() } }
                    rawOfDer(sig)
                }
                "/delete" -> { store().deleteEntry(alias); ByteArray(0) }
                else -> return reply(s, 404, "no such operation".toByteArray())
            })
        } catch (e: Exception) {
            reply(s, 500, (e.message ?: e.javaClass.simpleName).toByteArray())
        }
    }

    private fun reply(s: Socket, code: Int, body: ByteArray) {
        val o = s.getOutputStream()
        o.write("HTTP/1.1 $code X\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray())
        o.write(body)
        o.flush()
    }

    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    // StrongBox where there is one; the TEE otherwise.
    private fun <T> withStrongBox(make: (Boolean) -> T): T {
        if (strongBox) {
            try {
                return make(true)
            } catch (_: StrongBoxUnavailableException) {
            }
        }
        return make(false)
    }

    // With a screen lock (Android 11+), a key works only within 30 s of a
    // biometric or screen-lock check of the person (the app asks before it
    // runs the agent): PINs cannot be tried, nor the device key used, by
    // code running on an unlocked phone without the person. Without one,
    // only while the phone is unlocked.
    private var authBound = false

    // The activity in front, for the fingerprint prompt a key needs.
    @Volatile private var front = WeakReference<FragmentActivity>(null)

    fun inFront(a: FragmentActivity) { front = WeakReference(a) }

    // A key bound to a recent check refused: ask the person (on the main
    // thread), wait for them, and say whether they confirmed.
    private fun check(): Boolean {
        val a = front.get() ?: return false
        val done = CountDownLatch(1)
        var ok = false
        a.runOnUiThread {
            Biometric.authenticate(a, "Confirm it's you", "Symbolon needs your device key") { yes, _ -> ok = yes; done.countDown() }
        }
        done.await(2, TimeUnit.MINUTES)
        return ok
    }

    // Runs [op]; when the key wants a fresh check of the person, asks for
    // one and runs it again.
    private fun <T> withCheck(op: () -> T): T = try {
        op()
    } catch (e: UserNotAuthenticatedException) {
        if (!check()) throw e
        op()
    }

    fun bindAuth(c: Context) { authBound = Biometric.supported(c) }

    private fun spec(alias: String, sb: Boolean, ec: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
        if (ec) b.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
        if (Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(sb)
        if (authBound && Build.VERSION.SDK_INT >= 30) {
            b.setUserAuthenticationRequired(true).setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        } else if (Build.VERSION.SDK_INT >= 28) b.setUnlockedDeviceRequired(true)
        return b.build()
    }

    private fun makeHmac(alias: String) = withStrongBox { sb ->
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").run { init(spec(alias, sb, false)); generateKey() }
    }

    private fun makeEc(alias: String): ByteArray = withStrongBox { sb ->
        val kp = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run { initialize(spec(alias, sb, true)); generateKeyPair() }
        val w = (kp.public as ECPublicKey).w
        byteArrayOf(4) + fixed(w.affineX) + fixed(w.affineY)
    }

    private fun fixed(n: BigInteger): ByteArray {
        val b = n.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(32 - b.size) + b
    }

    // An ECDSA signature from DER (SEQUENCE { INTEGER r, INTEGER s }) to r || s.
    private fun rawOfDer(d: ByteArray): ByteArray {
        var p = 2
        if (d[1].toInt() and 0x80 != 0) p = 2 + (d[1].toInt() and 0x7f)
        fun int(): BigInteger {
            val len = d[p + 1].toInt() and 0xff
            val v = BigInteger(1, d.copyOfRange(p + 2, p + 2 + len))
            p += 2 + len
            return v
        }
        val r = int()
        val s = int()
        return fixed(r) + fixed(s)
    }
}
