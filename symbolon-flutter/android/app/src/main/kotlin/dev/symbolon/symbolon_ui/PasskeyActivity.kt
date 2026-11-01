package dev.symbolon.symbolon_ui

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.security.MessageDigest

// One passkey ceremony for the system (SPEC 10.4, 22.2): the Dart side
// (lib/passkey_main.dart) shows the site and the account, takes the PIN
// and runs the agent; this side hands it the request with the caller's
// origin as Android reports it, and returns the response.
@RequiresApi(34)
class PasskeyActivity : FlutterFragmentActivity() {
    companion object {
        const val CREATE = "dev.symbolon.CREATE_PASSKEY"
        const val GET = "dev.symbolon.GET_PASSKEY"

        fun pending(c: Context, action: String, rp: String?, cid: String?, requestCode: Int): PendingIntent {
            val i = Intent(c, PasskeyActivity::class.java).setAction(action).putExtra("rp", rp).putExtra("cid", cid)
            return PendingIntent.getActivity(c, requestCode, i, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
    }

    override fun getDartEntrypointFunctionName() = "passkeyMain"

    override fun onResume() {
        super.onResume()
        KeystoreServer.inFront(this)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "symbolon/platform").setMethodCallHandler { call, result ->
            if (Biometric.handle(this, call, result)) return@setMethodCallHandler
            when (call.method) {
                "paths" -> result.success(platformPaths(this))
                "keystore" -> result.success(KeystoreServer.info(this))
                else -> result.notImplemented()
            }
        }
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "symbolon/passkey").setMethodCallHandler { call, result ->
            try {
                when (call.method) {
                    "request" -> result.success(request())
                    "finish" -> { finishWith(call.argument<String>("json")!!); result.success(null) }
                    "cancel" -> { cancel(); result.success(null) }
                    else -> result.notImplemented()
                }
            } catch (e: Exception) {
                result.error("passkey", e.message, null)
            }
        }
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    // The caller's origin: a browser's page as the browser reports it (only
    // browsers on the privileged list may), else the app's own identity.
    private fun originOf(info: CallingAppInfo): Pair<String, Boolean> {
        val allow = assets.open("privileged_browsers.json").bufferedReader().readText()
        try {
            info.getOrigin(allow)?.let { return it.trimEnd('/') to true }
        } catch (_: Exception) {
        }
        val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
        return "android:apk-key-hash:${b64url(sha256(cert))}" to false
    }

    private fun request(): Map<String, Any?> {
        val create = intent.action == CREATE
        val info: CallingAppInfo
        val json: String
        val given: ByteArray?
        if (create) {
            val r = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: throw IllegalStateException("no request")
            val req = r.callingRequest as CreatePublicKeyCredentialRequest
            info = r.callingAppInfo
            json = req.requestJson
            given = req.clientDataHash
        } else {
            val r = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: throw IllegalStateException("no request")
            val opt = r.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().first()
            info = r.callingAppInfo
            json = opt.requestJson
            given = opt.clientDataHash
        }
        val (origin, browser) = originOf(info)
        // A browser supplies the hash of its own client data; for an app,
        // the client data is formed here.
        var clientData: String? = null
        val hash = given ?: run {
            val cd = JSONObject()
                .put("type", if (create) "webauthn.create" else "webauthn.get")
                .put("challenge", JSONObject(json).getString("challenge"))
                .put("origin", origin)
                .put("androidPackageName", info.packageName)
                .toString()
            clientData = cd
            sha256(cd.toByteArray())
        }
        return mapOf(
            "kind" to if (create) "create" else "get",
            "requestJson" to json,
            "origin" to origin,
            "browser" to browser,
            "callingPackage" to info.packageName,
            "clientDataHash" to hash.joinToString("") { "%02x".format(it) },
            "clientDataJSON" to clientData,
            "rp" to intent.getStringExtra("rp"),
            "cid" to intent.getStringExtra("cid"),
        )
    }

    private fun finishWith(json: String) {
        val out = Intent()
        if (intent.action == CREATE) PendingIntentHandler.setCreateCredentialResponse(out, CreatePublicKeyCredentialResponse(json))
        else PendingIntentHandler.setGetCredentialResponse(out, GetCredentialResponse(PublicKeyCredential(json)))
        setResult(RESULT_OK, out)
        finish()
    }

    private fun cancel() {
        val out = Intent()
        if (intent.action == CREATE) PendingIntentHandler.setCreateCredentialException(out, CreateCredentialCancellationException("cancelled"))
        else PendingIntentHandler.setGetCredentialException(out, GetCredentialCancellationException("cancelled"))
        setResult(RESULT_OK, out)
        finish()
    }
}
