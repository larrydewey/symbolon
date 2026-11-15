package dev.symbolon.symbolon_ui

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// The SSH signature window for another app on the phone (SPEC 16.1.1):
// lib/ssh_consent.dart's page, run from `sshConsentMain`. It is started only
// through the PendingIntent SshAgentService hands the calling app, so the
// request path and the peer come from the service, never from the caller.
// The window keeps its content out of screenshots and hides other apps'
// overlays while it is shown (A4).
class SshConsentActivity : FlutterFragmentActivity() {
    override fun getDartEntrypointFunctionName() = "sshConsentMain"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
    }

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
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "symbolon/ssh").setMethodCallHandler { call, result ->
            when (call.method) {
                "request" -> result.success(mapOf("path" to intent.getStringExtra("request"), "peer" to intent.getStringExtra("peer")))
                "done" -> { result.success(null); finish() }
                else -> result.notImplemented()
            }
        }
    }
}
