package dev.symbolon.symbolon_ui

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// The fill screen (SPEC 22.6 item 4): an activity of Symbolon's, outside the
// requesting app. The Dart side (lib/autofill_main.dart) shows the
// requester, opens the device with the agent and lets the person choose;
// this side gives it the request and turns the chosen values into a
// dataset for exactly the fields that were found. It cannot be captured,
// hides other apps' overlays, and ignores touches while anything covers it.
@androidx.annotation.RequiresApi(26)
class AutofillActivity : FlutterFragmentActivity() {
    companion object {
        fun extrasOf(r: Requester, found: List<Found>): Bundle = Bundle().apply {
            putString("pkg", r.pkg)
            putString("label", r.label)
            putStringArrayList("certs", ArrayList(r.certs))
            putString("installer", r.installer)
            putString("origin", r.origin)
            putStringArrayList("kinds", ArrayList(found.map { it.kind }))
            putParcelableArrayList("ids", ArrayList<AutofillId>(found.map { it.id }))
        }
    }

    override fun getDartEntrypointFunctionName() = "autofillMain"

    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        super.onCreate(savedInstanceState)
        // Before Android 12 overlays cannot be hidden: a touch made while
        // anything covers the screen is dropped instead.
        window.decorView.filterTouchesWhenObscured = true
    }

    override fun onResume() {
        super.onResume()
        KeystoreServer.inFront(this)
    }

    private val found: List<Found>
        get() = foundOf(intent.getStringArrayListExtra("kinds"),
            @Suppress("DEPRECATION") intent.getParcelableArrayListExtra<AutofillId>("ids"))

    private fun request(): Map<String, Any?> {
        val pkg = intent.getStringExtra("pkg") ?: ""
        val r = Requester(pkg, intent.getStringExtra("label") ?: pkg, intent.getStringArrayListExtra("certs") ?: arrayListOf(),
            intent.getStringExtra("installer") ?: "", intent.getStringExtra("origin") ?: "")
        return mapOf(
            "mode" to if (intent.action == SymbolonAutofillService.SAVE) "save" else "fill",
            "package" to r.pkg, "label" to r.label, "certs" to r.certs, "installer" to r.installer,
            "origin" to r.origin, "apkKeyHash" to r.apkKeyHash,
            "kinds" to found.map { it.kind }.distinct(),
            // Sites the app claims, to be confirmed by their Digital Asset Links.
            "claimed" to if (r.origin.isEmpty()) AutofillCore.claimedSites(this, pkg) else emptyList<String>(),
            "saveUser" to (intent.getStringExtra("saveUser") ?: ""),
            "savePassword" to (intent.getStringExtra("savePassword") ?: ""),
        )
    }

    // The chosen item's values, by kind, into the found fields only.
    private fun finishWith(values: Map<String, String>) {
        val b = Dataset.Builder(RemoteViews(packageName, R.layout.autofill_entry))
        var any = false
        for (f in found) values[f.kind]?.takeIf { it.isNotEmpty() }?.let { b.setValue(f.id, AutofillValue.forText(it)); any = true }
        if (!any) return cancel()
        setResult(Activity.RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, b.build()))
        finish()
    }

    private fun cancel() {
        setResult(Activity.RESULT_CANCELED)
        finish()
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
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "symbolon/autofill").setMethodCallHandler { call, result ->
            try {
                when (call.method) {
                    "request" -> result.success(request())
                    "finish" -> { finishWith(call.argument<Map<String, String>>("values") ?: emptyMap()); result.success(null) }
                    "done" -> { setResult(Activity.RESULT_OK); finish(); result.success(null) }
                    "cancel" -> { cancel(); result.success(null) }
                    else -> result.notImplemented()
                }
            } catch (e: Exception) {
                result.error("autofill", e.message, null)
            }
        }
    }
}
