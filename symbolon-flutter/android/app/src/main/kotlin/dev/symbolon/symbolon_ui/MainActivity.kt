package dev.symbolon.symbolon_ui

import android.content.ComponentName
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// The agent ships as lib/<abi>/libsymbolon.so: Android extracts native
// libraries to a directory it lets the app execute from (the app's data
// directory is not executable). The Dart side runs it as a subprocess.
class MainActivity : FlutterFragmentActivity() {
    private var scanner: QrScanner? = null

    // A page the activity was started for (dev.symbolon.action.SSH_KEYS),
    // until the Dart side takes it; later intents are sent to it directly.
    private var pendingPage: String? = null
    private var nav: MethodChannel? = null

    private fun pageFor(i: Intent?): String? = if (i?.action == "dev.symbolon.action.SSH_KEYS") "ssh-keys" else null

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        if (savedInstanceState == null) pendingPage = pageFor(intent)
        super.onCreate(savedInstanceState)
        // The recent-apps screen keeps a picture of the app as it was left,
        // taken before the app locks: Android 13+ shows a blank one instead.
        // Screenshots inside the app still work.
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        pageFor(intent)?.let { p -> nav?.invokeMethod("open", p) ?: run { pendingPage = p } }
    }

    override fun onResume() {
        super.onResume()
        KeystoreServer.inFront(this)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        scanner?.onPermission(requestCode, grantResults.firstOrNull() == android.content.pm.PackageManager.PERMISSION_GRANTED)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        scanner = QrScanner(this, flutterEngine)
        nav = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "symbolon/nav").apply {
            setMethodCallHandler { call, result ->
                if (call.method == "take") { result.success(pendingPage); pendingPage = null } else result.notImplemented()
            }
        }
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "symbolon/platform").setMethodCallHandler { call, result ->
            if (Biometric.handle(this, call, result)) return@setMethodCallHandler
            when (call.method) {
                "paths" -> result.success(platformPaths(this))
                "keystore" -> result.success(KeystoreServer.info(this))
                // The current network's DNS servers: Android has no
                // /etc/resolv.conf, so the agent is told (RESID_RESOLV_CONF).
                "dnsServers" -> result.success(dnsServers(this))
                // Android autofill (SPEC 22.6): whether Symbolon is the service,
                // the system page to choose it, and the apps a login may be linked to.
                "autofillEnabled" -> result.success(Build.VERSION.SDK_INT >= 26 &&
                    getSystemService(android.view.autofill.AutofillManager::class.java)?.hasEnabledAutofillServices() == true)
                "openAutofillSettings" -> {
                    startActivity(Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(android.net.Uri.parse("package:$packageName")))
                    result.success(true)
                }
                "installedApps" -> if (Build.VERSION.SDK_INT < 26) result.success(emptyList<Any>())
                    else Thread { val a = AutofillCore.installedApps(this); runOnUiThread { result.success(a) } }.start()
                // A secret for the clipboard, marked sensitive: Android 13+
                // then keeps it out of the copy preview and the keyboard's
                // clipboard suggestions. False before 13 (the Dart side copies).
                "copySensitive" -> {
                    if (Build.VERSION.SDK_INT >= 33) {
                        val clip = android.content.ClipData.newPlainText("Symbolon", call.arguments as String)
                        clip.description.extras = android.os.PersistableBundle().apply {
                            putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
                        }
                        (getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager).setPrimaryClip(clip)
                        result.success(true)
                    } else result.success(false)
                }
                // What the organization's device management set (res/xml/app_restrictions.xml).
                "managedConfig" -> {
                    val b = (getSystemService(android.content.Context.RESTRICTIONS_SERVICE) as android.content.RestrictionsManager).applicationRestrictions
                    result.success(mapOf(
                        "org_id" to (b.getString("org_id") ?: ""),
                        "org_founder" to (b.getString("org_founder") ?: ""),
                        "invite_code" to (b.getString("invite_code") ?: ""),
                        "disable_duress" to b.getBoolean("disable_duress", false),
                    ))
                }
                // Android 14+: whether passkey providers can be chosen, and
                // the system page where the user turns Symbolon on.
                "providerSupported" -> result.success(Build.VERSION.SDK_INT >= 34)
                "providerEnabled" -> result.success(Build.VERSION.SDK_INT >= 34 &&
                    getSystemService(android.credentials.CredentialManager::class.java)
                        .isEnabledCredentialProviderService(ComponentName(this, SymbolonCredentialService::class.java)))
                "openProviderSettings" -> {
                    if (Build.VERSION.SDK_INT >= 34) {
                        CredentialManager.create(this).createSettingsPendingIntent().send()
                        result.success(true)
                    } else result.success(false)
                }
                // Debug builds: this app asks the system for a passkey, as a
                // site's app would, to try the provider end to end.
                "testCreate" -> CredentialManager.create(this).createCredentialAsync(this, CreatePublicKeyCredentialRequest(call.arguments as String),
                    CancellationSignal(), mainExecutor, object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
                        override fun onResult(r: CreateCredentialResponse) = result.success((r as CreatePublicKeyCredentialResponse).registrationResponseJson)
                        override fun onError(e: CreateCredentialException) = result.error(e.type, e.message, null)
                    })
                "testGet" -> CredentialManager.create(this).getCredentialAsync(this, GetCredentialRequest(listOf(GetPublicKeyCredentialOption(call.arguments as String))),
                    CancellationSignal(), mainExecutor, object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                        override fun onResult(r: GetCredentialResponse) = result.success((r.credential as PublicKeyCredential).authenticationResponseJson)
                        override fun onError(e: GetCredentialException) = result.error(e.type, e.message, null)
                    })
                else -> result.notImplemented()
            }
        }
    }
}

fun dnsServers(a: android.content.Context): List<String> {
    if (Build.VERSION.SDK_INT < 23) return emptyList()
    val cm = a.getSystemService(android.net.ConnectivityManager::class.java) ?: return emptyList()
    val net = cm.activeNetwork ?: return emptyList()
    // IPv4 first; a link-local IPv6 server needs a scope the agent cannot name.
    val all = cm.getLinkProperties(net)?.dnsServers ?: return emptyList()
    return all.filter { !it.isLinkLocalAddress }.sortedBy { if (it is java.net.Inet4Address) 0 else 1 }.mapNotNull { it.hostAddress }
}

fun platformPaths(a: android.content.Context) = mapOf(
    "nativeLibraryDir" to a.applicationInfo.nativeLibraryDir,
    "filesDir" to a.filesDir.absolutePath,
)
