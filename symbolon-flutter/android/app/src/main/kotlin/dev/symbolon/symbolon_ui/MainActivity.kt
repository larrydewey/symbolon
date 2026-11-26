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
import androidx.credentials.providerevents.ProviderEventsManager
import androidx.credentials.providerevents.exception.ImportCredentialsCancellationException
import androidx.credentials.providerevents.exception.ImportCredentialsException
import androidx.credentials.providerevents.exception.ImportCredentialsNoExportOptionException
import androidx.credentials.providerevents.exception.ImportCredentialsProviderConfigurationException
import androidx.credentials.providerevents.exception.ImportCredentialsUnknownErrorException
import androidx.credentials.providerevents.transfer.CredentialTypes
import androidx.credentials.providerevents.transfer.ImportCredentialsRequest
import androidx.credentials.providerevents.transfer.ProviderImportCredentialsResponse
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
        // The recent-apps screen keeps a picture of the app as it was left,
        // taken before the app locks (an open vault item, a password shown).
        // Android 13+ shows a blank one instead, and screenshots inside the
        // app still work. Before 13 that cannot be turned off alone, so the
        // window is FLAG_SECURE there: no recents picture, and no
        // screenshots or screen recording either.
        if (Build.VERSION.SDK_INT < 33) window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
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
                // Duress alerts (SPEC 14.4): the last known location for the
                // unlock beacon, the permission for it (asked when alerts are
                // set up), and the household alert check (AlertWorker.kt).
                "lastLocation" -> result.success(AlertWorker.lastLocation(this))
                "askLocation" -> {
                    if (Build.VERSION.SDK_INT >= 23) requestPermissions(arrayOf(android.Manifest.permission.ACCESS_FINE_LOCATION, android.Manifest.permission.ACCESS_COARSE_LOCATION), 7301)
                    result.success(true)
                }
                "watchAlerts" -> {
                    if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 7302)
                    AlertWorker.watch(this, call.arguments as String)
                    result.success(true)
                }
                "checkAlerts" -> {
                    val dir = call.arguments as String
                    Thread { AlertWorker.check(applicationContext, dir); runOnUiThread { result.success(true) } }.start()
                }
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
                // Every copy (widgets.dart copyText). A secret is marked
                // sensitive and cleared after 30 s (SPEC 22.2), see Clip.
                "copy" -> {
                    Clip.copy(this, call.argument<String>("value") ?: "", call.argument<Boolean>("secret") == true)
                    result.success(true)
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
                // Credential Exchange: another app on this phone (Google
                // Password Manager, 1Password, Bitwarden...) hands its items
                // over after the person picks it and confirms. The answer
                // is the CXF JSON, for the agent (--format cxf).
                "importCredentials" -> if (Build.VERSION.SDK_INT < 26) result.error("unsupported", "Android 8 or later is needed", null)
                    else ProviderEventsManager.create(this).importCredentialsAsync(this,
                        ImportCredentialsRequest(setOf(CredentialTypes.CREDENTIAL_TYPE_BASIC_AUTH, CredentialTypes.CREDENTIAL_TYPE_PUBLIC_KEY,
                            CredentialTypes.CREDENTIAL_TYPE_TOTP, CredentialTypes.CREDENTIAL_TYPE_NOTE, CredentialTypes.CREDENTIAL_TYPE_CREDIT_CARD,
                            CredentialTypes.CREDENTIAL_TYPE_ADDRESS, CredentialTypes.CREDENTIAL_TYPE_SSH_KEY, CredentialTypes.CREDENTIAL_TYPE_CUSTOM_FIELDS,
                            CredentialTypes.CREDENTIAL_TYPE_WIFI, CredentialTypes.CREDENTIAL_TYPE_API_KEY, CredentialTypes.CREDENTIAL_TYPE_IDENTITY_DOCUMENT,
                            CredentialTypes.CREDENTIAL_TYPE_PASSPORT, CredentialTypes.CREDENTIAL_TYPE_DRIVERS_LICENSE, CredentialTypes.CREDENTIAL_TYPE_PERSON_NAME,
                            CredentialTypes.CREDENTIAL_TYPE_GENERATED_PASSWORD), emptySet()),
                        CancellationSignal(), mainExecutor, object : CredentialManagerCallback<ProviderImportCredentialsResponse, ImportCredentialsException> {
                            override fun onResult(r: ProviderImportCredentialsResponse) = result.success(r.response.responseJson)
                            override fun onError(e: ImportCredentialsException) = result.error(when {
                                // Backing out of the system's picker can arrive as an unknown error with no message.
                                e is ImportCredentialsCancellationException || (e is ImportCredentialsUnknownErrorException && e.message == null) -> "cancelled"
                                e is ImportCredentialsNoExportOptionException -> "none"
                                e is ImportCredentialsProviderConfigurationException -> "unavailable"
                                else -> "error"
                            }, e.message, null)
                        })
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

/**
 * The app's clipboard copies. Android 10+ lets an app in the background
 * write the clipboard but not read it, so the clear is scheduled here and
 * does not read the clipboard first: 30 s after a secret is copied, the
 * clipboard is cleared, whatever it then holds, unless this app copied
 * something else meanwhile. (A copy made in another app within those 30 s
 * is cleared too; leaving the secret there is worse.)
 */
object Clip {
    private val main = android.os.Handler(android.os.Looper.getMainLooper())
    private var clear: Runnable? = null
    const val KEEP_MS = 30_000L

    fun copy(c: android.content.Context, value: String, secret: Boolean) {
        val app = c.applicationContext
        val cm = app.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val clip = android.content.ClipData.newPlainText("Symbolon", value)
        // Keeps it out of the copy preview and the keyboard's clipboard
        // suggestions: the platform constant from Android 13, the same key
        // before (honoured by some keyboards and OEM builds).
        if (secret && Build.VERSION.SDK_INT >= 24) {
            clip.description.extras = android.os.PersistableBundle().apply {
                putBoolean(if (Build.VERSION.SDK_INT >= 33) android.content.ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
            }
        }
        clear?.let { main.removeCallbacks(it) }
        clear = null
        cm.setPrimaryClip(clip)
        if (!secret) return
        val r = Runnable {
            clear = null
            try {
                if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip()
                else cm.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
            } catch (_: Exception) {
            }
        }
        clear = r
        main.postDelayed(r, KEEP_MS)
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
