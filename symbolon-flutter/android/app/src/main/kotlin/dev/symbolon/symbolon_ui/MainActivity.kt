package dev.symbolon.symbolon_ui

import android.content.ComponentName
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
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "symbolon/platform").setMethodCallHandler { call, result ->
            if (Biometric.handle(this, call, result)) return@setMethodCallHandler
            when (call.method) {
                "paths" -> result.success(platformPaths(this))
                "keystore" -> result.success(KeystoreServer.info(this))
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

fun platformPaths(a: android.content.Context) = mapOf(
    "nativeLibraryDir" to a.applicationInfo.nativeLibraryDir,
    "filesDir" to a.filesDir.absolutePath,
)
