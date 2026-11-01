package dev.symbolon.symbolon_ui

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// Unlock with a fingerprint or face (or the phone's own screen lock): the
// Symbolon PIN is kept on the phone encrypted under a Keystore AES key
// that works only for a few seconds after the user proves they are there,
// and dies when a new fingerprint is enrolled (then the PIN is asked again).
//
// On a phone with a screen lock, the agent's Keystore keys are bound the
// same way (KeystoreServer), so every unlock or signature needs a recent
// check of the person, not only an unlocked phone.
object Biometric {
    private const val ALIAS = "symbolon-pin"
    private const val AUTH_SECONDS = 30
    const val AUTHENTICATORS = BIOMETRIC_STRONG or DEVICE_CREDENTIAL

    // Android 11+ with a secure lock screen: keys can require a fresh
    // biometric or screen-lock check.
    fun supported(c: Context): Boolean =
        Build.VERSION.SDK_INT >= 30 && (c.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

    fun hasBiometric(c: Context): Boolean = BiometricManager.from(c).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private fun pinFile(c: Context) = File(c.filesDir, "pin.enc")

    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(): SecretKey {
        (store().getKey(ALIAS, null) as SecretKey?)?.let { return it }
        val b = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) b.setUserAuthenticationParameters(AUTH_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run { init(b.build()); generateKey() }
    }

    // Shows the system prompt; then `done(true)` once the person is
    // verified, `done(false)` when they cancel or fail.
    fun authenticate(a: FragmentActivity, title: String, subtitle: String, done: (Boolean, String?) -> Unit) {
        val info = BiometricPrompt.PromptInfo.Builder().setTitle(title).setSubtitle(subtitle).setAllowedAuthenticators(AUTHENTICATORS).build()
        BiometricPrompt(a, ContextCompat.getMainExecutor(a), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) = done(true, null)
            override fun onAuthenticationError(code: Int, msg: CharSequence) = done(false, msg.toString())
        }).authenticate(info)
    }

    private fun encrypt(pin: String): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        return c.iv + c.doFinal(pin.toByteArray())
    }

    private fun decrypt(b: ByteArray): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b.copyOfRange(0, 12))) }
        return String(c.doFinal(b.copyOfRange(12, b.size)))
    }

    // The channel's methods (both activities):
    //   bioState      {supported, biometric, enrolled}
    //   bioEnroll     (pin) prompt, then keep the PIN encrypted
    //   bioUnlock     prompt, then the PIN; null when cancelled or the
    //                 key was invalidated (a new fingerprint: PIN again)
    //   bioAuthenticate  prompt only (the agent's keys need a recent check)
    //   bioForget
    fun handle(a: FragmentActivity, call: MethodCall, result: MethodChannel.Result): Boolean {
        when (call.method) {
            "bioState" -> result.success(mapOf("supported" to supported(a), "biometric" to hasBiometric(a), "enrolled" to pinFile(a).exists()))
            "bioEnroll" -> {
                val pin = call.argument<String>("pin") ?: return result.error("bio", "no PIN", null).let { true }
                authenticate(a, "Unlock Symbolon with your fingerprint", "Confirm it's you") { ok, err ->
                    if (!ok) result.error("cancelled", err, null)
                    else try {
                        pinFile(a).writeBytes(encrypt(pin))
                        result.success(true)
                    } catch (e: Exception) {
                        result.error("bio", e.message, null)
                    }
                }
            }
            "bioUnlock" -> {
                val f = pinFile(a)
                if (!f.exists()) return result.success(null).let { true }
                authenticate(a, "Unlock Symbolon", call.argument<String>("reason") ?: "Confirm it's you") { ok, err ->
                    if (!ok) result.error("cancelled", err, null)
                    else try {
                        result.success(decrypt(f.readBytes()))
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        f.delete()
                        store().deleteEntry(ALIAS)
                        result.success(null)
                    } catch (e: Exception) {
                        result.error("bio", e.message, null)
                    }
                }
            }
            "bioAuthenticate" -> authenticate(a, "Confirm it's you", call.argument<String>("reason") ?: "Symbolon needs to check it's you") { ok, err ->
                if (ok) result.success(true) else result.error("cancelled", err, null)
            }
            "bioForget" -> {
                pinFile(a).delete()
                store().deleteEntry(ALIAS)
                result.success(true)
            }
            else -> return false
        }
        return true
    }
}
