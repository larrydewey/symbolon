package dev.symbolon.symbolon_ui

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import org.json.JSONObject
import java.io.File

// Symbolon as an Android passkey provider (SPEC 22.1). The system asks
// which passkeys Symbolon has for a site, and whether it can make one;
// Symbolon answers from the app's list of passkeys (public data in
// settings.json) without the PIN. Choosing an entry opens PasskeyActivity,
// which asks for the PIN, shows the site, and has the agent sign with the
// cosigner. Cross-device sign-in (a QR code on a computer) reaches here
// through the system too.
@RequiresApi(34)
class SymbolonCredentialService : CredentialProviderService() {

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onError(CreateCredentialUnknownException("Symbolon holds only passkeys"))
            return
        }
        val pi = PasskeyActivity.pending(this, PasskeyActivity.CREATE, null, null, requestCode = 1)
        callback.onResult(BeginCreateCredentialResponse(listOf(CreateEntry("Symbolon", pi))))
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val known = credentials()
        val entries = mutableListOf<CredentialEntry>()
        var code = 100
        for (option in request.beginGetCredentialOptions) {
            if (option !is BeginGetPublicKeyCredentialOption) continue
            val req = JSONObject(option.requestJson)
            val rp = req.optString("rpId")
            val allowed = req.optJSONArray("allowCredentials")?.let { a -> (0 until a.length()).map { a.getJSONObject(it).getString("id") }.toSet() }
            for (c in known) {
                if (c.rp != rp) continue
                if (allowed != null && allowed.isNotEmpty() && b64url(hex(c.id)) !in allowed) continue
                val pi = PasskeyActivity.pending(this, PasskeyActivity.GET, c.rp, c.id, requestCode = code++)
                entries.add(PublicKeyCredentialEntry.Builder(this, c.userName.ifEmpty { c.rp }, pi, option)
                    .setDisplayName(if (c.displayName.isNotEmpty()) c.displayName else c.rp).build())
            }
        }
        callback.onResult(BeginGetCredentialResponse(entries))
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) = callback.onResult(null)

    private data class Known(val rp: String, val id: String, val userName: String, val displayName: String)

    private fun credentials(): List<Known> {
        val f = File(filesDir, "settings.json")
        if (!f.exists()) return emptyList()
        return try {
            val a = JSONObject(f.readText()).optJSONArray("credentials") ?: return emptyList()
            (0 until a.length()).map { a.getJSONObject(it) }.map {
                Known(it.getString("rp"), it.getString("id"), it.optString("userName"), it.optString("displayName"))
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
}

fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

fun b64url(b: ByteArray): String = Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
