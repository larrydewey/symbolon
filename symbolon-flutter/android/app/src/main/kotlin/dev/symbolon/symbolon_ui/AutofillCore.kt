package dev.symbolon.symbolon_ui

import android.app.assist.AssistStructure
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

// What Android autofill asks about (SPEC 22.6): which fields a screen has,
// by the kinds the agent knows, and who is asking. Nothing here reads a
// value from the vault.

/** One field to fill: its kind (an autocomplete token) and its id. */
data class Found(val kind: String, val id: AutofillId)

/** The requester: the app holding the focused field, as the platform reports it. */
data class Requester(
    val pkg: String,
    val label: String,
    val certs: List<String>,        // SHA-256 of each signing certificate, lower-case hex
    val installer: String,          // the package that installed it, "" when unknown
    val origin: String,             // a privileged browser's page origin, else ""
) {
    /** The app's identity: android:apk-key-hash: and the base64url SHA-256 of its first signer. */
    val apkKeyHash: String
        get() = if (certs.isEmpty()) "" else "android:apk-key-hash:" + android.util.Base64.encodeToString(
            certs[0].chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
            android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP,
        )
}

@androidx.annotation.RequiresApi(26)
object AutofillCore {
    val LOGIN = setOf("username", "email", "current-password", "new-password", "one-time-code")
    val CARD = setOf("cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc")

    // Autofill hints (View and androidx HintConstants) to our kinds.
    private val HINTS = mapOf(
        "username" to "username", "newusername" to "username", "emailaddress" to "email", "email" to "email",
        "password" to "current-password", "currentpassword" to "current-password", "current-password" to "current-password",
        "newpassword" to "new-password", "new-password" to "new-password",
        "smsotpcode" to "one-time-code", "2faappotpcode" to "one-time-code", "one-time-code" to "one-time-code",
        "creditcardnumber" to "cc-number", "cc-number" to "cc-number",
        "creditcardsecuritycode" to "cc-csc", "cc-csc" to "cc-csc",
        "creditcardexpirationdate" to "cc-exp", "cc-exp" to "cc-exp",
        "creditcardexpirationmonth" to "cc-exp-month", "cc-exp-month" to "cc-exp-month",
        "creditcardexpirationyear" to "cc-exp-year", "cc-exp-year" to "cc-exp-year",
        "cc-name" to "cc-name", "creditcardholdername" to "cc-name",
    )

    private val NEW_PASSWORD = Regex("new.?pass|confirm|repeat|retype|re.?enter|again|choose|create", RegexOption.IGNORE_CASE)
    private val OTP = Regex("\\b(otp|totp|2fa|mfa)\\b|one.?time.?(code|pass)|verification.?code|auth(entication|enticator)?.?code|two.?factor", RegexOption.IGNORE_CASE)
    private val USER = Regex("user.?name|login|e.?mail|account|identifier", RegexOption.IGNORE_CASE)

    /**
     * The fields of the screen: visible text fields we can classify, and the
     * page they are on ("scheme://domain" as the browser reports it, "" for
     * an app's own views).
     *
     * The page is the focused field's, else the first classified field's.
     * Each field's page is the nearest web domain at or above it, so a frame
     * of another site inside the page has its own; only the fields of the
     * page itself are kept, never a frame's of another site (SPEC 22.2). The
     * scheme is the node's own (API 28+); where the browser does not give
     * one it is left "?", unknown, and [originOf] then names no page: http
     * is never taken for https (SPEC 22.5 step 4).
     */
    fun fields(s: AssistStructure): Pair<List<Found>, String> {
        val all = mutableListOf<Pair<Found, String>>()
        var focused: String? = null
        fun walk(n: AssistStructure.ViewNode, above: String) {
            val d = n.webDomain
            val here = if (d.isNullOrEmpty()) above else {
                val scheme = (if (Build.VERSION.SDK_INT >= 28) n.webScheme else null)?.lowercase()
                (if (scheme.isNullOrEmpty()) "?" else scheme) + "://" + d.lowercase()
            }
            val id = n.autofillId
            // Only visible fields: a hidden field is how a screen collects
            // more than it shows (SPEC 22.6 item 1).
            if (id != null && n.visibility == View.VISIBLE && n.autofillType == View.AUTOFILL_TYPE_TEXT) kindOf(n)?.let {
                all += Pair(Found(it, id), here)
                if (n.isFocused && focused == null) focused = here
            }
            for (i in 0 until n.childCount) walk(n.getChildAt(i), here)
        }
        for (i in 0 until s.windowNodeCount) walk(s.getWindowNodeAt(i).rootViewNode, "")
        val web = focused ?: all.firstOrNull()?.second ?: ""
        return Pair(samePage(all, web), web)
    }

    /** The fields of [all] on the page [web], the only ones a fill may reach. */
    fun samePage(all: List<Pair<Found, String>>, web: String): List<Found> = all.filter { it.second == web }.map { it.first }

    private fun text(n: AssistStructure.ViewNode): String =
        listOfNotNull(n.idEntry, n.hint?.toString(), n.contentDescription?.toString(),
            n.htmlInfo?.attributes?.firstOrNull { it.first == "name" }?.second,
            n.htmlInfo?.attributes?.firstOrNull { it.first == "id" }?.second).joinToString(" ")

    fun kindOf(n: AssistStructure.ViewNode): String? {
        n.autofillHints?.forEach { h -> HINTS[h.lowercase().replace("_", "")]?.let { return it } }
        val html = n.htmlInfo?.attributes
        html?.firstOrNull { it.first == "autocomplete" }?.second?.lowercase()?.split(Regex("\\s+"))?.lastOrNull()?.let { t ->
            if (t in LOGIN || t in CARD) return t
        }
        val t = text(n)
        val htmlType = html?.firstOrNull { it.first == "type" }?.second?.lowercase()
        val cls = n.inputType and InputType.TYPE_MASK_CLASS
        val variation = n.inputType and InputType.TYPE_MASK_VARIATION
        val password = htmlType == "password" ||
            (cls == InputType.TYPE_CLASS_TEXT && variation in setOf(InputType.TYPE_TEXT_VARIATION_PASSWORD, InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD, InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)) ||
            (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD)
        if (password) return if (NEW_PASSWORD.containsMatchIn(t)) "new-password" else "current-password"
        if (OTP.containsMatchIn(t)) return "one-time-code"
        val email = htmlType == "email" || (cls == InputType.TYPE_CLASS_TEXT && variation in setOf(InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS, InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS))
        if (email) return "email"
        if (USER.containsMatchIn(t)) return "username"
        return null
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    /** The requester for [pkg]; [web] is the page a browser reported, kept only for a privileged browser. */
    fun requester(c: Context, pkg: String, web: String): Requester {
        val pm = c.packageManager
        val certs = try {
            if (Build.VERSION.SDK_INT >= 28) {
                val si = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
                (si?.apkContentsSigners ?: emptyArray()).map { hex(sha256(it.toByteArray())) }
            } else {
                @Suppress("DEPRECATION")
                (pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures ?: emptyArray()).map { hex(sha256(it.toByteArray())) }
            }
        } catch (_: Exception) { emptyList() }
        val label = try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() } catch (_: Exception) { pkg }
        val installer = try {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName ?: "" else @Suppress("DEPRECATION") (pm.getInstallerPackageName(pkg) ?: "")
        } catch (_: Exception) { "" }
        val origin = if (web.isNotEmpty() && privilegedBrowser(c, pkg, certs)) originOf(web) else ""
        return Requester(pkg, label, certs, installer, origin)
    }

    // https://host[:port] in lower case; http only on loopback (SPEC 22.5
    // step 4). Any other scheme, or one the browser did not give ("?"),
    // names no page: "", so no login for a site is offered.
    fun originOf(web: String): String {
        val cut = web.indexOf("://")
        if (cut <= 0) return ""
        val scheme = web.substring(0, cut).lowercase()
        val hp = web.substring(cut + 3).lowercase()
        if (hp.isEmpty() || !hp.all { it in "abcdefghijklmnopqrstuvwxyz0123456789.-:" }) return ""
        val parts = hp.split(":")
        if (parts.size > 2 || parts[0].isEmpty() || (parts.size == 2 && (parts[1].isEmpty() || parts[1].length > 5 || !parts[1].all { it.isDigit() }))) return ""
        val host = parts[0]
        return when {
            scheme == "https" -> "https://$hp"
            scheme == "http" && (host == "localhost" || host == "127.0.0.1") -> "http://$hp"
            else -> ""
        }
    }

    /** Whether [pkg], signed by one of [certs], is on the privileged-browser list (22.1). */
    fun privilegedBrowser(c: Context, pkg: String, certs: List<String>): Boolean {
        val apps = JSONObject(c.assets.open("privileged_browsers.json").bufferedReader().readText()).getJSONArray("apps")
        for (i in 0 until apps.length()) {
            val info = apps.getJSONObject(i).getJSONObject("info")
            if (info.getString("package_name") != pkg) continue
            val sigs = info.getJSONArray("signatures")
            for (j in 0 until sigs.length()) {
                val f = sigs.getJSONObject(j).getString("cert_fingerprint_sha256").replace(":", "").lowercase()
                if (f in certs) return true
            }
        }
        return false
    }

    /**
     * The sites [pkg] says it shares logins with: its manifest's
     * asset_statements (the statements a site's Digital Asset Links must
     * confirm, SPEC 22.6 item 3). Only these are looked up, never every
     * site in the vault.
     */
    fun claimedSites(c: Context, pkg: String): List<String> {
        val pm = c.packageManager
        return try {
            val ai = pm.getApplicationInfo(pkg, PackageManager.GET_META_DATA)
            val res = ai.metaData?.getInt("asset_statements", 0) ?: 0
            if (res == 0) return emptyList()
            val arr = JSONArray(pm.getResourcesForApplication(ai).getString(res))
            val out = mutableSetOf<String>()
            for (i in 0 until arr.length()) {
                val st = arr.getJSONObject(i)
                val url = st.optString("include").ifEmpty { st.optJSONObject("target")?.optString("site") ?: "" }
                val host = try { android.net.Uri.parse(url).host?.lowercase() } catch (_: Exception) { null }
                if (!host.isNullOrEmpty() && url.startsWith("https://")) out += host
            }
            out.toList().take(8)
        } catch (_: Exception) { emptyList() }
    }

    /** The apps a person may link a login to: launchable ones, with their identity. */
    fun installedApps(c: Context): List<Map<String, Any?>> {
        val pm = c.packageManager
        val launch = android.content.Intent(android.content.Intent.ACTION_MAIN).addCategory(android.content.Intent.CATEGORY_LAUNCHER)
        val pkgs = pm.queryIntentActivities(launch, 0).map { it.activityInfo.packageName }.toSet() - c.packageName
        return pkgs.map { p ->
            val r = requester(c, p, "")
            mapOf("package" to p, "label" to r.label, "certs" to r.certs, "installer" to r.installer)
        }.sortedBy { (it["label"] as String).lowercase() }
    }
}
