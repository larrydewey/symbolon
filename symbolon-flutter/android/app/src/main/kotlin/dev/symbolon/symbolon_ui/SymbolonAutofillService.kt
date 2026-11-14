package dev.symbolon.symbolon_ui

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.widget.RemoteViews

// Symbolon as Android's autofill service (SPEC 22.6). A fill request is
// answered without opening anything: one locked entry, "Fill with
// Symbolon", that names no item, account or site. Choosing it opens the
// fill screen (AutofillActivity), which shows the requester, opens the
// device and fills. After a form is sent, the system's own prompt may offer
// to save it; saving opens the same screen.
@androidx.annotation.RequiresApi(26)
class SymbolonAutofillService : AutofillService() {
    companion object {
        const val FILL = "dev.symbolon.AUTOFILL"
        const val SAVE = "dev.symbolon.AUTOFILL_SAVE"
        private var requests = 0
    }

    override fun onFillRequest(request: FillRequest, cancel: CancellationSignal, callback: FillCallback) {
        val s = request.fillContexts.last().structure
        val (found, web) = AutofillCore.fields(s)
        val pkg = s.activityComponent.packageName
        // Not Symbolon itself, and nothing for a screen with no field we fill.
        if (found.isEmpty() || pkg == packageName) return callback.onSuccess(null)
        val r = AutofillCore.requester(this, pkg, web)
        val i = Intent(this, AutofillActivity::class.java).setAction(FILL)
            .putExtras(AutofillActivity.extrasOf(r, found))
        val sender = PendingIntent.getActivity(this, ++requests, i, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender
        val entry = RemoteViews(packageName, R.layout.autofill_entry)
        val ids = found.map { it.id }.toTypedArray()
        val b = FillResponse.Builder().setAuthentication(ids, sender, entry)
        saveInfo(found)?.let { b.setSaveInfo(it) }
        callback.onSuccess(b.build())
    }

    // The system offers to save when a password field (and perhaps a
    // username) was filled in and the form went away.
    private fun saveInfo(found: List<Found>): SaveInfo? {
        val pw = found.filter { it.kind == "current-password" || it.kind == "new-password" }.map { it.id }
        if (pw.isEmpty()) return null
        val user = found.filter { it.kind == "username" || it.kind == "email" }.map { it.id }
        val b = SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (user.isEmpty()) 0 else SaveInfo.SAVE_DATA_TYPE_USERNAME), pw.toTypedArray())
        if (user.isNotEmpty()) b.setOptionalIds(user.toTypedArray())
        return b.build()
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        if (Build.VERSION.SDK_INT < 28) return callback.onFailure("Saving needs Android 9 or later")
        val s = request.fillContexts.last().structure
        val (found, web) = AutofillCore.fields(s)
        val values = HashMap<String, String>()
        fun walk(n: android.app.assist.AssistStructure.ViewNode) {
            val id = n.autofillId
            val f = found.firstOrNull { it.id == id }
            val v = n.autofillValue
            if (f != null && v != null && v.isText && v.textValue.isNotEmpty() && f.kind !in values) values[f.kind] = v.textValue.toString()
            for (i in 0 until n.childCount) walk(n.getChildAt(i))
        }
        for (i in 0 until s.windowNodeCount) walk(s.getWindowNodeAt(i).rootViewNode)
        val pw = values["new-password"] ?: values["current-password"]
        if (pw == null) return callback.onSuccess()
        val r = AutofillCore.requester(this, s.activityComponent.packageName, web)
        val i = Intent(this, AutofillActivity::class.java).setAction(SAVE)
            .putExtras(AutofillActivity.extrasOf(r, emptyList()))
            .putExtra("saveUser", values["username"] ?: values["email"] ?: "")
            .putExtra("savePassword", pw)
        val sender = PendingIntent.getActivity(this, ++requests, i, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE).intentSender
        callback.onSuccess(sender)
    }
}

/** Found fields to and from an intent: kinds and ids side by side. */
fun foundOf(kinds: ArrayList<String>?, ids: ArrayList<AutofillId>?): List<Found> =
    if (kinds == null || ids == null || kinds.size != ids.size) emptyList() else kinds.indices.map { Found(kinds[it], ids[it]) }
