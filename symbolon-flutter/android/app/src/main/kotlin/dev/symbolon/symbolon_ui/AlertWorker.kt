package dev.symbolon.symbolon_ui

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import java.io.File
import java.util.concurrent.TimeUnit

// Household duress alerts (SPEC 14.4): about every 15 minutes, and at every
// app start, the agent reads this device's alert inbox on the relay
// (`device alerts inbox DIR`, no PIN: the alert key is kept apart for it)
// and each new alert becomes a notification.
class AlertWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        val dir = inputData.getString("dir") ?: return Result.failure()
        check(applicationContext, dir)
        return Result.success()
    }

    companion object {
        private const val CHANNEL = "duress-alerts"
        private const val WORK = "symbolon-household-alerts"

        /** Starts the periodic check (kept across restarts by WorkManager). */
        fun watch(c: Context, dir: String) {
            val req = PeriodicWorkRequestBuilder<AlertWorker>(15, TimeUnit.MINUTES)
                .setInputData(workDataOf("dir" to dir))
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(c).enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.UPDATE, req)
        }

        /** Whether this device receives household alerts (DIR/alert-key). */
        fun registered(dir: String) = File(dir, "alert-key").exists()

        /** Runs the agent once and shows what it found. */
        fun check(c: Context, dir: String) {
            if (!registered(dir)) return
            val bin = File(c.applicationInfo.nativeLibraryDir, "libsymbolon.so").absolutePath
            val out = try {
                val p = ProcessBuilder(bin, "device", "alerts", "inbox", dir).redirectErrorStream(false).start()
                p.outputStream.close()
                val text = p.inputStream.bufferedReader().readText()
                if (!p.waitFor(120, TimeUnit.SECONDS)) { p.destroy(); return }
                text
            } catch (e: Exception) {
                return
            }
            out.lines().filter { it.startsWith("alert ") }.forEach { line ->
                val p = line.trim().split(" ")
                if (p.size == 3) show(c, unhex(p[1]), unhex(p[2]))
            }
        }

        private fun unhex(h: String): String =
            if (h == "-" || h.length % 2 != 0) "" else String(ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }, Charsets.UTF_8)

        private fun show(c: Context, subject: String, text: String) {
            val nm = c.getSystemService(NotificationManager::class.java)
            if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL) == null) {
                nm.createNotificationChannel(NotificationChannel(CHANNEL, "Duress alerts", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "When someone in your household unlocks Symbolon with their duress PIN"
                })
            }
            if (Build.VERSION.SDK_INT >= 33 && c.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
            val open = PendingIntent.getActivity(c, 0, Intent(c, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val n = NotificationCompat.Builder(c, CHANNEL)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(subject)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
            try {
                NotificationManagerCompat.from(c).notify((subject + text).hashCode(), n)
            } catch (e: SecurityException) {
                // notifications turned off
            }
        }

        /**
         * The phone's last known location as "LAT,LON,ACC,AGE" (1e-7 degrees,
         * meters, seconds), or "" without the permission or a fix. Only what
         * the system already has: no new fix, so no location indicator.
         */
        fun lastLocation(c: Context): String {
            val fine = c.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
            val coarse = c.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
            if (!fine && !coarse) return ""
            val lm = c.getSystemService(LocationManager::class.java) ?: return ""
            val best: Location = try {
                lm.getProviders(true).mapNotNull { lm.getLastKnownLocation(it) }.maxByOrNull { it.elapsedRealtimeNanos }
            } catch (e: SecurityException) {
                null
            } ?: return ""
            val ageS = ((android.os.SystemClock.elapsedRealtimeNanos() - best.elapsedRealtimeNanos) / 1_000_000_000L).coerceAtLeast(0)
            val lat = Math.round(best.latitude * 1e7)
            val lon = Math.round(best.longitude * 1e7)
            val acc = if (best.hasAccuracy()) Math.round(best.accuracy.toDouble()) else 0L
            return "$lat,$lon,$acc,$ageS"
        }
    }
}
