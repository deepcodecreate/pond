package com.pond.inspector.scan

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.pond.inspector.MainActivity
import com.pond.inspector.R

class ScanNotifier(private val context: Context) {
    private val manager = context.getSystemService(NotificationManager::class.java)

    fun ensureChannel() {
        if (Build.VERSION.SDK_INT < 26) return
        val channel = NotificationChannel(
            CHANNEL,
            context.getString(R.string.channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.description = context.getString(R.string.channel_desc)
        manager.createNotificationChannel(channel)
    }

    fun progress(done: Int, total: Int) {
        if (!manager.areNotificationsEnabled()) return
        ensureChannel()
        val notification = base(context.getString(R.string.notif_running, done, total))
            .setOngoing(true)
            .setProgress(total.coerceAtLeast(1), done, false)
            .build()
        manager.notify(ID, notification)
    }

    fun finish(attention: Int) {
        if (!manager.areNotificationsEnabled()) return
        ensureChannel()
        val text = if (attention == 0) {
            context.getString(R.string.notif_clean)
        } else {
            context.getString(R.string.notif_done, attention)
        }
        manager.notify(ID, base(text).setOngoing(false).build())
    }

    fun cancel() {
        manager.cancel(ID)
    }

    private fun base(text: String): NotificationCompat.Builder {
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
    }

    private companion object {
        const val CHANNEL = "pond.scan"
        const val ID = 42
    }
}
