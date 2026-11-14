package com.pond.inspector.ui.components

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.core.content.ContextCompat

fun copyToClipboard(context: Context, label: String, text: String) {
    val manager = context.getSystemService(ClipboardManager::class.java) ?: return
    manager.setPrimaryClip(ClipData.newPlainText(label, text))
    if (Build.VERSION.SDK_INT < 33) {
        Toast.makeText(context, label, Toast.LENGTH_SHORT).show()
    }
}

fun shareText(context: Context, text: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    val chooser = Intent.createChooser(send, null).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(chooser)
}

fun needsNotificationPermission(context: Context): Boolean =
    Build.VERSION.SDK_INT >= 33 &&
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
        PackageManager.PERMISSION_GRANTED

fun openUrl(context: Context, url: String) {
    val view = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(view)
    } catch (_: Exception) {
        copyToClipboard(context, url, url)
    }
}

const val GITHUB_URL = "https://github.com/deepcodecreate"
