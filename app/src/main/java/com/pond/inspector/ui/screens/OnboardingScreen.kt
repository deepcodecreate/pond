package com.pond.inspector.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cloud
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.Sync
import androidx.compose.material3.Button
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.pond.inspector.PondViewModel
import com.pond.inspector.ui.LocalIconShape
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.LocalReduced
import com.pond.inspector.ui.components.PondCard
import com.pond.inspector.ui.components.SwitchRow
import com.pond.inspector.ui.components.needsNotificationPermission
import com.pond.inspector.ui.components.rememberHaptic
import com.pond.inspector.ui.theme.PondMark
import com.pond.inspector.ui.theme.iconShape
import com.pond.inspector.ui.tr

@Composable
fun OnboardingScreen(vm: PondViewModel, onDone: () -> Unit) {
    val pad = LocalPad.current
    val context = LocalContext.current
    val haptic = rememberHaptic()
    var notifications by remember { mutableStateOf(false) }
    var liveUpdate by remember { mutableStateOf(true) }
    var onlineCrl by remember { mutableStateOf(false) }

    fun finish() {
        vm.finishOnboarding(notifications, liveUpdate, onlineCrl)
        onDone()
    }

    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (!granted) {
            notifications = false
            liveUpdate = false
        }
        finish()
    }

    Box(
        Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surface)
            .windowInsetsPadding(WindowInsets.safeDrawing),
    ) {
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = pad.plus(8.dp), vertical = pad),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            Spacer(Modifier.height(24.dp))
            Box(
                Modifier
                    .size(132.dp)
                    .clip(iconShape(LocalIconShape.current))
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center,
            ) {
                CompositionLocalProvider(LocalContentColor provides MaterialTheme.colorScheme.onPrimaryContainer) {
                    PondMark(scanning = true, reduced = LocalReduced.current)
                }
            }
            Text(
                tr("Welcome to Pond", "به پاند خوش آمدید"),
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(
                tr(
                    "Pond reads the signals this device shows to an ordinary app and lays them out with their limits. Nothing leaves the device unless you allow it below.",
                    "پاند سیگنال‌هایی را که این دستگاه به یک اپ معمولی نشان می‌دهد می‌خواند و همراه با محدودیت‌هایشان نمایش می‌دهد. تا وقتی پایین اجازه ندهید چیزی از دستگاه بیرون نمی‌رود.",
                ),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            PondCard(Modifier.fillMaxWidth()) {
                SwitchRow(
                    title = tr("Result notification", "اعلان نتیجه"),
                    subtitle = tr("Notify when a scan finishes", "پس از پایان اسکن اعلان بدهد"),
                    icon = Icons.Rounded.Notifications,
                    checked = notifications,
                    onChange = { notifications = it },
                )
                SwitchRow(
                    title = tr("Live progress", "پیشرفت زنده"),
                    subtitle = tr("Show a progress notification while scanning", "هنگام اسکن اعلان پیشرفت نشان بدهد"),
                    icon = Icons.Rounded.Sync,
                    checked = liveUpdate,
                    onChange = { liveUpdate = it },
                )
                SwitchRow(
                    title = tr("Refresh Google revocation list", "تازه‌سازی فهرست ابطال گوگل"),
                    subtitle = tr(
                        "Downloads Google's public list. No certificate is uploaded.",
                        "فهرست عمومی گوگل را دانلود می‌کند. گواهی‌ای آپلود نمی‌شود.",
                    ),
                    icon = Icons.Rounded.Cloud,
                    checked = onlineCrl,
                    onChange = { onlineCrl = it },
                )
            }
            Button(
                onClick = {
                    haptic.confirm()
                    if ((notifications || liveUpdate) && needsNotificationPermission(context)) {
                        permission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                    } else {
                        finish()
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
            ) {
                Text(tr("Start first scan", "شروع اولین اسکن"))
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}
