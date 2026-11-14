package com.pond.inspector.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cloud
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Sync
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.pond.inspector.PondViewModel
import com.pond.inspector.model.DetectorIds
import com.pond.inspector.scan.Catalog
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.components.PondCard
import com.pond.inspector.ui.components.PondTopBar
import com.pond.inspector.ui.components.SectionTitle
import com.pond.inspector.ui.components.SwitchRow
import com.pond.inspector.ui.components.needsNotificationPermission
import com.pond.inspector.ui.components.rememberHaptic
import com.pond.inspector.ui.components.withExtra
import com.pond.inspector.ui.num
import com.pond.inspector.ui.text
import com.pond.inspector.ui.tr

@Composable
fun ScanSettingsScreen(vm: PondViewModel, onBack: () -> Unit) {
    val prefs by vm.scan.collectAsStateWithLifecycle()
    val s = prefs ?: return
    val pad = LocalPad.current
    val context = LocalContext.current
    val haptic = rememberHaptic()
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()

    val notificationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) vm.updateScan { it.copy(notifications = true) }
    }

    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = { PondTopBar(tr("Scanning", "اسکن"), scroll, onBack) },
    ) { inner ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = inner.withExtra(horizontal = pad, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(pad * 0.75f),
        ) {
            item { SectionTitle(tr("Behavior", "رفتار")) }
            item {
                PondCard {
                    SwitchRow(
                        title = tr("Scan on launch", "اسکن هنگام باز شدن"),
                        subtitle = tr("Run all enabled checks when the app opens", "با باز شدن برنامه همهٔ بررسی‌های فعال اجرا شود"),
                        icon = Icons.Rounded.PlayArrow,
                        checked = s.autoScan,
                        onChange = { value -> vm.updateScan { it.copy(autoScan = value) } },
                    )
                    SwitchRow(
                        title = tr("Result notification", "اعلان نتیجه"),
                        subtitle = tr("Notify when a scan finishes", "پس از پایان اسکن اعلان بدهد"),
                        icon = Icons.Rounded.Notifications,
                        checked = s.notifications,
                        onChange = { value ->
                            if (value && needsNotificationPermission(context)) {
                                notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                            } else {
                                vm.updateScan { it.copy(notifications = value) }
                            }
                        },
                    )
                    SwitchRow(
                        title = tr("Live progress", "پیشرفت زنده"),
                        subtitle = tr("Show a progress notification while scanning", "هنگام اسکن اعلان پیشرفت نشان بدهد"),
                        icon = Icons.Rounded.Sync,
                        checked = s.liveUpdate,
                        onChange = { value ->
                            if (value && needsNotificationPermission(context)) {
                                notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                            }
                            vm.updateScan { it.copy(liveUpdate = value) }
                        },
                    )
                    SwitchRow(
                        title = tr("Refresh Google revocation list", "تازه‌سازی فهرست ابطال گوگل"),
                        subtitle = tr(
                            "The TEE check downloads Google's public list. No certificate is uploaded.",
                            "بررسی TEE فهرست عمومی گوگل را دانلود می‌کند. گواهی‌ای آپلود نمی‌شود.",
                        ),
                        icon = Icons.Rounded.Cloud,
                        checked = s.onlineCrl,
                        onChange = { value -> vm.updateScan { it.copy(onlineCrl = value) } },
                    )
                }
            }

            item {
                SectionTitle(
                    tr("Checks", "بررسی‌ها") + "  ·  " + num(s.enabled.size) + " / " + num(Catalog.all.size),
                )
            }
            item {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FilledTonalButton(
                        onClick = {
                            haptic.tap()
                            vm.updateScan { it.copy(enabled = DetectorIds.all) }
                        },
                        modifier = Modifier.weight(1f),
                    ) { Text(tr("Enable all", "فعال‌سازی همه")) }
                    OutlinedButton(
                        onClick = {
                            haptic.tap()
                            vm.updateScan { it.copy(enabled = emptySet()) }
                        },
                        modifier = Modifier.weight(1f),
                    ) { Text(tr("Disable all", "غیرفعال‌سازی همه")) }
                }
            }
            item {
                PondCard {
                    Catalog.all.forEach { detector ->
                        SwitchRow(
                            title = detector.title.text(),
                            checked = detector.id in s.enabled,
                            onChange = { value ->
                                vm.updateScan {
                                    it.copy(
                                        enabled = if (value) it.enabled + detector.id else it.enabled - detector.id,
                                    )
                                }
                            },
                        )
                    }
                }
            }
            item {
                Text(
                    tr("Changes apply to the next scan.", "تغییرات در اسکن بعدی اعمال می‌شوند."),
                    modifier = Modifier.padding(horizontal = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
