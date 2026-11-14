package com.pond.inspector.ui.screens

import com.pond.inspector.ui.components.pondIconButtonColors
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
import com.pond.inspector.logic.displayValue
import com.pond.inspector.ui.LocalBarInset
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.LocalPersian
import com.pond.inspector.ui.components.EvidenceRow
import com.pond.inspector.ui.components.PondCard
import com.pond.inspector.ui.components.PondTopBar
import com.pond.inspector.ui.components.copyToClipboard
import com.pond.inspector.ui.components.rememberHaptic
import com.pond.inspector.ui.components.tabInsets
import com.pond.inspector.ui.components.withExtra
import com.pond.inspector.ui.tr

@Composable
fun DeviceScreen(vm: PondViewModel) {
    val rows by vm.device.collectAsStateWithLifecycle()
    val pad = LocalPad.current
    val persian = LocalPersian.current
    val context = LocalContext.current
    val haptic = rememberHaptic()
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    val copied = tr("Copied", "کپی شد")

    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        contentWindowInsets = tabInsets(),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = {
            PondTopBar(
                title = tr("Device", "دستگاه"),
                scrollBehavior = scroll,
                actions = {
                    FilledTonalIconButton(
                        colors = pondIconButtonColors(),onClick = {
                        haptic.tap()
                        vm.refreshDevice()
                    }) {
                        Icon(Icons.Rounded.Refresh, contentDescription = tr("Refresh", "تازه‌سازی"))
                    }
                    FilledTonalIconButton(
                        colors = pondIconButtonColors(),
                        onClick = {
                            haptic.confirm()
                            val text = rows.joinToString("\n") {
                                "${it.label.get(persian)}: ${displayValue(it.value, persian)}"
                            }
                            copyToClipboard(context, copied, text)
                        },
                        enabled = rows.isNotEmpty(),
                    ) {
                        Icon(Icons.Rounded.ContentCopy, contentDescription = tr("Copy all", "کپی همه"))
                    }
                },
            )
        },
    ) { inner ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = inner.withExtra(horizontal = pad, top = 4.dp, bottom = LocalBarInset.current + 16.dp),
            verticalArrangement = Arrangement.spacedBy(pad * 0.75f),
        ) {
            item {
                PondCard {
                    rows.forEachIndexed { index, row ->
                        if (index > 0) {
                            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                        }
                        EvidenceRow(row)
                    }
                }
            }
            item {
                Text(
                    tr("Long-press a value to copy it.", "برای کپی کردن، روی مقدار نگه دارید."),
                    modifier = Modifier.padding(horizontal = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
