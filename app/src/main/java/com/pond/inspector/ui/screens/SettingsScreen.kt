package com.pond.inspector.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.unit.dp
import com.pond.inspector.ui.LocalBarInset
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.components.PondCard
import com.pond.inspector.ui.components.PondTopBar
import com.pond.inspector.ui.components.ShapeIcon
import com.pond.inspector.ui.components.tabInsets
import com.pond.inspector.ui.components.withExtra
import com.pond.inspector.ui.tr

@Composable
fun SettingsScreen(
    onAppearance: () -> Unit,
    onScan: () -> Unit,
    onAbout: () -> Unit,
) {
    val pad = LocalPad.current
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        contentWindowInsets = tabInsets(),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = { PondTopBar(tr("Settings", "تنظیمات"), scroll) },
    ) { inner ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = inner.withExtra(horizontal = pad, top = 4.dp, bottom = LocalBarInset.current + 16.dp),
            verticalArrangement = Arrangement.spacedBy(pad * 0.75f),
        ) {
            item {
                HubRow(
                    icon = Icons.Rounded.Palette,
                    title = tr("Appearance", "ظاهر"),
                    subtitle = tr(
                        "Colors, shapes, text size, motion, language",
                        "رنگ، شکل‌ها، اندازهٔ متن، حرکت، زبان",
                    ),
                    onClick = onAppearance,
                )
            }
            item {
                HubRow(
                    icon = Icons.Rounded.Search,
                    title = tr("Scanning", "اسکن"),
                    subtitle = tr(
                        "Auto scan, notifications, checks to run",
                        "اسکن خودکار، اعلان‌ها، بررسی‌های فعال",
                    ),
                    onClick = onScan,
                )
            }
            item {
                HubRow(
                    icon = Icons.Rounded.Info,
                    title = tr("About", "درباره"),
                    subtitle = tr(
                        "What Pond checks and what it cannot see",
                        "پاند چه چیزی را بررسی می‌کند و چه چیزی را نمی‌بیند",
                    ),
                    onClick = onAbout,
                )
            }
        }
    }
}

@Composable
private fun HubRow(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit) {
    PondCard(onClick = onClick) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            ShapeIcon(
                icon = icon,
                container = MaterialTheme.colorScheme.primaryContainer,
                content = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
