package com.pond.inspector.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.ui.platform.LocalContext
import com.pond.inspector.ui.components.GITHUB_URL
import com.pond.inspector.ui.components.openUrl
import com.pond.inspector.ui.components.rememberHaptic
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.unit.dp
import com.pond.inspector.BuildConfig
import com.pond.inspector.scan.Catalog
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.components.PondCard
import com.pond.inspector.ui.components.PondTopBar
import com.pond.inspector.ui.components.SectionTitle
import com.pond.inspector.ui.components.ShapeIcon
import com.pond.inspector.ui.components.withExtra
import com.pond.inspector.ui.detectorIcon
import com.pond.inspector.ui.localizeDigits
import com.pond.inspector.ui.LocalPersian
import com.pond.inspector.ui.text
import com.pond.inspector.ui.tr

@Composable
fun AboutScreen(onBack: () -> Unit) {
    val pad = LocalPad.current
    val persian = LocalPersian.current
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    val context = LocalContext.current
    val haptic = rememberHaptic()
    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = { PondTopBar(tr("About", "درباره"), scroll, onBack) },
    ) { inner ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = inner.withExtra(horizontal = pad, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(pad * 0.75f),
        ) {
            item {
                PondCard(container = MaterialTheme.colorScheme.primaryContainer, outlined = false) {
                    Text(
                        tr("Pond", "پاند") + "  " + localizeDigits(BuildConfig.VERSION_NAME, persian),
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Text(
                        tr(
                            "Pond reads the signals an ordinary app can see on this device: boot state, build identity, root and hook traces, keystore hardware. It runs on the device and sends nothing anywhere, except the optional Google revocation list refresh.",
                            "پاند سیگنال‌هایی را می‌خواند که یک اپ معمولی روی این دستگاه می‌بیند: وضعیت بوت، هویت بیلد، ردپای روت و هوک، سخت‌افزار keystore. همه‌چیز روی خود دستگاه اجرا می‌شود و چیزی جایی فرستاده نمی‌شود، جز تازه‌سازی اختیاری فهرست ابطال گوگل.",
                        ),
                        modifier = Modifier.padding(top = 8.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                }
            }
            item {
                PondCard {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(14.dp),
                    ) {
                        ShapeIcon(
                            icon = Icons.Rounded.Code,
                            container = MaterialTheme.colorScheme.primaryContainer,
                            content = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                        Column(Modifier.weight(1f)) {
                            Text(
                                tr("Developer", "توسعه‌دهنده"),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                "@deepcodecreate",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                        }
                        FilledTonalButton(onClick = {
                            haptic.tap()
                            openUrl(context, GITHUB_URL)
                        }) {
                            Text("GitHub")
                            Icon(
                                Icons.AutoMirrored.Rounded.OpenInNew,
                                contentDescription = null,
                                modifier = Modifier.padding(start = 6.dp),
                            )
                        }
                    }
                }
            }
            item {
                PondCard(container = MaterialTheme.colorScheme.surfaceContainerHigh) {
                    Text(
                        tr(
                            "A clear result is not proof of an unmodified device. Root that hides well from this app will look clear, and a match is a signal, not proof of what an app is doing. This is not a Play Integrity verdict.",
                            "نتیجهٔ سالم ثابت نمی‌کند دستگاه دست‌نخورده است. روتی که از این اپ خوب پنهان شود سالم به نظر می‌رسد و یک تطابق سیگنال است، نه اثبات رفتار اپ. این حکم Play Integrity نیست.",
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
            item { SectionTitle(tr("Checks and their limits", "بررسی‌ها و محدودیت‌هایشان")) }
            Catalog.all.forEach { detector ->
                item(key = detector.id) {
                    PondCard {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            ShapeIcon(
                                icon = detectorIcon(detector.id),
                                container = MaterialTheme.colorScheme.primaryContainer,
                                content = MaterialTheme.colorScheme.onPrimaryContainer,
                                size = 40.dp,
                            )
                            Text(detector.title.text(), style = MaterialTheme.typography.titleMedium)
                        }
                        Column(Modifier.padding(top = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(detector.about.text(), style = MaterialTheme.typography.bodyMedium)
                            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                            Text(
                                detector.limits.text(),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}
