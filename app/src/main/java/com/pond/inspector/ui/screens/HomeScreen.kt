package com.pond.inspector.ui.screens

import com.pond.inspector.ui.components.pondIconButtonColors
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.tween
import androidx.compose.runtime.remember
import com.pond.inspector.ui.LocalBarInset
import com.pond.inspector.ui.components.appear
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.pond.inspector.PondViewModel
import com.pond.inspector.model.DetectorReport
import com.pond.inspector.model.Status
import com.pond.inspector.model.needsAttention
import com.pond.inspector.model.severity
import com.pond.inspector.model.worst
import com.pond.inspector.scan.Catalog
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.LocalPersian
import com.pond.inspector.ui.LocalReduced
import com.pond.inspector.ui.components.PondCard
import com.pond.inspector.ui.components.PondTopBar
import com.pond.inspector.ui.components.SectionTitle
import com.pond.inspector.ui.components.ShapeIcon
import com.pond.inspector.ui.components.StatusPill
import com.pond.inspector.ui.components.rememberHaptic
import com.pond.inspector.ui.components.shareText
import com.pond.inspector.ui.components.tabInsets
import com.pond.inspector.ui.components.withExtra
import com.pond.inspector.ui.detectorIcon
import com.pond.inspector.ui.num
import com.pond.inspector.ui.text
import com.pond.inspector.ui.theme.PondMark
import com.pond.inspector.ui.theme.iconShape
import com.pond.inspector.ui.theme.statusColors
import com.pond.inspector.ui.tr

@Composable
fun HomeScreen(
    vm: PondViewModel,
    onOpen: (String) -> Unit,
) {
    val reports by vm.reports.collectAsStateWithLifecycle()
    val running by vm.running.collectAsStateWithLifecycle()
    val pad = LocalPad.current
    val persian = LocalPersian.current
    val context = LocalContext.current
    val haptic = rememberHaptic()
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    val barInset = LocalBarInset.current
    val seen = remember { mutableSetOf<Any>() }

    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        contentWindowInsets = tabInsets(),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = {
            PondTopBar(
                title = tr("Pond", "پاند"),
                scrollBehavior = scroll,
                actions = {
                    FilledTonalIconButton(
                        colors = pondIconButtonColors(),
                        onClick = {
                            haptic.tap()
                            shareText(context, vm.reportText(persian))
                        },
                        enabled = reports.isNotEmpty() && !running,
                    ) {
                        Icon(Icons.Rounded.Share, contentDescription = tr("Share report", "اشتراک گزارش"))
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                modifier = Modifier.padding(bottom = barInset),
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                text = { Text(if (running) tr("Scanning", "در حال اسکن") else tr("Scan", "اسکن")) },
                icon = { Icon(Icons.Rounded.Refresh, contentDescription = null) },
                onClick = {
                    haptic.tap()
                    vm.rescan()
                },
            )
        },
    ) { inner ->
        val ordered = if (running) reports else reports.sortedBy { it.status.severity() }
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = inner.withExtra(horizontal = pad, top = 4.dp, bottom = barInset + 88.dp),
            verticalArrangement = Arrangement.spacedBy(pad * 0.75f),
        ) {
            item(key = "hero") {
                Hero(reports = reports, running = running, modifier = Modifier.animateItem().appear(seen, "hero", 0))
            }
            if (ordered.isNotEmpty()) {
                item(key = "title") {
                    SectionTitle(tr("Checks", "بررسی‌ها"), Modifier.animateItem())
                }
            }
            itemsIndexed(ordered, key = { _, r -> r.id }) { index, report ->
                DetectorCard(
                    report = report,
                    onClick = { onOpen(report.id) },
                    modifier = Modifier.animateItem().appear(seen, report.id, index + 1),
                )
            }
            item(key = "note") {
                Text(
                    tr(
                        "Signals only. A clear result is not proof the device is unmodified, and nothing here is a Play Integrity verdict.",
                        "فقط سیگنال است. نتیجهٔ سالم ثابت نمی‌کند دستگاه دست‌نخورده است و چیزی در اینجا حکم Play Integrity نیست.",
                    ),
                    modifier = Modifier
                        .padding(horizontal = 8.dp, vertical = 8.dp)
                        .animateItem(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun Hero(reports: List<DetectorReport>, running: Boolean, modifier: Modifier = Modifier) {
    val total = reports.size
    val done = reports.count { it.status != Status.PENDING }
    val attention = reports.count { it.status.needsAttention() }
    val clear = reports.count { it.status == Status.CLEAR }
    val other = (done - attention - clear).coerceAtLeast(0)
    val overall = when {
        running -> Status.PENDING
        total == 0 -> Status.UNSUPPORTED
        attention > 0 -> worst(reports.map { it.status }.filter { it.needsAttention() })
        reports.any { it.status == Status.INFO } -> Status.INFO
        else -> Status.CLEAR
    }
    val scheme = MaterialTheme.colorScheme
    val (contentTarget, containerTarget) = when (overall) {
        Status.PENDING, Status.UNSUPPORTED -> scheme.onPrimaryContainer to scheme.primaryContainer
        else -> statusColors(overall)
    }
    val title = when {
        total == 0 -> tr("Ready to scan", "آمادهٔ اسکن")
        running -> tr("Scanning…", "در حال اسکن…")
        attention > 0 -> tr("${attention} signals need attention", "${num(attention)} سیگنال توجه می‌خواهد")
        else -> tr("No signals need attention", "سیگنالی که توجه بخواهد نیست")
    }
    val subtitle = when {
        total == 0 -> tr("Tap Scan to read this device's signals.", "برای خواندن سیگنال‌های این دستگاه روی اسکن بزنید.")
        running -> tr("${done} of ${total} checks finished", "${num(done)} از ${num(total)} بررسی تمام شد")
        else -> tr("${total} checks finished", "${num(total)} بررسی تمام شد")
    }
    val content by animateColorAsState(contentTarget, tween(500), label = "heroContent")
    val container by animateColorAsState(containerTarget, tween(500), label = "heroContainer")
    val progressTarget = if (total == 0) 0f else done.toFloat() / total
    val progress by animateFloatAsState(progressTarget, tween(450), label = "heroProgress")
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .animateContentSize(),
        shape = MaterialTheme.shapes.extraLarge,
        color = container,
        contentColor = content,
    ) {
        Column(
            Modifier.padding(LocalPad.current.plus(4.dp)),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Box(
                    Modifier
                        .size(96.dp)
                        .clip(iconShape(com.pond.inspector.ui.LocalIconShape.current))
                        .background(content.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    CompositionLocalProvider(LocalContentColor provides content) {
                        PondMark(scanning = running, reduced = LocalReduced.current)
                    }
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(title, style = MaterialTheme.typography.headlineSmall)
                    Text(subtitle, style = MaterialTheme.typography.bodyMedium)
                }
            }
            if (running) {
                LinearProgressIndicator(
                    progress = { progress },
                    modifier = Modifier.fillMaxWidth(),
                    color = content,
                    trackColor = content.copy(alpha = 0.2f),
                )
            }
            if (total > 0) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Stat(attention, tr("Attention", "توجه"), content, Modifier.weight(1f))
                    Stat(clear, tr("Clear", "سالم"), content, Modifier.weight(1f))
                    Stat(other, tr("Other", "سایر"), content, Modifier.weight(1f))
                }
            }
        }
    }
}

@Composable
private fun Stat(count: Int, label: String, content: Color, modifier: Modifier = Modifier) {
    val shown by animateIntAsState(count, tween(600), label = "stat")
    Surface(
        modifier = modifier,
        shape = MaterialTheme.shapes.large,
        color = content.copy(alpha = 0.10f),
        contentColor = content,
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .padding(vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(num(shown), style = MaterialTheme.typography.titleLarge)
            Text(label, style = MaterialTheme.typography.labelMedium, maxLines = 1)
        }
    }
}

@Composable
private fun DetectorCard(report: DetectorReport, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val detector = Catalog.byId(report.id)
    val (content, container) = statusColors(report.status)
    PondCard(modifier = modifier, onClick = onClick) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            ShapeIcon(detectorIcon(report.id), container, content)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    detector?.title?.text() ?: report.id,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    report.summary.text(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                if (report.status != Status.PENDING) {
                    Spacer(Modifier.height(6.dp))
                    StatusPill(report.status)
                }
            }
            if (report.status == Status.PENDING) {
                CircularProgressIndicator(Modifier.size(28.dp), strokeWidth = 3.dp)
            } else {
                Icon(
                    Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
