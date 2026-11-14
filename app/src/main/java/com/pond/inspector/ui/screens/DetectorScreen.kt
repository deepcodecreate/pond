package com.pond.inspector.ui.screens

import com.pond.inspector.ui.components.pondIconButtonColors
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material3.Surface
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import com.pond.inspector.logic.displayValue
import com.pond.inspector.model.DetectorReport
import com.pond.inspector.model.Evidence
import com.pond.inspector.model.Phrase
import com.pond.inspector.model.Section
import com.pond.inspector.ui.LocalPersian
import com.pond.inspector.ui.sectionIcon
import com.pond.inspector.ui.statusIcon
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.pond.inspector.PondViewModel
import com.pond.inspector.model.Status
import com.pond.inspector.scan.Catalog
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.LocalShowRaw
import com.pond.inspector.ui.components.EvidenceRow
import com.pond.inspector.ui.components.PondCard
import com.pond.inspector.ui.components.PondTopBar
import com.pond.inspector.ui.components.SectionTitle
import com.pond.inspector.ui.components.ShapeIcon
import com.pond.inspector.ui.components.StatusPill
import com.pond.inspector.ui.components.rememberHaptic
import com.pond.inspector.ui.components.withExtra
import com.pond.inspector.ui.detectorIcon
import com.pond.inspector.ui.num
import com.pond.inspector.ui.text
import com.pond.inspector.ui.theme.statusColors
import com.pond.inspector.ui.tr

@Composable
fun DetectorScreen(vm: PondViewModel, id: String, onBack: () -> Unit) {
    val reports by vm.reports.collectAsStateWithLifecycle()
    val running by vm.running.collectAsStateWithLifecycle()
    val report = reports.firstOrNull { it.id == id }
    val detector = Catalog.byId(id)
    val pad = LocalPad.current
    val raw = LocalShowRaw.current
    val haptic = rememberHaptic()
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    val status = report?.status ?: Status.PENDING
    val (content, container) = statusColors(status)

    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = {
            PondTopBar(
                title = detector?.title?.text() ?: id,
                scrollBehavior = scroll,
                onBack = onBack,
                actions = {
                    FilledTonalIconButton(
                        colors = pondIconButtonColors(),
                        onClick = {
                            haptic.tap()
                            vm.rescan()
                        },
                        enabled = !running,
                    ) {
                        Icon(Icons.Rounded.Refresh, contentDescription = tr("Rescan", "اسکن دوباره"))
                    }
                },
            )
        },
    ) { inner ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = inner.withExtra(horizontal = pad, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(pad * 0.75f),
        ) {
            if (report == null) {
                item { PondCard { CircularProgressIndicator(Modifier.padding(8.dp)) } }
            } else {
                item { DuckCard(report, detector, content, container, raw) }
            }
        }
    }
}

private data class Tile(val label: String, val value: String, val level: Status)

@Composable
private fun DuckCard(
    report: DetectorReport,
    detector: com.pond.inspector.scan.Detector?,
    content: Color,
    container: Color,
    raw: Boolean,
) {
    val persian = LocalPersian.current
    val scheme = MaterialTheme.colorScheme
    val all = report.evidence + report.sections.flatMap { it.evidence }
    val counts = all.groupingBy { it.level }.eachCount()
    val metrics: List<Tile> = if (report.metrics.isNotEmpty()) {
        report.metrics.map { Tile(it.label.get(persian), it.value.get(persian), it.level) }
    } else listOf(
        Tile(tr("Checks", "بررسی‌ها"), num(all.size), Status.INFO),
        Tile(tr("Passed", "سالم"), num(counts[Status.CLEAR] ?: 0), Status.CLEAR),
        Tile(tr("Warnings", "هشدارها"), num(counts[Status.WARNING] ?: 0), if ((counts[Status.WARNING] ?: 0) > 0) Status.WARNING else Status.INFO),
        Tile(tr("Detected", "شناسایی"), num((counts[Status.DANGER] ?: 0) + (counts[Status.ERROR] ?: 0)), if (((counts[Status.DANGER] ?: 0) + (counts[Status.ERROR] ?: 0)) > 0) Status.DANGER else Status.INFO),
    )
    val sections: List<Section> = if (report.sections.isNotEmpty()) report.sections else {
        val bad = report.evidence.filter { it.level == Status.DANGER || it.level == Status.WARNING || it.level == Status.ERROR }
        val good = report.evidence.filter { it.level == Status.CLEAR }
        val rest = report.evidence.filter { it !in bad && it !in good }
        listOfNotNull(
            if (bad.isNotEmpty()) Section("findings", Phrase("Findings", "یافته‌ها"), bad,
                if (bad.any { it.level != Status.WARNING }) Status.DANGER else Status.WARNING) else null,
            if (good.isNotEmpty()) Section("passed", Phrase("Passed checks", "بررسی‌های سالم"), good) else null,
            if (rest.isNotEmpty()) Section("context", Phrase("Details", "جزئیات"), rest) else null,
        )
    }
    val impact = report.impact ?: Phrase(
        when (report.status) {
            Status.CLEAR -> "No sign of tampering was found by this check. Apps relying on it should see a normal device."
            Status.INFO -> "Informational only; nothing here is a problem by itself."
            Status.WARNING -> "Something looks unusual. Strict apps may treat this device with suspicion."
            Status.DANGER -> "Strong evidence of modification. Apps that enforce device integrity will likely refuse or limit service."
            else -> "This check could not complete, so it neither clears nor accuses the device."
        },
        when (report.status) {
            Status.CLEAR -> "نشانه‌ای از دستکاری پیدا نشد. اپ‌هایی که به این بررسی تکیه می‌کنند دستگاه را عادی می‌بینند."
            Status.INFO -> "فقط اطلاعاتی است؛ هیچ‌چیز اینجا به‌تنهایی مشکل نیست."
            Status.WARNING -> "چیزی غیرعادی است. اپ‌های سخت‌گیر ممکن است به دستگاه مشکوک شوند."
            Status.DANGER -> "شواهد قوی از تغییر دستگاه. اپ‌هایی که یکپارچگی را اجباری می‌کنند احتمالاً سرویس را رد یا محدود می‌کنند."
            else -> "این بررسی کامل نشد، پس نه دستگاه را تأیید می‌کند نه متهم."
        },
    )
    PondCard(container = scheme.surfaceContainer) {
        Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            ShapeIcon(detectorIcon(report.id), content.copy(alpha = 0.14f), content, size = 48.dp)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                StatusPill(report.status)
                Text(report.summary.get(persian), style = MaterialTheme.typography.titleMedium)
            }
        }
        report.caption?.let {
            Text(it.get(persian), style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant)
        }
        metrics.chunked(2).forEach { row ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                row.forEach { t ->
                    val tint = if (t.level == Status.INFO) scheme.onSurface else statusColors(t.level).first
                    Surface(
                        Modifier.weight(1f),
                        shape = MaterialTheme.shapes.medium,
                        color = scheme.surfaceContainerHigh,
                    ) {
                        Column(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(t.label, style = MaterialTheme.typography.labelMedium, color = scheme.onSurfaceVariant)
                            Text(
                                displayValue(t.value, persian),
                                style = MaterialTheme.typography.titleSmall.copy(textDirection = TextDirection.Content),
                                color = tint,
                            )
                        }
                    }
                }
                if (row.size == 1) Spacer(Modifier.weight(1f))
            }
        }
        if (report.highlights.isNotEmpty()) Column(verticalArrangement = Arrangement.spacedBy(8.dp)) { report.highlights.forEach { h ->
            val (hc, hb) = statusColors(h.level)
            Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.medium, color = hb, contentColor = hc) {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 11.dp), horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(statusIcon(h.level), null, Modifier.size(18.dp))
                    Text(
                        "${h.label.get(persian)}: ${displayValue(h.value.get(persian), persian)}",
                        style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold, textDirection = TextDirection.Content),
                    )
                }
            }
        } }
        Column(Modifier.padding(top = 2.dp)) {
        sections.forEach { DuckSection(report.id, it) }
        val extra = buildList {
            add(Section("impact", Phrase("Impact", "تأثیر"), emptyList(), note = impact))
            detector?.let {
                add(Section("methods", Phrase("Detection methods", "روش‌های تشخیص"), emptyList(),
                    note = Phrase(it.about.en + "\n\n" + it.limits.en, it.about.fa + "\n\n" + it.limits.fa)))
            }
            add(Section("summary", Phrase("Scan summary", "خلاصهٔ اسکن"), listOf(
                Evidence(Phrase("Checks run", "بررسی‌های انجام‌شده"), all.size.toString()),
                Evidence(Phrase("Result", "نتیجه"), report.status.name.lowercase(), report.status),
                Evidence(Phrase("Duration", "مدت"), "${report.durationMs} ms"),
            ) + listOfNotNull(report.score?.let { Evidence(Phrase("Score", "امتیاز"), it.toString()) })))
        }
        extra.forEach { DuckSection(report.id, it, startOpen = it.key == "impact") }
        }
        }
    }
}

@Composable
private fun DuckSection(reportId: String, section: Section, startOpen: Boolean = section.severity != null) {
    val scheme = MaterialTheme.colorScheme
    val persian = LocalPersian.current
    var open by rememberSaveable(reportId, section.key) { mutableStateOf(startOpen) }
    Column(Modifier.fillMaxWidth()) {
        Row(
            Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.medium)
                .clickable { open = !open }
                .padding(vertical = 10.dp, horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(sectionIcon(section.key), null, tint = scheme.primary, modifier = Modifier.size(22.dp))
            Text(section.title.get(persian), Modifier.weight(1f), style = MaterialTheme.typography.titleSmall)
            section.severity?.let { sev ->
                val (c, b) = statusColors(sev)
                val label = when (sev) {
                    Status.DANGER, Status.ERROR -> tr("High", "زیاد")
                    Status.WARNING -> tr("Medium", "متوسط")
                    else -> tr("Low", "کم")
                }
                Surface(shape = CircleShape, color = b, contentColor = c) {
                    Text(label, Modifier.padding(horizontal = 10.dp, vertical = 3.dp), style = MaterialTheme.typography.labelMedium)
                }
            }
            Icon(
                if (open) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                null, tint = scheme.onSurfaceVariant,
            )
        }
        AnimatedVisibility(open) {
            Column(Modifier.padding(start = 8.dp, bottom = 8.dp)) {
                section.note?.let {
                    Text(
                        it.get(persian),
                        Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        color = scheme.onSurfaceVariant,
                    )
                }
                section.evidence.forEachIndexed { i, row ->
                    if (i > 0) HorizontalDivider(color = scheme.outlineVariant.copy(alpha = 0.4f))
                    EvidenceRow(row)
                }
            }
        }
        HorizontalDivider(color = scheme.outlineVariant.copy(alpha = 0.3f))
    }
}
