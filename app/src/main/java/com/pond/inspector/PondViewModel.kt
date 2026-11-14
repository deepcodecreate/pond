package com.pond.inspector

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.pond.inspector.data.PondStore
import com.pond.inspector.model.AppearancePrefs
import com.pond.inspector.model.DetectorReport
import com.pond.inspector.model.Evidence
import com.pond.inspector.model.ScanPrefs
import com.pond.inspector.logic.displayValue
import com.pond.inspector.model.needsAttention
import com.pond.inspector.scan.Catalog
import com.pond.inspector.scan.DeviceFacts
import com.pond.inspector.scan.ScanNotifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.system.measureTimeMillis

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class PondViewModel(app: Application) : AndroidViewModel(app) {
    private val probeDispatcher = Dispatchers.IO.limitedParallelism(2)

    private val store = PondStore(app)
    private val notifier = ScanNotifier(app)

    val appearance: StateFlow<AppearancePrefs?> = store.appearance
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    val scan: StateFlow<ScanPrefs?> = store.scan
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    private val _reports = MutableStateFlow<List<DetectorReport>>(emptyList())
    val reports: StateFlow<List<DetectorReport>> = _reports

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running

    private val _device = MutableStateFlow<List<Evidence>>(emptyList())
    val device: StateFlow<List<Evidence>> = _device

    private var scanJob: Job? = null
    private var generation = 0
    private var autoStarted = false

    init {
        viewModelScope.launch {
            val prefs = store.scan.first()
            refreshDevice()
            kotlinx.coroutines.delay(700)
            if (!autoStarted && prefs.onboardingDone && prefs.autoScan) {
                autoStarted = true
                rescan(prefs)
            }
        }
    }

    fun updateAppearance(block: (AppearancePrefs) -> AppearancePrefs) {
        viewModelScope.launch { store.updateAppearance(block) }
    }

    fun updateScan(block: (ScanPrefs) -> ScanPrefs) {
        viewModelScope.launch { store.updateScan(block) }
    }

    fun resetAppearance() {
        updateAppearance { AppearancePrefs(language = it.language) }
    }

    fun finishOnboarding(notifications: Boolean, liveUpdate: Boolean, onlineCrl: Boolean) {
        viewModelScope.launch {
            var next = ScanPrefs()
            store.updateScan {
                next = it.copy(
                    onboardingDone = true,
                    notifications = notifications,
                    liveUpdate = liveUpdate,
                    onlineCrl = onlineCrl,
                )
                next
            }
            autoStarted = true
            rescan(next)
        }
    }

    fun refreshDevice() {
        viewModelScope.launch(Dispatchers.IO) {
            _device.value = DeviceFacts.collect()
        }
    }

    fun rescan(override: ScanPrefs? = null) {
        val prefs = override ?: scan.value ?: return
        scanJob?.cancel()
        val gen = ++generation
        val active = Catalog.all.filter { it.id in prefs.enabled }
        _reports.value = active.map { DetectorReport.pending(it.id) }
        if (active.isEmpty()) {
            _running.value = false
            return
        }
        _running.value = true
        refreshDevice()
        scanJob = viewModelScope.launch {
            val acc = linkedMapOf<String, DetectorReport>()
            if (prefs.liveUpdate) notifier.progress(0, active.size)
            coroutineScope {
                active.map { detector ->
                    async(probeDispatcher) {
                        val report = try {
                            var produced: DetectorReport
                            val took = measureTimeMillis {
                                produced = detector.probe(getApplication(), prefs)
                            }
                            produced.copy(durationMs = took)
                        } catch (cancelled: kotlinx.coroutines.CancellationException) {
                            throw cancelled
                        } catch (error: Throwable) {
                            DetectorReport.failed(detector.id, error.message ?: error.javaClass.simpleName)
                        }
                        withContext(Dispatchers.Main) {
                            if (gen != generation) return@withContext
                            acc[detector.id] = report
                            _reports.value = active.map { acc[it.id] ?: DetectorReport.pending(it.id) }
                            if (prefs.liveUpdate) notifier.progress(acc.size, active.size)
                        }
                    }
                }.awaitAll()
            }
            if (gen != generation) return@launch
            _running.value = false
            val attention = _reports.value.count { it.status.needsAttention() }
            when {
                prefs.notifications -> notifier.finish(attention)
                prefs.liveUpdate -> notifier.cancel()
            }
        }
    }

    fun reportText(persian: Boolean): String {
        val lines = StringBuilder()
        lines.appendLine(if (persian) "گزارش پاند" else "Pond report")
        lines.appendLine(
            if (persian) {
                "فقط سیگنال است. حکم Play Integrity نیست و سالم بودن را ثابت نمی‌کند."
            } else {
                "Signals only. Not a Play Integrity verdict and not proof the device is unmodified."
            },
        )
        lines.appendLine()
        lines.appendLine(if (persian) "دستگاه" else "Device")
        _device.value.forEach { row ->
            lines.appendLine("${row.label.get(persian)}: ${displayValue(row.value, persian)}")
        }
        lines.appendLine()
        _reports.value.forEach { report ->
            val detector = Catalog.byId(report.id)
            lines.appendLine("${detector?.title?.get(persian) ?: report.id} · ${report.status.name}")
            lines.appendLine(report.summary.get(persian))
            report.evidence.forEach { row ->
                lines.appendLine("  ${row.label.get(persian)}: ${displayValue(row.value, persian)}")
            }
            lines.appendLine()
        }
        return lines.toString().trimEnd()
    }
}
