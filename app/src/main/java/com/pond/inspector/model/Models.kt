package com.pond.inspector.model

import androidx.compose.runtime.Immutable

enum class Status {
    PENDING,
    CLEAR,
    INFO,
    WARNING,
    DANGER,
    UNSUPPORTED,
    ERROR,
}

fun Status.severity(): Int = when (this) {
    Status.ERROR -> 0
    Status.DANGER -> 1
    Status.WARNING -> 2
    Status.INFO -> 3
    Status.UNSUPPORTED -> 4
    Status.CLEAR -> 5
    Status.PENDING -> 6
}

fun worst(statuses: Iterable<Status>): Status =
    statuses.minByOrNull { it.severity() } ?: Status.CLEAR

fun Status.needsAttention(): Boolean =
    this == Status.DANGER || this == Status.WARNING || this == Status.ERROR

@Immutable
data class Phrase(val en: String, val fa: String) {
    fun get(persian: Boolean): String = if (persian) fa else en
}

@Immutable
data class Evidence(
    val label: Phrase,
    val value: String,
    val level: Status = Status.INFO,
    val detail: Phrase? = null,
)

@Immutable
data class Metric(
    val label: Phrase,
    val value: Phrase,
    val level: Status = Status.INFO,
)

@Immutable
data class Section(
    val key: String,
    val title: Phrase,
    val evidence: List<Evidence>,
    val severity: Status? = null,
    val note: Phrase? = null,
)

@Immutable
data class DetectorReport(
    val id: String,
    val status: Status,
    val summary: Phrase,
    val evidence: List<Evidence>,
    val durationMs: Long = 0L,
    val caption: Phrase? = null,
    val metrics: List<Metric> = emptyList(),
    val highlights: List<Metric> = emptyList(),
    val sections: List<Section> = emptyList(),
    val impact: Phrase? = null,
    val score: Int? = null,
) {
    companion object {
        fun pending(id: String) = DetectorReport(
            id = id,
            status = Status.PENDING,
            summary = Phrase("Running", "در حال بررسی"),
            evidence = emptyList(),
        )

        fun failed(id: String, message: String) = DetectorReport(
            id = id,
            status = Status.ERROR,
            summary = Phrase("This check failed", "این بررسی شکست خورد"),
            evidence = listOf(Evidence(Phrase("Error", "خطا"), message, Status.ERROR)),
        )
    }
}

enum class ThemeMode { System, Light, Dark }

enum class PaletteStyle {
    TonalSpot,
    Vibrant,
    Expressive,
    Rainbow,
    FruitSalad,
    Content,
    Fidelity,
    Neutral,
    Monochrome,
}

enum class MotionStyle { Expressive, Standard, Reduced }

enum class DensityStyle { Comfortable, Compact }

enum class AppLanguage { System, English, Persian }

enum class IconShapeId { Cookie4, Clover4, Sunny, Gem, Puffy, Arch, SoftBurst, Flower }

data class AppearancePrefs(
    val themeMode: ThemeMode = ThemeMode.System,
    val wallpaperColors: Boolean = true,
    val seed: Int = 0xFF0F6E6B.toInt(),
    val palette: PaletteStyle = PaletteStyle.TonalSpot,
    val contrast: Float = 0f,
    val pureBlack: Boolean = false,
    val cornerScale: Float = 1f,
    val textScale: Float = 1f,
    val motion: MotionStyle = MotionStyle.Expressive,
    val haptics: Boolean = true,
    val iconShape: IconShapeId = IconShapeId.Cookie4,
    val density: DensityStyle = DensityStyle.Comfortable,
    val language: AppLanguage = AppLanguage.System,
    val showRaw: Boolean = false,
)

data class ScanPrefs(
    val autoScan: Boolean = true,
    val notifications: Boolean = false,
    val liveUpdate: Boolean = true,
    val onlineCrl: Boolean = false,
    val onboardingDone: Boolean = false,
    val enabled: Set<String> = DetectorIds.all,
)

object DetectorIds {
    const val BOOTLOADER = "bootloader"
    const val CUSTOM_ROM = "customrom"
    const val DANGEROUS = "dangerousapps"
    const val MANAGERS = "rootmanagers"
    const val SU = "su"
    const val SELINUX = "selinux"
    const val PROPS = "sysprops"
    const val ADB = "adb"
    const val KERNEL = "kernel"
    const val MOUNT = "mount"
    const val MEMORY = "memory"
    const val LSPOSED = "lsposed"
    const val ZYGISK = "zygisk"
    const val NATIVE = "nativeroot"
    const val VIRTUAL = "virtualization"
    const val TEE = "tee"
    const val INTEGRITY = "integrity"
    const val DEVELOPER = "developer"
    const val DEBUGGER = "debugger"
    const val FRIDA = "frida"
    const val HOOKS = "hooks"
    const val ROOT_FILES = "rootfiles"
    const val PARTITIONS = "partitions"
    const val AVB = "avb"
    const val BUILD = "buildcheck"
    const val INJECTION = "injection"
    const val SYSFILES = "sysfiles"
    const val HARDENING = "hardening"
    const val TIME = "time"
    const val NETWORK = "network"
    const val USER_CA = "usercerts"
    const val ACCESSIBILITY = "accessibility"
    const val CLONES = "clones"
    const val APPENV = "appenv"
    const val EMULATOR = "emulator"
    const val HARDWARE = "hardware"
    const val POSTURE = "posture"
    const val GMS = "gms"
    const val SPOOF = "spooftools"
    const val HIDE = "hidetools"

    val legacy: Set<String> = linkedSetOf(
        BOOTLOADER, CUSTOM_ROM, DANGEROUS, MANAGERS, SU, SELINUX, PROPS, ADB, KERNEL,
        MOUNT, MEMORY, LSPOSED, ZYGISK, NATIVE, VIRTUAL, TEE, INTEGRITY,
    )

    val all: Set<String> = linkedSetOf(
        BOOTLOADER,
        CUSTOM_ROM,
        DANGEROUS,
        MANAGERS,
        SU,
        SELINUX,
        PROPS,
        ADB,
        KERNEL,
        MOUNT,
        MEMORY,
        LSPOSED,
        ZYGISK,
        NATIVE,
        VIRTUAL,
        TEE,
        INTEGRITY,
        DEVELOPER,
        DEBUGGER,
        FRIDA,
        HOOKS,
        ROOT_FILES,
        PARTITIONS,
        AVB,
        BUILD,
        INJECTION,
        SYSFILES,
        HARDENING,
        TIME,
        NETWORK,
        USER_CA,
        ACCESSIBILITY,
        CLONES,
        APPENV,
        EMULATOR,
        HARDWARE,
        POSTURE,
        GMS,
        SPOOF,
        HIDE,
    )
}

val SEED_PRESETS: List<Int> = listOf(
    0xFF0F6E6B,
    0xFF1565C0,
    0xFF6750A4,
    0xFFB3261E,
    0xFF8E4E00,
    0xFF3F6B2A,
    0xFF6D4C41,
    0xFF455A64,
).map { it.toInt() }
