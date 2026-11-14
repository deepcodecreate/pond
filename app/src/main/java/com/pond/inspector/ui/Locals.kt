package com.pond.inspector.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.Android
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.Dangerous
import androidx.compose.material.icons.rounded.DeveloperBoard
import androidx.compose.material.icons.rounded.Devices
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.material.icons.rounded.HourglassTop
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.Usb
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material.icons.rounded.Accessibility
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.Cloud
import androidx.compose.material.icons.rounded.Computer
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Gavel
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material.icons.rounded.PinDrop
import androidx.compose.material.icons.rounded.Policy
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.SdStorage
import androidx.compose.material.icons.rounded.Sensors
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.runtime.Composable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.pond.inspector.model.DetectorIds
import com.pond.inspector.model.IconShapeId
import com.pond.inspector.model.Phrase
import com.pond.inspector.model.Status

val LocalPersian = staticCompositionLocalOf { false }
val LocalPad = staticCompositionLocalOf<Dp> { 16.dp }
val LocalIconShape = staticCompositionLocalOf { IconShapeId.Cookie4 }
val LocalShowRaw = staticCompositionLocalOf { false }
val LocalReduced = staticCompositionLocalOf { false }
val LocalBarInset = staticCompositionLocalOf<Dp> { 0.dp }

@Composable
fun tr(en: String, fa: String): String = if (LocalPersian.current) fa else en

@Composable
fun Phrase.text(): String = get(LocalPersian.current)

fun localizeDigits(text: String, persian: Boolean): String {
    if (!persian) return text
    val out = StringBuilder(text.length)
    for (c in text) {
        out.append(if (c in '0'..'9') '۰' + (c - '0') else c)
    }
    return out.toString()
}

@Composable
fun num(value: Int): String = localizeDigits(value.toString(), LocalPersian.current)

@Composable
fun statusLabel(status: Status): String = when (status) {
    Status.CLEAR -> tr("Clear", "سالم")
    Status.INFO -> tr("Info", "اطلاع")
    Status.WARNING -> tr("Warning", "هشدار")
    Status.DANGER -> tr("Detected", "شناسایی شد")
    Status.UNSUPPORTED -> tr("Unsupported", "ناپشتیبان")
    Status.ERROR -> tr("Error", "خطا")
    Status.PENDING -> tr("Running", "در حال بررسی")
}

fun statusIcon(status: Status): ImageVector = when (status) {
    Status.CLEAR -> Icons.Rounded.CheckCircle
    Status.INFO -> Icons.Rounded.Info
    Status.WARNING -> Icons.Rounded.Warning
    Status.DANGER -> Icons.Rounded.Dangerous
    Status.UNSUPPORTED -> Icons.Rounded.Block
    Status.ERROR -> Icons.Rounded.ErrorOutline
    Status.PENDING -> Icons.Rounded.HourglassTop
}

fun detectorIcon(id: String): ImageVector = when (id) {
    DetectorIds.BOOTLOADER -> Icons.Rounded.Lock
    DetectorIds.CUSTOM_ROM -> Icons.Rounded.Android
    DetectorIds.DANGEROUS -> Icons.Rounded.Apps
    DetectorIds.MANAGERS -> Icons.Rounded.AdminPanelSettings
    DetectorIds.SU -> Icons.Rounded.Terminal
    DetectorIds.SELINUX -> Icons.Rounded.Security
    DetectorIds.PROPS -> Icons.Rounded.Tune
    DetectorIds.ADB -> Icons.Rounded.Usb
    DetectorIds.KERNEL -> Icons.Rounded.DeveloperBoard
    DetectorIds.MOUNT -> Icons.Rounded.Storage
    DetectorIds.MEMORY -> Icons.Rounded.Memory
    DetectorIds.LSPOSED -> Icons.Rounded.Extension
    DetectorIds.ZYGISK -> Icons.Rounded.Bolt
    DetectorIds.NATIVE -> Icons.Rounded.Code
    DetectorIds.VIRTUAL -> Icons.Rounded.Devices
    DetectorIds.TEE -> Icons.Rounded.Key
    DetectorIds.INTEGRITY -> Icons.Rounded.VerifiedUser
    DetectorIds.DEVELOPER -> Icons.Rounded.Build
    DetectorIds.DEBUGGER -> Icons.Rounded.BugReport
    DetectorIds.FRIDA -> Icons.Rounded.Sensors
    DetectorIds.HOOKS -> Icons.Rounded.Link
    DetectorIds.ROOT_FILES -> Icons.Rounded.FolderOpen
    DetectorIds.PARTITIONS -> Icons.Rounded.SdStorage
    DetectorIds.AVB -> Icons.Rounded.Verified
    DetectorIds.BUILD -> Icons.Rounded.Fingerprint
    DetectorIds.INJECTION -> Icons.Rounded.Layers
    DetectorIds.SYSFILES -> Icons.Rounded.Description
    DetectorIds.HARDENING -> Icons.Rounded.Gavel
    DetectorIds.TIME -> Icons.Rounded.Schedule
    DetectorIds.NETWORK -> Icons.Rounded.VpnKey
    DetectorIds.USER_CA -> Icons.Rounded.Policy
    DetectorIds.ACCESSIBILITY -> Icons.Rounded.Accessibility
    DetectorIds.CLONES -> Icons.Rounded.ContentCopy
    DetectorIds.APPENV -> Icons.Rounded.PhoneAndroid
    DetectorIds.EMULATOR -> Icons.Rounded.Computer
    DetectorIds.HARDWARE -> Icons.Rounded.Smartphone
    DetectorIds.POSTURE -> Icons.Rounded.Shield
    DetectorIds.GMS -> Icons.Rounded.Cloud
    DetectorIds.SPOOF -> Icons.Rounded.PinDrop
    DetectorIds.HIDE -> Icons.Rounded.VisibilityOff
    else -> Icons.Rounded.Info
}

fun sectionIcon(key: String): ImageVector = when (key) {
    "trust" -> Icons.Rounded.Shield
    "attestation", "probes" -> Icons.Rounded.Key
    "boot" -> Icons.Rounded.Lock
    "chain" -> Icons.Rounded.Link
    "revocation" -> Icons.Rounded.Policy
    "anomalies", "findings" -> Icons.Rounded.Warning
    "behavior", "knobs", "mode" -> Icons.Rounded.Tune
    "identity", "build" -> Icons.Rounded.Fingerprint
    "creds", "root" -> Icons.Rounded.AdminPanelSettings
    "exposure" -> Icons.Rounded.VisibilityOff
    "context", "tiers" -> Icons.Rounded.Layers
    "passed" -> Icons.Rounded.CheckCircle
    "impact" -> Icons.Rounded.BugReport
    "methods" -> Icons.Rounded.Search
    "summary" -> Icons.Rounded.Description
    else -> Icons.Rounded.Info
}
