package com.pond.inspector.scan

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.pond.inspector.logic.Signals
import com.pond.inspector.model.DetectorIds
import com.pond.inspector.model.DetectorReport
import com.pond.inspector.model.Evidence
import com.pond.inspector.model.Phrase
import com.pond.inspector.model.ScanPrefs
import com.pond.inspector.model.Status
import com.pond.inspector.model.worst
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.UUID

data class Detector(
    val id: String,
    val title: Phrase,
    val about: Phrase,
    val limits: Phrase,
    val probe: suspend (Context, ScanPrefs) -> DetectorReport,
)

internal fun ev(en: String, fa: String, value: String, level: Status = Status.INFO) =
    Evidence(Phrase(en, fa), value.ifBlank { "—" }, level)

internal fun report(
    id: String,
    status: Status,
    en: String,
    fa: String,
    evidence: List<Evidence>,
    caption: Phrase? = null,
    metrics: List<com.pond.inspector.model.Metric> = emptyList(),
    highlights: List<com.pond.inspector.model.Metric> = emptyList(),
    sections: List<com.pond.inspector.model.Section> = emptyList(),
    impact: Phrase? = null,
    score: Int? = null,
) = DetectorReport(
    id = id,
    status = status,
    summary = Phrase(en, fa),
    evidence = evidence,
    caption = caption,
    metrics = metrics,
    highlights = highlights,
    sections = sections,
    impact = impact,
    score = score,
)

object Catalog {
    val all: List<Detector> = listOf(
        bootloader(),
        customRom(),
        dangerousApps(),
        rootManagers(),
        su(),
        selinuxDeep(),
        props(),
        adb(),
        kernelDeep(),
        mount(),
        memory(),
        lsposed(),
        zygisk(),
        nativeRoot(),
        virtualization(),
        teeDeep(),
        integrityDeep(),
    ) + extraDetectors()

    fun byId(id: String): Detector? = all.firstOrNull { it.id == id }
}

private fun bootloader() = Detector(
    id = DetectorIds.BOOTLOADER,
    title = Phrase("Bootloader", "بوت‌لودر"),
    about = Phrase(
        "Reads verified-boot properties exposed to apps: verifiedbootstate, flash lock, and vbmeta device state.",
        "پراپرتی‌های verified boot که از اپ دیده می‌شوند را می‌خواند: وضعیت بوت، قفل فلش و vbmeta.",
    ),
    limits = Phrase(
        "A green state does not prove the images are original. Some kernels hide or rewrite these properties.",
        "سبز بودن ثابت نمی‌کند ایمیج‌ها اصل هستند. بعضی کرنل‌ها این پراپرتی‌ها را پنهان یا عوض می‌کنند.",
    ),
    probe = { _, _ ->
        val props = AndroidFacts.props(
            listOf(
                "ro.boot.verifiedbootstate",
                "ro.boot.flash.locked",
                "ro.boot.vbmeta.device_state",
                "ro.boot.verifiedbooterror",
                "ro.boot.warranty_bit",
            ),
        )
        val status = Signals.bootState(
            props["ro.boot.verifiedbootstate"].orEmpty(),
            props["ro.boot.flash.locked"].orEmpty(),
            props["ro.boot.vbmeta.device_state"].orEmpty(),
            props["ro.boot.verifiedbooterror"].orEmpty(),
        )
        val summary = when (status) {
            Status.CLEAR -> "Verified boot looks locked" to "بوت تأییدشده قفل به نظر می‌رسد"
            Status.WARNING -> "Unlocked or non-green verified boot" to "بوت‌لودر باز است یا وضعیت سبز نیست"
            Status.DANGER -> "Verified boot reported an error" to "verified boot خطا گزارش کرده"
            Status.UNSUPPORTED -> "Boot properties were not readable" to "پراپرتی‌های بوت خوانده نشدند"
            else -> "Boot state is unusual" to "وضعیت بوت نامعمول است"
        }
        report(
            DetectorIds.BOOTLOADER,
            status,
            summary.first,
            summary.second,
            props.map { (key, value) ->
                ev(key, key, value, if (value.isBlank()) Status.UNSUPPORTED else Status.INFO)
            },
        )
    },
)

private fun customRom() = Detector(
    id = DetectorIds.CUSTOM_ROM,
    title = Phrase("Custom ROM", "رام سفارشی"),
    about = Phrase(
        "Looks at build tags, build type, and fingerprint strings for test-keys or community ROM names.",
        "تگ بیلد، نوع بیلد و اثرانگشت را برای test-keys یا نام رام‌های جامعه بررسی می‌کند.",
    ),
    limits = Phrase(
        "A stock-looking fingerprint can be spoofed. This is not a signature check of the system image.",
        "اثرانگشت شبیه استوک می‌تواند جعل شود. این امضای ایمیج سیستم را بررسی نمی‌کند.",
    ),
    probe = { _, _ ->
        val tags = AndroidFacts.prop("ro.build.tags").ifBlank { Build.TAGS }
        val type = AndroidFacts.prop("ro.build.type").ifBlank { Build.TYPE }
        val fingerprint = AndroidFacts.prop("ro.build.fingerprint").ifBlank { Build.FINGERPRINT }
        val display = AndroidFacts.prop("ro.build.display.id").ifBlank { Build.DISPLAY }
        val status = Signals.romState(tags, type, "$fingerprint $display")
        val summary = when (status) {
            Status.WARNING -> "Test-keys or a non-user build" to "test-keys یا بیلد غیر user"
            Status.INFO -> "Community ROM name in the fingerprint" to "نام رام جامعه در اثرانگشت دیده شد"
            Status.CLEAR -> "User build with release-looking tags" to "بیلد user با تگ شبیه انتشار"
            else -> "Build identity was incomplete" to "هویت بیلد ناقص بود"
        }
        report(
            DetectorIds.CUSTOM_ROM,
            status,
            summary.first,
            summary.second,
            listOf(
                ev("ro.build.tags", "ro.build.tags", tags, if ("test-keys" in tags) Status.WARNING else Status.INFO),
                ev("ro.build.type", "ro.build.type", type, if (type != "user") Status.WARNING else Status.INFO),
                ev("Fingerprint", "اثرانگشت", fingerprint),
                ev("Display", "نمایش", display),
            ),
        )
    },
)

internal data class KnownApp(val packageName: String, val label: String, val level: Status)

private val managerApps = listOf(
    KnownApp("com.topjohnwu.magisk", "Magisk", Status.DANGER),
    KnownApp("io.github.vvb2060.magisk", "Magisk", Status.DANGER),
    KnownApp("io.github.huskydg.magisk", "Magisk Delta", Status.DANGER),
    KnownApp("me.weishu.kernelsu", "KernelSU", Status.DANGER),
    KnownApp("com.rifsxd.ksunext", "KernelSU Next", Status.DANGER),
    KnownApp("me.bmax.apatch", "APatch", Status.DANGER),
    KnownApp("eu.chainfire.supersu", "SuperSU", Status.DANGER),
    KnownApp("com.noshufou.android.su", "Superuser", Status.DANGER),
    KnownApp("com.koushikdutta.superuser", "Superuser", Status.DANGER),
    KnownApp("com.thirdparty.superuser", "Superuser", Status.DANGER),
    KnownApp("com.yellowes.su", "Superuser", Status.DANGER),
    KnownApp("eu.chainfire.supersu.pro", "SuperSU Pro", Status.DANGER),
    KnownApp("me.phh.superuser", "phh Superuser", Status.DANGER),
    KnownApp("com.kingouser.com", "KingoUser", Status.DANGER),
    KnownApp("com.kingroot.kinguser", "KingRoot", Status.DANGER),
    KnownApp("com.baidu.easyroot", "Baidu Easy Root", Status.DANGER),
    KnownApp("com.qihoo.permmgr", "360 Root", Status.DANGER),
    KnownApp("com.alephzain.framaroot", "Framaroot", Status.DANGER),
    KnownApp("com.dianxinos.superuser", "DX Superuser", Status.DANGER),
    KnownApp("com.mgyun.shua.su", "Shuame Root", Status.DANGER),
    KnownApp("com.m0narx.su", "m0narx su", Status.DANGER),
    KnownApp("com.zachspong.temprootremovejb", "Temp Root Remover", Status.DANGER),
    KnownApp("com.sukisu.ultra", "SukiSU Ultra", Status.DANGER),
    KnownApp("io.github.a13e300.ksuwebui", "KernelSU WebUI", Status.DANGER),
    KnownApp("stericson.busybox", "BusyBox Installer", Status.WARNING),
    KnownApp("com.jrummy.busybox.installer", "BusyBox Installer", Status.WARNING),
)

private val dangerousApps = listOf(
    KnownApp("org.lsposed.manager", "LSPosed Manager", Status.DANGER),
    KnownApp("io.github.lsposed.manager", "LSPosed Manager", Status.DANGER),
    KnownApp("org.lsposed.lspatch", "LSPatch", Status.DANGER),
    KnownApp("de.robv.android.xposed.installer", "Xposed Installer", Status.DANGER),
    KnownApp("org.meowcat.edxposed.manager", "EdXposed Manager", Status.DANGER),
    KnownApp("com.dimonvideo.luckypatcher", "Lucky Patcher", Status.WARNING),
    KnownApp("com.chelpus.lackypatch", "Lucky Patcher", Status.WARNING),
    KnownApp("com.chelpus.luckypatcher", "Lucky Patcher", Status.WARNING),
    KnownApp("com.android.vending.billing.InAppBillingService.LUCK", "Lucky Patcher", Status.WARNING),
    KnownApp("com.gameguardian", "GameGuardian", Status.WARNING),
    KnownApp("com.tsng.hidemyapplist", "Hide My Applist", Status.WARNING),
    KnownApp("bin.mt.plus", "MT Manager", Status.INFO),
    KnownApp("bin.mt.plus.canary", "MT Manager Canary", Status.INFO),
    KnownApp("moe.shizuku.privileged.api", "Shizuku", Status.INFO),
    KnownApp("moe.shizuku.manager", "Shizuku", Status.INFO),
    KnownApp("com.solohsu.android.edxp.manager", "EdXposed Manager", Status.DANGER),
    KnownApp("io.va.exposed", "VirtualXposed", Status.DANGER),
    KnownApp("me.weishu.exp", "Taichi", Status.DANGER),
    KnownApp("com.saurik.substrate", "Cydia Substrate", Status.DANGER),
    KnownApp("catch_.me_.if_.you_.can_", "GameGuardian", Status.WARNING),
    KnownApp("com.android.vending.billing.InAppBillingService.COIN", "Lucky Patcher", Status.WARNING),
    KnownApp("cc.madkite.freedom", "Freedom", Status.WARNING),
    KnownApp("com.xmodgame", "X-mod Game", Status.WARNING),
    KnownApp("com.gmail.heagoo.apkeditor", "APK Editor", Status.INFO),
    KnownApp("com.termux", "Termux", Status.INFO),
    KnownApp("com.keramidas.TitaniumBackup", "Titanium Backup", Status.INFO),
    KnownApp("com.omarea.vtools", "Scene", Status.INFO),
)

internal fun scanApps(context: Context, known: List<KnownApp>, id: String, clearEn: String, clearFa: String, hitEn: String, hitFa: String): DetectorReport {
    val installed = AndroidFacts.installedPackages(context)
    val names = installed.map { it.packageName }.toSet()
    val limited = names.size <= 3
    val hits = known.filter { it.packageName in names }
    val status = when {
        limited && hits.isEmpty() -> Status.UNSUPPORTED
        hits.isEmpty() -> Status.CLEAR
        else -> worst(hits.map { it.level })
    }
    val summary = when {
        limited && hits.isEmpty() -> "Package visibility looks limited" to "دید به فهرست اپ‌ها محدود به نظر می‌رسد"
        hits.isEmpty() -> clearEn to clearFa
        else -> hitEn to hitFa
    }
    val evidence = buildList {
        add(ev("Visible packages", "اپ‌های قابل‌دیدن", names.size.toString(), if (limited) Status.UNSUPPORTED else Status.INFO))
        if (hits.isEmpty()) {
            add(ev("Matches", "تطابق", "0", Status.CLEAR))
        } else {
            hits.forEach { hit ->
                add(ev(hit.label, hit.label, hit.packageName, hit.level))
            }
        }
    }
    return report(id, status, summary.first, summary.second, evidence)
}

private fun dangerousApps() = Detector(
    id = DetectorIds.DANGEROUS,
    title = Phrase("Dangerous apps", "اپ‌های حساس"),
    about = Phrase(
        "Compares the visible package list with well-known hook, patch, and hide tools.",
        "فهرست اپ‌های قابل‌دیدن را با ابزارهای شناخته‌شدهٔ هوک، پچ و مخفی‌سازی مقایسه می‌کند.",
    ),
    limits = Phrase(
        "Hidden packages and renamed builds are invisible. A match is a signal, not proof of what the app is doing.",
        "بسته‌های مخفی و بیلدهای تغییرنام‌داده‌شده دیده نمی‌شوند. تطابق یک سیگنال است، نه اثبات رفتار اپ.",
    ),
    probe = { context, _ ->
        scanApps(
            context,
            dangerousApps,
            DetectorIds.DANGEROUS,
            "No listed modification tools are visible",
            "ابزار تغییر فهرست‌شده‌ای دیده نشد",
            "A known modification tool is visible",
            "یک ابزار تغییر شناخته‌شده دیده شد",
        )
    },
)

private fun rootManagers() = Detector(
    id = DetectorIds.MANAGERS,
    title = Phrase("Root managers", "مدیرهای روت"),
    about = Phrase(
        "Looks for manager packages of Magisk, KernelSU, APatch, and older su apps.",
        "بسته‌های مدیر Magisk، KernelSU، APatch و اپ‌های قدیمی su را جست‌وجو می‌کند.",
    ),
    limits = Phrase(
        "A manager can be hidden from the package list. Absence here is not absence on the device.",
        "مدیر روت می‌تواند از فهرست بسته‌ها پنهان شود. نبودن اینجا یعنی نبودن روی دستگاه نیست.",
    ),
    probe = { context, _ ->
        scanApps(
            context,
            managerApps,
            DetectorIds.MANAGERS,
            "No root manager package is visible",
            "بستهٔ مدیر روت دیده نشد",
            "A root manager package is visible",
            "بستهٔ مدیر روت دیده شد",
        )
    },
)

private val suPaths = listOf(
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/vendor/bin/su",
    "/debug_ramdisk/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/xbin/busybox",
    "/system/bin/busybox",
    "/system/sbin/su",
    "/su/bin/su",
    "/su/xbin/su",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/data/local/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/data/local/tmp/su",
    "/system/xbin/daemonsu",
    "/system/xbin/sugote",
    "/system/xbin/supolicy",
    "/system/bin/magisk",
    "/system/xbin/ku.sud",
    "/cache/su",
    "/dev/su",
)

private fun su() = Detector(
    id = DetectorIds.SU,
    title = Phrase("SU", "باینری SU"),
    about = Phrase(
        "Checks common su and busybox paths, every directory on PATH, then asks the shell whether `su` is on PATH.",
        "مسیرهای رایج su و busybox و همهٔ پوشه‌های PATH را چک می‌کند و از شل می‌پرسد su روی PATH هست یا نه.",
    ),
    limits = Phrase(
        "Paths outside this mount namespace are invisible. A missing file is not a proof of no root.",
        "مسیرهای بیرون از این namespace مانت دیده نمی‌شوند. نبودن فایل اثباتِ نبودن روت نیست.",
    ),
    probe = { _, _ ->
        val pathDirs = (System.getenv("PATH") ?: "").split(":").filter { it.isNotBlank() }.map { it.trimEnd('/') + "/su" }
        val found = (suPaths + pathDirs).distinct().filter { AndroidFacts.exists(it) }
        val which = AndroidFacts.runCommand("sh", "-c", "command -v su")
        val status = when {
            found.isNotEmpty() || which.isNotBlank() -> Status.DANGER
            else -> Status.CLEAR
        }
        val summary = if (status == Status.DANGER) {
            "An su binary is visible to this app" to "باینری su برای این اپ قابل‌دیدن است"
        } else {
            "No su binary on the paths this app can see" to "در مسیرهایی که این اپ می‌بیند su نیست"
        }
        report(
            DetectorIds.SU,
            status,
            summary.first,
            summary.second,
            buildList {
                (suPaths + pathDirs).distinct().filter { it in found || it in suPaths }.forEach { path ->
                    val present = path in found
                    add(ev(path, path, if (present) "present" else "not visible", if (present) Status.DANGER else Status.CLEAR))
                }
                add(ev("command -v su", "command -v su", which.ifBlank { "not found" }, if (which.isBlank()) Status.CLEAR else Status.DANGER))
            },
        )
    },
)

private fun props() = Detector(
    id = DetectorIds.PROPS,
    title = Phrase("System properties", "پراپرتی‌های سیستم"),
    about = Phrase(
        "Reads a short list of security properties: ro.secure, ro.debuggable, and adbd.",
        "فهرست کوتاهی از پراپرتی‌های امنیتی را می‌خواند: ro.secure، ro.debuggable و adbd.",
    ),
    limits = Phrase(
        "Properties can be reset by a resetprop tool. This is not a full property audit.",
        "پراپرتی‌ها را می‌توان با resetprop عوض کرد. این حسابرسی کامل پراپرتی‌ها نیست.",
    ),
    probe = { _, _ ->
        val keys = listOf(
            "ro.secure", "ro.debuggable", "ro.adb.secure", "service.adb.root", "init.svc.adbd", "ro.build.selinux",
            "ro.allow.mock.location", "persist.sys.usb.config", "sys.usb.config", "service.adb.tcp.port",
            "persist.adb.tcp.port", "persist.sys.root_access", "ro.boot.selinux", "ro.boot.mode", "ro.build.flavor",
            "ro.build.description", "ro.lineage.version", "ro.crdroid.version", "ro.modversion",
        )
        val values = AndroidFacts.props(keys)
        fun weak(key: String, value: String): Boolean = when (key) {
            "ro.secure" -> value == "0"
            "ro.debuggable" -> value == "1"
            "ro.adb.secure" -> value == "0"
            "service.adb.root" -> value == "1"
            "ro.allow.mock.location" -> value == "1"
            "service.adb.tcp.port", "persist.adb.tcp.port" -> (value.toIntOrNull() ?: -1) > 0
            "persist.sys.root_access" -> value.isNotBlank() && value != "0"
            "ro.boot.selinux" -> value.equals("permissive", ignoreCase = true)
            "ro.build.flavor" -> value.contains("userdebug") || value.contains("eng")
            "persist.sys.usb.config", "sys.usb.config" -> value.contains("adb")
            else -> false
        }
        val bad = values.filter { (key, value) -> weak(key, value) && key != "persist.sys.usb.config" && key != "sys.usb.config" }
        val status = if (bad.isNotEmpty()) Status.WARNING else Status.CLEAR
        val summary = if (bad.isNotEmpty()) {
            "A debug or insecure property is set" to "یک پراپرتی دیباگ یا ناامن تنظیم شده"
        } else {
            "The checked properties look like a user build" to "پراپرتی‌های بررسی‌شده شبیه بیلد user هستند"
        }
        report(
            DetectorIds.PROPS,
            status,
            summary.first,
            summary.second,
            values.filter { (key, value) -> value.isNotBlank() || key in keys.take(6) }.map { (key, value) ->
                val level = when {
                    key == "persist.sys.usb.config" || key == "sys.usb.config" -> Status.INFO
                    weak(key, value) -> Status.WARNING
                    else -> Status.INFO
                }
                ev(key, key, value, level)
            },
        )
    },
)

private fun adb() = Detector(
    id = DetectorIds.ADB,
    title = Phrase("ADB runtime", "اجرای ADB"),
    about = Phrase(
        "Reads the developer-options and USB debugging switches from Settings.",
        "کلید گزینه‌های توسعه‌دهنده و USB debugging را از تنظیمات می‌خواند.",
    ),
    limits = Phrase(
        "Wireless debugging and an already-connected adbd are not fully described by these two switches.",
        "دیباگ بی‌سیم و adbd از قبل وصل‌شده با این دو کلید کامل توصیف نمی‌شوند.",
    ),
    probe = { context, _ ->
        val resolver = context.contentResolver
        val adb = android.provider.Settings.Global.getInt(resolver, android.provider.Settings.Global.ADB_ENABLED, 0)
        val dev = android.provider.Settings.Global.getInt(resolver, android.provider.Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0)
        val status = if (adb == 1) Status.INFO else Status.CLEAR
        val summary = if (adb == 1) {
            "USB debugging is enabled" to "USB debugging روشن است"
        } else {
            "USB debugging is off" to "USB debugging خاموش است"
        }
        report(
            DetectorIds.ADB,
            status,
            summary.first,
            summary.second,
            listOf(
                ev("ADB enabled", "ADB روشن", adb.toString(), if (adb == 1) Status.INFO else Status.CLEAR),
                ev("Developer settings", "تنظیمات توسعه‌دهنده", dev.toString(), if (dev == 1) Status.INFO else Status.CLEAR),
            ),
        )
    },
)

private fun mount() = Detector(
    id = DetectorIds.MOUNT,
    title = Phrase("Mount", "مانت"),
    about = Phrase(
        "Scans this process mount table for magisk, zygisk, KernelSU, APatch, and debug_ramdisk.",
        "جدول مانت همین پروسه را برای magisk، zygisk، KernelSU، APatch و debug_ramdisk می‌گردد.",
    ),
    limits = Phrase(
        "Other mount namespaces are not visible. A clean table is not a clean device.",
        "namespaceهای مانت دیگر دیده نمی‌شوند. جدول تمیز یعنی دستگاه تمیز نیست.",
    ),
    probe = { _, _ ->
        val text = AndroidFacts.readText("/proc/self/mountinfo", 200_000)
        if (text == null) {
            report(
                DetectorIds.MOUNT,
                Status.UNSUPPORTED,
                "mountinfo was not readable",
                "mountinfo خوانده نشد",
                listOf(ev("/proc/self/mountinfo", "/proc/self/mountinfo", "unreadable", Status.UNSUPPORTED)),
            )
        } else {
            val hits = Signals.mountHits(text)
            val lines = text.lineSequence().count { it.isNotBlank() }
            val status = if (hits.isNotEmpty()) Status.DANGER else Status.CLEAR
            val summary = if (hits.isNotEmpty()) {
                "Mount table mentions ${hits.joinToString()}" to "جدول مانت به ${hits.joinToString()} اشاره دارد"
            } else {
                "No listed root mount tokens" to "توکن مانت روتِ فهرست‌شده‌ای نیست"
            }
            val samples = text.lineSequence()
                .filter { line -> hits.any { token -> token in line.lowercase() } }
                .take(6)
                .joinToString("\n")
            report(
                DetectorIds.MOUNT,
                status,
                summary.first,
                summary.second,
                listOf(
                    ev("Mount rows", "ردیف‌های مانت", lines.toString()),
                    ev("Tokens", "توکن‌ها", hits.joinToString().ifBlank { "none" }, status),
                    ev("Sample", "نمونه", samples.ifBlank { "—" }, status),
                ),
            )
        }
    },
)

private fun memory() = Detector(
    id = DetectorIds.MEMORY,
    title = Phrase("Memory maps", "نقشه‌های حافظه"),
    about = Phrase(
        "Scans this process maps for frida, zygisk, lsposed, riru, substrate, and magisk.",
        "نقشه‌های همین پروسه را برای frida، zygisk، lsposed، riru، substrate و magisk می‌گردد.",
    ),
    limits = Phrase(
        "Hooks that never map those names into this process are invisible.",
        "هوک‌هایی که این نام‌ها را داخل همین پروسه map نکنند دیده نمی‌شوند.",
    ),
    probe = { _, _ ->
        val text = AndroidFacts.readText("/proc/self/maps", 400_000)
        if (text == null) {
            report(
                DetectorIds.MEMORY,
                Status.UNSUPPORTED,
                "maps was not readable",
                "maps خوانده نشد",
                emptyList(),
            )
        } else {
            val hits = Signals.mapHits(text)
            val status = if (hits.isNotEmpty()) Status.DANGER else Status.CLEAR
            val summary = if (hits.isNotEmpty()) {
                "Maps mention ${hits.joinToString()}" to "نقشه‌ها به ${hits.joinToString()} اشاره دارند"
            } else {
                "No listed injection tokens in this process" to "توکن تزریقِ فهرست‌شده‌ای در این پروسه نیست"
            }
            report(
                DetectorIds.MEMORY,
                status,
                summary.first,
                summary.second,
                listOf(ev("Tokens", "توکن‌ها", hits.joinToString().ifBlank { "none" }, status)),
            )
        }
    },
)

private fun lsposed() = Detector(
    id = DetectorIds.LSPOSED,
    title = Phrase("LSPosed", "LSPosed"),
    about = Phrase(
        "Correlates LSPosed or Xposed manager packages with map tokens.",
        "بسته‌های مدیر LSPosed یا Xposed را با توکن‌های نقشه کنار هم می‌گذارد.",
    ),
    limits = Phrase(
        "A hidden manager and a hook that does not map those names will not show up.",
        "مدیر مخفی و هوکی که این نام‌ها را map نکند دیده نمی‌شود.",
    ),
    probe = { context, _ ->
        val names = AndroidFacts.installedPackages(context).map { it.packageName }.toSet()
        val managers = listOf("org.lsposed.manager", "io.github.lsposed.manager", "org.lsposed.lspatch", "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager")
            .filter { it in names }
        val maps = AndroidFacts.readText("/proc/self/maps", 400_000).orEmpty()
        val tokens = Signals.mapHits(maps).filter { it == "lsposed" || it == "xposed" }
        val status = when {
            managers.isNotEmpty() || tokens.isNotEmpty() -> Status.DANGER
            names.size <= 3 && maps.isBlank() -> Status.UNSUPPORTED
            else -> Status.CLEAR
        }
        val summary = if (status == Status.DANGER) {
            "LSPosed or Xposed evidence is visible" to "شواهد LSPosed یا Xposed دیده شد"
        } else {
            "No LSPosed evidence in the places this app can see" to "در جاهایی که این اپ می‌بیند شواهد LSPosed نیست"
        }
        report(
            DetectorIds.LSPOSED,
            status,
            summary.first,
            summary.second,
            listOf(
                ev("Manager packages", "بسته‌های مدیر", managers.joinToString().ifBlank { "none" }, if (managers.isEmpty()) Status.CLEAR else Status.DANGER),
                ev("Map tokens", "توکن‌های نقشه", tokens.joinToString().ifBlank { "none" }, if (tokens.isEmpty()) Status.CLEAR else Status.DANGER),
            ),
        )
    },
)

private fun zygisk() = Detector(
    id = DetectorIds.ZYGISK,
    title = Phrase("Zygisk", "Zygisk"),
    about = Phrase(
        "Looks for zygisk strings in this process and for a visible Magisk manager.",
        "رشتهٔ zygisk را در همین پروسه و مدیر Magisk قابل‌دیدن را جست‌وجو می‌کند.",
    ),
    limits = Phrase(
        "Zygisk that is not mapped into this process, and a hidden Magisk app, will not show up.",
        "Zygisk که در این پروسه map نشده و اپ Magisk مخفی دیده نمی‌شوند.",
    ),
    probe = { context, _ ->
        val names = AndroidFacts.installedPackages(context).map { it.packageName }.toSet()
        val magiskIds = listOf("com.topjohnwu.magisk", "io.github.vvb2060.magisk", "io.github.huskydg.magisk")
        val magisk = magiskIds.filter { it in names }
        val maps = AndroidFacts.readText("/proc/self/maps", 400_000).orEmpty()
        val mounts = AndroidFacts.readText("/proc/self/mountinfo", 200_000).orEmpty()
        val token = "zygisk" in maps.lowercase() || "zygisk" in mounts.lowercase()
        val status = when {
            token -> Status.DANGER
            magisk.isNotEmpty() -> Status.WARNING
            else -> Status.CLEAR
        }
        val summary = when (status) {
            Status.DANGER -> "Zygisk is mentioned in maps or mounts" to "zygisk در نقشه یا مانت آمده"
            Status.WARNING -> "A Magisk manager is visible, without a zygisk map token" to "مدیر Magisk دیده شد، بدون توکن zygisk در نقشه"
            else -> "No zygisk token in this process" to "توکن zygisk در این پروسه نیست"
        }
        report(
            DetectorIds.ZYGISK,
            status,
            summary.first,
            summary.second,
            listOf(
                ev("zygisk token", "توکن zygisk", token.toString(), if (token) Status.DANGER else Status.CLEAR),
                ev("Magisk package", "بستهٔ Magisk", magisk.distinct().joinToString().ifBlank { "none" }, if (magisk.isEmpty()) Status.CLEAR else Status.WARNING),
            ),
        )
    },
)

private fun nativeRoot() = Detector(
    id = DetectorIds.NATIVE,
    title = Phrase("Native root", "روت محلی"),
    about = Phrase(
        "Correlates su paths, root-manager packages, and map or mount tokens. There is no native exploit probe.",
        "مسیر su، بستهٔ مدیر روت و توکن نقشه یا مانت را کنار هم می‌گذارد. پروب اکسپلویت نیتیو ندارد.",
    ),
    limits = Phrase(
        "Root that hides every one of those signals from this app process will look clear.",
        "روتی که همهٔ این سیگنال‌ها را از همین پروسه پنهان کند، سالم به نظر می‌رسد.",
    ),
    probe = { context, _ ->
        val suFound = suPaths.any { AndroidFacts.exists(it) } || AndroidFacts.runCommand("sh", "-c", "command -v su").isNotBlank()
        val names = AndroidFacts.installedPackages(context).map { it.packageName }.toSet()
        val managers = managerApps.filter { it.packageName in names }.map { it.label }
        val maps = Signals.mapHits(AndroidFacts.readText("/proc/self/maps", 400_000).orEmpty())
        val mounts = Signals.mountHits(AndroidFacts.readText("/proc/self/mountinfo", 200_000).orEmpty())
        val tags = AndroidFacts.prop("ro.build.tags")
        val status = when {
            suFound || managers.isNotEmpty() || maps.isNotEmpty() || mounts.isNotEmpty() -> Status.DANGER
            "test-keys" in tags -> Status.WARNING
            else -> Status.CLEAR
        }
        val summary = when (status) {
            Status.DANGER -> "A root-related signal is visible" to "یک سیگنال مرتبط با روت دیده شد"
            Status.WARNING -> "Only test-keys, no su or manager" to "فقط test-keys، بدون su یا مدیر"
            else -> "No correlated root signal in this process" to "سیگنال روتِ هم‌بسته در این پروسه نیست"
        }
        report(
            DetectorIds.NATIVE,
            status,
            summary.first,
            summary.second,
            listOf(
                ev("su visible", "su قابل‌دیدن", suFound.toString(), if (suFound) Status.DANGER else Status.CLEAR),
                ev("Managers", "مدیرها", managers.distinct().joinToString().ifBlank { "none" }, if (managers.isEmpty()) Status.CLEAR else Status.DANGER),
                ev("Map tokens", "توکن‌های نقشه", maps.joinToString().ifBlank { "none" }, if (maps.isEmpty()) Status.CLEAR else Status.DANGER),
                ev("Mount tokens", "توکن‌های مانت", mounts.joinToString().ifBlank { "none" }, if (mounts.isEmpty()) Status.CLEAR else Status.DANGER),
            ),
        )
    },
)

private fun virtualization() = Detector(
    id = DetectorIds.VIRTUAL,
    title = Phrase("Virtualization", "مجازی‌سازی"),
    about = Phrase(
        "Looks for emulator hardware, product, and qemu properties.",
        "سخت‌افزار، محصول و پراپرتی qemu شبیه‌ساز را جست‌وجو می‌کند.",
    ),
    limits = Phrase(
        "A production virtual device with a stock-looking identity will not match these strings.",
        "دستگاه مجازی تولیدی با هویت شبیه استوک با این رشته‌ها جور نمی‌شود.",
    ),
    probe = { _, _ ->
        val qemu = AndroidFacts.prop("ro.kernel.qemu")
        val hits = Signals.virtualHits(Build.FINGERPRINT, Build.HARDWARE, Build.PRODUCT, Build.MODEL, qemu)
        val status = if (hits.isNotEmpty()) Status.WARNING else Status.CLEAR
        val summary = if (hits.isNotEmpty()) {
            "This looks like an emulator or virtual device" to "این شبیه شبیه‌ساز یا دستگاه مجازی است"
        } else {
            "No common emulator identity" to "هویت رایج شبیه‌ساز دیده نشد"
        }
        report(
            DetectorIds.VIRTUAL,
            status,
            summary.first,
            summary.second,
            listOf(
                ev("Hardware", "سخت‌افزار", Build.HARDWARE),
                ev("Product", "محصول", Build.PRODUCT),
                ev("Model", "مدل", Build.MODEL),
                ev("ro.kernel.qemu", "ro.kernel.qemu", qemu.ifBlank { "—" }),
                ev("Hits", "تطابق‌ها", hits.joinToString().ifBlank { "none" }, status),
            ),
        )
    },
)

object DeviceFacts {
    fun collect(): List<Evidence> {
        val props = AndroidFacts.props(
            listOf(
                "ro.build.version.security_patch",
                "ro.boot.verifiedbootstate",
                "ro.product.cpu.abi",
                "ro.crypto.state",
            ),
        )
        val kernel = AndroidFacts.readText("/proc/version", 500).orEmpty().lineSequence().firstOrNull().orEmpty()
        return listOf(
            ev("Brand", "برند", Build.BRAND),
            ev("Manufacturer", "سازنده", Build.MANUFACTURER),
            ev("Model", "مدل", Build.MODEL),
            ev("Device", "دستگاه", Build.DEVICE),
            ev("Product", "محصول", Build.PRODUCT),
            ev("Hardware", "سخت‌افزار", Build.HARDWARE),
            ev("Board", "برد", Build.BOARD),
            ev("Android", "اندروید", Build.VERSION.RELEASE),
            ev("SDK", "SDK", Build.VERSION.SDK_INT.toString()),
            ev("Security patch", "وصلهٔ امنیتی", props["ro.build.version.security_patch"].orEmpty().ifBlank { Build.VERSION.SECURITY_PATCH }),
            ev("Fingerprint", "اثرانگشت", Build.FINGERPRINT),
            ev("Build ID", "شناسهٔ بیلد", Build.ID),
            ev("Type", "نوع", Build.TYPE),
            ev("Tags", "تگ‌ها", Build.TAGS),
            ev("ABI", "ABI", Build.SUPPORTED_ABIS.joinToString()),
            ev("Bootloader", "بوت‌لودر", Build.BOOTLOADER),
            ev("Verified boot", "بوت تأییدشده", props["ro.boot.verifiedbootstate"].orEmpty()),
            ev("Encryption", "رمزنگاری", props["ro.crypto.state"].orEmpty()),
            ev("Kernel", "کرنل", kernel.ifBlank { System.getProperty("os.version").orEmpty() }),
        )
    }
}
