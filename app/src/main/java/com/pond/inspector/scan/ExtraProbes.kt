package com.pond.inspector.scan

import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.SystemClock
import android.provider.Settings
import com.pond.inspector.model.DetectorIds
import com.pond.inspector.model.DetectorReport
import com.pond.inspector.model.Evidence
import com.pond.inspector.model.Phrase
import com.pond.inspector.model.Status
import java.io.File

internal fun det(
    id: String,
    titleEn: String,
    titleFa: String,
    aboutEn: String,
    aboutFa: String,
    limitsEn: String,
    limitsFa: String,
    run: (Context) -> DetectorReport,
) = Detector(
    id = id,
    title = Phrase(titleEn, titleFa),
    about = Phrase(aboutEn, aboutFa),
    limits = Phrase(limitsEn, limitsFa),
    probe = { context, _ -> run(context) },
)

internal fun listDir(path: String): List<String> = try {
    File(path).list()?.toList().orEmpty()
} catch (_: Exception) {
    emptyList()
}

internal fun lvl(bad: Boolean, badLevel: Status = Status.WARNING): Status = if (bad) badLevel else Status.CLEAR

internal fun globalInt(context: Context, name: String, default: Int = 0): Int = try {
    Settings.Global.getInt(context.contentResolver, name, default)
} catch (_: Exception) {
    default
}

internal fun secureInt(context: Context, name: String, default: Int = 0): Int = try {
    Settings.Secure.getInt(context.contentResolver, name, default)
} catch (_: Exception) {
    default
}

internal fun secureString(context: Context, name: String): String = try {
    Settings.Secure.getString(context.contentResolver, name).orEmpty()
} catch (_: Exception) {
    ""
}

internal fun extraDetectors(): List<Detector> = listOf(
    developer(),
    debugger(),
    frida(),
    hooks(),
    rootFiles(),
    partitions(),
    avb(),
    buildCheck(),
    injection(),
    sysFiles(),
    hardeningDeep(),
    clockCheck(),
) + envDetectors()

private fun developer() = det(
    DetectorIds.DEVELOPER,
    "Developer options", "گزینه‌های توسعه‌دهنده",
    "Reads developer settings that change how safe the device is: developer mode, USB and wireless debugging, wait-for-debugger, mock location, and the adb TCP port.",
    "تنظیمات توسعه‌دهنده‌ای را که امنیت دستگاه را عوض می‌کنند می‌خواند: حالت توسعه‌دهنده، دیباگ USB و بی‌سیم، انتظار برای دیباگر، موقعیت جعلی و پورت TCP adb.",
    "Settings can be changed or hidden by a hooked Settings provider. Mock-location apps are not listed here.",
    "تنظیمات را می‌توان با هوک روی Settings عوض یا پنهان کرد. اپ‌های موقعیت جعلی اینجا فهرست نمی‌شوند.",
) { context ->
    val dev = globalInt(context, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
    val adb = globalInt(context, Settings.Global.ADB_ENABLED)
    val wifi = globalInt(context, "adb_wifi_enabled")
    val waitDebugger = globalInt(context, Settings.Global.WAIT_FOR_DEBUGGER)
    val stayAwake = globalInt(context, Settings.Global.STAY_ON_WHILE_PLUGGED_IN)
    val mock = secureInt(context, "mock_location")
    val tcp = AndroidFacts.prop("service.adb.tcp.port").ifBlank { AndroidFacts.prop("persist.adb.tcp.port") }
    val tcpOpen = (tcp.toIntOrNull() ?: -1) > 0
    val status = when {
        wifi == 1 || tcpOpen || waitDebugger == 1 || mock == 1 -> Status.WARNING
        dev == 1 || adb == 1 -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.WARNING -> "A risky developer setting is on" to "یک تنظیم توسعه‌دهندهٔ پرخطر روشن است"
        Status.INFO -> "Developer mode or USB debugging is on" to "حالت توسعه‌دهنده یا دیباگ USB روشن است"
        else -> "Developer options are off" to "گزینه‌های توسعه‌دهنده خاموش است"
    }
    report(
        DetectorIds.DEVELOPER, status, summary.first, summary.second,
        listOf(
            ev("Developer mode", "حالت توسعه‌دهنده", if (dev == 1) "on" else "off", if (dev == 1) Status.INFO else Status.CLEAR),
            ev("USB debugging", "دیباگ USB", if (adb == 1) "on" else "off", if (adb == 1) Status.INFO else Status.CLEAR),
            ev("Wireless debugging", "دیباگ بی‌سیم", if (wifi == 1) "on" else "off", lvl(wifi == 1)),
            ev("adb TCP port", "پورت TCP adb", tcp.ifBlank { "off" }, lvl(tcpOpen)),
            ev("Wait for debugger", "انتظار برای دیباگر", if (waitDebugger == 1) "on" else "off", lvl(waitDebugger == 1)),
            ev("Mock location", "موقعیت جعلی", if (mock == 1) "on" else "off", lvl(mock == 1)),
            ev("Stay awake while charging", "بیدار ماندن هنگام شارژ", stayAwake.toString()),
        ),
    )
}

private fun debugger() = det(
    DetectorIds.DEBUGGER,
    "Debugger and tracer", "دیباگر و تریسر",
    "Checks whether something is attached to this process: a ptrace tracer (TracerPid), a Java debugger, a JDWP thread, and whether this build is debuggable.",
    "بررسی می‌کند چیزی به این پروسه وصل است یا نه: tracer از نوع ptrace (TracerPid)، دیباگر جاوا، ترد JDWP و debuggable بودن همین بیلد.",
    "A tracer that attaches after the scan, or one that hides TracerPid, is not seen.",
    "tracerای که بعد از اسکن وصل شود یا TracerPid را پنهان کند دیده نمی‌شود.",
) { context ->
    val status0 = AndroidFacts.readText("/proc/self/status", 8_000).orEmpty()
    val tracer = status0.lineSequence().firstOrNull { it.startsWith("TracerPid") }
        ?.substringAfter(':')?.trim()?.toIntOrNull() ?: -1
    val connected = Debug.isDebuggerConnected()
    val waiting = Debug.waitingForDebugger()
    val threads = listDir("/proc/self/task").mapNotNull { tid ->
        AndroidFacts.readText("/proc/self/task/$tid/comm", 64)?.trim()
    }
    val jdwp = threads.any { it.contains("JDWP", ignoreCase = true) }
    val debuggable = (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
    val status = when {
        tracer > 0 || connected -> Status.DANGER
        waiting || jdwp -> Status.WARNING
        tracer < 0 -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.DANGER -> "A tracer or debugger is attached" to "یک tracer یا دیباگر وصل است"
        Status.WARNING -> "A debug thread is active" to "یک ترد دیباگ فعال است"
        Status.INFO -> "TracerPid was not readable" to "TracerPid خوانده نشد"
        else -> "Nothing is attached to this process" to "چیزی به این پروسه وصل نیست"
    }
    report(
        DetectorIds.DEBUGGER, status, summary.first, summary.second,
        listOf(
            ev("TracerPid", "TracerPid", if (tracer < 0) "unreadable" else tracer.toString(), if (tracer > 0) Status.DANGER else if (tracer == 0) Status.CLEAR else Status.UNSUPPORTED),
            ev("Java debugger connected", "دیباگر جاوا وصل است", connected.toString(), lvl(connected, Status.DANGER)),
            ev("Waiting for debugger", "منتظر دیباگر", waiting.toString(), lvl(waiting)),
            ev("JDWP thread", "ترد JDWP", jdwp.toString(), lvl(jdwp)),
            ev("This build is debuggable", "این بیلد debuggable است", debuggable.toString(), if (debuggable) Status.INFO else Status.CLEAR),
            ev("Threads", "تردها", threads.size.toString()),
        ),
    )
}

private fun portOpen(port: Int): Boolean = try {
    java.net.Socket().use { socket ->
        socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 250)
        true
    }
} catch (_: Exception) {
    false
}

private fun frida() = det(
    DetectorIds.FRIDA,
    "Frida", "Frida",
    "Looks for Frida in four places: the default server ports on loopback, well-known server files, thread names inside this process, and open file descriptors and mapped libraries.",
    "Frida را در چهار جا جست‌وجو می‌کند: پورت‌های پیش‌فرض سرور روی loopback، فایل‌های شناخته‌شدهٔ سرور، نام تردهای همین پروسه، و fdهای باز و کتابخانه‌های map‌شده.",
    "A renamed server on a custom port, or a gadget that hides its threads, will not show up.",
    "سرور تغییرنام‌داده روی پورت دلخواه یا gadget که تردهایش را پنهان کند دیده نمی‌شود.",
) { _ ->
    val ports = listOf(27042, 27043, 27047).filter { portOpen(it) }
    val files = listOf(
        "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server", "/data/local/tmp/frida-server-arm64",
        "/data/local/tmp/frida-gadget.so", "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida",
    ).filter { AndroidFacts.exists(it) }
    val names = listDir("/proc/self/task").mapNotNull { tid ->
        AndroidFacts.readText("/proc/self/task/$tid/comm", 64)?.trim()
    }
    val strongThreads = names.filter { n -> listOf("gum-js-loop", "pool-frida", "frida", "linjector").any { n.contains(it) } }
    val weakThreads = names.filter { it == "gmain" || it == "gdbus" }
    val fds = listDir("/proc/self/fd").mapNotNull { fd ->
        try {
            File("/proc/self/fd/$fd").canonicalPath
        } catch (_: Exception) {
            null
        }
    }.filter { it.contains("frida", ignoreCase = true) || it.contains("linjector", ignoreCase = true) }
    val maps = com.pond.inspector.logic.Signals.mapHits(AndroidFacts.readText("/proc/self/maps", 400_000).orEmpty())
        .filter { it == "frida" || it == "frida-gum" }
    val strong = ports.isNotEmpty() || files.isNotEmpty() || strongThreads.isNotEmpty() || fds.isNotEmpty() || maps.isNotEmpty()
    val status = when {
        strong -> Status.DANGER
        weakThreads.isNotEmpty() -> Status.WARNING
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.DANGER -> "Frida evidence is visible" to "شواهد Frida دیده شد"
        Status.WARNING -> "Threads that Frida also uses are running" to "تردهایی که Frida هم استفاده می‌کند در حال اجراست"
        else -> "No Frida evidence on the paths this app can see" to "در مسیرهایی که این اپ می‌بیند شاهدی از Frida نیست"
    }
    report(
        DetectorIds.FRIDA, status, summary.first, summary.second,
        listOf(
            ev("Open server ports", "پورت‌های باز سرور", ports.joinToString().ifBlank { "none" }, lvl(ports.isNotEmpty(), Status.DANGER)),
            ev("Server files", "فایل‌های سرور", files.joinToString().ifBlank { "none" }, lvl(files.isNotEmpty(), Status.DANGER)),
            ev("Frida threads", "تردهای Frida", strongThreads.distinct().joinToString().ifBlank { "none" }, lvl(strongThreads.isNotEmpty(), Status.DANGER)),
            ev("glib threads", "تردهای glib", weakThreads.distinct().joinToString().ifBlank { "none" }, lvl(weakThreads.isNotEmpty())),
            ev("File descriptors", "fdها", fds.take(3).joinToString().ifBlank { "none" }, lvl(fds.isNotEmpty(), Status.DANGER)),
            ev("Map tokens", "توکن‌های نقشه", maps.joinToString().ifBlank { "none" }, lvl(maps.isNotEmpty(), Status.DANGER)),
        ),
    )
}

private fun hooks() = det(
    DetectorIds.HOOKS,
    "Hook frameworks", "فریمورک‌های هوک",
    "Looks inside this process for Xposed, LSPosed and Substrate: loadable framework classes, hook frames in the call stack, and injected environment variables.",
    "داخل همین پروسه دنبال Xposed و LSPosed و Substrate می‌گردد: کلاس‌های قابل‌بارگذاری فریمورک، فریم‌های هوک در call stack و متغیرهای محیطی تزریق‌شده.",
    "Frameworks that hide their classes from this app's classloader, or that do not hook this process, are not seen.",
    "فریمورکی که کلاس‌هایش را از classloader این اپ پنهان کند یا این پروسه را هوک نکند دیده نمی‌شود.",
) { _ ->
    fun loadable(name: String): Boolean = try {
        Class.forName(name, false, ClassLoader.getSystemClassLoader())
        true
    } catch (_: Throwable) {
        false
    }
    val classes = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "com.saurik.substrate.MS",
        "org.lsposed.lspd.nativebridge.NativeAPI",
        "io.github.libxposed.api.XposedInterface",
    ).filter { loadable(it) }
    val tokens = listOf("xposed", "lsphooker", "edxp", "lspd", "substrate", "riru", "zygisk", "sandhook")
    val frames = Throwable().stackTrace.map { it.className + "." + it.methodName }
        .filter { frame -> tokens.any { frame.contains(it, ignoreCase = true) } }
    val classpath = System.getenv("CLASSPATH").orEmpty()
    val classpathHit = tokens.any { classpath.contains(it, ignoreCase = true) }
    val vxp = System.getProperty("vxp") != null
    val status = if (classes.isNotEmpty() || frames.isNotEmpty() || classpathHit || vxp) Status.DANGER else Status.CLEAR
    val summary = if (status == Status.DANGER) {
        "A hook framework is active in this process" to "یک فریمورک هوک در این پروسه فعال است"
    } else {
        "No hook framework inside this process" to "فریمورک هوکی داخل این پروسه نیست"
    }
    report(
        DetectorIds.HOOKS, status, summary.first, summary.second,
        listOf(
            ev("Framework classes", "کلاس‌های فریمورک", classes.joinToString().ifBlank { "none" }, lvl(classes.isNotEmpty(), Status.DANGER)),
            ev("Hook frames in stack", "فریم‌های هوک در stack", frames.take(3).joinToString().ifBlank { "none" }, lvl(frames.isNotEmpty(), Status.DANGER)),
            ev("CLASSPATH", "CLASSPATH", if (classpathHit) classpath.take(120) else "none", lvl(classpathHit, Status.DANGER)),
            ev("vxp property", "پراپرتی vxp", vxp.toString(), lvl(vxp, Status.DANGER)),
        ),
    )
}

private data class Artifact(val path: String, val group: String)

private val rootArtifacts: List<Artifact> = listOf(
    "/sbin/.magisk", "/sbin/.core", "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/modules",
    "/data/adb/modules_update", "/data/adb/post-fs-data.d", "/data/adb/service.d", "/cache/magisk.log",
    "/data/magisk", "/data/adb/lspd", "/debug_ramdisk/.magisk",
).map { Artifact(it, "Magisk") } + listOf(
    "/data/adb/ksu", "/data/adb/ksud",
).map { Artifact(it, "KernelSU") } + listOf(
    "/data/adb/ap", "/data/adb/apd",
).map { Artifact(it, "APatch") } + listOf(
    "/system/app/Superuser.apk", "/system/app/SuperSU", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon",
    "/system/xbin/sugote", "/system/xbin/sugote-mksh", "/system/xbin/supolicy", "/system/bin/.ext/.su",
    "/su", "/su/bin", "/su/xbin", "/dev/com.koushikdutta.superuser.daemon", "/system/etc/su.d", "/system/su.d",
).map { Artifact(it, "SuperSU") } + listOf(
    "/system/framework/XposedBridge.jar", "/system/xposed.prop", "/system/bin/app_process32_xposed",
    "/system/bin/app_process64_xposed", "/system/lib/libxposed_art.so", "/system/lib64/libxposed_art.so",
    "/data/misc/riru", "/data/adb/riru",
).map { Artifact(it, "Xposed") }

private fun rootFiles() = det(
    DetectorIds.ROOT_FILES,
    "Root artifacts", "ردپای روت",
    "Checks a list of files and folders that Magisk, KernelSU, APatch, SuperSU and Xposed leave behind.",
    "فهرستی از فایل‌ها و پوشه‌هایی را که Magisk و KernelSU و APatch و SuperSU و Xposed به جا می‌گذارند چک می‌کند.",
    "Most of these live under /data/adb, which untrusted apps usually cannot see. An unreadable path reads as missing.",
    "بیشترشان زیر /data/adb هستند که اپ‌های معمولی معمولاً نمی‌بینند. مسیر غیرقابل‌دسترس مثل نبودن دیده می‌شود.",
) { _ ->
    val hits = rootArtifacts.filter { AndroidFacts.exists(it.path) }
    val status = if (hits.isNotEmpty()) Status.DANGER else Status.CLEAR
    val groups = hits.map { it.group }.distinct()
    val summary = if (hits.isNotEmpty()) {
        "Root files found: ${groups.joinToString()}" to "فایل‌های روت پیدا شد: ${groups.joinToString()}"
    } else {
        "None of the ${rootArtifacts.size} listed root files are visible" to "هیچ‌یک از ${rootArtifacts.size} فایل روتِ فهرست‌شده دیده نمی‌شود"
    }
    report(
        DetectorIds.ROOT_FILES, status, summary.first, summary.second,
        buildList {
            add(ev("Paths checked", "مسیرهای بررسی‌شده", rootArtifacts.size.toString()))
            if (hits.isEmpty()) {
                add(ev("Matches", "تطابق", "0", Status.CLEAR))
            } else {
                hits.forEach { add(ev(it.group, it.group, it.path, Status.DANGER)) }
            }
        },
    )
}

private data class MountRow(val device: String, val point: String, val type: String, val opts: List<String>)

private fun partitions() = det(
    DetectorIds.PARTITIONS,
    "System partitions", "پارتیشن‌های سیستم",
    "Reads the mount table for signs that system partitions were changed: writable /system or /vendor, overlay or tmpfs on top of them, and bind mounts inside /system.",
    "جدول مانت را دنبال نشانهٔ دست‌کاری پارتیشن‌های سیستم می‌خواند: /system یا /vendor قابل‌نوشتن، overlay یا tmpfs روی آن‌ها و bind mount داخل /system.",
    "Only the mount namespace of this app is visible. Root tools that unmount themselves for apps leave nothing here.",
    "فقط namespace مانت همین اپ دیده می‌شود. ابزار روتی که برای اپ‌ها خودش را آن‌مانت کند چیزی اینجا نمی‌گذارد.",
) { _ ->
    val text = AndroidFacts.readText("/proc/mounts", 150_000)
    if (text == null) {
        report(
            DetectorIds.PARTITIONS, Status.UNSUPPORTED, "The mount table was not readable", "جدول مانت خوانده نشد",
            listOf(ev("/proc/mounts", "/proc/mounts", "unreadable", Status.UNSUPPORTED)),
        )
    } else {
        val rows = text.lineSequence().map { it.split(' ') }.filter { it.size >= 4 }
            .map { MountRow(it[0], it[1], it[2], it[3].split(',')) }.toList()
        val watched = listOf("/system", "/vendor", "/product", "/system_ext", "/odm")
        val rw = rows.filter { it.point in watched && "rw" in it.opts }
        val covered = rows.filter { it.point in watched && (it.type == "overlay" || it.type == "tmpfs") }
        val allowed = setOf("/system/vendor", "/system/product", "/system/system_ext", "/system/odm")
        val binds = rows.filter { it.point.startsWith("/system/") && it.point !in allowed }
        val rootRw = rows.any { it.point == "/" && "rw" in it.opts && it.type !in setOf("tmpfs", "rootfs") }
        val status = when {
            rw.isNotEmpty() || covered.isNotEmpty() || binds.isNotEmpty() || rootRw -> Status.WARNING
            else -> Status.CLEAR
        }
        val summary = if (status == Status.WARNING) {
            "A system partition looks modified" to "یک پارتیشن سیستم دست‌کاری‌شده به نظر می‌رسد"
        } else {
            "System partitions are read-only and unmodified" to "پارتیشن‌های سیستم فقط‌خواندنی و دست‌نخورده‌اند"
        }
        report(
            DetectorIds.PARTITIONS, status, summary.first, summary.second,
            listOf(
                ev("Mount rows", "ردیف‌های مانت", rows.size.toString()),
                ev("Writable system mounts", "مانت‌های سیستمِ قابل‌نوشتن", rw.joinToString { it.point }.ifBlank { "none" }, lvl(rw.isNotEmpty())),
                ev("Overlay or tmpfs on system", "overlay یا tmpfs روی سیستم", covered.joinToString { it.point + " (" + it.type + ")" }.ifBlank { "none" }, lvl(covered.isNotEmpty())),
                ev("Bind mounts in /system", "bind mount در /system", binds.take(4).joinToString { it.point }.ifBlank { "none" }, lvl(binds.isNotEmpty())),
                ev("Root filesystem writable", "فایل‌سیستم ریشه قابل‌نوشتن", rootRw.toString(), lvl(rootRw)),
            ),
        )
    }
}

private fun avb() = det(
    DetectorIds.AVB,
    "Boot consistency", "سازگاری بوت",
    "Compares boot properties with each other and with the hardware-attested boot state, so a spoofed \"locked and green\" cannot hide an unlocked bootloader.",
    "پراپرتی‌های بوت را با هم و با وضعیت بوتِ تأییدشده توسط سخت‌افزار مقایسه می‌کند تا «قفل و سبز»ِ جعلی بوت‌لودر باز را پنهان نکند.",
    "If attestation is unavailable, only the properties can be compared with each other.",
    "اگر attestation در دسترس نباشد فقط پراپرتی‌ها با هم مقایسه می‌شوند.",
) { context ->
    val props = AndroidFacts.props(
        listOf(
            "ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.boot.vbmeta.device_state", "ro.boot.veritymode",
            "ro.boot.vbmeta.avb_version", "ro.boot.vbmeta.hash_alg", "ro.boot.vbmeta.digest", "ro.boot.slot_suffix",
            "ro.boot.bootloader",
        ),
    )
    val v = props["ro.boot.verifiedbootstate"].orEmpty().lowercase()
    val lock = props["ro.boot.flash.locked"].orEmpty()
    val vb = props["ro.boot.vbmeta.device_state"].orEmpty().lowercase()
    val verity = props["ro.boot.veritymode"].orEmpty().lowercase()
    val digest = props["ro.boot.vbmeta.digest"].orEmpty()
    val propGreen = v == "green"
    val propLocked = lock == "1" || vb == "locked"
    val propUnlocked = lock == "0" || vb == "unlocked"
    val selfContradiction = (propGreen && propUnlocked) || (v == "orange" && propLocked)
    val a = Attestation.read(context)
    val root = a.desc?.root
    val attestedLocked = root?.deviceLocked == true
    val attestedState = root?.bootState
    val spoofed = root != null && ((propLocked && !attestedLocked) || (propGreen && attestedState != null && attestedState != 0 && attestedState != 1))
    val reversed = root != null && !spoofed && (propUnlocked && attestedLocked)
    val allBlank = props.values.all { it.isBlank() }
    val status = when {
        selfContradiction || spoofed -> Status.DANGER
        reversed || verity == "disabled" -> Status.WARNING
        allBlank -> Status.UNSUPPORTED
        root == null -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when {
        selfContradiction -> "Boot properties contradict each other" to "پراپرتی‌های بوت با هم تناقض دارند"
        spoofed -> "Properties say locked, but hardware attests otherwise" to "پراپرتی‌ها قفل می‌گویند اما سخت‌افزار خلافش را تأیید می‌کند"
        reversed -> "Hardware says locked, properties say unlocked" to "سخت‌افزار قفل می‌گوید، پراپرتی‌ها باز"
        verity == "disabled" -> "dm-verity is disabled" to "dm-verity غیرفعال است"
        allBlank -> "Boot properties were not readable" to "پراپرتی‌های بوت خوانده نشدند"
        root == null -> "Properties agree, no attestation to compare" to "پراپرتی‌ها هم‌خوانند، attestation برای مقایسه نبود"
        else -> "Boot properties and hardware attestation agree" to "پراپرتی‌های بوت و attestation سخت‌افزار هم‌خوانند"
    }
    report(
        DetectorIds.AVB, status, summary.first, summary.second,
        buildList {
            add(ev("verifiedbootstate", "verifiedbootstate", v, if (propGreen) Status.CLEAR else Status.INFO))
            add(ev("flash.locked", "flash.locked", lock, if (lock == "1") Status.CLEAR else if (lock == "0") Status.WARNING else Status.INFO))
            add(ev("vbmeta.device_state", "vbmeta.device_state", vb, if (vb == "locked") Status.CLEAR else if (vb == "unlocked") Status.WARNING else Status.INFO))
            add(ev("veritymode", "veritymode", verity, if (verity == "disabled") Status.WARNING else Status.INFO))
            add(ev("vbmeta.digest", "vbmeta.digest", digest.take(32), Status.INFO))
            add(ev("avb_version", "avb_version", props["ro.boot.vbmeta.avb_version"].orEmpty()))
            add(ev("Properties contradict", "تناقض پراپرتی‌ها", selfContradiction.toString(), lvl(selfContradiction, Status.DANGER)))
            add(ev("Attested bootloader locked", "قفل بودن بوت‌لودر (attestation)", root?.deviceLocked?.toString() ?: "unknown", if (root == null) Status.INFO else if (attestedLocked) Status.CLEAR else Status.WARNING))
            add(ev("Attested boot state", "وضعیت بوت (attestation)", attestedState?.toString() ?: "unknown", if (attestedState == 0) Status.CLEAR else Status.INFO))
            add(ev("Properties match attestation", "پراپرتی‌ها با attestation می‌خوانند", (!spoofed && !reversed).toString(), lvl(spoofed, Status.DANGER)))
        },
    )
}

private fun buildCheck() = det(
    DetectorIds.BUILD,
    "Build consistency", "سازگاری بیلد",
    "Cross-checks the build identity the framework reports against the raw properties: fingerprint format and layers, model, patch level, SDK level, build time, and Pixel fingerprints on non-Pixel hardware.",
    "هویت بیلد را که فریمورک گزارش می‌کند با پراپرتی‌های خام مقایسه می‌کند: قالب و لایه‌های اثرانگشت، مدل، سطح وصله، SDK، زمان بیلد و اثرانگشت پیکسل روی سخت‌افزار غیر پیکسل.",
    "A spoof that rewrites every layer consistently will pass. This finds careless or partial spoofing.",
    "جعلی که همهٔ لایه‌ها را هم‌خوان عوض کند رد می‌شود. این بررسی جعل ناقص یا بی‌دقت را پیدا می‌کند.",
) { _ ->
    val rows = mutableListOf<Evidence>()
    var bad = 0
    fun check(en: String, fa: String, ok: Boolean, value: String, level: Status = Status.WARNING) {
        if (!ok) bad++
        rows += ev(en, fa, value, if (ok) Status.CLEAR else level)
    }
    val fpApi = Build.FINGERPRINT
    val fpProp = AndroidFacts.prop("ro.build.fingerprint")
    val shape = Regex("^[^/\\s]+/[^/\\s]+/[^:/\\s]+:[^/\\s]+/[^/\\s]+/[^:/\\s]+:[^/\\s]+/[^/\\s]+$")
    check("Fingerprint format", "قالب اثرانگشت", shape.matches(fpApi), fpApi.take(60))
    check("Framework matches property", "فریمورک با پراپرتی می‌خواند", fpProp.isBlank() || fpProp == fpApi, if (fpProp.isBlank()) "—" else if (fpProp == fpApi) "equal" else "differs")
    val modelProp = AndroidFacts.prop("ro.product.model")
    check("Model matches property", "مدل با پراپرتی می‌خواند", modelProp.isBlank() || modelProp == Build.MODEL, Build.MODEL)
    val manufacturerProp = AndroidFacts.prop("ro.product.manufacturer")
    check("Manufacturer matches property", "سازنده با پراپرتی می‌خواند", manufacturerProp.isBlank() || manufacturerProp.equals(Build.MANUFACTURER, ignoreCase = true), Build.MANUFACTURER)
    val pixelPrint = fpApi.startsWith("google/")
    check("Pixel fingerprint on Pixel hardware", "اثرانگشت پیکسل روی سخت‌افزار پیکسل", !pixelPrint || Build.MANUFACTURER.equals("google", ignoreCase = true), Build.MANUFACTURER)
    val patchProp = AndroidFacts.prop("ro.build.version.security_patch")
    check("Patch level matches property", "سطح وصله با پراپرتی می‌خواند", patchProp.isBlank() || patchProp == Build.VERSION.SECURITY_PATCH, Build.VERSION.SECURITY_PATCH)
    val sdkProp = AndroidFacts.prop("ro.build.version.sdk").toIntOrNull()
    check("SDK matches property", "SDK با پراپرتی می‌خواند", sdkProp == null || sdkProp == Build.VERSION.SDK_INT, Build.VERSION.SDK_INT.toString())
    val utc = AndroidFacts.prop("ro.build.date.utc").toLongOrNull()
    check("Build time matches property", "زمان بیلد با پراپرتی می‌خواند", utc == null || Math.abs(utc * 1000L - Build.TIME) < 86_400_000L, Build.TIME.toString())
    val incrementalOk = Build.VERSION.INCREMENTAL.isBlank() || fpApi.contains(Build.VERSION.INCREMENTAL)
    check("Incremental is in the fingerprint", "incremental در اثرانگشت است", incrementalOk, Build.VERSION.INCREMENTAL)
    val idOk = Build.ID.isBlank() || fpApi.contains(Build.ID)
    check("Build ID is in the fingerprint", "شناسهٔ بیلد در اثرانگشت است", idOk, Build.ID, Status.INFO)
    val sysFp = AndroidFacts.prop("ro.system.build.fingerprint")
    val vendorFp = AndroidFacts.prop("ro.vendor.build.fingerprint")
    val brandSys = sysFp.substringBefore('/')
    val brandVendor = vendorFp.substringBefore('/')
    check("System and vendor brand agree", "برند سیستم و وندور یکی است", sysFp.isBlank() || vendorFp.isBlank() || brandSys == brandVendor, "$brandSys / $brandVendor", Status.INFO)
    val romProps = listOf("ro.lineage.version", "ro.crdroid.version", "ro.modversion", "ro.miui.ui.version.name", "ro.pixelexperience.version", "ro.evolution.version")
        .filter { AndroidFacts.prop(it).isNotBlank() }
    rows += ev("Custom ROM properties", "پراپرتی‌های رام سفارشی", romProps.joinToString().ifBlank { "none" }, if (romProps.isEmpty()) Status.CLEAR else Status.INFO)
    val status = if (bad == 0) Status.CLEAR else Status.WARNING
    val summary = if (bad == 0) {
        "Build identity is consistent across layers" to "هویت بیلد در همهٔ لایه‌ها یکسان است"
    } else {
        "$bad build identity checks disagree" to "$bad بررسی هویت بیلد با هم نمی‌خواند"
    }
    report(DetectorIds.BUILD, status, summary.first, summary.second, rows)
}

private fun injection() = det(
    DetectorIds.INJECTION,
    "Injected code", "کد تزریق‌شده",
    "Looks for code loaded into this process from places apps never load from: LD_PRELOAD, libraries mapped from /data/local/tmp or /data/adb, and executable memfd regions.",
    "کدی را که از جاهای غیرعادی داخل این پروسه بارگذاری شده جست‌وجو می‌کند: LD_PRELOAD، کتابخانه‌های map‌شده از /data/local/tmp یا /data/adb و ناحیه‌های اجرایی memfd.",
    "Injection that cleans its own mapping or loads from a normal-looking path is not caught.",
    "تزریقی که map خودش را پاک کند یا از مسیر عادی بارگذاری شود گرفته نمی‌شود.",
) { _ ->
    val preload = System.getenv("LD_PRELOAD").orEmpty()
    val maps = AndroidFacts.readText("/proc/self/maps", 600_000)
    val badDirs = listOf("/data/local/tmp", "/data/adb", "/dev/shm", "/sdcard", "/storage/", "/mnt/")
    val flagged = mutableListOf<String>()
    var rows = 0
    maps?.lineSequence()?.forEach { line ->
        if (line.isBlank()) return@forEach
        rows++
        val parts = line.trim().split(Regex("\\s+"), limit = 6)
        if (parts.size < 6) return@forEach
        val perms = parts[1]
        val path = parts[5]
        val dirHit = badDirs.any { path.startsWith(it) }
        val memfd = path.startsWith("/memfd:") && perms.contains('x') &&
            !path.contains("jit-cache") && !path.contains("jit-zygote-cache")
        val deletedLib = path.endsWith(".so (deleted)")
        if (dirHit || memfd || deletedLib) flagged += path
    }
    val distinct = flagged.distinct()
    val status = when {
        preload.isNotBlank() || distinct.isNotEmpty() -> Status.DANGER
        maps == null -> Status.UNSUPPORTED
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.DANGER -> "Code was loaded from an unusual place" to "کد از جای غیرعادی بارگذاری شده"
        Status.UNSUPPORTED -> "maps was not readable" to "maps خوانده نشد"
        else -> "No code loaded from unusual places" to "کدی از جای غیرعادی بارگذاری نشده"
    }
    report(
        DetectorIds.INJECTION, status, summary.first, summary.second,
        listOf(
            ev("LD_PRELOAD", "LD_PRELOAD", preload.ifBlank { "none" }, lvl(preload.isNotBlank(), Status.DANGER)),
            ev("Mapped regions", "ناحیه‌های map‌شده", rows.toString()),
            ev("Unusual mappings", "mapهای غیرعادی", distinct.take(5).joinToString("\n").ifBlank { "none" }, lvl(distinct.isNotEmpty(), Status.DANGER)),
        ),
    )
}

private fun sysFiles() = det(
    DetectorIds.SYSFILES,
    "System files", "فایل‌های سیستم",
    "Reads files that custom setups commonly touch: the hosts file, init.d and su.d folders, init scripts that mention root tools, and debug flags in build.prop.",
    "فایل‌هایی را که تنظیمات سفارشی معمولاً دست می‌زنند می‌خواند: فایل hosts، پوشه‌های init.d و su.d، اسکریپت‌های init که به ابزار روت اشاره دارند و پرچم‌های دیباگ در build.prop.",
    "Modern systems hide some of these files from apps, and a systemless mod does not change them.",
    "سیستم‌های جدید بعضی از این فایل‌ها را از اپ‌ها پنهان می‌کنند و مود systemless آن‌ها را عوض نمی‌کند.",
) { _ ->
    val hostsText = AndroidFacts.readText("/system/etc/hosts", 60_000)
    val entries = hostsText.orEmpty().lineSequence().map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .filter { line -> !line.contains("localhost") }.toList()
    val sensitive = entries.filter { line ->
        listOf("google", "gstatic", "play", "android", "attest", "safetynet").any { line.contains(it, ignoreCase = true) }
    }
    val initD = listOf("/system/etc/init.d", "/system/su.d", "/system/etc/su.d").filter { listDir(it).isNotEmpty() }
    val initScripts = listDir("/system/etc/init").filter { name ->
        listOf("magisk", "supersu", "xposed", "ksu").any { name.contains(it, ignoreCase = true) }
    }
    val buildProp = AndroidFacts.readText("/system/build.prop", 200_000)
    val flags = buildProp.orEmpty().lineSequence().map { it.trim() }.filter {
        it == "ro.debuggable=1" || it == "ro.secure=0" || it == "ro.allow.mock.location=1" || it == "ro.adb.secure=0"
    }.toList()
    val status = when {
        sensitive.isNotEmpty() || initScripts.isNotEmpty() -> Status.DANGER
        entries.isNotEmpty() || initD.isNotEmpty() || flags.isNotEmpty() -> Status.WARNING
        hostsText == null && buildProp == null -> Status.UNSUPPORTED
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.DANGER -> "System files mention root tools or Google endpoints" to "فایل‌های سیستم به ابزار روت یا آدرس‌های گوگل اشاره دارند"
        Status.WARNING -> "System files were customized" to "فایل‌های سیستم شخصی‌سازی شده‌اند"
        Status.UNSUPPORTED -> "System files were not readable" to "فایل‌های سیستم خوانده نشدند"
        else -> "System files look stock" to "فایل‌های سیستم استوک به نظر می‌رسند"
    }
    report(
        DetectorIds.SYSFILES, status, summary.first, summary.second,
        listOf(
            ev("Extra hosts entries", "ورودی‌های اضافی hosts", entries.take(4).joinToString("\n").ifBlank { if (hostsText == null) "unreadable" else "none" }, if (entries.isEmpty()) Status.CLEAR else Status.WARNING),
            ev("Google-related hosts entries", "ورودی‌های hosts مرتبط با گوگل", sensitive.take(3).joinToString("\n").ifBlank { "none" }, lvl(sensitive.isNotEmpty(), Status.DANGER)),
            ev("init.d or su.d folders", "پوشه‌های init.d یا su.d", initD.joinToString().ifBlank { "none" }, lvl(initD.isNotEmpty())),
            ev("Root init scripts", "اسکریپت‌های init روت", initScripts.joinToString().ifBlank { "none" }, lvl(initScripts.isNotEmpty(), Status.DANGER)),
            ev("build.prop debug flags", "پرچم‌های دیباگ build.prop", flags.joinToString().ifBlank { if (buildProp == null) "unreadable" else "none" }, if (flags.isEmpty()) Status.CLEAR else Status.WARNING),
        ),
    )
}

private fun clockCheck() = det(
    DetectorIds.TIME,
    "Clock and time", "ساعت و زمان",
    "Checks that the clock was not tampered with: automatic time and time zone, the clock against the build date, and uptime from two independent sources.",
    "دست‌کاری نشدن ساعت را بررسی می‌کند: زمان و منطقهٔ زمانی خودکار، ساعت در برابر تاریخ بیلد و آپ‌تایم از دو منبع مستقل.",
    "A device whose real network time is wrong in a consistent way cannot be told apart without a trusted time server.",
    "دستگاهی که زمان واقعی‌اش به‌صورت هم‌خوان غلط است بدون سرور زمان معتبر تشخیص داده نمی‌شود.",
) { context ->
    val autoTime = globalInt(context, Settings.Global.AUTO_TIME, -1)
    val autoZone = globalInt(context, Settings.Global.AUTO_TIME_ZONE, -1)
    val now = System.currentTimeMillis()
    val beforeBuild = Build.TIME > 0 && now < Build.TIME
    val bootClock = AndroidFacts.readText("/proc/uptime", 64)?.trim()?.substringBefore(' ')?.toDoubleOrNull()
    val elapsedSec = SystemClock.elapsedRealtime() / 1000.0
    val skew = if (bootClock == null) null else Math.abs(bootClock - elapsedSec)
    val hooked = skew != null && skew > 60.0
    val manual = autoTime == 0
    val status = when {
        hooked || beforeBuild -> Status.WARNING
        manual -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when {
        hooked -> "Two uptime sources disagree" to "دو منبع آپ‌تایم با هم نمی‌خواند"
        beforeBuild -> "The clock is earlier than the build date" to "ساعت از تاریخ بیلد عقب‌تر است"
        manual -> "Automatic time is off" to "زمان خودکار خاموش است"
        else -> "The clock looks consistent" to "ساعت سازگار به نظر می‌رسد"
    }
    report(
        DetectorIds.TIME, status, summary.first, summary.second,
        listOf(
            ev("Automatic time", "زمان خودکار", if (autoTime == 1) "on" else if (autoTime == 0) "off" else "unknown", if (autoTime == 0) Status.INFO else Status.CLEAR),
            ev("Automatic time zone", "منطقهٔ زمانی خودکار", if (autoZone == 1) "on" else if (autoZone == 0) "off" else "unknown", if (autoZone == 0) Status.INFO else Status.CLEAR),
            ev("Time zone", "منطقهٔ زمانی", java.util.TimeZone.getDefault().id),
            ev("Clock before build date", "ساعت قبل از تاریخ بیلد", beforeBuild.toString(), lvl(beforeBuild)),
            ev("Uptime skew", "اختلاف آپ‌تایم", skew?.let { "%.1f s".format(it) } ?: "unknown", lvl(hooked)),
        ),
    )
}
