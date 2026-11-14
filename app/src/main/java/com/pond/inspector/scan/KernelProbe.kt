package com.pond.inspector.scan

import android.os.Build
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.pond.inspector.model.DetectorIds
import com.pond.inspector.model.Evidence
import com.pond.inspector.model.Metric
import com.pond.inspector.model.Phrase
import com.pond.inspector.model.Status
import java.io.File

internal enum class Reach { READABLE, DENIED, MISSING, ERROR }

internal fun reach(path: String): Reach = try {
    val fd = Os.open(path, OsConstants.O_RDONLY, 0)
    try {
        Os.close(fd)
    } catch (_: Exception) {
    }
    Reach.READABLE
} catch (error: ErrnoException) {
    when (error.errno) {
        OsConstants.EACCES, OsConstants.EPERM -> Reach.DENIED
        OsConstants.ENOENT, OsConstants.ENOTDIR -> Reach.MISSING
        else -> Reach.ERROR
    }
} catch (_: Throwable) {
    Reach.ERROR
}

private fun statExists(path: String): Boolean? = try {
    Os.stat(path)
    true
} catch (error: ErrnoException) {
    when (error.errno) {
        OsConstants.ENOENT, OsConstants.ENOTDIR -> false
        else -> null
    }
} catch (_: Throwable) {
    null
}

private fun shellExists(path: String): Boolean? {
    val out = AndroidFacts.runCommand("sh", "-c", "[ -e '" + path.replace("'", "") + "' ] && echo y || echo n")
    return when (out.trim()) {
        "y" -> true
        "n" -> false
        else -> null
    }
}

private fun metric(en: String, fa: String, valueEn: String, valueFa: String, level: Status) =
    Metric(Phrase(en, fa), Phrase(valueEn, valueFa), level)

private fun statusField(status: String, key: String): String =
    status.lineSequence().firstOrNull { it.startsWith("$key:") }?.substringAfter(':')?.trim().orEmpty()

private val kernelEol = mapOf(
    "3.18" to "2017", "4.4" to "2022-02", "4.9" to "2023-01", "4.14" to "2024-01", "4.19" to "2024-12", "5.4" to "2025-12",
)

private val kernelRootTokens = listOf("kernelsu", "ksu", "sukisu", "apatch", "magisk", "kpm", "nethunter", "supersu")

private val stockSuffix = Regex("^(g[0-9a-f]{6,}|ab\\d+|\\d+|perf|qgki|gki|debug|android\\d+|\\d+\\.\\d+|dirty|smp|preempt)$", RegexOption.IGNORE_CASE)

internal fun kernelDeep() = Detector(
    id = DetectorIds.KERNEL,
    title = Phrase("Kernel", "کرنل"),
    about = Phrase(
        "Reads the kernel identity from four independent sources (the uname syscall, the JVM property, the shell, and /proc), compares them with each other, looks for root-kernel names and custom build labels, checks the support status of the kernel branch, and inspects the credentials this process runs with: uid, capabilities, seccomp and SELinux domain. It also compares how a few sensitive paths look through the Java API, the stat syscall and the shell.",
        "هویت کرنل را از چهار منبع مستقل می‌خواند (سیستم‌کال uname، پراپرتی JVM، شل و /proc)، آن‌ها را با هم مقایسه می‌کند، دنبال نام کرنل‌های روت و برچسب بیلد سفارشی می‌گردد، وضعیت پشتیبانی شاخهٔ کرنل را می‌سنجد و اعتبارنامه‌هایی را که این پروسه با آن‌ها اجرا می‌شود بررسی می‌کند: uid، capabilityها، seccomp و دامنهٔ SELinux. همچنین ظاهر چند مسیر حساس را از راه API جاوا، سیستم‌کال stat و شل مقایسه می‌کند.",
    ),
    limits = Phrase(
        "A kernel that rewrites uname for every reader, or hides itself from this app's domain, will look clean. A custom label is information, not proof of tampering.",
        "کرنلی که uname را برای همهٔ خواننده‌ها بازنویسی کند یا خودش را از دامنهٔ این اپ پنهان کند سالم دیده می‌شود. برچسب سفارشی اطلاع است، نه اثبات دست‌کاری.",
    ),
    probe = { _, _ ->
        val uts = try {
            Os.uname()
        } catch (_: Throwable) {
            null
        }
        val sysRelease = uts?.release.orEmpty()
        val sysVersion = uts?.version.orEmpty()
        val machine = uts?.machine.orEmpty()
        val nodename = uts?.nodename.orEmpty()
        val propRelease = System.getProperty("os.version").orEmpty()
        val shellAll = AndroidFacts.runCommand("uname", "-a")
        val shellRelease = AndroidFacts.runCommand("uname", "-r")
        val shellVersion = AndroidFacts.runCommand("uname", "-v")
        val procVersion = AndroidFacts.readText("/proc/version", 4_000)?.trim()
        val procCmdline = AndroidFacts.readText("/proc/cmdline", 4_000)?.trim()

        val releases = listOf(sysRelease, propRelease, shellRelease).filter { it.isNotBlank() }
        val releaseConsistent = releases.distinct().size <= 1
        val versions = listOf(sysVersion, shellVersion).filter { it.isNotBlank() }
        val versionConsistent = versions.distinct().size <= 1
        val release = releases.firstOrNull().orEmpty()

        val identity = mutableListOf<Evidence>()
        identity += evd(
            "uname -a", "uname -a", if (shellAll.isBlank()) "unavailable" else "captured", if (shellAll.isBlank()) Status.INFO else Status.CLEAR,
            shellAll.ifBlank { "The shell did not return uname output." },
            shellAll.ifBlank { "شل خروجی uname را برنگرداند." },
        )
        identity += evd(
            "/proc/version", "/proc/version", if (procVersion.isNullOrBlank()) "unavailable" else "captured",
            if (procVersion.isNullOrBlank()) Status.INFO else Status.CLEAR,
            procVersion ?: "No readable data surfaced for /proc/version.",
            procVersion ?: "داده‌ای از /proc/version خوانده نشد.",
        )
        identity += evd(
            "/proc/cmdline", "/proc/cmdline", if (procCmdline.isNullOrBlank()) "unavailable" else "captured",
            if (procCmdline.isNullOrBlank()) Status.INFO else Status.CLEAR,
            procCmdline?.take(300) ?: "No readable data surfaced for /proc/cmdline.",
            procCmdline?.take(300) ?: "داده‌ای از /proc/cmdline خوانده نشد.",
        )
        identity += evd(
            "uname() syscall", "سیستم‌کال uname()", if (uts == null) "unavailable" else "captured", if (uts == null) Status.INFO else Status.CLEAR,
            "sysname ${uts?.sysname.orEmpty()}\nnodename $nodename\nrelease $sysRelease\nmachine $machine",
        )
        identity += evd(
            "Kernel release across sources", "نسخهٔ کرنل بین منابع",
            if (releases.size <= 1) "single source" else if (releaseConsistent) "consistent (${releases.size})" else "inconsistent",
            if (!releaseConsistent) Status.DANGER else if (releases.size <= 1) Status.INFO else Status.CLEAR,
            "System.getProperty(\"os.version\") = $propRelease\nuname() syscall = $sysRelease\nuname -r = $shellRelease",
        )
        identity += evd(
            "Kernel build version across sources", "نسخهٔ بیلد کرنل بین منابع",
            if (versions.size <= 1) "single source" else if (versionConsistent) "consistent (${versions.size})" else "inconsistent",
            if (!versionConsistent) Status.DANGER else if (versions.size <= 1) Status.INFO else Status.CLEAR,
            "uname() syscall = $sysVersion\nuname -v = $shellVersion",
        )

        val anomalies = mutableListOf<Evidence>()
        val blob = (release + " " + sysVersion + " " + shellAll + " " + procVersion.orEmpty() + " " + procCmdline.orEmpty()).lowercase()
        val rootNames = kernelRootTokens.filter { it in blob }
        anomalies += evd(
            "Root kernel names", "نام کرنل‌های روت", rootNames.joinToString().ifBlank { "none" },
            if (rootNames.isEmpty()) Status.CLEAR else Status.DANGER,
            "Looked for ${kernelRootTokens.joinToString()} in the release, version and command line.",
            "دنبال ${kernelRootTokens.joinToString()} در نسخه، ورژن و خط فرمان گشته شد.",
        )
        if (!releaseConsistent) {
            anomalies += evd(
                "Release differs between readers", "نسخه بین خواننده‌ها فرق دارد", "true", Status.DANGER,
                "A kernel or a hook is answering differently depending on how it is asked.",
                "کرنل یا یک هوک بسته به روش پرسش جواب متفاوت می‌دهد.",
            )
        }
        val match = Regex("^(\\d+)\\.(\\d+)\\.(\\d+)(.*)$").find(release)
        var branch = ""
        var label = ""
        if (match != null) {
            branch = match.groupValues[1] + "." + match.groupValues[2]
            val suffix = match.groupValues[4].trim('-', ' ')
            val tokens = suffix.split('-').filter { it.isNotBlank() }
            label = tokens.filter { !stockSuffix.matches(it) }.joinToString("-")
            val gki = Regex("android\\d+-\\d+\\.\\d+").containsMatchIn(release)
            anomalies += evd("Kernel branch", "شاخهٔ کرنل", branch + if (gki) " (GKI)" else "", Status.INFO, "Full release: $release", "نسخهٔ کامل: $release")
            val eol = kernelEol[branch]
            if (eol != null) {
                anomalies += evd(
                    "Upstream support", "پشتیبانی بالادستی", "ended $eol", Status.INFO,
                    "The upstream long-term branch $branch is past its end of life. Vendors may still backport fixes, so this is context, not a fault.",
                    "شاخهٔ بلندمدت $branch بالادستی از پایان عمر گذشته است. سازنده‌ها ممکن است همچنان وصله بدهند، پس این زمینه است نه ایراد.",
                )
            }
            anomalies += evd(
                "Custom build label", "برچسب بیلد سفارشی", label.ifBlank { "none" }, Status.INFO,
                if (label.isBlank()) "The release string only has stock fields." else "The release carries a non-stock label: $label. Custom kernels are common on modified devices.",
                if (label.isBlank()) "رشتهٔ نسخه فقط فیلدهای استوک دارد." else "نسخه برچسب غیراستوک دارد: $label. کرنل سفارشی روی دستگاه‌های تغییرداده‌شده رایج است.",
            )
            if (suffix.contains("dirty", ignoreCase = true)) {
                anomalies += evd("Dirty build", "بیلد dirty", "true", Status.INFO, "The kernel was built from a tree with uncommitted changes.", "کرنل از درختی با تغییرات کامیت‌نشده ساخته شده.")
            }
        }
        anomalies += evd(
            "Hostname", "نام میزبان", nodename.ifBlank { "unknown" },
            if (nodename.isBlank() || nodename == "localhost") Status.CLEAR else Status.INFO,
            "Apps normally see \"localhost\". Any other name usually leaks the machine the kernel was built or flashed from.",
            "اپ‌ها معمولاً «localhost» می‌بینند. هر نام دیگر معمولاً ماشینی را لو می‌دهد که کرنل روی آن ساخته یا فلش شده.",
        )
        val abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        val archMismatch = (machine.startsWith("x86") && abi.startsWith("arm")) || (machine.startsWith("aarch") && abi.startsWith("x86"))
        anomalies += evd(
            "Architecture", "معماری", machine.ifBlank { "unknown" } + " / " + abi,
            if (archMismatch) Status.WARNING else Status.CLEAR,
            "Kernel machine and primary ABI must describe the same CPU family.",
            "معماری کرنل و ABI اصلی باید به یک خانوادهٔ CPU اشاره کنند.",
        )
        val built = Regex("([A-Z][a-z]{2}) +([A-Z][a-z]{2}) +(\\d{1,2}) +(\\d\\d:\\d\\d:\\d\\d) +(?:\\S+ +)?(\\d{4})").find(sysVersion)
        if (built != null) {
            val text = built.groupValues[2] + " " + built.groupValues[3] + " " + built.groupValues[5]
            val millis = try {
                java.text.SimpleDateFormat("MMM d yyyy", java.util.Locale.US).parse(text)?.time
            } catch (_: Exception) {
                null
            }
            val future = millis != null && millis > System.currentTimeMillis() + 86_400_000L
            val newer = millis != null && Build.TIME > 0 && millis > Build.TIME + 30L * 86_400_000L
            anomalies += evd(
                "Kernel build date", "تاریخ بیلد کرنل", text,
                if (future) Status.WARNING else Status.INFO,
                if (future) "The build date is in the future, so the clock or the string was altered."
                else if (newer) "This kernel is newer than the system image, which usually means it was flashed separately."
                else "The kernel was built around the same time as the system image.",
                if (future) "تاریخ بیلد در آینده است، پس ساعت یا رشته دست‌کاری شده."
                else if (newer) "این کرنل از ایمیج سیستم جدیدتر است، یعنی معمولاً جداگانه فلش شده."
                else "کرنل تقریباً هم‌زمان با ایمیج سیستم ساخته شده.",
            )
        }

        val behavior = mutableListOf<Evidence>()
        var layerMismatch = 0
        var sensitiveSeen = 0
        val probes = listOf(
            "/system/bin/su", "/sbin/.magisk", "/data/adb/magisk", "/data/adb/ksu", "/dev/ksu",
            "/system/bin/sh", "/proc/self/maps",
        )
        probes.forEach { path ->
            val java = try {
                File(path).exists()
            } catch (_: Exception) {
                null
            }
            val syscall = statExists(path)
            val shell = shellExists(path)
            val known = listOf(java, syscall, shell).filterNotNull()
            val mismatch = known.distinct().size > 1
            if (mismatch) layerMismatch++
            val sensitive = path != "/system/bin/sh" && path != "/proc/self/maps"
            if (sensitive && known.any { it }) sensitiveSeen++
            behavior += evd(
                path, path,
                if (mismatch) "layers disagree" else if (known.isEmpty()) "unknown" else if (known.first()) "present" else "not visible",
                if (mismatch) Status.WARNING else if (sensitive && known.any { it }) Status.DANGER else Status.CLEAR,
                "Java File.exists = $java\nstat() syscall = $syscall\nshell test -e = $shell",
            )
        }

        val creds = mutableListOf<Evidence>()
        val status0 = AndroidFacts.readText("/proc/self/status", 8_000).orEmpty()
        val uid = statusField(status0, "Uid").split(Regex("\\s+")).mapNotNull { it.toIntOrNull() }
        val gid = statusField(status0, "Gid").split(Regex("\\s+")).mapNotNull { it.toIntOrNull() }
        val seccomp = statusField(status0, "Seccomp")
        val noNewPrivs = statusField(status0, "NoNewPrivs")
        val capEff = statusField(status0, "CapEff")
        val capPrm = statusField(status0, "CapPrm")
        val capBnd = statusField(status0, "CapBnd")
        val myUid = android.os.Process.myUid()
        val rootUid = uid.any { it == 0 } || gid.any { it == 0 }
        val uidMismatch = uid.isNotEmpty() && uid.any { it != myUid }
        fun zero(hex: String) = hex.isNotBlank() && hex.trimStart('0').isEmpty()
        val capsRaised = (capEff.isNotBlank() && !zero(capEff)) || (capPrm.isNotBlank() && !zero(capPrm))
        val context = AndroidFacts.readText("/proc/self/attr/current", 256)?.trim { it == '\u0000' || it.isWhitespace() }.orEmpty()
        val domain = context.split(':').getOrNull(2).orEmpty()
        val domainBad = domain.isNotBlank() && (domain == "su" || domain.contains("magisk") || domain == "kernel" || domain == "init" || domain == "shell")
        creds += evd("Uid (real, effective, saved)", "Uid (واقعی، مؤثر، ذخیره)", uid.joinToString().ifBlank { "unreadable" }, if (rootUid || uidMismatch) Status.DANGER else if (uid.isEmpty()) Status.INFO else Status.CLEAR,
            "An app process runs as one non-zero uid, equal to the uid Android assigned to this package ($myUid).",
            "پروسهٔ اپ با یک uid غیرصفر اجرا می‌شود که برابر uid اختصاص‌یافته به این پکیج ($myUid) است.")
        creds += evd("Gid", "Gid", gid.joinToString().ifBlank { "unreadable" }, if (gid.any { it == 0 }) Status.DANGER else if (gid.isEmpty()) Status.INFO else Status.CLEAR, "Group ids of the process.", "شناسهٔ گروه‌های پروسه.")
        creds += evd("Effective capabilities", "capabilityهای مؤثر", capEff.ifBlank { "unreadable" }, if (capsRaised) Status.DANGER else if (capEff.isBlank()) Status.INFO else Status.CLEAR,
            "Unprivileged apps hold no capabilities, so this must be all zeros. CapPrm = $capPrm, CapBnd = $capBnd.",
            "اپ‌های بدون دسترسی ویژه هیچ capability ندارند، پس باید همه صفر باشد. CapPrm = $capPrm، CapBnd = $capBnd.")
        creds += evd("Seccomp", "Seccomp", when (seccomp) { "2" -> "filter"; "1" -> "strict"; "0" -> "off"; else -> "unreadable" },
            if (seccomp == "0") Status.WARNING else if (seccomp.isBlank()) Status.INFO else Status.CLEAR,
            "Zygote installs a seccomp filter on every app. Mode 0 means the filter is missing.",
            "Zygote روی هر اپ فیلتر seccomp می‌گذارد. حالت ۰ یعنی فیلتر نیست.")
        creds += evd("NoNewPrivs", "NoNewPrivs", noNewPrivs.ifBlank { "unreadable" }, if (noNewPrivs == "0") Status.INFO else if (noNewPrivs.isBlank()) Status.INFO else Status.CLEAR,
            "Apps normally cannot gain privileges through exec.", "اپ‌ها معمولاً نمی‌توانند با exec دسترسی بگیرند.")
        creds += evd("SELinux domain", "دامنهٔ SELinux", context.ifBlank { "unreadable" }, if (domainBad) Status.DANGER else if (context.isBlank()) Status.INFO else Status.CLEAR,
            "Apps run in untrusted_app or a close sibling. su, magisk, kernel or shell would mean a privileged context.",
            "اپ‌ها در untrusted_app یا نزدیک به آن اجرا می‌شوند. su و magisk و kernel و shell یعنی زمینهٔ دارای امتیاز.")

        val bootProps = AndroidFacts.props(listOf("ro.boot.selinux", "ro.boot.verifiedbootstate", "ro.boot.veritymode", "ro.boot.mode", "ro.bootmode", "ro.boot.hardware", "ro.boot.slot_suffix", "ro.boot.force_normal_boot"))
        val bootRows = mutableListOf<Evidence>()
        val bootDetail = Phrase("Derived from ro.boot.* because /proc/cmdline is not readable.", "از ro.boot.* گرفته شده چون /proc/cmdline خوانده نمی‌شود.")
        var bootBad = false
        bootProps.forEach { (key, value) ->
            if (value.isBlank()) return@forEach
            val bad = (key == "ro.boot.selinux" && value.equals("permissive", true)) ||
                (key == "ro.boot.veritymode" && value.equals("disabled", true)) ||
                (key == "ro.boot.mode" && value.equals("recovery", true))
            if (bad) bootBad = true
            bootRows += Evidence(Phrase(key, key), value, if (bad) Status.WARNING else Status.INFO, if (procCmdline.isNullOrBlank()) bootDetail else null)
        }
        if (bootRows.isEmpty()) bootRows += evd("Boot parameters", "پارامترهای بوت", "unavailable", Status.INFO, "No ro.boot.* properties were readable.", "هیچ ro.boot.* خوانده نشد.")
        val cmdlineHits = kernelRootTokens.filter { procCmdline.orEmpty().contains(it, ignoreCase = true) }
        if (cmdlineHits.isNotEmpty()) {
            bootBad = true
            bootRows += evd("Root tokens in cmdline", "توکن روت در cmdline", cmdlineHits.joinToString(), Status.DANGER, "The kernel command line names a root framework.", "خط فرمان کرنل نام یک فریمورک روت را دارد.")
        }

        val dangers = anomalies.count { it.level == Status.DANGER } + behavior.count { it.level == Status.DANGER } +
            creds.count { it.level == Status.DANGER } + bootRows.count { it.level == Status.DANGER } +
            identity.count { it.level == Status.DANGER }
        val warnings = anomalies.count { it.level == Status.WARNING } + behavior.count { it.level == Status.WARNING } +
            creds.count { it.level == Status.WARNING } + bootRows.count { it.level == Status.WARNING }
        val status = when {
            dangers > 0 -> Status.DANGER
            warnings > 0 -> Status.WARNING
            uts == null && release.isBlank() -> Status.UNSUPPORTED
            else -> Status.CLEAR
        }
        val summary = when (status) {
            Status.DANGER -> "Kernel anomalies were detected" to "ناهنجاری در کرنل شناسایی شد"
            Status.WARNING -> "Kernel behavior looks unusual" to "رفتار کرنل غیرعادی به نظر می‌رسد"
            Status.UNSUPPORTED -> "The kernel identity could not be read" to "هویت کرنل خوانده نشد"
            else -> "No suspicious kernel markers" to "نشانهٔ مشکوکی در کرنل نیست"
        }
        val identityLevel = if (rootNames.isNotEmpty() || !releaseConsistent || !versionConsistent) Status.DANGER else Status.CLEAR
        val behaviorLevel = if (sensitiveSeen > 0 || rootUid || uidMismatch || capsRaised || domainBad) Status.DANGER else if (layerMismatch > 0 || seccomp == "0") Status.WARNING else Status.CLEAR
        val bootLevel = if (bootBad) Status.WARNING else Status.CLEAR
        val sections = listOf(
            sectionOf("identity", "Kernel identity", "هویت کرنل", identity),
            sectionOf("anomalies", "Anomalies", "ناهنجاری‌ها", anomalies),
            sectionOf("behavior", "Kernel behavior", "رفتار کرنل", behavior),
            sectionOf("creds", "Process credentials", "اعتبارنامهٔ پروسه", creds),
            sectionOf("boot", "Boot parameters", "پارامترهای بوت", bootRows),
        )
        report(
            DetectorIds.KERNEL, status, summary.first, summary.second, sections.flatMap { it.evidence },
            caption = Phrase(
                "${kernelRootTokens.size} marker families · ${probes.size} path probes · syscall, shell and /proc",
                "${kernelRootTokens.size} خانوادهٔ نشانه · ${probes.size} پروب مسیر · سیستم‌کال، شل و /proc",
            ),
            metrics = listOf(
                metric("Identity", "هویت", if (identityLevel == Status.CLEAR) "Clean" else "Suspicious", if (identityLevel == Status.CLEAR) "سالم" else "مشکوک", identityLevel),
                metric("Behavior", "رفتار", if (behaviorLevel == Status.CLEAR) "OK" else "Anomalous", if (behaviorLevel == Status.CLEAR) "عادی" else "غیرعادی", behaviorLevel),
                metric("Boot", "بوت", if (bootLevel == Status.CLEAR) "Clean" else "Suspicious", if (bootLevel == Status.CLEAR) "سالم" else "مشکوک", bootLevel),
                metric("Syscalls", "سیستم‌کال", if (uts != null) "Available" else "Unavailable", if (uts != null) "در دسترس" else "در دسترس نیست", if (uts != null) Status.CLEAR else Status.INFO),
            ),
            sections = sections,
            impact = Phrase(
                if (status == Status.DANGER) "A root kernel, a hook on kernel answers, or a privileged process context was found. Anything the app reads from the system can be rewritten, so every other check is weaker."
                else if (status == Status.WARNING) "Something about the kernel or process looks different from a stock app environment. It may be harmless, such as a custom kernel, but it deserves a look."
                else "The kernel answers consistently across syscall, JVM, shell and /proc, and this process runs with normal app credentials.",
                if (status == Status.DANGER) "کرنل روت، هوک روی پاسخ‌های کرنل یا زمینهٔ پروسه با امتیاز بالا پیدا شد. هر چیزی که اپ از سیستم می‌خواند قابل بازنویسی است، پس بقیهٔ بررسی‌ها هم ضعیف‌تر می‌شوند."
                else if (status == Status.WARNING) "چیزی در کرنل یا پروسه با محیط استوک یک اپ فرق دارد. ممکن است بی‌ضرر باشد، مثل کرنل سفارشی، اما ارزش بررسی دارد."
                else "کرنل در سیستم‌کال، JVM، شل و /proc یکسان جواب می‌دهد و این پروسه با اعتبارنامهٔ عادی یک اپ اجرا می‌شود.",
            ),
        )
    },
)

internal fun selinuxDeep() = Detector(
    id = DetectorIds.SELINUX,
    title = Phrase("SELinux", "SELinux"),
    about = Phrase(
        "Reads the enforce flag when it is visible. When Android blocks that read (the normal case from Android 10), it infers the mode instead: a policy that denies an ordinary app access to files it could otherwise read means enforcement is on. It also reads this process's SELinux context and the boot parameter, and tests several policy-protected files.",
        "پرچم enforce را وقتی دیده شود می‌خواند. وقتی اندروید آن خواندن را مسدود می‌کند (حالت عادی از اندروید ۱۰)، حالت را استنباط می‌کند: سیاستی که به یک اپ معمولی اجازهٔ خواندن فایل‌هایی را نمی‌دهد که از نظر دسترسی عادی قابل خواندن‌اند یعنی enforcement روشن است. زمینهٔ SELinux همین پروسه و پارامتر بوت را هم می‌خواند و چند فایل محافظت‌شده با سیاست را آزمایش می‌کند.",
    ),
    limits = Phrase(
        "An inferred mode is strong evidence, not a direct reading. It does not audit policy rules, other processes' contexts, or a custom sepolicy.",
        "حالت استنباط‌شده شاهد قوی است، نه خواندن مستقیم. قواعد سیاست، کانتکست پروسه‌های دیگر یا sepolicy سفارشی را حسابرسی نمی‌کند.",
    ),
    probe = { _, _ ->
        val enforceRead = AndroidFacts.readText("/sys/fs/selinux/enforce", 16)?.trim()
        val getenforce = AndroidFacts.runCommand("getenforce").trim()
        val direct = (enforceRead?.ifBlank { null } ?: getenforce.ifBlank { null })
        val directMode = when (direct?.lowercase()) {
            "1", "enforcing" -> "enforcing"
            "0", "permissive" -> "permissive"
            else -> null
        }
        val enforceReach = reach("/sys/fs/selinux/enforce")
        val fsReach = reach("/sys/fs/selinux")
        val bootProp = AndroidFacts.prop("ro.boot.selinux").lowercase()
        val probes = listOf("/sys/fs/selinux/enforce", "/proc/net/tcp", "/proc/stat", "/sys/class/net/wlan0/address", "/sys/devices/system/cpu/vulnerabilities/meltdown")
        val results = probes.map { it to reach(it) }
        val denied = results.count { it.second == Reach.DENIED }
        val readable = results.count { it.second == Reach.READABLE }
        val context = AndroidFacts.readText("/proc/self/attr/current", 256)?.trim { it == '\u0000' || it.isWhitespace() }.orEmpty()
        val parts = context.split(':')
        val domain = parts.getOrNull(2).orEmpty()
        val categories = parts.drop(4).joinToString(":")
        val domainBad = domain.isNotBlank() && (domain == "su" || domain.contains("magisk") || domain == "kernel" || domain == "init" || domain == "shell" || domain == "system_server")
        val inferredEnforcing = directMode == null && (enforceReach == Reach.DENIED || denied >= 2)
        val mode = directMode ?: if (inferredEnforcing) "enforcing (inferred)" else if (readable == probes.size && Build.VERSION.SDK_INT >= 30) "permissive (suspected)" else "unknown"
        val permissive = directMode == "permissive" || bootProp == "permissive" || mode.startsWith("permissive")
        val status = when {
            domainBad -> Status.DANGER
            directMode == "permissive" || bootProp == "permissive" -> Status.WARNING
            mode.startsWith("permissive") -> Status.WARNING
            mode.startsWith("enforcing") -> Status.CLEAR
            fsReach == Reach.MISSING -> Status.WARNING
            else -> Status.INFO
        }
        val summary = when {
            domainBad -> "This process runs in a privileged SELinux domain" to "این پروسه در دامنهٔ SELinux دارای امتیاز اجرا می‌شود"
            permissive -> "SELinux is permissive" to "SELinux در حالت permissive است"
            directMode == "enforcing" -> "SELinux is enforcing" to "SELinux در حالت enforcing است"
            mode.startsWith("enforcing") -> "SELinux is enforcing (inferred from denied reads)" to "SELinux در حالت enforcing است (استنباط از خواندن‌های ردشده)"
            fsReach == Reach.MISSING -> "The SELinux filesystem is not present" to "فایل‌سیستم SELinux وجود ندارد"
            else -> "SELinux mode could not be determined" to "حالت SELinux مشخص نشد"
        }
        val modeLevel = if (permissive) Status.WARNING else if (mode.startsWith("enforcing")) Status.CLEAR else Status.INFO
        val rows = mutableListOf<Evidence>()
        rows += evd("Mode", "حالت", mode, modeLevel,
            if (directMode != null) "Read directly from the enforce flag." else "The enforce flag is blocked for apps. $denied of ${probes.size} policy-protected files were denied, which only happens while enforcing.",
            if (directMode != null) "مستقیم از پرچم enforce خوانده شد." else "پرچم enforce برای اپ‌ها مسدود است. $denied از ${probes.size} فایل محافظت‌شده رد شد، که فقط در حالت enforcing رخ می‌دهد.")
        rows += evd("/sys/fs/selinux/enforce", "/sys/fs/selinux/enforce", enforceRead ?: when (enforceReach) { Reach.DENIED -> "denied by policy"; Reach.MISSING -> "missing"; else -> "unreadable" },
            if (enforceRead != null) modeLevel else if (enforceReach == Reach.DENIED) Status.CLEAR else Status.INFO,
            "A denial here is the expected result for an app on Android 10 and later.", "رد شدن اینجا نتیجهٔ مورد انتظار برای یک اپ در اندروید ۱۰ به بعد است.")
        rows += ev("getenforce", "getenforce", getenforce.ifBlank { "unavailable" }, if (getenforce.isBlank()) Status.INFO else modeLevel)
        rows += ev("ro.boot.selinux", "ro.boot.selinux", bootProp.ifBlank { "—" }, if (bootProp == "permissive") Status.WARNING else Status.INFO)
        rows += evd("SELinux filesystem", "فایل‌سیستم SELinux", when (fsReach) { Reach.READABLE -> "readable"; Reach.DENIED -> "present, restricted"; Reach.MISSING -> "missing"; else -> "unknown" },
            if (fsReach == Reach.MISSING) Status.WARNING else Status.CLEAR, "/sys/fs/selinux is where the kernel exposes the policy.", "/sys/fs/selinux جایی است که کرنل سیاست را نشان می‌دهد.")
        val contextRows = listOf(
            evd("Process context", "زمینهٔ پروسه", context.ifBlank { "unreadable" }, if (domainBad) Status.DANGER else if (context.isBlank()) Status.INFO else Status.CLEAR,
                "u:r:domain:s0:categories. An app should be untrusted_app or a sibling.", "u:r:domain:s0:categories. یک اپ باید untrusted_app یا نزدیک به آن باشد."),
            ev("Domain", "دامنه", domain.ifBlank { "—" }, if (domainBad) Status.DANGER else Status.INFO),
            ev("Categories", "دسته‌ها", categories.ifBlank { "—" }),
        )
        val probeRows = results.map { (path, r) ->
            ev(path, path, when (r) { Reach.READABLE -> "readable"; Reach.DENIED -> "denied"; Reach.MISSING -> "missing"; else -> "error" }, if (r == Reach.DENIED) Status.CLEAR else Status.INFO)
        }
        val sections = listOf(
            sectionOf("mode", "Enforcement", "اجرای سیاست", rows),
            sectionOf("context", "Process context", "زمینهٔ پروسه", contextRows),
            sectionOf("probes", "Policy probes", "پروب‌های سیاست", probeRows),
        )
        report(
            DetectorIds.SELINUX, status, summary.first, summary.second, sections.flatMap { it.evidence },
            caption = Phrase("${probes.size} policy probes · process context · boot parameter", "${probes.size} پروب سیاست · زمینهٔ پروسه · پارامتر بوت"),
            metrics = listOf(
                metric("Mode", "حالت", mode.substringBefore(' ').replaceFirstChar { it.uppercase() }, mode.substringBefore(' ').replaceFirstChar { it.uppercase() }, modeLevel),
                metric("Domain", "دامنه", domain.ifBlank { "—" }, domain.ifBlank { "—" }, if (domainBad) Status.DANGER else if (domain.isBlank()) Status.INFO else Status.CLEAR),
                metric("Denied", "ردشده", "$denied / ${probes.size}", "$denied / ${probes.size}", if (denied >= 2) Status.CLEAR else Status.INFO),
                metric("Policy fs", "fs سیاست", if (fsReach == Reach.MISSING) "Missing" else "Present", if (fsReach == Reach.MISSING) "نیست" else "هست", if (fsReach == Reach.MISSING) Status.WARNING else Status.CLEAR),
            ),
            sections = sections,
            impact = Phrase(
                if (permissive) "Permissive SELinux logs violations but does not stop them. Root tools and injected code can reach data the policy would normally protect."
                else "With SELinux enforcing, apps and injected code stay confined by the policy even when something else is modified.",
                if (permissive) "SELinux در حالت permissive تخلف‌ها را ثبت می‌کند اما جلویشان را نمی‌گیرد. ابزار روت و کد تزریق‌شده به داده‌ای می‌رسند که سیاست معمولاً محافظتش می‌کند."
                else "وقتی SELinux در حالت enforcing است، اپ‌ها و کد تزریق‌شده حتی در صورت تغییر چیز دیگری در چارچوب سیاست می‌مانند.",
            ),
        )
    },
)

private data class Knob(val path: String, val en: String, val fa: String, val good: (String) -> Boolean, val goodText: String)

internal fun hardeningDeep() = Detector(
    id = DetectorIds.HARDENING,
    title = Phrase("Kernel hardening", "سخت‌سازی کرنل"),
    about = Phrase(
        "Opens kernel tunables that a normal user build restricts for apps: kptr_restrict, dmesg_restrict, perf_event_paranoid, ASLR, mmap limits, plus kernel symbols, debugfs, the module list and the config. A read that Android denies counts as hardened; a read that succeeds is checked against the safe value.",
        "تنظیمات کرنلی را که بیلد user معمولی برای اپ‌ها محدود می‌کند باز می‌کند: kptr_restrict، dmesg_restrict، perf_event_paranoid، ASLR، محدودیت‌های mmap، به‌علاوهٔ نمادهای کرنل، debugfs، فهرست ماژول‌ها و کانفیگ. خواندنی که اندروید رد کند یعنی سخت‌شده؛ خواندنی که موفق شود با مقدار امن سنجیده می‌شود.",
    ),
    limits = Phrase(
        "Values differ by vendor without meaning root. A tunable that Android hides from apps cannot be audited here, only inferred as restricted.",
        "مقدارها بین سازنده‌ها فرق دارد و لزوماً به معنی روت نیست. تنظیمی که اندروید از اپ‌ها پنهان کند اینجا قابل حسابرسی نیست و فقط محدود فرض می‌شود.",
    ),
    probe = { _, _ ->
        val knobs = listOf(
            Knob("/proc/sys/kernel/kptr_restrict", "kptr_restrict", "kptr_restrict", { it != "0" }, "1 or 2"),
            Knob("/proc/sys/kernel/dmesg_restrict", "dmesg_restrict", "dmesg_restrict", { it == "1" }, "1"),
            Knob("/proc/sys/kernel/perf_event_paranoid", "perf_event_paranoid", "perf_event_paranoid", { (it.toIntOrNull() ?: 0) >= 2 }, "2 or higher"),
            Knob("/proc/sys/kernel/randomize_va_space", "randomize_va_space", "randomize_va_space", { it == "2" }, "2"),
            Knob("/proc/sys/vm/mmap_min_addr", "mmap_min_addr", "mmap_min_addr", { (it.toLongOrNull() ?: 0L) >= 4096L }, "4096 or higher"),
            Knob("/proc/sys/vm/mmap_rnd_bits", "mmap_rnd_bits", "mmap_rnd_bits", { (it.toIntOrNull() ?: 0) >= 24 }, "24 or higher"),
            Knob("/proc/sys/kernel/unprivileged_bpf_disabled", "unprivileged_bpf_disabled", "unprivileged_bpf_disabled", { it != "0" }, "1 or 2"),
        )
        val knobRows = mutableListOf<Evidence>()
        var weak = 0
        var blocked = 0
        knobs.forEach { k ->
            when (reach(k.path)) {
                Reach.READABLE -> {
                    val value = AndroidFacts.readText(k.path, 32)?.trim().orEmpty()
                    val ok = value.isNotBlank() && k.good(value)
                    if (!ok) weak++
                    knobRows += evd(k.en, k.fa, value.ifBlank { "unreadable" }, if (ok) Status.CLEAR else Status.WARNING,
                        "Safe value: ${k.goodText}. ${k.path}", "مقدار امن: ${k.goodText}. ${k.path}")
                }
                Reach.DENIED -> {
                    blocked++
                    knobRows += evd(k.en, k.fa, "blocked", Status.CLEAR,
                        "Android denies apps access to ${k.path}, which is the hardened behavior.", "اندروید دسترسی اپ‌ها به ${k.path} را رد می‌کند و این رفتار سخت‌شده است.")
                }
                Reach.MISSING -> knobRows += evd(k.en, k.fa, "not present", Status.INFO, "This kernel does not have ${k.path}.", "این کرنل ${k.path} را ندارد.")
                Reach.ERROR -> knobRows += evd(k.en, k.fa, "unknown", Status.INFO, "The read failed in an unexpected way.", "خواندن به شکل غیرمنتظره‌ای شکست خورد.")
            }
        }
        val exposure = mutableListOf<Evidence>()
        var danger = false
        val symbolsReach = reach("/proc/kallsyms")
        val symbolLine = if (symbolsReach == Reach.READABLE) AndroidFacts.readText("/proc/kallsyms", 400)?.lineSequence()?.firstOrNull().orEmpty() else ""
        val symbolsLeak = symbolLine.isNotBlank() && symbolLine.trimStart().take(8).any { it != '0' && it != ' ' }
        if (symbolsLeak) danger = true
        exposure += evd("Kernel symbols", "نمادهای کرنل", if (symbolsLeak) "visible" else if (symbolsReach == Reach.READABLE) "zeroed" else if (symbolsReach == Reach.DENIED) "blocked" else "not present",
            if (symbolsLeak) Status.DANGER else Status.CLEAR, "Real addresses in /proc/kallsyms help an attacker defeat KASLR.", "آدرس‌های واقعی در /proc/kallsyms به مهاجم کمک می‌کند KASLR را دور بزند.")
        val debugReach = reach("/sys/kernel/debug")
        val debugList = if (debugReach == Reach.READABLE) listDir("/sys/kernel/debug") else emptyList()
        exposure += evd("debugfs", "debugfs", if (debugList.isNotEmpty()) "listable" else when (debugReach) { Reach.DENIED -> "blocked"; Reach.MISSING -> "not mounted"; else -> "empty" },
            if (debugList.isNotEmpty()) Status.WARNING else Status.CLEAR, "A listable debugfs exposes driver internals to apps.", "debugfs قابل‌فهرست جزئیات درایورها را به اپ‌ها نشان می‌دهد.")
        val modulesReach = reach("/proc/modules")
        val modules = if (modulesReach == Reach.READABLE) AndroidFacts.readText("/proc/modules", 100_000).orEmpty().lineSequence().map { it.substringBefore(' ') }.filter { it.isNotBlank() }.toList() else emptyList()
        val rootModules = modules.filter { m -> listOf("kernelsu", "ksu", "apatch", "kpm", "magisk").any { m.contains(it, ignoreCase = true) } }
        if (rootModules.isNotEmpty()) danger = true
        exposure += evd("Loaded modules", "ماژول‌های بارگذاری‌شده", if (modulesReach == Reach.READABLE) modules.size.toString() else if (modulesReach == Reach.DENIED) "blocked" else "not present",
            Status.INFO, "The module list is readable only on some kernels.", "فهرست ماژول‌ها فقط روی بعضی کرنل‌ها قابل خواندن است.")
        exposure += evd("Root-related modules", "ماژول‌های مرتبط با روت", rootModules.joinToString().ifBlank { "none" }, if (rootModules.isEmpty()) Status.CLEAR else Status.DANGER,
            "kernelsu, ksu, apatch, kpm or magisk in the module list.", "kernelsu، ksu، apatch، kpm یا magisk در فهرست ماژول‌ها.")
        val configReach = reach("/proc/config.gz")
        exposure += evd("Kernel config", "کانفیگ کرنل", when (configReach) { Reach.READABLE -> "readable"; Reach.DENIED -> "blocked"; Reach.MISSING -> "not exposed"; else -> "unknown" },
            Status.INFO, "/proc/config.gz shows how the kernel was built.", "/proc/config.gz نشان می‌دهد کرنل چطور ساخته شده.")
        val status = when {
            danger -> Status.DANGER
            weak > 0 || debugList.isNotEmpty() -> Status.WARNING
            else -> Status.CLEAR
        }
        val summary = when (status) {
            Status.DANGER -> "Kernel internals are exposed to apps" to "درونیات کرنل برای اپ‌ها باز است"
            Status.WARNING -> "A kernel hardening setting is relaxed" to "یکی از تنظیمات سخت‌سازی کرنل شل شده"
            else -> if (blocked > 0) "Android blocks apps from the kernel tunables" to "اندروید دسترسی اپ‌ها به تنظیمات کرنل را می‌بندد"
            else "Kernel hardening looks normal" to "سخت‌سازی کرنل عادی به نظر می‌رسد"
        }
        val sections = listOf(
            sectionOf("knobs", "Kernel tunables", "تنظیمات کرنل", knobRows),
            sectionOf("exposure", "Exposure", "افشا", exposure),
        )
        report(
            DetectorIds.HARDENING, status, summary.first, summary.second, sections.flatMap { it.evidence },
            caption = Phrase("${knobs.size} tunables · symbols · debugfs · modules · config", "${knobs.size} تنظیم · نمادها · debugfs · ماژول‌ها · کانفیگ"),
            metrics = listOf(
                metric("Blocked", "مسدود", "$blocked / ${knobs.size}", "$blocked / ${knobs.size}", if (blocked > 0) Status.CLEAR else Status.INFO),
                metric("Weak", "ضعیف", weak.toString(), weak.toString(), if (weak > 0) Status.WARNING else Status.CLEAR),
                metric("Symbols", "نمادها", if (symbolsLeak) "Visible" else "Hidden", if (symbolsLeak) "دیده می‌شود" else "پنهان", if (symbolsLeak) Status.DANGER else Status.CLEAR),
                metric("debugfs", "debugfs", if (debugList.isNotEmpty()) "Open" else "Closed", if (debugList.isNotEmpty()) "باز" else "بسته", if (debugList.isNotEmpty()) Status.WARNING else Status.CLEAR),
            ),
            sections = sections,
            impact = Phrase(
                "Relaxed kernel settings make it easier for local code to find kernel addresses, read logs or watch other processes. They are common on custom kernels and rooted devices, and rare on a locked stock build.",
                "تنظیمات شل کرنل پیدا کردن آدرس‌های کرنل، خواندن لاگ‌ها و تماشای پروسه‌های دیگر را برای کد محلی آسان می‌کند. روی کرنل‌های سفارشی و دستگاه‌های روت‌شده رایج است و روی بیلد استوک قفل‌شده نادر.",
            ),
        )
    },
)
