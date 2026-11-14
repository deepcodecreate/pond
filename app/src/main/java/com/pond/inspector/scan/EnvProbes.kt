package com.pond.inspector.scan

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.camera2.CameraManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.UserManager
import android.view.accessibility.AccessibilityManager
import com.pond.inspector.model.DetectorIds
import com.pond.inspector.model.Status
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate

internal fun envDetectors(): List<Detector> = listOf(
    network(),
    userCerts(),
    accessibility(),
    clones(),
    appEnv(),
    emulatorFiles(),
    hardware(),
    posture(),
    gms(),
    spoofTools(),
    hideTools(),
)

private fun isSystemApp(context: Context, pkg: String): Boolean = try {
    val flags = context.packageManager.getApplicationInfo(pkg, 0).flags
    (flags and ApplicationInfo.FLAG_SYSTEM) != 0 || (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
} catch (_: Exception) {
    false
}

private fun network() = det(
    DetectorIds.NETWORK,
    "Network path", "مسیر شبکه",
    "Looks at how traffic leaves the device: an active VPN, a system or JVM proxy, tunnel interfaces, and the private DNS mode.",
    "بررسی می‌کند ترافیک از چه مسیری خارج می‌شود: VPN فعال، پروکسی سیستم یا JVM، رابط‌های تونل و حالت DNS خصوصی.",
    "A VPN is not a fault by itself. A transparent proxy that the OS does not know about is invisible.",
    "VPN به‌تنهایی ایراد نیست. پروکسی شفافی که سیستم‌عامل از آن خبر ندارد دیده نمی‌شود.",
) { context ->
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    var vpn = false
    var transports = ""
    var linkProxy = ""
    var dns = ""
    try {
        if (cm != null) {
            val net = cm.activeNetwork
            if (net != null) {
                val caps = cm.getNetworkCapabilities(net)
                if (caps != null) {
                    vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                        !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    val names = mutableListOf<String>()
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) names += "wifi"
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) names += "cellular"
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) names += "ethernet"
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) names += "bluetooth"
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) names += "vpn"
                    transports = names.joinToString()
                }
                val lp = cm.getLinkProperties(net)
                val proxy = lp?.httpProxy
                if (proxy != null) linkProxy = proxy.host + ":" + proxy.port
                dns = lp?.dnsServers?.joinToString { it.hostAddress.orEmpty() }.orEmpty()
            }
        }
    } catch (_: Exception) {
    }
    val jvmProxy = listOf("http.proxyHost", "https.proxyHost", "socksProxyHost")
        .mapNotNull { key -> System.getProperty(key)?.takeIf { it.isNotBlank() }?.let { "$key=$it" } }
    val globalProxy = try {
        android.provider.Settings.Global.getString(context.contentResolver, "http_proxy").orEmpty()
            .takeIf { it.isNotBlank() && it != ":0" }.orEmpty()
    } catch (_: Exception) {
        ""
    }
    val tunnels = try {
        java.net.NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .filter { iface -> try { iface.isUp } catch (_: Exception) { false } }
            .map { it.name }
            .filter { n -> listOf("tun", "ppp", "tap", "wg", "ipsec", "utun").any { n.startsWith(it) } }
    } catch (_: Exception) {
        emptyList()
    }
    val dnsMode = try {
        android.provider.Settings.Global.getString(context.contentResolver, "private_dns_mode").orEmpty()
    } catch (_: Exception) {
        ""
    }
    val proxied = linkProxy.isNotBlank() || jvmProxy.isNotEmpty() || globalProxy.isNotBlank()
    val hiddenTunnel = tunnels.isNotEmpty() && !vpn
    val status = when {
        proxied || hiddenTunnel -> Status.WARNING
        vpn || tunnels.isNotEmpty() -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when {
        proxied -> "Traffic goes through a proxy" to "ترافیک از یک پروکسی می‌گذرد"
        hiddenTunnel -> "A tunnel interface is up without a VPN" to "رابط تونل بدون VPN فعال است"
        vpn || tunnels.isNotEmpty() -> "A VPN is active" to "یک VPN فعال است"
        else -> "A direct connection, no proxy or VPN" to "اتصال مستقیم، بدون پروکسی یا VPN"
    }
    report(
        DetectorIds.NETWORK, status, summary.first, summary.second,
        listOf(
            ev("Transport", "نوع اتصال", transports.ifBlank { "unknown" }),
            ev("VPN active", "VPN فعال", vpn.toString(), if (vpn) Status.INFO else Status.CLEAR),
            ev("Tunnel interfaces", "رابط‌های تونل", tunnels.joinToString().ifBlank { "none" }, if (tunnels.isEmpty()) Status.CLEAR else Status.INFO),
            ev("Link proxy", "پروکسی لینک", linkProxy.ifBlank { "none" }, lvl(linkProxy.isNotBlank())),
            ev("JVM proxy", "پروکسی JVM", jvmProxy.joinToString().ifBlank { "none" }, lvl(jvmProxy.isNotEmpty())),
            ev("Global proxy setting", "تنظیم پروکسی سراسری", globalProxy.ifBlank { "none" }, lvl(globalProxy.isNotBlank())),
            ev("Private DNS", "DNS خصوصی", dnsMode.ifBlank { "unknown" }),
            ev("DNS servers", "سرورهای DNS", dns.ifBlank { "—" }),
        ),
    )
}

private fun userCerts() = det(
    DetectorIds.USER_CA,
    "User certificates", "گواهی‌های کاربر",
    "Lists certificate authorities that were installed by the user instead of shipped with the system. These are what a traffic-inspecting proxy needs.",
    "مراجع گواهی را که کاربر نصب کرده و همراه سیستم نیامده فهرست می‌کند. پروکسی‌های بازرسی ترافیک به همین‌ها نیاز دارند.",
    "Apps that opt out of user certificates ignore them, and a system-installed root (Magisk module) looks like a normal one.",
    "اپ‌هایی که گواهی کاربر را قبول ندارند آن را نادیده می‌گیرند و ریشهٔ نصب‌شده در سیستم (ماژول Magisk) عادی به نظر می‌رسد.",
) { _ ->
    try {
        val store = KeyStore.getInstance("AndroidCAStore")
        store.load(null)
        val aliases = store.aliases().toList()
        val user = aliases.filter { it.startsWith("user:") }
        val subjects = user.mapNotNull { alias ->
            (store.getCertificate(alias) as? X509Certificate)?.subjectX500Principal?.name
        }
        val tools = listOf("mitmproxy", "charles", "portswigger", "burp", "fiddler", "httpcanary", "reqable", "pcapdroid", "httptoolkit")
        val toolHits = subjects.filter { s -> tools.any { s.contains(it, ignoreCase = true) } }
        val status = when {
            toolHits.isNotEmpty() -> Status.DANGER
            user.isNotEmpty() -> Status.WARNING
            else -> Status.CLEAR
        }
        val summary = when (status) {
            Status.DANGER -> "A traffic-inspection certificate is installed" to "گواهی ابزار بازرسی ترافیک نصب شده"
            Status.WARNING -> "User-installed certificates are present" to "گواهی‌های نصب‌شده توسط کاربر وجود دارد"
            else -> "Only system certificate authorities" to "فقط مراجع گواهی سیستمی"
        }
        report(
            DetectorIds.USER_CA, status, summary.first, summary.second,
            listOf(
                ev("System authorities", "مراجع سیستمی", (aliases.size - user.size).toString()),
                ev("User-installed", "نصب‌شده توسط کاربر", user.size.toString(), lvl(user.isNotEmpty())),
                ev("Subjects", "سوژه‌ها", subjects.take(4).joinToString("\n").ifBlank { "none" }, lvl(subjects.isNotEmpty())),
                ev("Inspection tool names", "نام ابزارهای بازرسی", toolHits.take(3).joinToString("\n").ifBlank { "none" }, lvl(toolHits.isNotEmpty(), Status.DANGER)),
            ),
        )
    } catch (error: Exception) {
        report(
            DetectorIds.USER_CA, Status.UNSUPPORTED, "The certificate store was not readable", "مخزن گواهی خوانده نشد",
            listOf(ev("AndroidCAStore", "AndroidCAStore", error.javaClass.simpleName, Status.UNSUPPORTED)),
        )
    }
}

private fun accessibility() = det(
    DetectorIds.ACCESSIBILITY,
    "Accessibility and admin", "دسترس‌پذیری و ادمین",
    "Lists what can read the screen or act for the user: enabled accessibility services, notification listeners, and device administrators. Services that ship with the system are separated from installed ones.",
    "فهرست می‌کند چه چیزی می‌تواند صفحه را بخواند یا به جای کاربر عمل کند: سرویس‌های دسترس‌پذیری فعال، شنونده‌های اعلان و ادمین‌های دستگاه. سرویس‌های همراه سیستم از نصب‌شده‌ها جدا می‌شوند.",
    "Legitimate tools such as password managers and screen readers also appear here. A match is context, not proof of abuse.",
    "ابزارهای مشروع مثل مدیر رمز و صفحه‌خوان هم اینجا دیده می‌شوند. تطابق زمینه است، نه اثبات سوءاستفاده.",
) { context ->
    val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
    val services = try {
        am?.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK).orEmpty()
    } catch (_: Exception) {
        emptyList()
    }
    val servicePackages = services.mapNotNull { it.resolveInfo?.serviceInfo?.packageName }.distinct()
    val userServices = servicePackages.filter { !isSystemApp(context, it) }
    val listeners = secureString(context, "enabled_notification_listeners").split(":")
        .mapNotNull { ComponentName.unflattenFromString(it)?.packageName }.distinct()
    val userListeners = listeners.filter { !isSystemApp(context, it) }
    val admins = try {
        (context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager)
            ?.activeAdmins.orEmpty().map { it.packageName }.distinct()
    } catch (_: Exception) {
        emptyList()
    }
    val userAdmins = admins.filter { !isSystemApp(context, it) }
    val status = when {
        userServices.isNotEmpty() || userAdmins.isNotEmpty() -> Status.WARNING
        userListeners.isNotEmpty() -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.WARNING -> "An installed app can read the screen or administer the device" to "یک اپ نصب‌شده می‌تواند صفحه را بخواند یا دستگاه را مدیریت کند"
        Status.INFO -> "An installed app listens to notifications" to "یک اپ نصب‌شده به اعلان‌ها گوش می‌دهد"
        else -> "No installed accessibility service or admin is active" to "هیچ سرویس دسترس‌پذیری یا ادمین نصب‌شده‌ای فعال نیست"
    }
    report(
        DetectorIds.ACCESSIBILITY, status, summary.first, summary.second,
        listOf(
            ev("Accessibility services", "سرویس‌های دسترس‌پذیری", servicePackages.joinToString().ifBlank { "none" }),
            ev("Installed services", "سرویس‌های نصب‌شده", userServices.joinToString().ifBlank { "none" }, lvl(userServices.isNotEmpty())),
            ev("Notification listeners", "شنونده‌های اعلان", userListeners.joinToString().ifBlank { "none" }, if (userListeners.isEmpty()) Status.CLEAR else Status.INFO),
            ev("Device administrators", "ادمین‌های دستگاه", userAdmins.joinToString().ifBlank { "none" }, lvl(userAdmins.isNotEmpty())),
        ),
    )
}

private val cloneApps = listOf(
    KnownApp("com.lbe.parallel.intl", "Parallel Space", Status.WARNING),
    KnownApp("com.lbe.parallel.intl.arm64", "Parallel Space", Status.WARNING),
    KnownApp("com.excelliance.dualaid", "Dual Space", Status.WARNING),
    KnownApp("com.ludashi.dualspace", "Dual Space", Status.WARNING),
    KnownApp("com.applisto.appcloner", "App Cloner", Status.WARNING),
    KnownApp("com.lody.virtual", "VirtualApp", Status.WARNING),
    KnownApp("top.niunaijun.blackboxa32", "BlackBox", Status.WARNING),
    KnownApp("top.niunaijun.blackboxa64", "BlackBox", Status.WARNING),
    KnownApp("com.polestar.super.clone", "Super Clone", Status.WARNING),
    KnownApp("com.excean.maid", "Multi Space", Status.WARNING),
    KnownApp("com.vphonegaga.titan", "VPhoneGaGa", Status.WARNING),
    KnownApp("multi.parallel.dualspace.cloner", "Multi Parallel", Status.WARNING),
    KnownApp("com.oasisfeng.island", "Island", Status.INFO),
    KnownApp("net.typeblog.shelter", "Shelter", Status.INFO),
    KnownApp("com.catchingnow.icebox", "Ice Box", Status.INFO),
)

private fun clones() = det(
    DetectorIds.CLONES,
    "Clone and sandbox apps", "اپ‌های کلون و سندباکس",
    "Compares the visible package list with parallel-space, virtual-app and work-profile tools that run other apps in a copy.",
    "فهرست اپ‌های قابل‌دیدن را با ابزارهای parallel space و virtual app و work profile مقایسه می‌کند که اپ‌های دیگر را در نسخهٔ کپی اجرا می‌کنند.",
    "A cloner that is hidden or renamed is not listed. The App environment check looks at the running process itself.",
    "کلونر مخفی یا تغییرنام‌داده فهرست نمی‌شود. بررسی «محیط اپ» خودِ پروسهٔ در حال اجرا را می‌سنجد.",
) { context ->
    scanApps(
        context, cloneApps, DetectorIds.CLONES,
        "No listed clone or sandbox app is visible", "اپ کلون یا سندباکسِ فهرست‌شده‌ای دیده نشد",
        "A clone or sandbox app is visible", "یک اپ کلون یا سندباکس دیده شد",
    )
}

private fun appEnv() = det(
    DetectorIds.APPENV,
    "App environment", "محیط اپ",
    "Checks the process this scan runs in: user profile, data directory, uid, process name, install location, and installer. A virtual container changes these.",
    "پروسه‌ای را که این اسکن در آن اجرا می‌شود می‌سنجد: پروفایل کاربر، پوشهٔ داده، uid، نام پروسه، محل نصب و نصب‌کننده. کانتینر مجازی این‌ها را عوض می‌کند.",
    "A container that fakes all of these consistently will pass. A work profile is flagged even when it is legitimate.",
    "کانتینری که همهٔ این‌ها را هم‌خوان جعل کند رد می‌شود. work profile حتی اگر مشروع باشد علامت می‌خورد.",
) { context ->
    val uid = android.os.Process.myUid()
    val userId = uid / 100000
    val info = context.applicationInfo
    val dataDir = info.dataDir.orEmpty()
    val dataOk = dataDir.endsWith("/" + context.packageName)
    val uidOk = info.uid == uid
    val cmdline = AndroidFacts.readText("/proc/self/cmdline", 256).orEmpty().substringBefore('\u0000').trim()
    val cmdOk = cmdline.isBlank() || cmdline == context.packageName || cmdline.startsWith(context.packageName + ":")
    val source = info.sourceDir.orEmpty()
    val sourceOk = source.startsWith("/data/app/") || (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
    val managed = if (Build.VERSION.SDK_INT >= 30) {
        (context.getSystemService(Context.USER_SERVICE) as? UserManager)?.isManagedProfile == true
    } else {
        false
    }
    val installer = try {
        if (Build.VERSION.SDK_INT >= 30) {
            context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            context.packageManager.getInstallerPackageName(context.packageName)
        }
    } catch (_: Exception) {
        null
    }
    val status = when {
        !dataOk || !uidOk -> Status.DANGER
        userId != 0 || managed || !cmdOk || !sourceOk -> Status.WARNING
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.DANGER -> "This app runs inside a virtual container" to "این اپ داخل یک کانتینر مجازی اجرا می‌شود"
        Status.WARNING -> "This app runs in a secondary profile or an unusual path" to "این اپ در پروفایل دوم یا مسیر غیرعادی اجرا می‌شود"
        else -> "This app runs in the main profile from a normal path" to "این اپ در پروفایل اصلی و از مسیر عادی اجرا می‌شود"
    }
    report(
        DetectorIds.APPENV, status, summary.first, summary.second,
        listOf(
            ev("User id", "شناسهٔ کاربر", userId.toString(), lvl(userId != 0)),
            ev("Work profile", "work profile", managed.toString(), lvl(managed)),
            ev("Data dir matches package", "پوشهٔ داده با پکیج می‌خواند", dataOk.toString(), lvl(!dataOk, Status.DANGER)),
            ev("uid matches", "uid می‌خواند", uidOk.toString(), lvl(!uidOk, Status.DANGER)),
            ev("Process name", "نام پروسه", cmdline.ifBlank { "unreadable" }, lvl(!cmdOk)),
            ev("APK location", "محل APK", source.take(60), lvl(!sourceOk)),
            ev("Installer", "نصب‌کننده", installer ?: "none", Status.INFO),
        ),
    )
}

private fun emulatorFiles() = det(
    DetectorIds.EMULATOR,
    "Emulator traces", "ردپای شبیه‌ساز",
    "Looks for files, properties, vendor names and CPU hints that QEMU, Genymotion, BlueStacks, Nox, LDPlayer, MEmu and VirtualBox leave behind, plus ARM translation layers.",
    "فایل‌ها، پراپرتی‌ها، نام سازنده و نشانه‌های CPU را که QEMU و Genymotion و BlueStacks و Nox و LDPlayer و MEmu و VirtualBox به جا می‌گذارند جست‌وجو می‌کند، به‌علاوهٔ لایه‌های ترجمهٔ ARM.",
    "An emulator that rewrites its identity and hides these files is not caught here. Waydroid and ARC are reported as hints.",
    "شبیه‌سازی که هویتش را عوض کند و این فایل‌ها را پنهان کند اینجا گرفته نمی‌شود. Waydroid و ARC به‌صورت اشاره گزارش می‌شوند.",
) { context ->
    val paths = listOf(
        "/dev/qemu_pipe", "/dev/socket/qemud", "/dev/goldfish_pipe", "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props", "/system/bin/androVM-prop", "/system/bin/microvirt-prop",
        "/system/lib/libdroid4x.so", "/system/bin/windroyed", "/system/bin/nox-prop", "/system/bin/ttVM-prop",
        "/data/bluestacks.prop", "/dev/vboxguest", "/dev/vboxuser", "/fstab.vbox86", "/init.vbox86.rc",
        "/ueventd.vbox86.rc", "/fstab.nox", "/init.nox.rc", "/fstab.andy", "/ueventd.andy.rc",
        "/init.goldfish.rc", "/fstab.goldfish", "/fstab.ranchu", "/init.ranchu.rc", "/ueventd.ranchu.rc",
        "/ueventd.goldfish.rc",
    )
    val files = paths.filter { AndroidFacts.exists(it) }
    val props = AndroidFacts.props(listOf("ro.kernel.qemu", "ro.boot.qemu", "ro.hardware", "ro.boot.hardware", "ro.build.characteristics", "ro.dalvik.vm.native.bridge"))
    val hardware = listOf(props["ro.hardware"].orEmpty(), props["ro.boot.hardware"].orEmpty()).map { it.lowercase() }
    val propHits = mutableListOf<String>()
    if (props["ro.kernel.qemu"] == "1" || props["ro.boot.qemu"] == "1") propHits += "qemu"
    hardware.filter { it in listOf("goldfish", "ranchu", "vbox86") }.forEach { propHits += it }
    if (props["ro.build.characteristics"].orEmpty().contains("emulator", ignoreCase = true)) propHits += "emulator"
    val blob = listOf(Build.MANUFACTURER, Build.BRAND, Build.MODEL, Build.PRODUCT, Build.DEVICE, Build.BOARD)
        .joinToString(" ").lowercase()
    val vendors = listOf("genymotion", "bluestacks", "nox", "ldplayer", "memu", "microvirt", "andy", "droid4x", "tiantian", "vbox86", "windroy")
        .filter { it in blob }
    val bridge = props["ro.dalvik.vm.native.bridge"].orEmpty()
    val translated = bridge.isNotBlank() && bridge != "0"
    val cpuInfo = AndroidFacts.readText("/proc/cpuinfo", 40_000).orEmpty().lowercase()
    val hypervisor = cpuInfo.contains("hypervisor")
    val x86 = Build.SUPPORTED_ABIS.any { it.startsWith("x86") }
    val arc = context.packageManager.hasSystemFeature("org.chromium.arc")
    val hit = files.isNotEmpty() || propHits.isNotEmpty() || vendors.isNotEmpty() || translated || hypervisor
    val status = when {
        hit -> Status.WARNING
        x86 || arc -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.WARNING -> "Emulator or virtual-machine traces are visible" to "ردپای شبیه‌ساز یا ماشین مجازی دیده می‌شود"
        Status.INFO -> "An x86 or ChromeOS device, no emulator traces" to "دستگاه x86 یا ChromeOS، بدون ردپای شبیه‌ساز"
        else -> "No emulator traces" to "ردپای شبیه‌سازی دیده نشد"
    }
    report(
        DetectorIds.EMULATOR, status, summary.first, summary.second,
        listOf(
            ev("Emulator files", "فایل‌های شبیه‌ساز", files.take(5).joinToString().ifBlank { "none" }, lvl(files.isNotEmpty())),
            ev("Property hits", "تطابق پراپرتی", propHits.joinToString().ifBlank { "none" }, lvl(propHits.isNotEmpty())),
            ev("Vendor names", "نام سازنده‌ها", vendors.joinToString().ifBlank { "none" }, lvl(vendors.isNotEmpty())),
            ev("ARM translation layer", "لایهٔ ترجمهٔ ARM", bridge.ifBlank { "none" }, lvl(translated)),
            ev("CPU hypervisor flag", "پرچم hypervisor در CPU", hypervisor.toString(), lvl(hypervisor)),
            ev("x86 ABI", "ABI از نوع x86", x86.toString(), if (x86) Status.INFO else Status.CLEAR),
            ev("ChromeOS (ARC)", "ChromeOS (ARC)", arc.toString(), if (arc) Status.INFO else Status.CLEAR),
        ),
    )
}

private fun hardware() = det(
    DetectorIds.HARDWARE,
    "Hardware realism", "واقعی بودن سخت‌افزار",
    "Checks that the hardware looks like a phone: number and names of sensors, camera count, system features, and a live battery reading.",
    "بررسی می‌کند سخت‌افزار شبیه گوشی باشد: تعداد و نام سنسورها، تعداد دوربین، ویژگی‌های سیستم و خوانش زندهٔ باتری.",
    "Tablets and TV boxes legitimately lack some sensors. Good emulators and sensor spoofers can fake all of this.",
    "تبلت و اندروید‌باکس به‌طور طبیعی بعضی سنسورها را ندارند. شبیه‌ساز خوب و جعل سنسور می‌تواند همه را تقلید کند.",
) { context ->
    val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
    val sensors = sm?.getSensorList(Sensor.TYPE_ALL).orEmpty()
    val fakeNames = sensors.map { it.name.orEmpty() }.filter { n ->
        listOf("goldfish", "ranchu", "aosp on", "genymotion", "virtual", "vbox", "emulator", "acpi").any { n.contains(it, ignoreCase = true) }
    }
    fun has(type: Int) = sm?.getDefaultSensor(type) != null
    val pm = context.packageManager
    val cameras = try {
        (context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager)?.cameraIdList?.size ?: -1
    } catch (_: Exception) {
        -1
    }
    val battery = try {
        context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
    } catch (_: Exception) {
        null
    }
    val temperature = battery?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1
    val voltage = battery?.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1) ?: -1
    val tooFew = sensors.size < 4
    val status = when {
        fakeNames.isNotEmpty() -> Status.WARNING
        tooFew -> Status.WARNING
        else -> Status.CLEAR
    }
    val summary = when {
        fakeNames.isNotEmpty() -> "Sensor names look virtual" to "نام سنسورها مجازی به نظر می‌رسد"
        tooFew -> "Very few sensors for a phone" to "برای یک گوشی سنسور بسیار کم است"
        else -> "The hardware looks like a real phone" to "سخت‌افزار شبیه گوشی واقعی است"
    }
    report(
        DetectorIds.HARDWARE, status, summary.first, summary.second,
        listOf(
            ev("Sensors", "سنسورها", sensors.size.toString(), lvl(tooFew)),
            ev("Virtual-looking sensor names", "نام سنسورِ مجازی‌نما", fakeNames.take(3).joinToString().ifBlank { "none" }, lvl(fakeNames.isNotEmpty())),
            ev("Accelerometer", "شتاب‌سنج", has(Sensor.TYPE_ACCELEROMETER).toString(), if (has(Sensor.TYPE_ACCELEROMETER)) Status.CLEAR else Status.INFO),
            ev("Gyroscope", "ژیروسکوپ", has(Sensor.TYPE_GYROSCOPE).toString(), if (has(Sensor.TYPE_GYROSCOPE)) Status.CLEAR else Status.INFO),
            ev("Magnetometer", "قطب‌نما", has(Sensor.TYPE_MAGNETIC_FIELD).toString(), if (has(Sensor.TYPE_MAGNETIC_FIELD)) Status.CLEAR else Status.INFO),
            ev("Proximity", "نزدیکی", has(Sensor.TYPE_PROXIMITY).toString(), if (has(Sensor.TYPE_PROXIMITY)) Status.CLEAR else Status.INFO),
            ev("Light", "نور", has(Sensor.TYPE_LIGHT).toString(), if (has(Sensor.TYPE_LIGHT)) Status.CLEAR else Status.INFO),
            ev("Cameras", "دوربین‌ها", if (cameras < 0) "unknown" else cameras.toString(), if (cameras == 0) Status.INFO else Status.CLEAR),
            ev("Telephony", "تلفن", pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY).toString()),
            ev("Bluetooth", "بلوتوث", pm.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH).toString()),
            ev("Wi-Fi", "وای‌فای", pm.hasSystemFeature(PackageManager.FEATURE_WIFI).toString()),
            ev("Fingerprint sensor", "حسگر اثرانگشت", pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT).toString()),
            ev("Battery temperature", "دمای باتری", if (temperature < 0) "unknown" else (temperature / 10.0).toString() + " °C"),
            ev("Battery voltage", "ولتاژ باتری", if (voltage < 0) "unknown" else "$voltage mV"),
        ),
    )
}

private fun posture() = det(
    DetectorIds.POSTURE,
    "Security posture", "وضعیت امنیتی",
    "Reads the basics that decide how well the device protects its data: screen lock, storage encryption, patch age, Android version, app verification, and OEM unlock.",
    "پایه‌هایی را که تعیین می‌کنند دستگاه چقدر از داده‌اش محافظت می‌کند می‌خواند: قفل صفحه، رمزنگاری حافظه، عمر وصله، نسخهٔ اندروید، تأیید اپ‌ها و OEM unlock.",
    "These describe configuration, not compromise. A device can be perfectly configured and still be rooted.",
    "این‌ها تنظیمات را توصیف می‌کنند، نه نفوذ را. دستگاهی می‌تواند کاملاً درست تنظیم شده باشد و باز هم روت باشد.",
) { context ->
    val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
    val locked = km?.isDeviceSecure == true
    val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
    val encStatus = try {
        dpm?.storageEncryptionStatus ?: -1
    } catch (_: Exception) {
        -1
    }
    val encrypted = encStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
        encStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY ||
        encStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER ||
        AndroidFacts.prop("ro.crypto.state") == "encrypted"
    val cryptoType = AndroidFacts.prop("ro.crypto.type")
    val age: Long? = try {
        java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.parse(Build.VERSION.SECURITY_PATCH), java.time.LocalDate.now())
    } catch (_: Exception) {
        null
    }
    val verifier = globalInt(context, "package_verifier_enable", -1)
    val verifyAdb = globalInt(context, "verifier_verify_adb_installs", -1)
    val oemUnlock = AndroidFacts.prop("sys.oem_unlock_allowed")
    val oldPatch = age != null && age > 365
    val oldAndroid = Build.VERSION.SDK_INT < 33
    val status = when {
        !locked || !encrypted || oldPatch || verifier == 0 -> Status.WARNING
        oldAndroid || oemUnlock == "1" -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when (status) {
        Status.WARNING -> "A basic protection is missing or out of date" to "یک محافظت پایه وجود ندارد یا قدیمی است"
        Status.INFO -> "Protections are on, with minor notes" to "محافظت‌ها روشن است، با چند نکتهٔ کوچک"
        else -> "Lock, encryption and patches look healthy" to "قفل، رمزنگاری و وصله‌ها سالم به نظر می‌رسند"
    }
    report(
        DetectorIds.POSTURE, status, summary.first, summary.second,
        listOf(
            ev("Screen lock set", "قفل صفحه تنظیم شده", locked.toString(), if (locked) Status.CLEAR else Status.WARNING),
            ev("Storage encrypted", "حافظه رمز شده", encrypted.toString(), if (encrypted) Status.CLEAR else Status.WARNING),
            ev("Encryption type", "نوع رمزنگاری", cryptoType.ifBlank { "—" }),
            ev("Security patch age", "عمر وصلهٔ امنیتی", age?.let { "$it days" } ?: "unknown", if (oldPatch) Status.WARNING else if (age == null) Status.INFO else Status.CLEAR),
            ev("Android version", "نسخهٔ اندروید", Build.VERSION.RELEASE + " (SDK " + Build.VERSION.SDK_INT + ")", if (oldAndroid) Status.INFO else Status.CLEAR),
            ev("App verification", "تأیید اپ‌ها", if (verifier < 0) "unknown" else if (verifier == 1) "on" else "off", if (verifier == 0) Status.WARNING else if (verifier == 1) Status.CLEAR else Status.INFO),
            ev("Verify adb installs", "تأیید نصب از adb", if (verifyAdb < 0) "unknown" else if (verifyAdb == 1) "on" else "off", if (verifyAdb == 0) Status.INFO else Status.CLEAR),
            ev("OEM unlock allowed", "OEM unlock مجاز", oemUnlock.ifBlank { "unknown" }, if (oemUnlock == "1") Status.INFO else Status.CLEAR),
        ),
    )
}

@Suppress("DEPRECATION")
private fun packageInfo(context: Context, name: String): PackageInfo? = try {
    val flags = PackageManager.GET_SIGNING_CERTIFICATES
    if (Build.VERSION.SDK_INT >= 33) {
        context.packageManager.getPackageInfo(name, PackageManager.PackageInfoFlags.of(flags.toLong()))
    } else {
        context.packageManager.getPackageInfo(name, flags)
    }
} catch (_: Exception) {
    null
}

private fun signerDigest(info: PackageInfo?): String = try {
    val bytes = info?.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
    if (bytes == null) {
        ""
    } else {
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
} catch (_: Exception) {
    ""
}

private fun gms() = det(
    DetectorIds.GMS,
    "Google Play services", "سرویس‌های گوگل پلی",
    "Checks that Google Play services and the Play Store are present, are system apps, and are not a replacement such as microG. Play Integrity needs the real ones.",
    "بررسی می‌کند سرویس‌های گوگل پلی و فروشگاه پلی وجود داشته باشند، اپ سیستمی باشند و جایگزینی مثل microG نباشند. Play Integrity به نسخهٔ واقعی نیاز دارد.",
    "The signing digest is shown for you to compare; it is not checked against a pinned value.",
    "هش امضا برای مقایسهٔ شما نمایش داده می‌شود و با مقدار پین‌شده سنجیده نمی‌شود.",
) { context ->
    val gmsInfo = packageInfo(context, "com.google.android.gms")
    val store = packageInfo(context, "com.android.vending")
    val gsf = packageInfo(context, "com.google.android.gsf")
    val pm = context.packageManager
    val label = try {
        gmsInfo?.applicationInfo?.let { pm.getApplicationLabel(it).toString() }.orEmpty()
    } catch (_: Exception) {
        ""
    }
    val replacements = listOf("org.microg.gms.droidguard", "com.mgoogle.android.gms", "app.revanced.android.gms", "org.microg.nlp.backend.ichnaea")
        .filter { packageInfo(context, it) != null }
    val microg = label.contains("microG", ignoreCase = true) || replacements.isNotEmpty()
    val gmsSystem = gmsInfo != null && isSystemApp(context, "com.google.android.gms")
    val storeSystem = store != null && isSystemApp(context, "com.android.vending")
    val status = when {
        microg -> Status.WARNING
        gmsInfo == null -> Status.WARNING
        !gmsSystem -> Status.WARNING
        store == null || !storeSystem -> Status.INFO
        else -> Status.CLEAR
    }
    val summary = when {
        microg -> "A GMS replacement such as microG is installed" to "جایگزین GMS مثل microG نصب است"
        gmsInfo == null -> "Google Play services is not installed" to "سرویس‌های گوگل پلی نصب نیست"
        !gmsSystem -> "Play services is not a system app" to "سرویس‌های پلی اپ سیستمی نیست"
        store == null || !storeSystem -> "Play Store is missing or not a system app" to "فروشگاه پلی نیست یا اپ سیستمی نیست"
        else -> "Play services and Play Store are the system copies" to "سرویس‌های پلی و فروشگاه پلی نسخهٔ سیستمی هستند"
    }
    report(
        DetectorIds.GMS, status, summary.first, summary.second,
        listOf(
            ev("Play services", "سرویس‌های پلی", gmsInfo?.versionName ?: "absent", if (gmsInfo == null) Status.WARNING else Status.CLEAR),
            ev("Play services label", "نام سرویس‌های پلی", label.ifBlank { "—" }, lvl(microg)),
            ev("Play services is a system app", "سرویس‌های پلی سیستمی است", gmsSystem.toString(), if (gmsInfo == null) Status.INFO else lvl(!gmsSystem)),
            ev("Play Store", "فروشگاه پلی", store?.versionName ?: "absent", if (store == null) Status.INFO else Status.CLEAR),
            ev("Services framework", "Services Framework", gsf?.versionName ?: "absent", if (gsf == null) Status.INFO else Status.CLEAR),
            ev("Replacement packages", "بسته‌های جایگزین", replacements.joinToString().ifBlank { "none" }, lvl(replacements.isNotEmpty())),
            ev("Play services signing digest", "هش امضای سرویس‌های پلی", signerDigest(gmsInfo).take(64).ifBlank { "—" }),
            ev("Play Store signing digest", "هش امضای فروشگاه پلی", signerDigest(store).take(64).ifBlank { "—" }),
        ),
    )
}

private val spoofApps = listOf(
    KnownApp("com.lexa.fakegps", "Fake GPS", Status.WARNING),
    KnownApp("com.incorporateapps.fakegps.fre", "Fake GPS Location", Status.WARNING),
    KnownApp("ru.gavrikov.mocklocations", "Mock Locations", Status.WARNING),
    KnownApp("com.blogspot.newapphorizons.fakegps", "Fake GPS Free", Status.WARNING),
    KnownApp("com.theappninjas.fakegpsjoystick", "Fake GPS Joystick", Status.WARNING),
    KnownApp("com.evezzon.fakegps", "Fake GPS Location", Status.WARNING),
    KnownApp("com.gsmartstudio.fakegps", "Fake GPS", Status.WARNING),
    KnownApp("com.rosteam.gpsemulator", "GPS Emulator", Status.WARNING),
    KnownApp("app.greyshirts.sslcapture", "Packet Capture", Status.WARNING),
    KnownApp("com.minhui.networkcapture", "Network Capture", Status.WARNING),
    KnownApp("com.guoshi.httpcanary", "HttpCanary", Status.WARNING),
    KnownApp("com.guoshi.httpcanary.premium", "HttpCanary Premium", Status.WARNING),
    KnownApp("com.emanuelef.remote_capture", "PCAPdroid", Status.WARNING),
    KnownApp("com.reqable.android", "Reqable", Status.WARNING),
    KnownApp("tech.httptoolkit.android.v1", "HTTP Toolkit", Status.WARNING),
    KnownApp("org.sandroproxy.drony", "Drony", Status.INFO),
    KnownApp("org.proxydroid", "ProxyDroid", Status.INFO),
    KnownApp("com.cygery.repetitouch.pro", "Repetitouch", Status.INFO),
    KnownApp("com.truedevelopersstudio.autoclicker", "Auto Clicker", Status.INFO),
    KnownApp("com.touchsprite.android", "TouchSprite", Status.INFO),
    KnownApp("com.cih.game_cih", "Game CIH", Status.WARNING),
)

private fun spoofTools() = det(
    DetectorIds.SPOOF,
    "Spoofing and capture tools", "ابزارهای جعل و شنود",
    "Compares the visible package list with fake-location apps, traffic-capture proxies, memory editors and auto-clickers.",
    "فهرست اپ‌های قابل‌دیدن را با اپ‌های موقعیت جعلی، پروکسی‌های ضبط ترافیک، ویرایشگر حافظه و کلیک‌کنندهٔ خودکار مقایسه می‌کند.",
    "Renamed or hidden builds are invisible. Many of these have legitimate uses.",
    "بیلدهای تغییرنام‌داده یا مخفی دیده نمی‌شوند. بسیاری از این‌ها کاربرد مشروع هم دارند.",
) { context ->
    scanApps(
        context, spoofApps, DetectorIds.SPOOF,
        "No listed spoofing or capture app is visible", "اپ جعل یا شنودِ فهرست‌شده‌ای دیده نشد",
        "A spoofing or capture app is visible", "یک اپ جعل یا شنود دیده شد",
    )
}

private val hideApps = listOf(
    KnownApp("com.tsng.hidemyapplist", "Hide My Applist", Status.WARNING),
    KnownApp("com.devadvance.rootcloak", "RootCloak", Status.DANGER),
    KnownApp("com.devadvance.rootcloakplus", "RootCloak Plus", Status.DANGER),
    KnownApp("com.amphoras.hidemyroot", "Hide My Root", Status.DANGER),
    KnownApp("com.amphoras.hidemyrootadfree", "Hide My Root", Status.DANGER),
    KnownApp("com.formyhm.hideroot", "Hide Root", Status.DANGER),
    KnownApp("com.formyhm.hiderootPremium", "Hide Root Premium", Status.DANGER),
    KnownApp("com.ramdroid.appquarantine", "App Quarantine", Status.DANGER),
    KnownApp("com.ramdroid.appquarantinepro", "App Quarantine Pro", Status.DANGER),
    KnownApp("dev.dergoogler.mmrl", "MMRL", Status.WARNING),
    KnownApp("com.dergoogler.mmrl.wx", "MMRL", Status.WARNING),
    KnownApp("com.fox2code.mmm", "Fox's Magisk Module Manager", Status.WARNING),
    KnownApp("io.github.vvb2060.keyattestation", "Key Attestation", Status.INFO),
    KnownApp("io.github.vvb2060.mahoshojo", "Momo", Status.INFO),
    KnownApp("com.reveny.nativecheck", "Native Detector", Status.INFO),
    KnownApp("icu.nullptr.nativetest", "Native Test", Status.INFO),
    KnownApp("com.byxiaorun.detector", "Detector", Status.INFO),
    KnownApp("com.zhenxi.hunter", "Hunter", Status.INFO),
)

private fun hideTools() = det(
    DetectorIds.HIDE,
    "Root hiding tools", "ابزارهای پنهان‌سازی روت",
    "Compares the visible package list with root cloakers, app-hiding tools, Magisk module managers and well-known detector apps.",
    "فهرست اپ‌های قابل‌دیدن را با پنهان‌کننده‌های روت، ابزارهای مخفی‌سازی اپ، مدیرهای ماژول Magisk و اپ‌های شناخته‌شدهٔ تشخیص مقایسه می‌کند.",
    "Hiding tools hide themselves first, so a clean result here means little on its own. Detector apps are listed for context only.",
    "ابزارهای پنهان‌سازی اول خودشان را پنهان می‌کنند، پس نتیجهٔ سالم اینجا به‌تنهایی معنای کمی دارد. اپ‌های تشخیص فقط برای زمینه فهرست می‌شوند.",
) { context ->
    scanApps(
        context, hideApps, DetectorIds.HIDE,
        "No listed root-hiding tool is visible", "ابزار پنهان‌سازی روتِ فهرست‌شده‌ای دیده نشد",
        "A root-hiding tool is visible", "یک ابزار پنهان‌سازی روت دیده شد",
    )
}
