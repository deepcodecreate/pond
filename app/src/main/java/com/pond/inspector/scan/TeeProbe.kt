package com.pond.inspector.scan

import android.os.Build
import com.pond.inspector.logic.Signals
import com.pond.inspector.model.DetectorIds
import com.pond.inspector.model.DetectorReport
import com.pond.inspector.model.Evidence
import com.pond.inspector.model.Metric
import com.pond.inspector.model.Phrase
import com.pond.inspector.model.Section
import com.pond.inspector.model.Status

internal fun evd(en: String, fa: String, value: String, level: Status, detailEn: String, detailFa: String = detailEn) =
    Evidence(Phrase(en, fa), value.ifBlank { "—" }, level, Phrase(detailEn, detailFa))

internal fun sectionOf(key: String, en: String, fa: String, rows: List<Evidence>, note: Phrase? = null): Section {
    val severity = when {
        rows.any { it.level == Status.DANGER || it.level == Status.ERROR } -> Status.DANGER
        rows.any { it.level == Status.WARNING } -> Status.WARNING
        else -> null
    }
    return Section(key, Phrase(en, fa), rows, severity, note)
}

internal fun levelText(level: Int?): String = when (level) {
    0 -> "software"
    1 -> "trusted environment"
    2 -> "strongbox"
    null -> "—"
    else -> "unknown ($level)"
}

internal fun bootText(state: Int?): String = when (state) {
    0 -> "verified"
    1 -> "self-signed"
    2 -> "unverified"
    3 -> "failed"
    null -> "—"
    else -> "unknown ($state)"
}

internal fun patchText(v: Long?): String {
    if (v == null) return "—"
    val s = v.toString()
    return when (s.length) {
        6 -> s.substring(0, 4) + "-" + s.substring(4, 6)
        8 -> s.substring(0, 4) + "-" + s.substring(4, 6) + "-" + s.substring(6, 8)
        else -> s
    }
}

private fun metric(en: String, fa: String, valueEn: String, valueFa: String, level: Status) =
    Metric(Phrase(en, fa), Phrase(valueEn, valueFa), level)

internal fun teeDeep() = Detector(
    id = DetectorIds.TEE,
    title = Phrase("TEE", "TEE"),
    about = Phrase(
        "Generates a hardware-backed key with a random challenge and tries up to three key types, so one refusal does not end the check. It parses the full key attestation (security levels, verified boot state, lock state, boot hash, patch levels, bound app), verifies every certificate signature in the chain, compares the attested boot state with the system properties, and optionally checks the chain serials against Google's revocation list. Nothing is uploaded.",
        "یک کلید پشتوانه‌دار سخت‌افزاری با چالش تصادفی می‌سازد و تا سه نوع کلید را امتحان می‌کند تا یک رد شدن کار را تمام نکند. attestation کامل را تجزیه می‌کند (سطح امنیت، وضعیت بوت، قفل بودن، هش بوت، سطح وصله‌ها، اپ متصل)، امضای تک‌تک گواهی‌های زنجیره را بررسی می‌کند، وضعیت بوتِ تأییدشده را با پراپرتی‌های سیستم می‌سنجد و اختیاری سریال‌ها را با فهرست ابطال گوگل مقایسه می‌کند. چیزی آپلود نمی‌شود.",
    ),
    limits = Phrase(
        "The root is recognised by serial number or name, not pinned to Google's public key. A well-made spoof that replays a real chain can still pass. This is not a Play Integrity verdict.",
        "ریشه با شمارهٔ سریال یا نام شناسایی می‌شود و به کلید عمومی گوگل پین نشده. جعلی خوب که زنجیرهٔ واقعی را بازپخش کند ممکن است رد شود. این حکم Play Integrity نیست.",
    ),
    probe = { context, prefs ->
        val a = Attestation.read(context)
        val d = a.desc
        val r = d?.root
        val props = AndroidFacts.props(
            listOf("ro.boot.vbmeta.digest", "ro.boot.flash.locked", "ro.boot.verifiedbootstate", "ro.boot.vbmeta.device_state"),
        )
        val digest = props["ro.boot.vbmeta.digest"].orEmpty().lowercase()
        val attestedHash = r?.bootHash.orEmpty().lowercase()
        val hashKnown = digest.isNotBlank() && attestedHash.isNotBlank()
        val hashMatch = !hashKnown || digest == attestedHash
        val lock = props["ro.boot.flash.locked"].orEmpty()
        val vb = props["ro.boot.vbmeta.device_state"].orEmpty().lowercase()
        val bootProp = props["ro.boot.verifiedbootstate"].orEmpty().lowercase()
        val propLocked = lock == "1" || vb == "locked"
        val propGreen = bootProp == "green"
        val attestedState = r?.bootState
        val lockSpoof = r != null && propLocked && r.deviceLocked != true
        val greenSpoof = r != null && propGreen && attestedState != null && attestedState != 0 && attestedState != 1
        val bootBad = r != null && (attestedState != 0 || r.deviceLocked != true)

        var revoked = false
        var crlText = "off"
        var crlLevel = Status.INFO
        if (a.error == null && prefs.onlineCrl) {
            val crl = AndroidFacts.fetchAttestationStatus(a.serials)
            revoked = crl.revoked.isNotEmpty()
            crlText = if (!crl.ok) "offline" else if (revoked) "revoked" else "clean"
            crlLevel = if (!crl.ok) Status.WARNING else if (revoked) Status.DANGER else Status.CLEAR
        }

        if (a.error != null) {
            val rows = a.attempts.map { line ->
                evd(
                    line.substringBefore(':'), line.substringBefore(':'),
                    line.substringAfter(':').trim().take(160), Status.WARNING,
                    "The keystore refused this key request.", "کی‌استور این درخواست کلید را رد کرد.",
                )
            }.ifEmpty {
                listOf(ev("Keystore", "Keystore", a.error.take(160), Status.UNSUPPORTED))
            }
            val works = a.keystoreWorks
            val status = if (works) Status.WARNING else Status.UNSUPPORTED
            val summaryEn = if (works) "Keystore works but refuses to attest" else "Keystore attestation could not run"
            val summaryFa = if (works) "کی‌استور کار می‌کند اما attestation را رد می‌کند" else "attestation کی‌استور اجرا نشد"
            val base = listOf(
                ev("Keystore key creation", "ساخت کلید در کی‌استور", if (works) "works" else "failed", if (works) Status.CLEAR else Status.UNSUPPORTED),
                ev("Plain key security level", "سطح امنیت کلید ساده", a.levelName, if (a.hardware) Status.CLEAR else Status.INFO),
                ev("Attestation", "attestation", "refused", Status.WARNING),
            )
            report(
                DetectorIds.TEE, status, summaryEn, summaryFa, base + rows,
                caption = Phrase(
                    "Every attestation attempt failed, so nothing about the boot chain could be confirmed.",
                    "همهٔ تلاش‌های attestation شکست خورد، پس چیزی از زنجیرهٔ بوت تأیید نشد.",
                ),
                metrics = listOf(
                    metric("Verdict", "حکم", "Unavailable", "در دسترس نیست", Status.UNSUPPORTED),
                    metric("Score", "امتیاز", "—", "—", Status.UNSUPPORTED),
                    metric("Tier", "سطح", a.levelName, a.levelName, if (a.hardware) Status.CLEAR else Status.INFO),
                    metric("Trust", "اعتماد", "None", "هیچ", Status.UNSUPPORTED),
                ),
                sections = listOf(
                    sectionOf("attestation", "Attempts", "تلاش‌ها", base + rows),
                ),
                impact = Phrase(
                    "Strict apps usually need a working attestation. On a device whose keystore normally attests, a refusal often means a broken or revoked key box, or a module that intercepts keystore calls.",
                    "اپ‌های سخت‌گیر معمولاً attestation سالم می‌خواهند. روی دستگاهی که کی‌استورش عادتاً attest می‌کند، رد شدن اغلب یعنی key box خراب یا ابطال‌شده یا ماژولی که فراخوانی‌های کی‌استور را رهگیری می‌کند.",
                ),
            )
        } else {
            val deviceOs = Build.VERSION.RELEASE.substringBefore('.').toLongOrNull()
            val osMismatch = d?.osVersion != null && deviceOs != null && d.osVersion / 10000 != deviceOs
            val buildPatch = Build.VERSION.SECURITY_PATCH.replace("-", "")
            val patchBad = d?.osPatchLevel != null && buildPatch.length >= 6 && d.osPatchLevel.toString() != buildPatch.substring(0, 6)
            val chainOk = a.chainSigOk && a.rootSelfSigned

            var hard = 0
            var review = 0
            if (!a.chainSigOk) hard++
            if (a.chain.isNotEmpty() && !a.rootSelfSigned) hard++
            if (a.challengeOk == false) hard++
            if (a.appBound == false) hard++
            if (revoked) hard++
            if (!hashMatch) hard++
            if (lockSpoof || greenSpoof) hard++
            if (!a.hardware) review++
            if (bootBad && !lockSpoof && !greenSpoof) review++
            if (patchBad) review++
            if (osMismatch) review++
            if (!a.chainDatesOk) review++
            if (!a.googleRoot) review++
            if (!a.extensionPresent || d == null) review++
            if (d != null && d.keymasterLevel == 0) review++
            val score = (hard * 45 + review * 15).coerceAtMost(100)

            val trust = mutableListOf<Evidence>()
            trust += ev("Root identity", "هویت ریشه", a.rootKind, if (a.googleRoot) Status.CLEAR else Status.WARNING)
            trust += evd("Root self-signed", "ریشه خودامضا", a.rootSelfSigned.toString(), if (a.rootSelfSigned) Status.CLEAR else Status.DANGER, "The last certificate must sign itself.", "آخرین گواهی باید خودش را امضا کند.")
            trust += evd("Chain signatures valid", "امضاهای زنجیره معتبر", a.chainSigOk.toString(), if (a.chainSigOk) Status.CLEAR else Status.DANGER, "Each certificate is verified with the public key of the next one.", "هر گواهی با کلید عمومی گواهی بعدی راستی‌آزمایی می‌شود.")
            trust += ev("Chain dates valid", "تاریخ‌های زنجیره معتبر", a.chainDatesOk.toString(), if (a.chainDatesOk) Status.CLEAR else Status.WARNING)
            trust += ev("Chain length", "طول زنجیره", a.chain.size.toString())
            trust += evd("Challenge echoed", "بازتاب چالش", (a.challengeOk == true).toString(), if (a.challengeOk == true) Status.CLEAR else Status.DANGER, "The random challenge must come back inside the certificate, otherwise the chain was not made for this request.", "چالش تصادفی باید داخل گواهی برگردد، وگرنه زنجیره برای همین درخواست ساخته نشده.")
            trust += ev("Bound to this app", "متصل به همین اپ", a.appBound?.toString() ?: "unknown", if (a.appBound == false) Status.DANGER else if (a.appBound == true) Status.CLEAR else Status.INFO)

            val attest = mutableListOf<Evidence>()
            attest += ev("Key type used", "نوع کلید استفاده‌شده", a.mode.ifBlank { "ec" })
            if (a.attempts.isNotEmpty()) {
                attest += evd("Earlier attempts refused", "تلاش‌های ردشده قبلی", a.attempts.size.toString(), Status.WARNING, a.attempts.joinToString("\n").take(300))
            }
            attest += ev("Inside secure hardware", "داخل سخت‌افزار امن", a.hardware.toString(), if (a.hardware) Status.CLEAR else Status.WARNING)
            attest += ev("Key security level", "سطح امنیت کلید", a.levelName, if (a.hardware) Status.CLEAR else Status.WARNING)
            attest += ev("StrongBox", "StrongBox", if (a.strongBox) "available" else "not available")
            attest += ev("Attestation extension", "افزونهٔ attestation", if (a.extensionPresent) "present" else "absent", if (a.extensionPresent) Status.CLEAR else Status.WARNING)
            if (d != null) {
                attest += ev("Attestation version", "نسخهٔ attestation", d.attestationVersion.toString())
                attest += ev("Attestation security level", "سطح امنیت attestation", levelText(d.attestationLevel))
                attest += ev("KeyMint/Keymaster version", "نسخهٔ KeyMint/Keymaster", d.keymasterVersion.toString())
                attest += ev("KeyMint/Keymaster level", "سطح KeyMint/Keymaster", levelText(d.keymasterLevel), if (d.keymasterLevel == 0) Status.WARNING else Status.INFO)
                attest += ev("Key origin", "منشأ کلید", d.origin?.let { if (it == 0L) "generated" else it.toString() }.orEmpty())
                attest += ev("Unique ID length", "طول شناسهٔ یکتا", d.uniqueIdLength.toString())
                if (d.packages.isNotEmpty()) attest += ev("Attested package", "پکیج attestation‌شده", d.packages.joinToString())
                if (d.signatureDigests.isNotEmpty()) attest += ev("Signing digest", "هش امضا", d.signatureDigests.joinToString().take(80))
            }

            val boot = mutableListOf<Evidence>()
            if (r != null) {
                boot += ev("Verified boot state", "وضعیت بوت تأییدشده", bootText(r.bootState), if (r.bootState == 0) Status.CLEAR else Status.WARNING)
                boot += ev("Device locked", "قفل بودن دستگاه", r.deviceLocked.toString(), if (r.deviceLocked == true) Status.CLEAR else Status.WARNING)
                boot += ev("Verified boot key", "کلید بوت تأییدشده", r.verifiedBootKey.take(64))
                boot += ev("Attested boot hash", "هش بوتِ attestation", attestedHash.take(64))
                boot += ev("ro.boot.vbmeta.digest", "ro.boot.vbmeta.digest", digest.take(64).ifBlank { "—" })
                boot += evd(
                    "Boot hash matches digest", "هش بوت با digest می‌خواند",
                    if (hashKnown) hashMatch.toString() else "unknown",
                    if (!hashKnown) Status.INFO else if (hashMatch) Status.CLEAR else Status.DANGER,
                    "Attested verifiedBootHash did not match ro.boot.vbmeta.digest.".takeIf { hashKnown && !hashMatch }
                        ?: "Both values come from the same vbmeta image on an untouched device.",
                    "verifiedBootHash در attestation با ro.boot.vbmeta.digest نمی‌خواند.".takeIf { hashKnown && !hashMatch }
                        ?: "روی دستگاه دست‌نخورده هر دو مقدار از یک ایمیج vbmeta می‌آیند.",
                )
                boot += evd(
                    "Properties agree with hardware", "پراپرتی‌ها با سخت‌افزار می‌خوانند",
                    (!lockSpoof && !greenSpoof).toString(),
                    if (lockSpoof || greenSpoof) Status.DANGER else Status.CLEAR,
                    "The system properties claim a locked or green boot while the hardware reports otherwise.",
                    "پراپرتی‌های سیستم بوت قفل یا سبز نشان می‌دهند در حالی که سخت‌افزار خلافش را می‌گوید.",
                )
            } else {
                boot += ev("Root of trust", "ریشهٔ اعتماد", "absent", Status.WARNING)
            }
            boot += ev("OS version (attested)", "نسخهٔ OS (attestation)", d?.osVersion?.toString().orEmpty())
            boot += ev("OS version matches build", "نسخهٔ OS با بیلد می‌خواند", (!osMismatch).toString(), if (osMismatch) Status.WARNING else Status.CLEAR)
            boot += ev("OS patch level (attested)", "سطح وصلهٔ OS (attestation)", patchText(d?.osPatchLevel), if (patchBad) Status.WARNING else Status.INFO)
            boot += ev("Patch matches build", "وصله با بیلد می‌خواند", (!patchBad).toString(), if (patchBad) Status.WARNING else Status.CLEAR)
            boot += ev("Vendor patch level", "سطح وصلهٔ وندور", patchText(d?.vendorPatchLevel))
            boot += ev("Boot patch level", "سطح وصلهٔ بوت", patchText(d?.bootPatchLevel))

            val chain = a.chain.mapIndexed { index, c ->
                Evidence(
                    Phrase("Certificate ${index + 1}", "گواهی ${index + 1}"),
                    c.subject,
                    Status.INFO,
                    Phrase(
                        "issuer ${c.issuer.take(60)}\nserial ${c.serialHex.take(24)}\nvalid ${c.notBefore} to ${c.notAfter}\n${c.sigAlg} · ${c.keyInfo}",
                        "صادرکننده ${c.issuer.take(60)}\nسریال ${c.serialHex.take(24)}\nاعتبار ${c.notBefore} تا ${c.notAfter}\n${c.sigAlg} · ${c.keyInfo}",
                    ),
                )
            }

            val revocation = listOf(
                ev("Revocation list", "فهرست ابطال", crlText, crlLevel),
                evd(
                    "Revoked serials in chain", "سریال ابطال‌شده در زنجیره", if (revoked) "revoked" else if (prefs.onlineCrl) "none" else "off",
                    if (revoked) Status.DANGER else if (prefs.onlineCrl) Status.CLEAR else Status.INFO,
                    "Google publishes serials of attestation keys that were leaked or abused. A listed serial means the key box is public.",
                    "گوگل سریال کلیدهای attestation لو رفته یا سوءاستفاده‌شده را منتشر می‌کند. سریال فهرست‌شده یعنی key box عمومی است.",
                ),
            )

            val sections = listOf(
                sectionOf("trust", "Trust", "اعتماد", trust),
                sectionOf("attestation", "Attestation", "Attestation", attest),
                sectionOf("boot", "Boot state", "وضعیت بوت", boot),
                sectionOf("chain", "Certificate chain", "زنجیرهٔ گواهی", chain),
                sectionOf("revocation", "Revocation", "ابطال", revocation),
            )
            val flat = sections.flatMap { it.evidence }
            val localCount = flat.size
            val status = when {
                hard > 0 -> Status.DANGER
                review > 0 -> Status.WARNING
                else -> Status.CLEAR
            }
            val summary = when (status) {
                Status.DANGER -> "Policy-backed attestation anomalies were detected" to "ناهنجاری‌های مبتنی بر سیاست در attestation شناسایی شد"
                Status.WARNING -> "Attestation answered, but something does not line up" to "attestation جواب داد، اما چیزی نمی‌خواند"
                else -> "Hardware key, valid chain, locked and verified boot" to "کلید سخت‌افزاری، زنجیرهٔ معتبر، بوت قفل و تأییدشده"
            }
            val tier = when {
                a.strongBox || (d?.keymasterLevel ?: 0) >= 2 -> "StrongBox" to "StrongBox"
                a.hardware -> "TEE" to "TEE"
                else -> "Software" to "نرم‌افزار"
            }
            val trustLabel = if (a.googleRoot) "Google" to "گوگل" else "Unknown" to "نامشخص"
            report(
                DetectorIds.TEE, status, summary.first, summary.second, flat,
                caption = Phrase(
                    if (a.googleRoot && chainOk) "Local trust path: Google root, chain verified" else "Local trust path: ${a.rootKind}",
                    if (a.googleRoot && chainOk) "مسیر اعتماد محلی: ریشهٔ گوگل، زنجیره تأیید شد" else "مسیر اعتماد محلی: ${a.rootKind}",
                ),
                metrics = listOf(
                    metric("Verdict", "حکم", if (hard > 0) "Tampered" else if (review > 0) "Suspicious" else "Verified", if (hard > 0) "دستکاری‌شده" else if (review > 0) "مشکوک" else "تأییدشده", status),
                    metric("Score", "امتیاز", score.toString(), score.toString(), if (score >= 45) Status.DANGER else if (score > 0) Status.WARNING else Status.CLEAR),
                    metric("Tier", "سطح", tier.first, tier.second, if (a.hardware) Status.CLEAR else Status.WARNING),
                    metric("Trust", "اعتماد", trustLabel.first, trustLabel.second, if (a.googleRoot) Status.CLEAR else Status.WARNING),
                ),
                highlights = listOf(
                    metric("Local chain", "زنجیرهٔ محلی", if (chainOk) "Verified" else "Broken", if (chainOk) "تأیید شد" else "شکسته", if (chainOk) Status.CLEAR else Status.DANGER),
                    metric(
                        "Boot", "بوت",
                        if (!hashMatch || lockSpoof || greenSpoof) "Mismatch" else if (r == null) "Unknown" else "Match",
                        if (!hashMatch || lockSpoof || greenSpoof) "ناسازگار" else if (r == null) "نامشخص" else "سازگار",
                        if (!hashMatch || lockSpoof || greenSpoof) Status.DANGER else if (r == null) Status.INFO else Status.CLEAR,
                    ),
                    metric(
                        "Signals", "سیگنال‌ها",
                        "$hard policy hard • $review policy review • $localCount local",
                        "$hard سخت • $review بازبینی • $localCount محلی",
                        if (hard > 0) Status.DANGER else if (review > 0) Status.WARNING else Status.CLEAR,
                    ),
                    metric(
                        "CRL", "CRL",
                        crlText.replaceFirstChar { it.uppercase() },
                        when (crlText) { "revoked" -> "ابطال‌شده"; "clean" -> "پاک"; "offline" -> "آفلاین"; else -> "خاموش" },
                        crlLevel,
                    ),
                ),
                sections = sections,
                impact = Phrase(
                    when (status) {
                        Status.DANGER -> "The hardware-attested state contradicts what the system reports, or the key box is on the revocation list. Apps that trust boot properties can be fooled, and Play Integrity style checks are unlikely to pass."
                        Status.WARNING -> "Attestation answered but some values do not line up. Strict apps may rate this device as not fully trusted."
                        else -> "Hardware attestation agrees with the system. This is the strongest local sign that the boot chain is intact."
                    },
                    when (status) {
                        Status.DANGER -> "وضعیتِ تأییدشده توسط سخت‌افزار با گزارش سیستم تناقض دارد یا key box در فهرست ابطال است. اپ‌هایی که به پراپرتی‌های بوت اعتماد می‌کنند فریب می‌خورند و بررسی‌های شبیه Play Integrity به احتمال زیاد رد می‌شوند."
                        Status.WARNING -> "attestation جواب داد اما بعضی مقدارها نمی‌خواند. اپ‌های سخت‌گیر ممکن است دستگاه را کاملاً مطمئن ندانند."
                        else -> "attestation سخت‌افزار با سیستم هم‌خوان است. این قوی‌ترین نشانهٔ محلی برای سالم بودن زنجیرهٔ بوت است."
                    },
                ),
                score = score,
            )
        }
    },
)

internal fun integrityDeep() = Detector(
    id = DetectorIds.INTEGRITY,
    title = Phrase("Integrity test", "تست یکپارچگی"),
    about = Phrase(
        "A local integrity test modeled on the Play Integrity tiers. It combines the key attestation chain, boot and lock state, test-keys, su binaries, debug flags, fingerprint layers and security patch age into Basic, Device and Strong estimates. It does not call the Play Integrity API.",
        "یک تست یکپارچگی محلی به الگوی سطوح Play Integrity. زنجیرهٔ attestation، وضعیت بوت و قفل، test-keys، باینری su، پرچم‌های دیباگ، لایه‌های اثرانگشت و عمر وصلهٔ امنیتی را به تخمین Basic و Device و Strong تبدیل می‌کند. Play Integrity API صدا زده نمی‌شود.",
    ),
    limits = Phrase(
        "These are estimates, not Google's verdict. Play also weighs server-side signals this app cannot see, and a hidden root can still pass here.",
        "اینها تخمین است، نه حکم گوگل. Play سیگنال‌های سمت سرور را هم می‌سنجد که این اپ نمی‌بیند و روت پنهان ممکن است اینجا رد شود.",
    ),
    probe = { context, _ ->
        val a = Attestation.read(context)
        val tags = AndroidFacts.prop("ro.build.tags").ifBlank { Build.TAGS.orEmpty() }
        val secure = AndroidFacts.prop("ro.secure")
        val debuggable = AndroidFacts.prop("ro.debuggable")
        val systemFp = AndroidFacts.prop("ro.build.fingerprint").ifBlank { Build.FINGERPRINT }
        val vendorFp = AndroidFacts.prop("ro.vendor.build.fingerprint")
        val bootFp = AndroidFacts.prop("ro.bootimage.build.fingerprint")
        val mismatch = listOf(vendorFp, bootFp).any { it.isNotBlank() && it != systemFp }
        val testKeys = "test-keys" in tags
        val debug = debuggable == "1" || secure == "0"
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su",
            "/vendor/bin/su", "/su/bin/su", "/data/local/xbin/su", "/data/local/bin/su",
        )
        val suFound = suPaths.filter { AndroidFacts.exists(it) }
        val root = a.desc?.root
        val age: Long? = try {
            java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.parse(Build.VERSION.SECURITY_PATCH), java.time.LocalDate.now())
        } catch (_: Exception) {
            null
        }
        val attested = a.error == null && a.desc != null
        val tiers = Signals.integrityTiers(
            Signals.IntegrityInput(
                attestationPresent = attested,
                chainValid = a.chainSigOk && a.rootSelfSigned,
                challengeOk = a.challengeOk,
                appBound = a.appBound,
                testKeys = testKeys,
                hardware = a.hardware,
                locked = root?.deviceLocked,
                bootVerified = root?.let { it.bootState == 0 },
                rooted = suFound.isNotEmpty() || debug,
                googleRoot = a.googleRoot,
                patchAgeDays = age,
            ),
        )
        val status = when {
            a.error != null && !a.keystoreWorks -> Status.UNSUPPORTED
            a.error != null -> Status.WARNING
            tiers.strong -> Status.CLEAR
            tiers.device -> Status.INFO
            tiers.basic -> Status.WARNING
            else -> Status.DANGER
        }
        val summary = when {
            a.error != null && !a.keystoreWorks -> "The keystore could not run, so no estimate was possible" to "کی‌استور اجرا نشد، پس تخمین ممکن نبود"
            a.error != null -> "Attestation is refused, so every tier fails" to "attestation رد می‌شود، پس همهٔ سطح‌ها رد می‌شوند"
            status == Status.CLEAR -> "Passes Basic, Device and Strong estimates" to "تخمین Basic و Device و Strong را می‌گذراند"
            status == Status.INFO -> "Passes Basic and Device, not Strong" to "Basic و Device را می‌گذراند، Strong را نه"
            status == Status.WARNING -> "Passes Basic only" to "فقط Basic را می‌گذراند"
            else -> "Fails the Basic estimate" to "تخمین Basic را نمی‌گذراند"
        }
        fun pass(ok: Boolean) = if (ok) Status.CLEAR else Status.DANGER
        val chainOk = a.chainSigOk && a.rootSelfSigned
        val tierRows = listOf(
            ev("MEETS_BASIC_INTEGRITY (estimate)", "MEETS_BASIC_INTEGRITY (تخمین)", tiers.basic.toString(), pass(tiers.basic)),
            ev("MEETS_DEVICE_INTEGRITY (estimate)", "MEETS_DEVICE_INTEGRITY (تخمین)", tiers.device.toString(), pass(tiers.device)),
            ev("MEETS_STRONG_INTEGRITY (estimate)", "MEETS_STRONG_INTEGRITY (تخمین)", tiers.strong.toString(), if (tiers.strong) Status.CLEAR else Status.INFO),
            ev("Play Integrity API", "Play Integrity API", "not called · needs a Google Cloud project", Status.INFO),
        )
        val attRows = listOf(
            ev("Attestation produced", "attestation ساخته شد", attested.toString(), if (attested) Status.CLEAR else Status.WARNING),
            ev("Attestation chain valid", "زنجیرهٔ attestation معتبر", chainOk.toString(), pass(chainOk)),
            ev("Hardware-backed key", "کلید پشتوانه‌دار سخت‌افزاری", a.hardware.toString(), if (a.hardware) Status.CLEAR else Status.WARNING),
            ev("Google root", "ریشهٔ گوگل", a.googleRoot.toString(), if (a.googleRoot) Status.CLEAR else Status.INFO),
            ev("Bootloader locked", "بوت‌لودر قفل", root?.deviceLocked?.toString() ?: "unknown", if (root?.deviceLocked == true) Status.CLEAR else Status.WARNING),
            ev("Verified boot state", "وضعیت بوت تأییدشده", bootText(root?.bootState), if (root?.bootState == 0) Status.CLEAR else Status.WARNING),
        )
        val rootRows = listOf(
            ev("ro.build.tags", "ro.build.tags", tags.ifBlank { "—" }, if (testKeys) Status.WARNING else Status.CLEAR),
            ev("Debuggable or insecure", "debuggable یا ناامن", debug.toString(), if (debug) Status.WARNING else Status.CLEAR),
            ev("su binaries", "باینری su", if (suFound.isEmpty()) "none" else suFound.joinToString(), if (suFound.isEmpty()) Status.CLEAR else Status.DANGER),
        )
        val buildRows = listOf(
            ev("Security patch age", "عمر وصلهٔ امنیتی", age?.let { "$it days" } ?: "unknown", if (age != null && age <= 365) Status.CLEAR else Status.INFO),
            ev("Fingerprint mismatch", "اختلاف اثرانگشت", mismatch.toString(), if (mismatch) Status.INFO else Status.CLEAR),
            ev("System fingerprint", "اثرانگشت سیستم", systemFp),
            ev("Vendor fingerprint", "اثرانگشت وندور", vendorFp.ifBlank { "—" }),
        )
        val sections = listOf(
            sectionOf("tiers", "Tier estimates", "تخمین سطح‌ها", tierRows),
            sectionOf("attestation", "Attestation inputs", "ورودی‌های attestation", attRows),
            sectionOf("root", "Root signals", "سیگنال‌های روت", rootRows),
            sectionOf("build", "Build and patch", "بیلد و وصله", buildRows),
        )
        val level = { ok: Boolean -> if (ok) Status.CLEAR else Status.DANGER }
        report(
            DetectorIds.INTEGRITY, status, summary.first, summary.second, sections.flatMap { it.evidence },
            caption = Phrase(
                "Local estimate shaped like the Play Integrity tiers. Not a Google verdict.",
                "تخمین محلی به شکل سطوح Play Integrity. حکم گوگل نیست.",
            ),
            metrics = listOf(
                metric("Basic", "Basic", if (tiers.basic) "Pass" else "Fail", if (tiers.basic) "قبول" else "رد", level(tiers.basic)),
                metric("Device", "Device", if (tiers.device) "Pass" else "Fail", if (tiers.device) "قبول" else "رد", level(tiers.device)),
                metric("Strong", "Strong", if (tiers.strong) "Pass" else "Fail", if (tiers.strong) "قبول" else "رد", if (tiers.strong) Status.CLEAR else Status.INFO),
                metric("Patch age", "عمر وصله", age?.let { "$it d" } ?: "—", age?.let { "$it روز" } ?: "—", if (age != null && age <= 365) Status.CLEAR else Status.INFO),
            ),
            sections = sections,
            impact = Phrase(
                "Banking, wallet and some game apps ask Play Integrity for Device or Strong. If this estimate fails, the real check very likely fails too, whatever the settings say.",
                "اپ‌های بانکی، کیف پول و بعضی بازی‌ها از Play Integrity سطح Device یا Strong می‌خواهند. اگر این تخمین رد شود، بررسی واقعی هم به احتمال زیاد رد می‌شود.",
            ),
        )
    },
)
