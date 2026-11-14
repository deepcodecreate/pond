package com.pond.inspector.logic

import com.pond.inspector.model.Status

object Signals {
    private val romTokens = listOf(
        "lineage",
        "crdroid",
        "evolution",
        "pixelexperience",
        "graphene",
        "calyx",
        "arrowos",
        "derp",
        "statix",
        "havoc",
        "xiaomi.eu",
        "proton",
    )

    private val mapTokens = listOf(
        "frida" to "frida",
        "libgadget" to "frida",
        "gum-js" to "frida-gum",
        "linjector" to "frida",
        "libzygisk" to "zygisk",
        "zygisk" to "zygisk",
        "lsposed" to "lsposed",
        "lspd" to "lsposed",
        "xposed" to "xposed",
        "libriru" to "riru",
        "substrate" to "substrate",
        "magisk" to "magisk",
        "libmagisk" to "magisk",
        "libedxp" to "xposed",
        "libxposed" to "xposed",
        "libsandhook" to "sandhook",
        "libdobby" to "dobby",
        "libwhale" to "whale",
        "shamiko" to "shamiko",
    )

    private val mountTokens = listOf(
        "magisk",
        "zygisk",
        "kernelsu",
        "apatch",
        "debug_ramdisk",
        "/sbin/.magisk",
        "/data/adb",
        "shamiko",
        "lsposed",
        "riru",
    )

    fun bootState(verified: String, locked: String, vbmeta: String, error: String): Status {
        val v = verified.trim().lowercase()
        val vb = vbmeta.trim().lowercase()
        val lock = locked.trim()
        val broken = error.isNotBlank() && error != "0"
        if (v.isBlank() && lock.isBlank() && vb.isBlank() && !broken) return Status.UNSUPPORTED
        if (v == "red" || broken) return Status.DANGER
        val unlocked = v == "orange" || v == "yellow" || lock == "0" || vb == "unlocked"
        if (unlocked) return Status.WARNING
        if (v == "green" || lock == "1" || vb == "locked") return Status.CLEAR
        return Status.INFO
    }

    fun selinuxState(raw: String?): Status {
        val value = raw?.trim()?.lowercase().orEmpty()
        if (value.isBlank()) return Status.UNSUPPORTED
        return when (value) {
            "1", "enforcing" -> Status.CLEAR
            "0", "permissive" -> Status.WARNING
            else -> Status.INFO
        }
    }

    fun romState(tags: String, type: String, fingerprint: String): Status {
        val tag = tags.lowercase()
        val kind = type.trim().lowercase()
        val print = fingerprint.lowercase()
        if (tag.isBlank() && kind.isBlank() && print.isBlank()) return Status.UNSUPPORTED
        if ("test-keys" in tag) return Status.WARNING
        if (kind.isNotBlank() && kind != "user") return Status.WARNING
        if (romTokens.any { it in print }) return Status.INFO
        return Status.CLEAR
    }

    fun mapHits(text: String): List<String> {
        val lower = text.lowercase()
        return mapTokens.mapNotNull { (token, label) ->
            if (token in lower) label else null
        }.distinct()
    }

    fun mountHits(text: String): List<String> {
        val lower = text.lowercase()
        return mountTokens.filter { it in lower }.distinct()
    }

    fun virtualHits(
        fingerprint: String,
        hardware: String,
        product: String,
        model: String,
        qemu: String,
    ): List<String> {
        val hits = mutableListOf<String>()
        val blob = "$fingerprint $hardware $product $model".lowercase()
        if (qemu == "1") hits += "ro.kernel.qemu"
        listOf("goldfish", "ranchu", "vbox", "emulator", "genymotion", "sdk_gphone", "google_sdk", "bluestacks", "nox", "memu", "ldplayer", "microvirt", "vbox86")
            .filter { it in blob }
            .forEach { hits += it }
        if ("generic" in fingerprint.lowercase() && "sdk" in product.lowercase()) hits += "generic-sdk"
        return hits.distinct()
    }

    data class IntegrityInput(
        val attestationPresent: Boolean,
        val chainValid: Boolean,
        val challengeOk: Boolean?,
        val appBound: Boolean?,
        val testKeys: Boolean,
        val hardware: Boolean,
        val locked: Boolean?,
        val bootVerified: Boolean?,
        val rooted: Boolean,
        val googleRoot: Boolean,
        val patchAgeDays: Long?,
    )

    data class IntegrityTiers(val basic: Boolean, val device: Boolean, val strong: Boolean)

    fun integrityTiers(i: IntegrityInput): IntegrityTiers {
        val basic = i.attestationPresent && i.chainValid && i.challengeOk != false &&
            i.appBound != false && !i.testKeys
        val device = basic && i.hardware && i.locked == true && i.bootVerified == true && !i.rooted
        val age = i.patchAgeDays
        val strong = device && i.googleRoot && age != null && age <= 365
        return IntegrityTiers(basic, device, strong)
    }
}
