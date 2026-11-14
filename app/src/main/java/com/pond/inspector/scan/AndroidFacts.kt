package com.pond.inspector.scan

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

object AndroidFacts {
    fun prop(name: String): String {
        if (!name.matches(Regex("[A-Za-z0-9._-]+"))) return ""
        return runCommand("getprop", name)
    }

    fun props(names: List<String>): Map<String, String> =
        names.associateWith { prop(it) }

    fun runCommand(vararg args: String): String = try {
        val process = ProcessBuilder(*args)
            .redirectErrorStream(true)
            .start()
        val text = process.inputStream.bufferedReader().use { it.readText() }.trim()
        process.waitFor(1500, TimeUnit.MILLISECONDS)
        text
    } catch (_: Exception) {
        ""
    }

    fun readText(path: String, maxChars: Int = 180_000): String? = try {
        val file = File(path)
        if (!file.exists() || !file.canRead()) null
        else file.bufferedReader().use { reader ->
            val buf = CharArray(maxChars)
            val n = reader.read(buf)
            if (n <= 0) "" else String(buf, 0, n)
        }
    } catch (_: Exception) {
        null
    }

    fun exists(path: String): Boolean = try {
        File(path).exists()
    } catch (_: Exception) {
        false
    }

    fun installedPackages(context: Context): List<PackageInfo> = try {
        val pm = context.packageManager
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }
    } catch (_: Exception) {
        emptyList()
    }

    data class CrlFetch(val ok: Boolean, val detail: String, val revoked: List<String> = emptyList())

    fun fetchAttestationStatus(serials: List<String> = emptyList()): CrlFetch = try {
        val connection = (URL("https://android.googleapis.com/attestation/status").openConnection() as HttpURLConnection).apply {
            connectTimeout = 5000
            readTimeout = 5000
            requestMethod = "GET"
            instanceFollowRedirects = true
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "Pond/1.0")
        }
        try {
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            val entries = body.contains("\"entries\"")
            val revoked = if (entries && serials.isNotEmpty()) {
                try {
                    val keys = kotlinx.serialization.json.Json.parseToJsonElement(body)
                        .let { it as? kotlinx.serialization.json.JsonObject }
                        ?.get("entries")
                        ?.let { it as? kotlinx.serialization.json.JsonObject }
                        ?.keys.orEmpty()
                    serials.filter { it.lowercase() in keys }
                } catch (_: Exception) {
                    emptyList()
                }
            } else {
                emptyList()
            }
            CrlFetch(code in 200..299 && entries, "HTTP $code · ${body.length} bytes · entries=$entries", revoked)
        } finally {
            connection.disconnect()
        }
    } catch (error: Exception) {
        CrlFetch(false, error.javaClass.simpleName + (error.message?.let { ": $it" } ?: ""))
    }
}
