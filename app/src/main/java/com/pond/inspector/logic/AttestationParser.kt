package com.pond.inspector.logic

import androidx.compose.runtime.Immutable

@Immutable
data class RootOfTrust(
    val verifiedBootKey: String,
    val deviceLocked: Boolean?,
    val bootState: Int?,
    val bootHash: String?,
)

@Immutable
data class KeyDescription(
    val attestationVersion: Int,
    val attestationLevel: Int,
    val keymasterVersion: Int,
    val keymasterLevel: Int,
    val challenge: ByteArray,
    val uniqueIdLength: Int,
    val root: RootOfTrust?,
    val osVersion: Long?,
    val osPatchLevel: Long?,
    val vendorPatchLevel: Long?,
    val bootPatchLevel: Long?,
    val origin: Long?,
    val packages: List<String>,
    val signatureDigests: List<String>,
    val idTags: List<Int>,
)

object AttestationParser {
    const val OID = "1.3.6.1.4.1.11129.2.1.17"

    private class Tlv(val cls: Int, val constructed: Boolean, val tag: Int, val start: Int, val end: Int)

    private fun read(b: ByteArray, pos: Int, limit: Int): Tlv? {
        var p = pos
        if (p >= limit) return null
        val first = b[p++].toInt() and 0xFF
        val cls = first and 0xC0
        val constructed = (first and 0x20) != 0
        var tag = first and 0x1F
        if (tag == 0x1F) {
            tag = 0
            while (true) {
                if (p >= limit) return null
                val x = b[p++].toInt() and 0xFF
                tag = (tag shl 7) or (x and 0x7F)
                if ((x and 0x80) == 0) break
            }
        }
        if (p >= limit) return null
        var len = b[p++].toInt() and 0xFF
        if ((len and 0x80) != 0) {
            val n = len and 0x7F
            if (n == 0 || n > 4 || p + n > limit) return null
            len = 0
            repeat(n) { len = (len shl 8) or (b[p++].toInt() and 0xFF) }
        }
        if (len < 0 || p + len > limit) return null
        return Tlv(cls, constructed, tag, p, p + len)
    }

    private fun kids(b: ByteArray, t: Tlv): List<Tlv> {
        val out = ArrayList<Tlv>()
        var p = t.start
        while (p < t.end) {
            val c = read(b, p, t.end) ?: break
            out += c
            p = c.end
        }
        return out
    }

    private fun long(b: ByteArray, t: Tlv): Long {
        var v = 0L
        for (i in t.start until minOf(t.end, t.start + 8)) v = (v shl 8) or (b[i].toLong() and 0xFF)
        return v
    }

    private fun bytes(b: ByteArray, t: Tlv): ByteArray = b.copyOfRange(t.start, t.end)

    fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (x in bytes) {
            val v = x.toInt() and 0xFF
            sb.append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 0x0F])
        }
        return sb.toString()
    }

    private fun authList(b: ByteArray, seq: Tlv?): Map<Int, Tlv> {
        if (seq == null) return emptyMap()
        val out = HashMap<Int, Tlv>()
        for (entry in kids(b, seq)) {
            if (entry.cls != 0x80) continue
            val inner = read(b, entry.start, entry.end) ?: continue
            out[entry.tag] = inner
        }
        return out
    }

    fun parse(extensionValue: ByteArray): KeyDescription? {
        return try {
        val outer = read(extensionValue, 0, extensionValue.size) ?: return null
        val seq: Tlv = if (outer.tag == 0x04 && outer.cls == 0) {
            read(extensionValue, outer.start, outer.end) ?: return null
        } else {
            outer
        }
        val b = extensionValue
        val top = kids(b, seq)
        if (top.size < 8) return null
        val software = authList(b, top[6])
        val tee = authList(b, top[7])
        val merged = software + tee

        val rootSeq = merged[704]
        var root: RootOfTrust? = null
        if (rootSeq != null) {
            val r = kids(b, rootSeq)
            if (r.size >= 3) {
                root = RootOfTrust(
                    verifiedBootKey = hex(bytes(b, r[0])),
                    deviceLocked = b[r[1].start].toInt() != 0,
                    bootState = long(b, r[2]).toInt(),
                    bootHash = if (r.size > 3) hex(bytes(b, r[3])) else null,
                )
            }
        }

        val packages = ArrayList<String>()
        val digests = ArrayList<String>()
        val appId = merged[709]
        if (appId != null) {
            val appSeq = read(b, appId.start, appId.end)
            if (appSeq != null) {
                val parts = kids(b, appSeq)
                if (parts.isNotEmpty()) {
                    for (info in kids(b, parts[0])) {
                        val name = kids(b, info).firstOrNull() ?: continue
                        packages += String(b, name.start, name.end - name.start, Charsets.UTF_8)
                    }
                }
                if (parts.size > 1) {
                    for (d in kids(b, parts[1])) digests += hex(bytes(b, d))
                }
            }
        }

        KeyDescription(
            attestationVersion = long(b, top[0]).toInt(),
            attestationLevel = long(b, top[1]).toInt(),
            keymasterVersion = long(b, top[2]).toInt(),
            keymasterLevel = long(b, top[3]).toInt(),
            challenge = bytes(b, top[4]),
            uniqueIdLength = top[5].end - top[5].start,
            root = root,
            osVersion = merged[705]?.let { long(b, it) },
            osPatchLevel = merged[706]?.let { long(b, it) },
            vendorPatchLevel = merged[718]?.let { long(b, it) },
            bootPatchLevel = merged[719]?.let { long(b, it) },
            origin = merged[702]?.let { long(b, it) },
            packages = packages,
            signatureDigests = digests,
            idTags = merged.keys.filter { it in 710..717 }.sorted(),
        )
    } catch (_: Exception) {
        null
    }
    }
}
