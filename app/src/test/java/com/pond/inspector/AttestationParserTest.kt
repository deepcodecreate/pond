package com.pond.inspector

import com.pond.inspector.logic.AttestationParser
import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AttestationParserTest {
    private fun len(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
    }

    private fun tlv(tag: Int, vararg parts: ByteArray): ByteArray {
        val body = ByteArrayOutputStream().also { out -> parts.forEach { out.write(it) } }.toByteArray()
        return byteArrayOf(tag.toByte()) + len(body.size) + body
    }

    private fun int(v: Int) = tlv(0x02, byteArrayOf(v.toByte()))
    private fun enum(v: Int) = tlv(0x0A, byteArrayOf(v.toByte()))
    private fun octets(b: ByteArray) = tlv(0x04, b)
    private fun seq(vararg p: ByteArray) = tlv(0x30, *p)

    private fun explicit(n: Int, inner: ByteArray): ByteArray {
        val tagBytes = byteArrayOf(0xBF.toByte(), (0x80 or (n shr 7)).toByte(), (n and 0x7F).toByte())
        return tagBytes + len(inner.size) + inner
    }

    @Test
    fun parsesRootOfTrustAndPatchLevels() {
        val challenge = byteArrayOf(1, 2, 3, 4)
        val root = seq(octets(ByteArray(32) { 7 }), tlv(0x01, byteArrayOf(0xFF.toByte())), enum(0), octets(ByteArray(32) { 9 }))
        val tee = seq(
            explicit(704, root),
            explicit(705, int(14)),
            explicit(706, tlv(0x02, byteArrayOf(0x01, 0x34, 0x56))),
        )
        val desc = seq(int(4), enum(1), int(200), enum(1), octets(challenge), octets(ByteArray(0)), seq(), tee)
        val ext = tlv(0x04, desc)
        val parsed = AttestationParser.parse(ext)
        assertNotNull(parsed)
        parsed!!
        assertEquals(4, parsed.attestationVersion)
        assertEquals(1, parsed.attestationLevel)
        assertTrue(parsed.challenge.contentEquals(challenge))
        assertEquals(true, parsed.root?.deviceLocked)
        assertEquals(0, parsed.root?.bootState)
        assertEquals(14L, parsed.osVersion)
    }

    @Test
    fun garbageReturnsNull() {
        assertNull(AttestationParser.parse(byteArrayOf(1, 2, 3)))
        assertNull(AttestationParser.parse(ByteArray(0)))
    }
}
