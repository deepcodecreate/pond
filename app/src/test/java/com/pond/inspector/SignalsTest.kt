package com.pond.inspector

import com.pond.inspector.logic.Signals
import com.pond.inspector.model.Status
import com.pond.inspector.model.worst
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SignalsTest {
    @Test
    fun greenLockedBootloaderIsClear() {
        assertEquals(Status.CLEAR, Signals.bootState("green", "1", "locked", ""))
    }

    @Test
    fun orangeBootloaderIsWarning() {
        assertEquals(Status.WARNING, Signals.bootState("orange", "0", "unlocked", ""))
    }

    @Test
    fun redBootloaderIsDanger() {
        assertEquals(Status.DANGER, Signals.bootState("red", "1", "locked", ""))
    }

    @Test
    fun emptyBootloaderIsUnsupported() {
        assertEquals(Status.UNSUPPORTED, Signals.bootState("", "", "", ""))
    }

    @Test
    fun selinuxEnforcingIsClear() {
        assertEquals(Status.CLEAR, Signals.selinuxState("1"))
        assertEquals(Status.WARNING, Signals.selinuxState("Permissive"))
        assertEquals(Status.UNSUPPORTED, Signals.selinuxState(null))
    }

    @Test
    fun testKeysAreWarning() {
        assertEquals(Status.WARNING, Signals.romState("test-keys", "user", "google/husky/husky:15/AP3A"))
        assertEquals(Status.INFO, Signals.romState("release-keys", "user", "lineage_husky-userdebug"))
        assertEquals(Status.CLEAR, Signals.romState("release-keys", "user", "google/husky/husky:15"))
    }

    @Test
    fun mapAndMountTokens() {
        val hits = Signals.mapHits("7f00 r-xp /memfd:frida-agent\n/libzygisk.so")
        assertTrue(hits.contains("frida"))
        assertTrue(hits.contains("zygisk"))
        val mounts = Signals.mountHits("tmpfs /debug_ramdisk magisk rw")
        assertTrue(mounts.contains("magisk"))
        assertTrue(mounts.contains("debug_ramdisk"))
    }

    @Test
    fun emulatorHits() {
        val hits = Signals.virtualHits(
            fingerprint = "generic/sdk_gphone64_arm64/emu64a:14",
            hardware = "ranchu",
            product = "sdk_gphone64_arm64",
            model = "sdk_gphone64_arm64",
            qemu = "1",
        )
        assertTrue(hits.contains("ro.kernel.qemu"))
        assertTrue(hits.contains("ranchu"))
    }

    @Test
    fun worstStatusPrefersDangerOverClear() {
        assertEquals(Status.DANGER, worst(listOf(Status.CLEAR, Status.INFO, Status.DANGER)))
        assertEquals(Status.WARNING, worst(listOf(Status.CLEAR, Status.WARNING, Status.UNSUPPORTED)))
    }

    private fun input(
        present: Boolean = true,
        chain: Boolean = true,
        hardware: Boolean = true,
        locked: Boolean? = true,
        verified: Boolean? = true,
        rooted: Boolean = false,
        testKeys: Boolean = false,
        google: Boolean = true,
        age: Long? = 30,
    ) = Signals.IntegrityInput(present, chain, true, true, testKeys, hardware, locked, verified, rooted, google, age)

    @Test
    fun cleanDeviceMeetsAllTiers() {
        val t = Signals.integrityTiers(input())
        assertTrue(t.basic && t.device && t.strong)
    }

    @Test
    fun unlockedBootloaderLosesDeviceTier() {
        val t = Signals.integrityTiers(input(locked = false))
        assertTrue(t.basic)
        assertTrue(!t.device && !t.strong)
    }

    @Test
    fun oldPatchLosesStrongTierOnly() {
        val t = Signals.integrityTiers(input(age = 500))
        assertTrue(t.device && !t.strong)
    }

    @Test
    fun brokenChainFailsEverything() {
        val t = Signals.integrityTiers(input(chain = false))
        assertTrue(!t.basic && !t.device && !t.strong)
    }
}
