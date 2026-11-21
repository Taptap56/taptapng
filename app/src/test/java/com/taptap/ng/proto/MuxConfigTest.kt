package com.taptap.ng.proto

import com.taptap.ng.core.proto.*
import com.taptap.ng.data.SettingsStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * MuxConfig dari Settings (v1.0.5, kelompok D). Murni — tanpa
 * Context (SettingsStore butuh Context, jadi yang diuji adalah
 * [MuxConfig.fromSettingsValues] dengan nilai mentah yang sama
 * persis dengan yang dibaca [MuxConfig.fromSettings]).
 */
class MuxConfigTest {

    @Test
    fun `default mati dan sama dengan settings default`() {
        assertFalse(MuxConfig.DISABLED.enabled)
        assertEquals(SettingsStore.DEFAULT_MUX_CONCURRENCY.toInt(), MuxConfig.DEFAULT_CONCURRENCY)
        assertEquals(8, MuxConfig.DEFAULT_CONCURRENCY)
        assertEquals(8, MuxConfig.DEFAULT_XUDP_CONCURRENCY)
        assertEquals("reject", MuxConfig.DEFAULT_XUDP_QUIC)
        assertEquals(false, SettingsStore.DEFAULT_MUX_ENABLED)
        assertEquals("8", SettingsStore.DEFAULT_MUX_XUDP_CONCURRENCY)
        assertEquals("reject", SettingsStore.DEFAULT_MUX_XUDP_QUIC)
    }

    @Test
    fun `nilai settings valid dipakai apa adanya`() {
        val c = MuxConfig.fromSettingsValues(true, "8", "8", "reject")
        assertTrue(c.enabled)
        assertEquals(8, c.concurrency)
        assertEquals(8, c.xudpConcurrency)
        assertEquals("reject", c.xudpQuic)
    }

    @Test
    fun `concurrency dijepit 1 sampai 64`() {
        assertEquals(1, MuxConfig.fromSettingsValues(true, "0", "8", "reject").concurrency)
        assertEquals(1, MuxConfig.fromSettingsValues(true, "-1", "8", "reject").concurrency)
        assertEquals(64, MuxConfig.fromSettingsValues(true, "100", "8", "reject").concurrency)
        assertEquals(64, MuxConfig.fromSettingsValues(true, "8", "999", "reject").xudpConcurrency)
    }

    @Test
    fun `string bukan angka atau kosong memakai default`() {
        assertEquals(8, MuxConfig.fromSettingsValues(true, "abc", "8", "reject").concurrency)
        assertEquals(8, MuxConfig.fromSettingsValues(true, "", "", "").concurrency)
        assertEquals(8, MuxConfig.fromSettingsValues(true, "8", "xx", "").xudpConcurrency)
        assertEquals("reject", MuxConfig.fromSettingsValues(true, "8", "8", "").xudpQuic)
        assertEquals("reject", MuxConfig.fromSettingsValues(true, "8", "8", "   ").xudpQuic)
    }

    @Test
    fun `xudp tidak didukung di M2`() {
        // M2 tidak punya jalur UDP (TunForwarder TCP saja) — nilai
        // XUDP tersimpan tapi tidak pernah dipakai. Tes ini mengunci
        // status itu supaya tidak ada yang mengklaim XUDP jalan.
        val c = MuxConfig.fromSettingsValues(true, "8", "8", "reject")
        assertFalse(c.xudpSupported)
        assertFalse(MuxConfig.DISABLED.xudpSupported)
    }
}
