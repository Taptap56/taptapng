package com.taptap.ng.service

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.31 (battery, H5a): StreamIdleGate menutup stream dashboard
 * yang tidak ada konten barunya selama 60 detik — frame identik
 * (traffic 0,0 / koneksi kosong yang sama) tidak dihitung sebagai
 * aktivitas, jadi ketiga thread stream berhenti bangun tiap detik
 * saat dashboard di-background. Frame baru apa pun me-reset jam.
 */
class StreamIdleGateTest {

    @Test
    fun `frame pertama selalu dikirim dan belum idle`() {
        val gate = ClashApiServer.StreamIdleGate(idleTimeoutMs = 60_000L, startMs = 1_000L)
        assertTrue(gate.shouldSend("{\"up\":0}", 1_000L))
        assertFalse(gate.isIdle(1_000L + 59_999L))
    }

    @Test
    fun `frame identik tidak dikirim dan tidak me-reset jam idle`() {
        val gate = ClashApiServer.StreamIdleGate(idleTimeoutMs = 60_000L, startMs = 1_000L)
        assertTrue(gate.shouldSend("{\"up\":0,\"down\":0}", 1_000L))
        // 30 detik frame identik: tidak dikirim, jam jalan terus.
        assertFalse(gate.shouldSend("{\"up\":0,\"down\":0}", 31_000L))
        assertFalse(gate.isIdle(31_000L))
        // 60 detik sejak frame baru terakhir: idle -> stream ditutup.
        assertFalse(gate.shouldSend("{\"up\":0,\"down\":0}", 61_000L))
        assertTrue(gate.isIdle(61_000L))
    }

    @Test
    fun `frame baru me-reset jam idle`() {
        val gate = ClashApiServer.StreamIdleGate(idleTimeoutMs = 60_000L, startMs = 1_000L)
        assertTrue(gate.shouldSend("{\"up\":0}", 1_000L))
        assertFalse(gate.shouldSend("{\"up\":0}", 50_000L))
        // Konten berubah di detik ke-50: jam mulai lagi dari sini.
        assertTrue(gate.shouldSend("{\"up\":100}", 50_000L))
        assertFalse(gate.isIdle(50_000L + 59_999L))
        assertTrue(gate.isIdle(50_000L + 60_000L))
    }

    @Test
    fun `tidak ada frame sama sekali tetap idle sesudah timeout`() {
        val gate = ClashApiServer.StreamIdleGate(idleTimeoutMs = 60_000L, startMs = 1_000L)
        assertFalse(gate.isIdle(1_000L + 59_999L))
        assertTrue(gate.isIdle(1_000L + 60_000L))
    }

    @Test
    fun `traffic yang terus berubah tidak pernah idle`() {
        val gate = ClashApiServer.StreamIdleGate(idleTimeoutMs = 60_000L, startMs = 0L)
        var t = 0L
        repeat(120) {
            t += 1_000L
            assertTrue(gate.shouldSend("{\"up\":$t}", t))
            assertFalse(gate.isIdle(t))
        }
    }
}
