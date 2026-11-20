package com.taptap.ng.ui.main

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Row delay label (v1.0.13, fix B): a real ping shows "48ms", a
 * TCP fallback shows "48ms (TCP)" — so a TCP number is never
 * mistaken for a real ping.
 */
class DelayLabelTest {

    @Test
    fun `real ping shows bare ms`() {
        assertEquals("48ms", formatDelayLabel(48, DELAY_KIND_REAL))
        assertEquals("101ms", formatDelayLabel(101, DELAY_KIND_REAL))
        // No kind yet (old data): bare ms, like a real ping.
        assertEquals("48ms", formatDelayLabel(48, null))
    }

    @Test
    fun `tcp fallback shows TCP suffix`() {
        assertEquals("48ms (TCP)", formatDelayLabel(48, DELAY_KIND_TCP))
        assertEquals("101ms (TCP)", formatDelayLabel(101, "tcp"))
    }

    @Test
    fun `failed delay label keeps only the short stage`() {
        assertEquals("Timeout", formatDelayFailure(null))
        assertEquals("Timeout", formatDelayFailure("   "))
        assertEquals("TCP gagal", formatDelayFailure("TCP gagal: connect timed out after 10000 ms"))
        assertEquals("DNS gagal", formatDelayFailure("DNS gagal"))
        val long = formatDelayFailure("A".repeat(40))
        assertEquals(22, long.length)
        assertEquals("…", long.takeLast(1))
    }
}
