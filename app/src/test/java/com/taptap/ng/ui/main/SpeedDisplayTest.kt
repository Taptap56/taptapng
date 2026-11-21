package com.taptap.ng.ui.main

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Speed display in the main status bar (v1.0.5, group A — v2rayNG
 * "Enable speed display"): the rate comes from the newest SPEED
 * line in DialLog, and the setting gates whether it shows at all.
 * Pure string logic — no Application needed.
 */
class SpeedDisplayTest {

    private val windowLine =
        "[11:00:00.123] SPEED example.com:443 down=0.50MB 1.23MB/s tls+net=10ms ws=0ms vmess=0ms rd=12ms build=1ms tun=0ms"
    private val totalLine =
        "[11:00:05.123] SPEED example.com:443 TUTUP down=12.50MB 5.0s 2.50MB/s tls+net=100ms ws=0ms vmess=0ms rd=110ms build=5ms tun=1ms up=1.00MB upW=20ms upVmess=2ms frames=10 chunks=8 tunW=100"

    @Test
    fun `latest window line yields its download rate`() {
        assertEquals(
            "↓ 1.23 MB/s",
            SpeedDisplay.latestSpeedSummary(listOf(windowLine)),
        )
    }

    @Test
    fun `latest total line yields its download rate`() {
        assertEquals(
            "↓ 2.50 MB/s",
            SpeedDisplay.latestSpeedSummary(listOf(totalLine)),
        )
    }

    @Test
    fun `newest SPEED line wins over older ones`() {
        val lines = listOf(
            "[11:00:00.123] Starting profile 'x'...",
            windowLine,
            "[11:00:03.000] SPEED other:443 down=0.10MB 0.42MB/s tls+net=1ms ws=0ms vmess=0ms rd=2ms build=0ms tun=0ms",
        )
        assertEquals("↓ 0.42 MB/s", SpeedDisplay.latestSpeedSummary(lines))
    }

    @Test
    fun `no SPEED line means no speed to show`() {
        assertNull(
            SpeedDisplay.latestSpeedSummary(
                listOf("[11:00:00.123] Starting profile 'x'..."),
            ),
        )
        assertNull(SpeedDisplay.latestSpeedSummary(emptyList()))
    }

    @Test
    fun `speed off hides the view even with a SPEED line`() {
        assertNull(SpeedDisplay.formatSpeedText(false, "↓ 1.23 MB/s"))
    }

    @Test
    fun `speed on shows the summary`() {
        assertEquals(
            "↓ 1.23 MB/s",
            SpeedDisplay.formatSpeedText(true, "↓ 1.23 MB/s"),
        )
    }

    @Test
    fun `speed on with no data yet stays hidden`() {
        assertNull(SpeedDisplay.formatSpeedText(true, null))
    }
}
