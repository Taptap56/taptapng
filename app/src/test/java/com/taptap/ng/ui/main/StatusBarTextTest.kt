package com.taptap.ng.ui.main

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.7: while a delay test (ping) runs, the bottom status bar
 * shows "ping..." instead of the connection status, then the
 * connection status is restored. The 2 s service poll must not
 * overwrite "ping..." mid-test (the v1.0.9 flicker).
 */
class StatusBarTextTest {

    @Test
    fun `ping shows ping text and restores the connection status`() {
        val bar = StatusBarText()
        bar.syncServiceStatus("Connected: iflix cloudfront")
        assertEquals("Connected: iflix cloudfront", bar.text)

        bar.beginPing()
        assertTrue(bar.isTesting)
        assertEquals("ping...", bar.text)

        // The 2 s poll fires mid-test: it must not fight "ping...".
        bar.syncServiceStatus("Connected: iflix cloudfront")
        assertEquals("ping...", bar.text)

        bar.endPing("Connected: iflix cloudfront")
        assertFalse(bar.isTesting)
        assertEquals("Connected: iflix cloudfront", bar.text)
    }

    @Test
    fun `service sync works when idle`() {
        val bar = StatusBarText()
        bar.syncServiceStatus("Stopped")
        assertEquals("Stopped", bar.text)
        bar.syncServiceStatus("Connected: 81")
        assertEquals("Connected: 81", bar.text)
    }

    @Test
    fun `overlapping tests restore only when the last one ends`() {
        val bar = StatusBarText()
        bar.syncServiceStatus("Connected: iflix cloudfront")
        bar.beginPing()
        bar.beginPing()
        bar.endPing("Connected: iflix cloudfront")
        assertTrue(bar.isTesting)
        assertEquals("ping...", bar.text)
        bar.endPing("Connected: iflix cloudfront")
        assertFalse(bar.isTesting)
        assertEquals("Connected: iflix cloudfront", bar.text)
    }

    @Test
    fun `end ping without a test restores the status`() {
        val bar = StatusBarText()
        bar.endPing("Stopped")
        assertFalse(bar.isTesting)
        assertEquals("Stopped", bar.text)
    }
}
