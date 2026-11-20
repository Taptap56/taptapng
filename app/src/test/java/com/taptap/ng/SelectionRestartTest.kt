package com.taptap.ng

import com.taptap.ng.ui.main.shouldRestartOnSelect
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.10: v2rayNG restarts the running service when the user taps
 * a DIFFERENT server; TaptapNG only moved the accent bar and kept
 * the old entry running until a manual stop/start — the "cara
 * pilih akun kerasa beda" the user reported (2026-11-20 04:48).
 */
class SelectionRestartTest {

    @Test
    fun `restart when running and a different server is tapped`() {
        assertTrue(shouldRestartOnSelect(true, "guid-a", "guid-b"))
    }

    @Test
    fun `no restart when the same server is tapped`() {
        assertFalse(shouldRestartOnSelect(true, "guid-a", "guid-a"))
    }

    @Test
    fun `no restart when stopped`() {
        assertFalse(shouldRestartOnSelect(false, "guid-a", "guid-b"))
        assertFalse(shouldRestartOnSelect(false, null, "guid-b"))
    }

    @Test
    fun `restart when running and nothing was selected`() {
        assertTrue(shouldRestartOnSelect(true, null, "guid-b"))
    }
}
