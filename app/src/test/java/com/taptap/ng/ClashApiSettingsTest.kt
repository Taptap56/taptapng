package com.taptap.ng

import com.taptap.ng.data.SettingsStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Locks the M7 Clash API settings defaults (keys + values) and the
 * pure port parser. The accessors themselves need an Android
 * Context (no Robolectric in this module); the defaults live as
 * SettingsStore.DEFAULT_* constants and the getters read them, so
 * these assertions lock runtime behaviour, not just a copy.
 */
class ClashApiSettingsTest {

    @Test
    fun `clash api keys are stable`() {
        assertEquals("clash_api_enabled", SettingsStore.KEY_CLASH_API_ENABLED)
        assertEquals("clash_api_port", SettingsStore.KEY_CLASH_API_PORT)
        assertEquals("clash_api_secret", SettingsStore.KEY_CLASH_API_SECRET)
        assertEquals("clash_api_allow_lan", SettingsStore.KEY_CLASH_API_ALLOW_LAN)
    }

    @Test
    fun `clash api defaults are enabled on port 9091 with no secret and lan off`() {
        assertTrue(SettingsStore.DEFAULT_CLASH_API_ENABLED)
        assertEquals("9091", SettingsStore.DEFAULT_CLASH_API_PORT)
        assertEquals("", SettingsStore.DEFAULT_CLASH_API_SECRET)
        assertFalse(SettingsStore.DEFAULT_CLASH_API_ALLOW_LAN)
    }

    @Test
    fun `port parser accepts a valid port and falls back to 9091 otherwise`() {
        assertEquals(9091, SettingsStore.clashApiPortInt("9091"))
        assertEquals(8080, SettingsStore.clashApiPortInt("8080"))
        assertEquals(9091, SettingsStore.clashApiPortInt(""))
        assertEquals(9091, SettingsStore.clashApiPortInt("abc"))
        assertEquals(9091, SettingsStore.clashApiPortInt("0"))
        assertEquals(9091, SettingsStore.clashApiPortInt("70000"))
        assertEquals(9091, SettingsStore.clashApiPortInt("-1"))
    }
}
