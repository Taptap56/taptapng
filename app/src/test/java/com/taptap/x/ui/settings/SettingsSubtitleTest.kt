package com.taptap.x.ui.settings

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Locks the subtitle rule of v1.0.27 (mirroring v2rayNG's
 * SettingsListItem / SettingsEditItem): LIST and TEXT rows show the
 * current value as the summary under the title, SWITCH and ACTION
 * rows keep the static subtitle. Pure string logic — no Android
 * Context needed (there is no Robolectric in this module).
 */
class SettingsSubtitleTest {

    @Test
    fun `list row shows current value as subtitle`() {
        assertEquals(
            "System default",
            SettingsActivity.subtitleFor(
                showValueAsSubtitle = true,
                staticSubtitle = "App language",
                displayValue = "System default",
                notSupportedM2 = false,
                notSupportedLabel = "Not supported yet",
            ),
        )
    }

    @Test
    fun `text row shows current value as subtitle`() {
        assertEquals(
            "1.1.1.1",
            SettingsActivity.subtitleFor(
                showValueAsSubtitle = true,
                staticSubtitle = "DNS server for the VPN",
                displayValue = "1.1.1.1",
                notSupportedM2 = false,
                notSupportedLabel = "Not supported yet",
            ),
        )
    }

    @Test
    fun `switch row keeps static subtitle`() {
        assertEquals(
            "Show current speeds in the notification",
            SettingsActivity.subtitleFor(
                showValueAsSubtitle = false,
                staticSubtitle = "Show current speeds in the notification",
                displayValue = "On",
                notSupportedM2 = false,
                notSupportedLabel = "Not supported yet",
            ),
        )
    }

    @Test
    fun `blank value falls back to static subtitle`() {
        assertEquals(
            "DNS server for the VPN",
            SettingsActivity.subtitleFor(
                showValueAsSubtitle = true,
                staticSubtitle = "DNS server for the VPN",
                displayValue = "",
                notSupportedM2 = false,
                notSupportedLabel = "Not supported yet",
            ),
        )
    }

    @Test
    fun `not supported marker appended to value subtitle`() {
        assertEquals(
            "warn • Not supported yet",
            SettingsActivity.subtitleFor(
                showValueAsSubtitle = true,
                staticSubtitle = "Hev TUN log level",
                displayValue = "warn",
                notSupportedM2 = true,
                notSupportedLabel = "Not supported yet",
            ),
        )
    }

    @Test
    fun `not supported marker appended to static subtitle`() {
        assertEquals(
            "Use Hev TUN • Not supported yet",
            SettingsActivity.subtitleFor(
                showValueAsSubtitle = false,
                staticSubtitle = "Use Hev TUN",
                displayValue = "Off",
                notSupportedM2 = true,
                notSupportedLabel = "Not supported yet",
            ),
        )
    }
}
