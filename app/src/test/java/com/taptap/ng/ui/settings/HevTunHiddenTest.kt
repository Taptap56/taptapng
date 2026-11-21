package com.taptap.ng.ui.settings

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Hev TUN rows are hidden from Settings (v1.0.5, group A): Hev
 * TUN cannot run in TaptapNG — it needs the native
 * hev-socks5-tunnel library, and this app ships no .so on
 * purpose — so the three rows must not appear in the Settings
 * list at all (hiding, not labelling). The values stay stored;
 * only the UI rows go away.
 */
class HevTunHiddenTest {

    @Test
    fun `hidden keys are exactly the three hev tun settings`() {
        assertEquals(
            setOf("use_hev_tun", "hev_tun_log_level", "hev_tun_rw_timeout"),
            SettingsActivity.HIDDEN_SETTING_KEYS,
        )
    }

    @Test
    fun `visible keys drop the hev rows and keep the rest`() {
        val all = listOf(
            "ipv6_enabled", "prefer_ipv6", "local_dns_enabled",
            "fake_dns_enabled", "vpn_dns", "append_http_proxy",
            "vpn_bypass_lan", "vpn_interface_address", "vpn_mtu",
            "use_hev_tun", "hev_tun_log_level", "hev_tun_rw_timeout",
        )
        assertEquals(
            listOf(
                "ipv6_enabled", "prefer_ipv6", "local_dns_enabled",
                "fake_dns_enabled", "vpn_dns", "append_http_proxy",
                "vpn_bypass_lan", "vpn_interface_address", "vpn_mtu",
            ),
            SettingsActivity.visibleSettingKeys(all),
        )
    }

    @Test
    fun `no other vpn row is hidden`() {
        for (key in listOf("vpn_bypass_lan", "vpn_mtu", "vpn_dns", "ipv6_enabled")) {
            assertTrue(
                SettingsActivity.visibleSettingKeys(listOf(key)) == listOf(key),
                "$key must stay visible",
            )
        }
    }
}
