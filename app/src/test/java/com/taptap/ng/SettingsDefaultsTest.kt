package com.taptap.ng

import com.taptap.ng.data.SettingsStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Locks the v2rayNG settings defaults (v1.0.5) and the enablement
 * rules. Defaults live as SettingsStore.DEFAULT_* constants and the
 * property getters read them, so these assertions lock runtime
 * behaviour, not just a copy of the list. Pure functions only — no
 * Android Context needed (there is no Robolectric in this module).
 */
class SettingsDefaultsTest {

    @Test
    fun `ui defaults match v2rayNG`() {
        assertFalse(SettingsStore.DEFAULT_SPEED_ENABLED)
        // v1.0.28: default ON (v2rayNG default is OFF) — tanpa ini
        // tombol hapus menghapus langsung tanpa konfirmasi.
        assertTrue(SettingsStore.DEFAULT_CONFIRM_REMOVE)
        assertFalse(SettingsStore.DEFAULT_DOUBLE_COLUMN)
        assertFalse(SettingsStore.DEFAULT_GROUP_ALL_DISPLAY)
        assertTrue(SettingsStore.DEFAULT_DYNAMIC_COLOR)
        assertEquals("auto", SettingsStore.DEFAULT_LANGUAGE)
        assertEquals("0", SettingsStore.DEFAULT_UI_MODE_NIGHT)
    }

    @Test
    fun `vpn defaults match v2rayNG`() {
        assertFalse(SettingsStore.DEFAULT_IPV6_ENABLED)
        assertFalse(SettingsStore.DEFAULT_PREFER_IPV6)
        assertFalse(SettingsStore.DEFAULT_LOCAL_DNS)
        assertFalse(SettingsStore.DEFAULT_FAKE_DNS)
        assertEquals("", SettingsStore.DEFAULT_VPN_DNS)
        assertFalse(SettingsStore.DEFAULT_APPEND_HTTP_PROXY)
        // v1.0.4 stored "0" here; v2rayNG default is "1" (Bypass LAN).
        assertEquals("1", SettingsStore.DEFAULT_VPN_BYPASS_LAN)
        assertEquals("0", SettingsStore.DEFAULT_VPN_INTERFACE_ADDRESS)
        assertEquals("", SettingsStore.DEFAULT_VPN_MTU)
        assertTrue(SettingsStore.DEFAULT_USE_HEV_TUN)
        assertEquals("warn", SettingsStore.DEFAULT_HEV_TUN_LOG_LEVEL)
        assertEquals("", SettingsStore.DEFAULT_HEV_TUN_RW_TIMEOUT)
    }

    @Test
    fun `core defaults match v2rayNG`() {
        assertTrue(SettingsStore.DEFAULT_SNIFFING_ENABLED)
        assertFalse(SettingsStore.DEFAULT_ROUTE_ONLY_ENABLED)
        assertTrue(SettingsStore.DEFAULT_LOCAL_PROXY)
        assertFalse(SettingsStore.DEFAULT_PROXY_SHARING)
        assertFalse(SettingsStore.DEFAULT_DYNAMIC_SOCKS_PORT)
        assertEquals("", SettingsStore.DEFAULT_SOCKS_PORT)
        assertEquals("", SettingsStore.DEFAULT_SOCKS_USERNAME)
        assertEquals("", SettingsStore.DEFAULT_SOCKS_PASSWORD)
        assertTrue(SettingsStore.DEFAULT_SOCKS_UDP)
        assertEquals("", SettingsStore.DEFAULT_REMOTE_DNS)
        assertEquals("", SettingsStore.DEFAULT_DOMESTIC_DNS)
        assertEquals("", SettingsStore.DEFAULT_DNS_HOSTS)
        assertEquals("info", SettingsStore.DEFAULT_LOG_LEVEL)
        assertEquals("1", SettingsStore.DEFAULT_OUTBOUND_RESOLVE_METHOD)
    }

    @Test
    fun `mux defaults match v2rayNG`() {
        assertFalse(SettingsStore.DEFAULT_MUX_ENABLED)
        assertEquals("8", SettingsStore.DEFAULT_MUX_CONCURRENCY)
        assertEquals("8", SettingsStore.DEFAULT_MUX_XUDP_CONCURRENCY)
        assertEquals("reject", SettingsStore.DEFAULT_MUX_XUDP_QUIC)
    }

    @Test
    fun `fragment defaults match v2rayNG`() {
        assertFalse(SettingsStore.DEFAULT_FRAGMENT_ENABLED)
        assertEquals("tlshello", SettingsStore.DEFAULT_FRAGMENT_PACKETS)
        assertEquals("50-100", SettingsStore.DEFAULT_FRAGMENT_LENGTH)
        assertEquals("10-20", SettingsStore.DEFAULT_FRAGMENT_INTERVAL)
        assertEquals("10", SettingsStore.DEFAULT_FRAGMENT_MAX_SPLIT)
    }

    @Test
    fun `observatory defaults match v2rayNG`() {
        assertEquals("15m", SettingsStore.DEFAULT_OBSERVATORY_LEAST_PING)
        assertEquals("30m", SettingsStore.DEFAULT_OBSERVATORY_LEAST_LOAD)
        assertEquals("HEAD", SettingsStore.DEFAULT_OBSERVATORY_LEAST_LOAD_METHOD)
        assertEquals("1", SettingsStore.DEFAULT_OBSERVATORY_LEAST_LOAD_SAMPLING)
        assertEquals("30s", SettingsStore.DEFAULT_OBSERVATORY_LEAST_LOAD_TIMEOUT)
    }

    @Test
    fun `advanced and mode defaults match v2rayNG`() {
        assertFalse(SettingsStore.DEFAULT_IS_BOOTED)
        assertEquals("", SettingsStore.DEFAULT_DELAY_TEST_URL)
        assertEquals("16", SettingsStore.DEFAULT_REAL_PING_CONCURRENCY)
        assertEquals("", SettingsStore.DEFAULT_IP_API_URL)
        assertEquals("VPN", SettingsStore.DEFAULT_MODE)
        assertEquals("VPN", SettingsStore.MODE_VPN)
        assertFalse(SettingsStore.DEFAULT_ENABLE_ROOT_MODE)
        assertFalse(SettingsStore.DEFAULT_LAN_SHARING)
    }

    @Test
    fun `display defaults match v2rayNG AppConfig`() {
        assertEquals("1.1.1.1", SettingsStore.DISPLAY_VPN_DNS)
        // v1.0.21: MTU display default is 9000, not v2rayNG's 1500 —
        // the effective MTU default changed with it (the forwarder
        // builds 8960-byte segments on a 9000 MTU).
        assertEquals("9000", SettingsStore.DISPLAY_VPN_MTU)
        assertEquals("10.10.14.x", SettingsStore.DISPLAY_VPN_INTERFACE_ADDRESS)
        assertEquals("300,60", SettingsStore.DISPLAY_HEV_TUN_RW_TIMEOUT)
        assertEquals("10808", SettingsStore.DISPLAY_SOCKS_PORT)
        assertEquals("https://cloudflare-dns.com/dns-query", SettingsStore.DISPLAY_REMOTE_DNS)
        assertEquals("223.5.5.5", SettingsStore.DISPLAY_DOMESTIC_DNS)
        assertEquals("https://www.gstatic.com/generate_204", SettingsStore.DISPLAY_DELAY_TEST_URL)
        assertEquals("https://api.ip.sb/geoip", SettingsStore.DISPLAY_IP_API_URL)
    }

    @Test
    fun `blank stored value shows the display default`() {
        assertEquals("1.1.1.1", SettingsStore.displayOrDefault("", SettingsStore.DISPLAY_VPN_DNS))
        assertEquals("8.8.8.8", SettingsStore.displayOrDefault("8.8.8.8", SettingsStore.DISPLAY_VPN_DNS))
        assertEquals("10808", SettingsStore.displayOrDefault("  ", SettingsStore.DISPLAY_SOCKS_PORT))
    }

    @Test
    fun `fake dns only when local dns is on`() {
        assertTrue(SettingsStore.isFakeDnsAvailable(true))
        assertFalse(SettingsStore.isFakeDnsAvailable(false))
    }

    @Test
    fun `vpn dns only when mode is vpn and local dns is off`() {
        assertTrue(SettingsStore.isVpnDnsAvailable("VPN", false))
        assertFalse(SettingsStore.isVpnDnsAvailable("VPN", true))
        assertFalse(SettingsStore.isVpnDnsAvailable("OTHER", false))
    }

    @Test
    fun `vpn-only items only in vpn mode`() {
        assertTrue(SettingsStore.isVpnOnlyAvailable("VPN"))
        assertFalse(SettingsStore.isVpnOnlyAvailable("OTHER"))
        assertTrue(SettingsStore.isHevTunChildAvailable("VPN", true))
        assertFalse(SettingsStore.isHevTunChildAvailable("VPN", false))
        assertFalse(SettingsStore.isHevTunChildAvailable("OTHER", true))
    }

    @Test
    fun `local proxy is forced on while hev tun is on`() {
        assertTrue(SettingsStore.isLocalProxyEffective(false, true))
        assertTrue(SettingsStore.isLocalProxyEffective(true, false))
        assertFalse(SettingsStore.isLocalProxyEffective(false, false))
    }

    @Test
    fun `socks items need effective local proxy, port also needs fixed port`() {
        assertTrue(SettingsStore.isSocksItemAvailable(true, false))
        assertTrue(SettingsStore.isSocksItemAvailable(false, true))
        assertFalse(SettingsStore.isSocksItemAvailable(false, false))

        assertTrue(SettingsStore.isSocksPortAvailable(true, false, false))
        assertFalse(SettingsStore.isSocksPortAvailable(true, false, true))
        assertFalse(SettingsStore.isSocksPortAvailable(false, false, false))
    }
}
