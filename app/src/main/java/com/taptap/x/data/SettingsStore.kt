package com.taptap.x.data

import android.content.Context
import android.content.SharedPreferences
import androidx.appcompat.app.AppCompatDelegate

/**
 * Settings storage (SharedPreferences "taptapx_settings"), mirroring
 * v2rayNG's SettingsActivity groups + defaults (v1.0.5): UI, VPN,
 * Core (local proxy + DNS), Mux, Fragment, Observatory, Advanced,
 * Mode — in v2rayNG's order.
 *
 * Defaults live as DEFAULT_* constants in the companion object so a
 * JVM test can lock them without an Android Context; every property
 * getter reads its default from the matching constant.
 *
 * Stored values that are blank fall back to a *display* default
 * (DEFAULT_DISPLAY_*): v2rayNG stores "" and shows e.g. 1.1.1.1 /
 * 10808. The engine reads the raw stored value, not the display
 * default (see [TaptapVpnService]-side behaviour: remote DNS falls
 * back to 8.8.8.8 there when the stored value is not an IP literal).
 *
 * Mux / Fragment / Observatory / Hev TUN values are STORED only —
 * TaptapX M2 has no xray-core to apply them to. The UI labels them
 * "belum didukung di M2" and must never claim they work.
 */
class SettingsStore(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // UI
    var speedEnabled: Boolean
        get() = prefs.getBoolean(KEY_SPEED_ENABLED, DEFAULT_SPEED_ENABLED)
        set(v) = prefs.edit().putBoolean(KEY_SPEED_ENABLED, v).apply()
    var confirmRemove: Boolean
        get() = prefs.getBoolean(KEY_CONFIRM_REMOVE, DEFAULT_CONFIRM_REMOVE)
        set(v) = prefs.edit().putBoolean(KEY_CONFIRM_REMOVE, v).apply()
    var doubleColumnDisplay: Boolean
        get() = prefs.getBoolean(KEY_DOUBLE_COLUMN, DEFAULT_DOUBLE_COLUMN)
        set(v) = prefs.edit().putBoolean(KEY_DOUBLE_COLUMN, v).apply()
    var groupAllDisplay: Boolean
        get() = prefs.getBoolean(KEY_GROUP_ALL_DISPLAY, DEFAULT_GROUP_ALL_DISPLAY)
        set(v) = prefs.edit().putBoolean(KEY_GROUP_ALL_DISPLAY, v).apply()
    var dynamicColor: Boolean
        get() = prefs.getBoolean(KEY_DYNAMIC_COLOR, DEFAULT_DYNAMIC_COLOR)
        set(v) = prefs.edit().putBoolean(KEY_DYNAMIC_COLOR, v).apply()
    var language: String
        get() = prefs.getString(KEY_LANGUAGE, DEFAULT_LANGUAGE) ?: DEFAULT_LANGUAGE
        set(v) = prefs.edit().putString(KEY_LANGUAGE, v).apply()
    /** "0" = system, "1" = light, "2" = dark (same values as v2rayNG). */
    var uiModeNight: String
        get() = prefs.getString(KEY_UI_MODE_NIGHT, DEFAULT_UI_MODE_NIGHT) ?: DEFAULT_UI_MODE_NIGHT
        set(v) = prefs.edit().putString(KEY_UI_MODE_NIGHT, v).apply()

    // VPN
    var ipv6Enabled: Boolean
        get() = prefs.getBoolean(KEY_IPV6_ENABLED, DEFAULT_IPV6_ENABLED)
        set(v) = prefs.edit().putBoolean(KEY_IPV6_ENABLED, v).apply()
    var preferIpv6: Boolean
        get() = prefs.getBoolean(KEY_PREFER_IPV6, DEFAULT_PREFER_IPV6)
        set(v) = prefs.edit().putBoolean(KEY_PREFER_IPV6, v).apply()
    var localDnsEnabled: Boolean
        get() = prefs.getBoolean(KEY_LOCAL_DNS, DEFAULT_LOCAL_DNS)
        set(v) = prefs.edit().putBoolean(KEY_LOCAL_DNS, v).apply()
    var fakeDnsEnabled: Boolean
        get() = prefs.getBoolean(KEY_FAKE_DNS, DEFAULT_FAKE_DNS)
        set(v) = prefs.edit().putBoolean(KEY_FAKE_DNS, v).apply()
    var vpnDns: String
        get() = prefs.getString(KEY_VPN_DNS, DEFAULT_VPN_DNS) ?: DEFAULT_VPN_DNS
        set(v) = prefs.edit().putString(KEY_VPN_DNS, v).apply()
    var appendHttpProxy: Boolean
        get() = prefs.getBoolean(KEY_APPEND_HTTP_PROXY, DEFAULT_APPEND_HTTP_PROXY)
        set(v) = prefs.edit().putBoolean(KEY_APPEND_HTTP_PROXY, v).apply()
    var vpnBypassLan: String
        get() = prefs.getString(KEY_VPN_BYPASS_LAN, DEFAULT_VPN_BYPASS_LAN) ?: DEFAULT_VPN_BYPASS_LAN
        set(v) = prefs.edit().putString(KEY_VPN_BYPASS_LAN, v).apply()
    var vpnInterfaceAddress: String
        get() = prefs.getString(KEY_VPN_INTERFACE_ADDRESS, DEFAULT_VPN_INTERFACE_ADDRESS)
            ?: DEFAULT_VPN_INTERFACE_ADDRESS
        set(v) = prefs.edit().putString(KEY_VPN_INTERFACE_ADDRESS, v).apply()
    var vpnMtu: String
        get() = prefs.getString(KEY_VPN_MTU, DEFAULT_VPN_MTU) ?: DEFAULT_VPN_MTU
        set(v) = prefs.edit().putString(KEY_VPN_MTU, v).apply()
    var useHevTun: Boolean
        get() = prefs.getBoolean(KEY_USE_HEV_TUN, DEFAULT_USE_HEV_TUN)
        set(v) = prefs.edit().putBoolean(KEY_USE_HEV_TUN, v).apply()
    var hevTunLogLevel: String
        get() = prefs.getString(KEY_HEV_TUN_LOG_LEVEL, DEFAULT_HEV_TUN_LOG_LEVEL)
            ?: DEFAULT_HEV_TUN_LOG_LEVEL
        set(v) = prefs.edit().putString(KEY_HEV_TUN_LOG_LEVEL, v).apply()
    var hevTunRwTimeout: String
        get() = prefs.getString(KEY_HEV_TUN_RW_TIMEOUT, DEFAULT_HEV_TUN_RW_TIMEOUT)
            ?: DEFAULT_HEV_TUN_RW_TIMEOUT
        set(v) = prefs.edit().putString(KEY_HEV_TUN_RW_TIMEOUT, v).apply()

    // Core
    var sniffingEnabled: Boolean
        get() = prefs.getBoolean(KEY_SNIFFING_ENABLED, DEFAULT_SNIFFING_ENABLED)
        set(v) = prefs.edit().putBoolean(KEY_SNIFFING_ENABLED, v).apply()
    var routeOnlyEnabled: Boolean
        get() = prefs.getBoolean(KEY_ROUTE_ONLY_ENABLED, DEFAULT_ROUTE_ONLY_ENABLED)
        set(v) = prefs.edit().putBoolean(KEY_ROUTE_ONLY_ENABLED, v).apply()
    /** Local proxy (SOCKS, served by the tunnel when the engine lands). */
    var enableLocalProxy: Boolean
        get() = prefs.getBoolean(KEY_LOCAL_PROXY, DEFAULT_LOCAL_PROXY)
        set(v) = prefs.edit().putBoolean(KEY_LOCAL_PROXY, v).apply()
    var proxySharing: Boolean
        get() = prefs.getBoolean(KEY_PROXY_SHARING, DEFAULT_PROXY_SHARING)
        set(v) = prefs.edit().putBoolean(KEY_PROXY_SHARING, v).apply()
    var dynamicSocksPort: Boolean
        get() = prefs.getBoolean(KEY_DYNAMIC_SOCKS_PORT, DEFAULT_DYNAMIC_SOCKS_PORT)
        set(v) = prefs.edit().putBoolean(KEY_DYNAMIC_SOCKS_PORT, v).apply()
    var socksPort: String
        get() = prefs.getString(KEY_SOCKS_PORT, DEFAULT_SOCKS_PORT) ?: DEFAULT_SOCKS_PORT
        set(v) = prefs.edit().putString(KEY_SOCKS_PORT, v).apply()
    var socksUsername: String
        get() = prefs.getString(KEY_SOCKS_USERNAME, DEFAULT_SOCKS_USERNAME) ?: DEFAULT_SOCKS_USERNAME
        set(v) = prefs.edit().putString(KEY_SOCKS_USERNAME, v).apply()
    var socksPassword: String
        get() = prefs.getString(KEY_SOCKS_PASSWORD, DEFAULT_SOCKS_PASSWORD) ?: DEFAULT_SOCKS_PASSWORD
        set(v) = prefs.edit().putString(KEY_SOCKS_PASSWORD, v).apply()
    var socksEnableUdp: Boolean
        get() = prefs.getBoolean(KEY_SOCKS_UDP, DEFAULT_SOCKS_UDP)
        set(v) = prefs.edit().putBoolean(KEY_SOCKS_UDP, v).apply()
    var remoteDns: String
        get() = prefs.getString(KEY_REMOTE_DNS, DEFAULT_REMOTE_DNS) ?: DEFAULT_REMOTE_DNS
        set(v) = prefs.edit().putString(KEY_REMOTE_DNS, v).apply()
    var domesticDns: String
        get() = prefs.getString(KEY_DOMESTIC_DNS, DEFAULT_DOMESTIC_DNS) ?: DEFAULT_DOMESTIC_DNS
        set(v) = prefs.edit().putString(KEY_DOMESTIC_DNS, v).apply()
    var dnsHosts: String
        get() = prefs.getString(KEY_DNS_HOSTS, DEFAULT_DNS_HOSTS) ?: DEFAULT_DNS_HOSTS
        set(v) = prefs.edit().putString(KEY_DNS_HOSTS, v).apply()
    var coreLogLevel: String
        get() = prefs.getString(KEY_LOG_LEVEL, DEFAULT_LOG_LEVEL) ?: DEFAULT_LOG_LEVEL
        set(v) = prefs.edit().putString(KEY_LOG_LEVEL, v).apply()
    var outboundResolveMethod: String
        get() = prefs.getString(KEY_OUTBOUND_RESOLVE_METHOD, DEFAULT_OUTBOUND_RESOLVE_METHOD)
            ?: DEFAULT_OUTBOUND_RESOLVE_METHOD
        set(v) = prefs.edit().putString(KEY_OUTBOUND_RESOLVE_METHOD, v).apply()

    // Mux (stored only — no xray-core in M2)
    var muxEnabled: Boolean
        get() = prefs.getBoolean(KEY_MUX_ENABLED, DEFAULT_MUX_ENABLED)
        set(v) = prefs.edit().putBoolean(KEY_MUX_ENABLED, v).apply()
    var muxConcurrency: String
        get() = prefs.getString(KEY_MUX_CONCURRENCY, DEFAULT_MUX_CONCURRENCY)
            ?: DEFAULT_MUX_CONCURRENCY
        set(v) = prefs.edit().putString(KEY_MUX_CONCURRENCY, v).apply()
    var muxXudpConcurrency: String
        get() = prefs.getString(KEY_MUX_XUDP_CONCURRENCY, DEFAULT_MUX_XUDP_CONCURRENCY)
            ?: DEFAULT_MUX_XUDP_CONCURRENCY
        set(v) = prefs.edit().putString(KEY_MUX_XUDP_CONCURRENCY, v).apply()
    var muxXudpQuic: String
        get() = prefs.getString(KEY_MUX_XUDP_QUIC, DEFAULT_MUX_XUDP_QUIC) ?: DEFAULT_MUX_XUDP_QUIC
        set(v) = prefs.edit().putString(KEY_MUX_XUDP_QUIC, v).apply()

    // Fragment (stored only — no xray-core in M2)
    var fragmentEnabled: Boolean
        get() = prefs.getBoolean(KEY_FRAGMENT_ENABLED, DEFAULT_FRAGMENT_ENABLED)
        set(v) = prefs.edit().putBoolean(KEY_FRAGMENT_ENABLED, v).apply()
    var fragmentPackets: String
        get() = prefs.getString(KEY_FRAGMENT_PACKETS, DEFAULT_FRAGMENT_PACKETS)
            ?: DEFAULT_FRAGMENT_PACKETS
        set(v) = prefs.edit().putString(KEY_FRAGMENT_PACKETS, v).apply()
    var fragmentLength: String
        get() = prefs.getString(KEY_FRAGMENT_LENGTH, DEFAULT_FRAGMENT_LENGTH)
            ?: DEFAULT_FRAGMENT_LENGTH
        set(v) = prefs.edit().putString(KEY_FRAGMENT_LENGTH, v).apply()
    var fragmentInterval: String
        get() = prefs.getString(KEY_FRAGMENT_INTERVAL, DEFAULT_FRAGMENT_INTERVAL)
            ?: DEFAULT_FRAGMENT_INTERVAL
        set(v) = prefs.edit().putString(KEY_FRAGMENT_INTERVAL, v).apply()
    var fragmentMaxSplit: String
        get() = prefs.getString(KEY_FRAGMENT_MAX_SPLIT, DEFAULT_FRAGMENT_MAX_SPLIT)
            ?: DEFAULT_FRAGMENT_MAX_SPLIT
        set(v) = prefs.edit().putString(KEY_FRAGMENT_MAX_SPLIT, v).apply()

    // Observatory (stored only — no xray-core in M2)
    var observatoryLeastPing: String
        get() = prefs.getString(KEY_OBSERVATORY_LEAST_PING, DEFAULT_OBSERVATORY_LEAST_PING)
            ?: DEFAULT_OBSERVATORY_LEAST_PING
        set(v) = prefs.edit().putString(KEY_OBSERVATORY_LEAST_PING, v).apply()
    var observatoryLeastLoad: String
        get() = prefs.getString(KEY_OBSERVATORY_LEAST_LOAD, DEFAULT_OBSERVATORY_LEAST_LOAD)
            ?: DEFAULT_OBSERVATORY_LEAST_LOAD
        set(v) = prefs.edit().putString(KEY_OBSERVATORY_LEAST_LOAD, v).apply()
    var observatoryLeastLoadMethod: String
        get() = prefs.getString(KEY_OBSERVATORY_LEAST_LOAD_METHOD, DEFAULT_OBSERVATORY_LEAST_LOAD_METHOD)
            ?: DEFAULT_OBSERVATORY_LEAST_LOAD_METHOD
        set(v) = prefs.edit().putString(KEY_OBSERVATORY_LEAST_LOAD_METHOD, v).apply()
    var observatoryLeastLoadSampling: String
        get() = prefs.getString(KEY_OBSERVATORY_LEAST_LOAD_SAMPLING, DEFAULT_OBSERVATORY_LEAST_LOAD_SAMPLING)
            ?: DEFAULT_OBSERVATORY_LEAST_LOAD_SAMPLING
        set(v) = prefs.edit().putString(KEY_OBSERVATORY_LEAST_LOAD_SAMPLING, v).apply()
    var observatoryLeastLoadTimeout: String
        get() = prefs.getString(KEY_OBSERVATORY_LEAST_LOAD_TIMEOUT, DEFAULT_OBSERVATORY_LEAST_LOAD_TIMEOUT)
            ?: DEFAULT_OBSERVATORY_LEAST_LOAD_TIMEOUT
        set(v) = prefs.edit().putString(KEY_OBSERVATORY_LEAST_LOAD_TIMEOUT, v).apply()

    // Advanced
    var isBooted: Boolean
        get() = prefs.getBoolean(KEY_IS_BOOTED, DEFAULT_IS_BOOTED)
        set(v) = prefs.edit().putBoolean(KEY_IS_BOOTED, v).apply()
    var delayTestUrl: String
        get() = prefs.getString(KEY_DELAY_TEST_URL, DEFAULT_DELAY_TEST_URL) ?: DEFAULT_DELAY_TEST_URL
        set(v) = prefs.edit().putString(KEY_DELAY_TEST_URL, v).apply()
    var realPingConcurrency: String
        get() = prefs.getString(KEY_REAL_PING_CONCURRENCY, DEFAULT_REAL_PING_CONCURRENCY)
            ?: DEFAULT_REAL_PING_CONCURRENCY
        set(v) = prefs.edit().putString(KEY_REAL_PING_CONCURRENCY, v).apply()
    var ipApiUrl: String
        get() = prefs.getString(KEY_IP_API_URL, DEFAULT_IP_API_URL) ?: DEFAULT_IP_API_URL
        set(v) = prefs.edit().putString(KEY_IP_API_URL, v).apply()

    // Mode
    var mode: String
        get() = prefs.getString(KEY_MODE, DEFAULT_MODE) ?: DEFAULT_MODE
        set(v) = prefs.edit().putString(KEY_MODE, v).apply()
    var enableRootMode: Boolean
        get() = prefs.getBoolean(KEY_ENABLE_ROOT_MODE, DEFAULT_ENABLE_ROOT_MODE)
        set(v) = prefs.edit().putBoolean(KEY_ENABLE_ROOT_MODE, v).apply()
    var lanSharing: Boolean
        get() = prefs.getBoolean(KEY_LAN_SHARING, DEFAULT_LAN_SHARING)
        set(v) = prefs.edit().putBoolean(KEY_LAN_SHARING, v).apply()

    // ---- Effective values (v2rayNG rules, pure logic on stored state) ----

    /** Local proxy is forced on while Hev TUN is on. */
    val isLocalProxyEffective: Boolean
        get() = isLocalProxyEffective(enableLocalProxy, useHevTun)

    /** VPN-mode-only items (VPN DNS / bypass / interface / MTU / Hev TUN). */
    val isVpnMode: Boolean
        get() = mode == MODE_VPN

    /** Apply the stored theme mode (call from Application + Settings). */
    fun applyThemeMode() {
        AppCompatDelegate.setDefaultNightMode(
            when (uiModeNight) {
                "1" -> AppCompatDelegate.MODE_NIGHT_NO
                "2" -> AppCompatDelegate.MODE_NIGHT_YES
                else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
            }
        )
    }

    companion object {
        const val PREFS_NAME = "taptapx_settings"

        // Keys (never rename: existing installs already store under them).
        const val KEY_SPEED_ENABLED = "speed_enabled"
        const val KEY_CONFIRM_REMOVE = "confirm_remove"
        const val KEY_DOUBLE_COLUMN = "double_column_display"
        const val KEY_GROUP_ALL_DISPLAY = "group_all_display"
        const val KEY_DYNAMIC_COLOR = "dynamic_color"
        const val KEY_LANGUAGE = "language"
        const val KEY_UI_MODE_NIGHT = "ui_mode_night"
        const val KEY_IPV6_ENABLED = "ipv6_enabled"
        const val KEY_PREFER_IPV6 = "prefer_ipv6"
        const val KEY_LOCAL_DNS = "local_dns_enabled"
        const val KEY_FAKE_DNS = "fake_dns_enabled"
        const val KEY_VPN_DNS = "vpn_dns"
        const val KEY_APPEND_HTTP_PROXY = "append_http_proxy"
        const val KEY_VPN_BYPASS_LAN = "vpn_bypass_lan"
        const val KEY_VPN_INTERFACE_ADDRESS = "vpn_interface_address"
        const val KEY_VPN_MTU = "vpn_mtu"
        const val KEY_USE_HEV_TUN = "use_hev_tun"
        const val KEY_HEV_TUN_LOG_LEVEL = "hev_tun_log_level"
        const val KEY_HEV_TUN_RW_TIMEOUT = "hev_tun_rw_timeout"
        const val KEY_SNIFFING_ENABLED = "sniffing_enabled"
        const val KEY_ROUTE_ONLY_ENABLED = "route_only_enabled"
        const val KEY_LOCAL_PROXY = "enable_local_proxy"
        const val KEY_PROXY_SHARING = "proxy_sharing"
        const val KEY_DYNAMIC_SOCKS_PORT = "dynamic_socks_port"
        const val KEY_SOCKS_PORT = "socks_port"
        const val KEY_SOCKS_USERNAME = "socks_username"
        const val KEY_SOCKS_PASSWORD = "socks_password"
        const val KEY_SOCKS_UDP = "socks_enable_udp"
        const val KEY_REMOTE_DNS = "remote_dns"
        const val KEY_DOMESTIC_DNS = "domestic_dns"
        const val KEY_DNS_HOSTS = "dns_hosts"
        const val KEY_LOG_LEVEL = "core_loglevel"
        const val KEY_OUTBOUND_RESOLVE_METHOD = "outbound_resolve_method"
        const val KEY_MUX_ENABLED = "mux_enabled"
        const val KEY_MUX_CONCURRENCY = "mux_concurrency"
        const val KEY_MUX_XUDP_CONCURRENCY = "mux_xudp_concurrency"
        const val KEY_MUX_XUDP_QUIC = "mux_xudp_quic"
        const val KEY_FRAGMENT_ENABLED = "fragment_enabled"
        const val KEY_FRAGMENT_PACKETS = "fragment_packets"
        const val KEY_FRAGMENT_LENGTH = "fragment_length"
        const val KEY_FRAGMENT_INTERVAL = "fragment_interval"
        const val KEY_FRAGMENT_MAX_SPLIT = "fragment_max_split"
        const val KEY_OBSERVATORY_LEAST_PING = "observatory_least_ping"
        const val KEY_OBSERVATORY_LEAST_LOAD = "observatory_least_load"
        const val KEY_OBSERVATORY_LEAST_LOAD_METHOD = "observatory_least_load_method"
        const val KEY_OBSERVATORY_LEAST_LOAD_SAMPLING = "observatory_least_load_sampling"
        const val KEY_OBSERVATORY_LEAST_LOAD_TIMEOUT = "observatory_least_load_timeout"
        const val KEY_IS_BOOTED = "is_booted"
        const val KEY_DELAY_TEST_URL = "delay_test_url"
        const val KEY_REAL_PING_CONCURRENCY = "real_ping_concurrency"
        const val KEY_IP_API_URL = "ip_api_url"
        const val KEY_MODE = "mode"
        const val KEY_ENABLE_ROOT_MODE = "enable_root_mode"
        const val KEY_LAN_SHARING = "lan_sharing"

        // Defaults — v2rayNG values, locked by SettingsDefaultsTest.
        const val DEFAULT_SPEED_ENABLED = false
        const val DEFAULT_CONFIRM_REMOVE = false
        const val DEFAULT_DOUBLE_COLUMN = false
        const val DEFAULT_GROUP_ALL_DISPLAY = false
        const val DEFAULT_DYNAMIC_COLOR = true
        const val DEFAULT_LANGUAGE = "auto"
        const val DEFAULT_UI_MODE_NIGHT = "0"
        const val DEFAULT_IPV6_ENABLED = false
        const val DEFAULT_PREFER_IPV6 = false
        const val DEFAULT_LOCAL_DNS = false
        const val DEFAULT_FAKE_DNS = false
        const val DEFAULT_VPN_DNS = ""
        const val DEFAULT_APPEND_HTTP_PROXY = false
        /** v2rayNG default is "1" (Bypass LAN); v1.0.4 stored "0" — fixed in v1.0.5. */
        const val DEFAULT_VPN_BYPASS_LAN = "1"
        const val DEFAULT_VPN_INTERFACE_ADDRESS = "0"
        const val DEFAULT_VPN_MTU = ""
        const val DEFAULT_USE_HEV_TUN = true
        const val DEFAULT_HEV_TUN_LOG_LEVEL = "warn"
        const val DEFAULT_HEV_TUN_RW_TIMEOUT = ""
        const val DEFAULT_SNIFFING_ENABLED = true
        const val DEFAULT_ROUTE_ONLY_ENABLED = false
        const val DEFAULT_LOCAL_PROXY = true
        const val DEFAULT_PROXY_SHARING = false
        const val DEFAULT_DYNAMIC_SOCKS_PORT = false
        const val DEFAULT_SOCKS_PORT = ""
        const val DEFAULT_SOCKS_USERNAME = ""
        const val DEFAULT_SOCKS_PASSWORD = ""
        const val DEFAULT_SOCKS_UDP = true
        const val DEFAULT_REMOTE_DNS = ""
        const val DEFAULT_DOMESTIC_DNS = ""
        const val DEFAULT_DNS_HOSTS = ""
        const val DEFAULT_LOG_LEVEL = "warning"
        const val DEFAULT_OUTBOUND_RESOLVE_METHOD = "1"
        const val DEFAULT_MUX_ENABLED = false
        const val DEFAULT_MUX_CONCURRENCY = "8"
        const val DEFAULT_MUX_XUDP_CONCURRENCY = "8"
        const val DEFAULT_MUX_XUDP_QUIC = "reject"
        const val DEFAULT_FRAGMENT_ENABLED = false
        const val DEFAULT_FRAGMENT_PACKETS = "tlshello"
        const val DEFAULT_FRAGMENT_LENGTH = "50-100"
        const val DEFAULT_FRAGMENT_INTERVAL = "10-20"
        const val DEFAULT_FRAGMENT_MAX_SPLIT = "10"
        const val DEFAULT_OBSERVATORY_LEAST_PING = "3m"
        const val DEFAULT_OBSERVATORY_LEAST_LOAD = "5m"
        const val DEFAULT_OBSERVATORY_LEAST_LOAD_METHOD = "HEAD"
        const val DEFAULT_OBSERVATORY_LEAST_LOAD_SAMPLING = "2"
        const val DEFAULT_OBSERVATORY_LEAST_LOAD_TIMEOUT = "30s"
        const val DEFAULT_IS_BOOTED = false
        const val DEFAULT_DELAY_TEST_URL = ""
        const val DEFAULT_REAL_PING_CONCURRENCY = "16"
        const val DEFAULT_IP_API_URL = ""
        const val DEFAULT_ENABLE_ROOT_MODE = false
        const val DEFAULT_LAN_SHARING = false

        /** The only mode M2 implements. */
        const val MODE_VPN = "VPN"
        const val DEFAULT_MODE = MODE_VPN

        // Display defaults (v2rayNG AppConfig): shown when the stored value is blank.
        const val DISPLAY_VPN_DNS = "1.1.1.1"
        // v1.0.21: the effective MTU default is 9000 (was 1500).
        const val DISPLAY_VPN_MTU = "9000"
        const val DISPLAY_VPN_INTERFACE_ADDRESS = "10.10.14.x"
        const val DISPLAY_HEV_TUN_RW_TIMEOUT = "300,60"
        const val DISPLAY_SOCKS_PORT = "10808"
        const val DISPLAY_REMOTE_DNS = "https://cloudflare-dns.com/dns-query"
        const val DISPLAY_DOMESTIC_DNS = "223.5.5.5"
        const val DISPLAY_DELAY_TEST_URL = "https://www.gstatic.com/generate_204"
        const val DISPLAY_IP_API_URL = "https://api.ip.sb/geoip"

        /** Stored value, or the display default when blank. Pure — unit-testable. */
        fun displayOrDefault(stored: String, displayDefault: String): String =
            stored.ifBlank { displayDefault }

        // ---- Enablement rules (v2rayNG), pure functions on explicit state ----
        fun isFakeDnsAvailable(localDnsEnabled: Boolean): Boolean = localDnsEnabled
        fun isVpnDnsAvailable(mode: String, localDnsEnabled: Boolean): Boolean =
            mode == MODE_VPN && !localDnsEnabled

        fun isVpnOnlyAvailable(mode: String): Boolean = mode == MODE_VPN
        fun isHevTunChildAvailable(mode: String, useHevTun: Boolean): Boolean =
            mode == MODE_VPN && useHevTun

        fun isLocalProxyEffective(enableLocalProxy: Boolean, useHevTun: Boolean): Boolean =
            enableLocalProxy || useHevTun

        fun isSocksItemAvailable(enableLocalProxy: Boolean, useHevTun: Boolean): Boolean =
            isLocalProxyEffective(enableLocalProxy, useHevTun)

        fun isSocksPortAvailable(
            enableLocalProxy: Boolean,
            useHevTun: Boolean,
            dynamicSocksPort: Boolean,
        ): Boolean = isLocalProxyEffective(enableLocalProxy, useHevTun) && !dynamicSocksPort
    }
}
