package com.taptap.x.data

import android.content.Context
import android.content.SharedPreferences
import androidx.appcompat.app.AppCompatDelegate

/**
 * Settings storage (SharedPreferences), mirroring the v2rayNG
 * SettingsActivity groups that make sense for TaptapX: UI, VPN,
 * local proxy, DNS, advanced. Core-only settings (mux, fragment,
 * observatory, HEV tunnel) are deliberately NOT here — TaptapX has
 * no xray-core yet, so there is nothing to apply them to.
 */
class SettingsStore(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // UI
    var speedEnabled: Boolean
        get() = prefs.getBoolean(KEY_SPEED_ENABLED, false)
        set(v) = prefs.edit().putBoolean(KEY_SPEED_ENABLED, v).apply()
    var confirmRemove: Boolean
        get() = prefs.getBoolean(KEY_CONFIRM_REMOVE, false)
        set(v) = prefs.edit().putBoolean(KEY_CONFIRM_REMOVE, v).apply()
    var doubleColumnDisplay: Boolean
        get() = prefs.getBoolean(KEY_DOUBLE_COLUMN, false)
        set(v) = prefs.edit().putBoolean(KEY_DOUBLE_COLUMN, v).apply()
    var dynamicColor: Boolean
        get() = prefs.getBoolean(KEY_DYNAMIC_COLOR, true)
        set(v) = prefs.edit().putBoolean(KEY_DYNAMIC_COLOR, v).apply()
    var language: String
        get() = prefs.getString(KEY_LANGUAGE, "auto") ?: "auto"
        set(v) = prefs.edit().putString(KEY_LANGUAGE, v).apply()
    /** "0" = system, "1" = light, "2" = dark (same values as v2rayNG). */
    var uiModeNight: String
        get() = prefs.getString(KEY_UI_MODE_NIGHT, "0") ?: "0"
        set(v) = prefs.edit().putString(KEY_UI_MODE_NIGHT, v).apply()

    // VPN
    var ipv6Enabled: Boolean
        get() = prefs.getBoolean(KEY_IPV6_ENABLED, false)
        set(v) = prefs.edit().putBoolean(KEY_IPV6_ENABLED, v).apply()
    var preferIpv6: Boolean
        get() = prefs.getBoolean(KEY_PREFER_IPV6, false)
        set(v) = prefs.edit().putBoolean(KEY_PREFER_IPV6, v).apply()
    var localDnsEnabled: Boolean
        get() = prefs.getBoolean(KEY_LOCAL_DNS, false)
        set(v) = prefs.edit().putBoolean(KEY_LOCAL_DNS, v).apply()
    var fakeDnsEnabled: Boolean
        get() = prefs.getBoolean(KEY_FAKE_DNS, false)
        set(v) = prefs.edit().putBoolean(KEY_FAKE_DNS, v).apply()
    var vpnDns: String
        get() = prefs.getString(KEY_VPN_DNS, "") ?: ""
        set(v) = prefs.edit().putString(KEY_VPN_DNS, v).apply()
    var vpnBypassLan: String
        get() = prefs.getString(KEY_VPN_BYPASS_LAN, "0") ?: "0"
        set(v) = prefs.edit().putString(KEY_VPN_BYPASS_LAN, v).apply()
    var vpnMtu: String
        get() = prefs.getString(KEY_VPN_MTU, "") ?: ""
        set(v) = prefs.edit().putString(KEY_VPN_MTU, v).apply()

    // Local proxy (SOCKS, served by the tunnel when the engine lands)
    var enableLocalProxy: Boolean
        get() = prefs.getBoolean(KEY_LOCAL_PROXY, true)
        set(v) = prefs.edit().putBoolean(KEY_LOCAL_PROXY, v).apply()
    var socksPort: String
        get() = prefs.getString(KEY_SOCKS_PORT, "") ?: ""
        set(v) = prefs.edit().putString(KEY_SOCKS_PORT, v).apply()
    var dynamicSocksPort: Boolean
        get() = prefs.getBoolean(KEY_DYNAMIC_SOCKS_PORT, false)
        set(v) = prefs.edit().putBoolean(KEY_DYNAMIC_SOCKS_PORT, v).apply()
    var socksUsername: String
        get() = prefs.getString(KEY_SOCKS_USERNAME, "") ?: ""
        set(v) = prefs.edit().putString(KEY_SOCKS_USERNAME, v).apply()
    var socksPassword: String
        get() = prefs.getString(KEY_SOCKS_PASSWORD, "") ?: ""
        set(v) = prefs.edit().putString(KEY_SOCKS_PASSWORD, v).apply()
    var socksEnableUdp: Boolean
        get() = prefs.getBoolean(KEY_SOCKS_UDP, true)
        set(v) = prefs.edit().putBoolean(KEY_SOCKS_UDP, v).apply()
    var proxySharing: Boolean
        get() = prefs.getBoolean(KEY_PROXY_SHARING, false)
        set(v) = prefs.edit().putBoolean(KEY_PROXY_SHARING, v).apply()

    // DNS
    var remoteDns: String
        get() = prefs.getString(KEY_REMOTE_DNS, "") ?: ""
        set(v) = prefs.edit().putString(KEY_REMOTE_DNS, v).apply()
    var domesticDns: String
        get() = prefs.getString(KEY_DOMESTIC_DNS, "") ?: ""
        set(v) = prefs.edit().putString(KEY_DOMESTIC_DNS, v).apply()
    var dnsHosts: String
        get() = prefs.getString(KEY_DNS_HOSTS, "") ?: ""
        set(v) = prefs.edit().putString(KEY_DNS_HOSTS, v).apply()
    var coreLogLevel: String
        get() = prefs.getString(KEY_LOG_LEVEL, "warning") ?: "warning"
        set(v) = prefs.edit().putString(KEY_LOG_LEVEL, v).apply()

    // Advanced
    var isBooted: Boolean
        get() = prefs.getBoolean(KEY_IS_BOOTED, false)
        set(v) = prefs.edit().putBoolean(KEY_IS_BOOTED, v).apply()
    var delayTestUrl: String
        get() = prefs.getString(KEY_DELAY_TEST_URL, "") ?: ""
        set(v) = prefs.edit().putString(KEY_DELAY_TEST_URL, v).apply()
    var realPingConcurrency: String
        get() = prefs.getString(KEY_REAL_PING_CONCURRENCY, "16") ?: "16"
        set(v) = prefs.edit().putString(KEY_REAL_PING_CONCURRENCY, v).apply()
    var ipApiUrl: String
        get() = prefs.getString(KEY_IP_API_URL, "") ?: ""
        set(v) = prefs.edit().putString(KEY_IP_API_URL, v).apply()

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

        const val KEY_SPEED_ENABLED = "speed_enabled"
        const val KEY_CONFIRM_REMOVE = "confirm_remove"
        const val KEY_DOUBLE_COLUMN = "double_column_display"
        const val KEY_DYNAMIC_COLOR = "dynamic_color"
        const val KEY_LANGUAGE = "language"
        const val KEY_UI_MODE_NIGHT = "ui_mode_night"
        const val KEY_IPV6_ENABLED = "ipv6_enabled"
        const val KEY_PREFER_IPV6 = "prefer_ipv6"
        const val KEY_LOCAL_DNS = "local_dns_enabled"
        const val KEY_FAKE_DNS = "fake_dns_enabled"
        const val KEY_VPN_DNS = "vpn_dns"
        const val KEY_VPN_BYPASS_LAN = "vpn_bypass_lan"
        const val KEY_VPN_MTU = "vpn_mtu"
        const val KEY_LOCAL_PROXY = "enable_local_proxy"
        const val KEY_SOCKS_PORT = "socks_port"
        const val KEY_DYNAMIC_SOCKS_PORT = "dynamic_socks_port"
        const val KEY_SOCKS_USERNAME = "socks_username"
        const val KEY_SOCKS_PASSWORD = "socks_password"
        const val KEY_SOCKS_UDP = "socks_enable_udp"
        const val KEY_PROXY_SHARING = "proxy_sharing"
        const val KEY_REMOTE_DNS = "remote_dns"
        const val KEY_DOMESTIC_DNS = "domestic_dns"
        const val KEY_DNS_HOSTS = "dns_hosts"
        const val KEY_LOG_LEVEL = "core_loglevel"
        const val KEY_IS_BOOTED = "is_booted"
        const val KEY_DELAY_TEST_URL = "delay_test_url"
        const val KEY_REAL_PING_CONCURRENCY = "real_ping_concurrency"
        const val KEY_IP_API_URL = "ip_api_url"
    }
}
