package com.taptap.ng.ui.settings

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.switchmaterial.SwitchMaterial
import com.taptap.ng.R
import com.taptap.ng.TaptapNGApp
import com.taptap.ng.core.DialLog
import com.taptap.ng.data.SettingsStore
import com.taptap.ng.service.ClashApiServer

/**
 * Settings screen (v1.0.5), Views only: a RecyclerView of collapsible
 * sections mirroring v2rayNG's SettingsActivity — each section has a
 * header (title + expand/collapse arrow, initial state per v2rayNG)
 * and each item shows title + subtitle + current value. Disabled
 * items (per v2rayNG's enablement rules) are greyed out but keep
 * their stored value.
 *
 * No Compose, no new libraries. Values are stored in
 * [SettingsStore] ("taptapng_settings"). Since v1.0.5 the Mux
 * (TCP), Fragment, Observatory, Remote DNS and LAN-sharing values
 * ARE applied in-app and no longer carry the "belum didukung di
 * M2" badge; only the Mux XUDP pair, the Hev TUN rows (hidden
 * outright — no native lib is bundled) and root mode stay
 * stored-only / labelled, because M2 has no UDP path, no Hev
 * library and no iptables tunnel to apply them to.
 */
class SettingsActivity : AppCompatActivity() {

    private lateinit var store: SettingsStore
    private lateinit var adapter: SettingsAdapter

    /** Section ids expanded right now; defaults match v2rayNG. */
    private val expandedSections = mutableSetOf<String>()

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(TaptapNGApp.wrapLocale(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        store = SettingsStore(this)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        val saved = savedInstanceState?.getStringArrayList(KEY_EXPANDED)
        if (saved != null) {
            expandedSections.addAll(saved)
        } else {
            expandedSections.addAll(DEFAULT_EXPANDED)
        }

        adapter = SettingsAdapter(
            onSectionClick = { section ->
                if (!expandedSections.remove(section.id)) {
                    expandedSections.add(section.id)
                }
                refresh()
            },
            onItemTap = { item -> onItemTap(item) },
            onItemToggle = { item, checked -> onItemToggle(item, checked) },
        )
        val list = findViewById<RecyclerView>(R.id.settings_list)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = adapter
        refresh()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArrayList(KEY_EXPANDED, ArrayList(expandedSections))
    }

    private fun refresh() {
        adapter.rows = buildRows()
        adapter.notifyDataSetChanged()
    }

    // ---- Model -------------------------------------------------------

    private enum class Kind { SWITCH, TEXT, LIST, ACTION }

    private data class SettingItem(
        val key: String,
        val titleRes: Int,
        val subtitleRes: Int,
        val kind: Kind,
        val notSupportedM2: Boolean = false,
        val enabled: () -> Boolean = { true },
        /** Display value for TEXT / LIST items. */
        val displayValue: () -> String = { "" },
        val isOn: () -> Boolean = { false },
        val onToggle: (Boolean) -> Unit = {},
        /** Raw stored value prefilled in the edit dialog (TEXT). */
        val rawValue: () -> String = { "" },
        val inputType: Int = InputType.TYPE_CLASS_TEXT,
        /** Hint shown in the edit dialog (usually the display default). */
        val hint: String? = null,
        val onSaveText: (String) -> Unit = {},
        /** Entries / values for the single-choice dialog (LIST). */
        val listEntries: Array<String> = emptyArray(),
        val listValues: Array<String> = emptyArray(),
        val listCurrent: () -> String = { "" },
        val onSaveList: (String) -> Unit = {},
        /** Side effect after a change (theme / language recreate). */
        val afterChange: () -> Unit = {},
    )

    private data class Section(
        val id: String,
        val titleRes: Int,
        val items: List<SettingItem>,
    )

    private sealed interface Row {
        data class Header(val section: Section) : Row
        data class Item(val item: SettingItem) : Row
    }

    // ---- Building the sections (v2rayNG order + defaults) -----------

    private fun buildRows(): List<Row> {
        val rows = ArrayList<Row>()
        for (section in buildSections()) {
            rows += Row.Header(section)
            if (section.id in expandedSections) {
                for (item in section.items) rows += Row.Item(item)
            }
        }
        return rows
    }

    private fun buildSections(): List<Section> {
        val vpnMode = { store.isVpnMode }
        val localProxyEffective = { store.isLocalProxyEffective }
        return listOf(
            Section(
                "ui", R.string.set_section_ui,
                listOf(
                    switchItem(
                        "speed_enabled", R.string.set_speed_title, R.string.set_speed_sub,
                        isOn = { store.speedEnabled },
                        onToggle = { store.speedEnabled = it },
                    ),
                    switchItem(
                        "confirm_remove", R.string.set_confirm_remove_title, R.string.set_confirm_remove_sub,
                        isOn = { store.confirmRemove },
                        onToggle = { store.confirmRemove = it },
                    ),
                    switchItem(
                        "double_column_display", R.string.set_double_column_title, R.string.set_double_column_sub,
                        isOn = { store.doubleColumnDisplay },
                        onToggle = { store.doubleColumnDisplay = it },
                    ),
                    switchItem(
                        "group_all_display", R.string.set_group_all_title, R.string.set_group_all_sub,
                        isOn = { store.groupAllDisplay },
                        onToggle = { store.groupAllDisplay = it },
                    ),
                    switchItem(
                        "dynamic_color", R.string.set_dynamic_color_title, R.string.set_dynamic_color_sub,
                        isOn = { store.dynamicColor },
                        onToggle = { store.dynamicColor = it },
                    ),
                    listItem(
                        "language", R.string.set_language_title, R.string.set_language_sub,
                        entriesRes = R.array.language_entries,
                        valuesRes = R.array.language_values,
                        current = { store.language },
                        onSave = { store.language = it },
                        afterChange = { recreate() },
                    ),
                    listItem(
                        "ui_mode_night", R.string.set_ui_mode_title, R.string.set_ui_mode_sub,
                        entriesRes = R.array.ui_mode_night_entries,
                        valuesRes = R.array.ui_mode_night_values,
                        current = { store.uiModeNight },
                        onSave = { store.uiModeNight = it },
                        afterChange = {
                            store.applyThemeMode()
                            recreate()
                        },
                    ),
                ),
            ),
            Section(
                "vpn", R.string.set_section_vpn,
                listOf(
                    switchItem(
                        "ipv6_enabled", R.string.set_ipv6_title, R.string.set_ipv6_sub,
                        isOn = { store.ipv6Enabled },
                        onToggle = { store.ipv6Enabled = it },
                    ),
                    switchItem(
                        "prefer_ipv6", R.string.set_prefer_ipv6_title, R.string.set_prefer_ipv6_sub,
                        isOn = { store.preferIpv6 },
                        onToggle = { store.preferIpv6 = it },
                    ),
                    switchItem(
                        "local_dns_enabled", R.string.set_local_dns_title, R.string.set_local_dns_sub,
                        isOn = { store.localDnsEnabled },
                        onToggle = { store.localDnsEnabled = it },
                    ),
                    switchItem(
                        "fake_dns_enabled", R.string.set_fake_dns_title, R.string.set_fake_dns_sub,
                        enabled = { SettingsStore.isFakeDnsAvailable(store.localDnsEnabled) },
                        isOn = { store.fakeDnsEnabled },
                        onToggle = { store.fakeDnsEnabled = it },
                    ),
                    textItem(
                        "vpn_dns", R.string.set_vpn_dns_title, R.string.set_vpn_dns_sub,
                        enabled = {
                            SettingsStore.isVpnDnsAvailable(store.mode, store.localDnsEnabled)
                        },
                        rawValue = { store.vpnDns },
                        displayValue = {
                            SettingsStore.displayOrDefault(store.vpnDns, SettingsStore.DISPLAY_VPN_DNS)
                        },
                        hint = SettingsStore.DISPLAY_VPN_DNS,
                        onSave = { store.vpnDns = it },
                    ),
                    switchItem(
                        "append_http_proxy", R.string.set_append_http_proxy_title, R.string.set_append_http_proxy_sub,
                        isOn = { store.appendHttpProxy },
                        onToggle = { store.appendHttpProxy = it },
                    ),
                    listItem(
                        "vpn_bypass_lan", R.string.set_bypass_lan_title, R.string.set_bypass_lan_sub,
                        entriesRes = R.array.vpn_bypass_lan_entries,
                        valuesRes = R.array.vpn_bypass_lan_values,
                        enabled = vpnMode,
                        current = { store.vpnBypassLan },
                        onSave = { store.vpnBypassLan = it },
                    ),
                    textItem(
                        "vpn_interface_address", R.string.set_interface_address_title, R.string.set_interface_address_sub,
                        enabled = vpnMode,
                        rawValue = { store.vpnInterfaceAddress },
                        displayValue = {
                            val v = store.vpnInterfaceAddress
                            if (v.isBlank() || v == "0") SettingsStore.DISPLAY_VPN_INTERFACE_ADDRESS else v
                        },
                        hint = SettingsStore.DISPLAY_VPN_INTERFACE_ADDRESS,
                        onSave = { store.vpnInterfaceAddress = it },
                    ),
                    textItem(
                        "vpn_mtu", R.string.set_mtu_title, R.string.set_mtu_sub,
                        enabled = vpnMode,
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.vpnMtu },
                        displayValue = {
                            SettingsStore.displayOrDefault(store.vpnMtu, SettingsStore.DISPLAY_VPN_MTU)
                        },
                        hint = SettingsStore.DISPLAY_VPN_MTU,
                        onSave = { store.vpnMtu = it },
                    ),
                    switchItem(
                        "use_hev_tun", R.string.set_hev_tun_title, R.string.set_hev_tun_sub,
                        enabled = vpnMode,
                        notSupportedM2 = true,
                        isOn = { store.useHevTun },
                        onToggle = { store.useHevTun = it },
                    ),
                    textItem(
                        "hev_tun_log_level", R.string.set_hev_log_title, R.string.set_hev_log_sub,
                        enabled = {
                            SettingsStore.isHevTunChildAvailable(store.mode, store.useHevTun)
                        },
                        notSupportedM2 = true,
                        rawValue = { store.hevTunLogLevel },
                        displayValue = { store.hevTunLogLevel },
                        onSave = { store.hevTunLogLevel = it },
                    ),
                    textItem(
                        "hev_tun_rw_timeout", R.string.set_hev_timeout_title, R.string.set_hev_timeout_sub,
                        enabled = {
                            SettingsStore.isHevTunChildAvailable(store.mode, store.useHevTun)
                        },
                        notSupportedM2 = true,
                        rawValue = { store.hevTunRwTimeout },
                        displayValue = {
                            SettingsStore.displayOrDefault(
                                store.hevTunRwTimeout,
                                SettingsStore.DISPLAY_HEV_TUN_RW_TIMEOUT,
                            )
                        },
                        hint = SettingsStore.DISPLAY_HEV_TUN_RW_TIMEOUT,
                        onSave = { store.hevTunRwTimeout = it },
                    ),
                    // NOTE (v1.0.5, group A): the three Hev TUN rows
                    // above are REMOVED from the list by the
                    // HIDDEN_SETTING_KEYS filter below — Hev TUN
                    // cannot run in TaptapNG (it needs the native
                    // hev-socks5-tunnel library, and this app ships
                    // no .so on purpose). The values stay stored in
                    // SettingsStore (defaults unchanged) so an old
                    // install keeps its data; they are only hidden
                    // from the UI. The items stay declared here so
                    // the removal is one visible filter, not a
                    // silent deletion of the declarations.
                ).filter { it.key !in HIDDEN_SETTING_KEYS },
            ),
            Section(
                "core", R.string.set_section_core,
                listOf(
                    switchItem(
                        "sniffing_enabled", R.string.set_sniffing_title, R.string.set_sniffing_sub,
                        isOn = { store.sniffingEnabled },
                        onToggle = { store.sniffingEnabled = it },
                    ),
                    switchItem(
                        "route_only_enabled", R.string.set_route_only_title, R.string.set_route_only_sub,
                        isOn = { store.routeOnlyEnabled },
                        onToggle = { store.routeOnlyEnabled = it },
                    ),
                    switchItem(
                        "enable_local_proxy", R.string.set_local_proxy_title, R.string.set_local_proxy_sub,
                        // Forced on while Hev TUN is on: show on, disable the switch.
                        enabled = { !store.useHevTun },
                        isOn = { store.isLocalProxyEffective },
                        onToggle = { store.enableLocalProxy = it },
                    ),
                    switchItem(
                        "proxy_sharing", R.string.set_proxy_sharing_title, R.string.set_proxy_sharing_sub,
                        enabled = localProxyEffective,
                        isOn = { store.proxySharing },
                        onToggle = { store.proxySharing = it },
                    ),
                    switchItem(
                        "dynamic_socks_port", R.string.set_dynamic_port_title, R.string.set_dynamic_port_sub,
                        enabled = localProxyEffective,
                        isOn = { store.dynamicSocksPort },
                        onToggle = { store.dynamicSocksPort = it },
                    ),
                    textItem(
                        "socks_port", R.string.set_socks_port_title, R.string.set_socks_port_sub,
                        enabled = {
                            SettingsStore.isSocksPortAvailable(
                                store.enableLocalProxy, store.useHevTun, store.dynamicSocksPort,
                            )
                        },
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.socksPort },
                        displayValue = {
                            SettingsStore.displayOrDefault(store.socksPort, SettingsStore.DISPLAY_SOCKS_PORT)
                        },
                        hint = SettingsStore.DISPLAY_SOCKS_PORT,
                        onSave = { store.socksPort = it },
                    ),
                    textItem(
                        "socks_username", R.string.set_socks_user_title, R.string.set_socks_user_sub,
                        enabled = localProxyEffective,
                        rawValue = { store.socksUsername },
                        displayValue = { store.socksUsername.ifBlank { getString(R.string.set_not_set) } },
                        onSave = { store.socksUsername = it },
                    ),
                    textItem(
                        "socks_password", R.string.set_socks_pass_title, R.string.set_socks_pass_sub,
                        enabled = localProxyEffective,
                        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD,
                        rawValue = { store.socksPassword },
                        displayValue = {
                            if (store.socksPassword.isBlank()) getString(R.string.set_not_set) else "••••••"
                        },
                        onSave = { store.socksPassword = it },
                    ),
                    switchItem(
                        "socks_enable_udp", R.string.set_socks_udp_title, R.string.set_socks_udp_sub,
                        enabled = localProxyEffective,
                        isOn = { store.socksEnableUdp },
                        onToggle = { store.socksEnableUdp = it },
                    ),
                    textItem(
                        "remote_dns", R.string.set_remote_dns_title, R.string.set_remote_dns_sub,
                        // v1.0.4 (review Claude): nilai ini tersimpan
                        // tapi tidak lagi menggerakkan tunnel — DNS
                        // tunnel tetap 1.1.1.1/1.0.0.1 (v1.0.3). Beri
                        // label "Not supported yet" seperti setting
                        // core lain yang hanya tersimpan, bukan
                        // disembunyikan (nilainya tetap bisa diedit).
                        rawValue = { store.remoteDns },
                        displayValue = {
                            SettingsStore.displayOrDefault(store.remoteDns, SettingsStore.DISPLAY_REMOTE_DNS)
                        },
                        hint = SettingsStore.DISPLAY_REMOTE_DNS,
                        onSave = { store.remoteDns = it },
                    ),
                    textItem(
                        "domestic_dns", R.string.set_direct_dns_title, R.string.set_direct_dns_sub,
                        rawValue = { store.domesticDns },
                        displayValue = {
                            SettingsStore.displayOrDefault(store.domesticDns, SettingsStore.DISPLAY_DOMESTIC_DNS)
                        },
                        hint = SettingsStore.DISPLAY_DOMESTIC_DNS,
                        onSave = { store.domesticDns = it },
                    ),
                    textItem(
                        "dns_hosts", R.string.set_dns_hosts_title, R.string.set_dns_hosts_sub,
                        rawValue = { store.dnsHosts },
                        displayValue = { store.dnsHosts.ifBlank { getString(R.string.set_not_set) } },
                        onSave = { store.dnsHosts = it },
                    ),
                    listItem(
                        "core_loglevel", R.string.set_log_level_title, R.string.set_log_level_sub,
                        entriesRes = R.array.core_loglevel_entries,
                        valuesRes = R.array.core_loglevel_values,
                        current = { store.coreLogLevel },
                        onSave = { store.coreLogLevel = it },
                        // v1.0.5, group A: the level applies at once —
                        // no restart needed for DialLog verbosity.
                        afterChange = { DialLog.applyLevel(store.coreLogLevel) },
                    ),
                    textItem(
                        "outbound_resolve_method", R.string.set_resolve_title, R.string.set_resolve_sub,
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.outboundResolveMethod },
                        displayValue = { store.outboundResolveMethod },
                        onSave = { store.outboundResolveMethod = it },
                    ),
                ),
            ),
            Section(
                "mux", R.string.set_section_mux,
                listOf(
                    switchItem(
                        "mux_enabled", R.string.set_mux_title, R.string.set_mux_sub,
                        isOn = { store.muxEnabled },
                        onToggle = { store.muxEnabled = it },
                    ),
                    textItem(
                        "mux_concurrency", R.string.set_mux_conn_title, R.string.set_mux_conn_sub,
                        enabled = { store.muxEnabled },
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.muxConcurrency },
                        displayValue = { store.muxConcurrency },
                        onSave = { store.muxConcurrency = it },
                    ),
                    textItem(
                        "mux_xudp_concurrency", R.string.set_mux_xudp_title, R.string.set_mux_xudp_sub,
                        enabled = { store.muxEnabled },
                        notSupportedM2 = true,
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.muxXudpConcurrency },
                        displayValue = { store.muxXudpConcurrency },
                        onSave = { store.muxXudpConcurrency = it },
                    ),
                    textItem(
                        "mux_xudp_quic", R.string.set_mux_quic_title, R.string.set_mux_quic_sub,
                        enabled = { store.muxEnabled },
                        notSupportedM2 = true,
                        rawValue = { store.muxXudpQuic },
                        displayValue = { store.muxXudpQuic },
                        onSave = { store.muxXudpQuic = it },
                    ),
                ),
            ),
            Section(
                "fragment", R.string.set_section_fragment,
                listOf(
                    switchItem(
                        "fragment_enabled", R.string.set_fragment_title, R.string.set_fragment_sub,
                        isOn = { store.fragmentEnabled },
                        onToggle = { store.fragmentEnabled = it },
                    ),
                    textItem(
                        "fragment_packets", R.string.set_fragment_packets_title, R.string.set_fragment_packets_sub,
                        enabled = { store.fragmentEnabled },
                        rawValue = { store.fragmentPackets },
                        displayValue = { store.fragmentPackets },
                        onSave = { store.fragmentPackets = it },
                    ),
                    textItem(
                        "fragment_length", R.string.set_fragment_length_title, R.string.set_fragment_length_sub,
                        enabled = { store.fragmentEnabled },
                        rawValue = { store.fragmentLength },
                        displayValue = { store.fragmentLength },
                        onSave = { store.fragmentLength = it },
                    ),
                    textItem(
                        "fragment_interval", R.string.set_fragment_interval_title, R.string.set_fragment_interval_sub,
                        enabled = { store.fragmentEnabled },
                        rawValue = { store.fragmentInterval },
                        displayValue = { store.fragmentInterval },
                        onSave = { store.fragmentInterval = it },
                    ),
                    textItem(
                        "fragment_max_split", R.string.set_fragment_split_title, R.string.set_fragment_split_sub,
                        enabled = { store.fragmentEnabled },
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.fragmentMaxSplit },
                        displayValue = { store.fragmentMaxSplit },
                        onSave = { store.fragmentMaxSplit = it },
                    ),
                ),
            ),
            Section(
                "observatory", R.string.set_section_observatory,
                listOf(
                    textItem(
                        "observatory_least_ping", R.string.set_obs_ping_title, R.string.set_obs_ping_sub,
                        rawValue = { store.observatoryLeastPing },
                        displayValue = { store.observatoryLeastPing },
                        onSave = { store.observatoryLeastPing = it },
                    ),
                    textItem(
                        "observatory_least_load", R.string.set_obs_load_title, R.string.set_obs_load_sub,
                        rawValue = { store.observatoryLeastLoad },
                        displayValue = { store.observatoryLeastLoad },
                        onSave = { store.observatoryLeastLoad = it },
                    ),
                    textItem(
                        "observatory_least_load_method", R.string.set_obs_method_title, R.string.set_obs_method_sub,
                        rawValue = { store.observatoryLeastLoadMethod },
                        displayValue = { store.observatoryLeastLoadMethod },
                        onSave = { store.observatoryLeastLoadMethod = it },
                    ),
                    textItem(
                        "observatory_least_load_sampling", R.string.set_obs_sampling_title, R.string.set_obs_sampling_sub,
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.observatoryLeastLoadSampling },
                        displayValue = { store.observatoryLeastLoadSampling },
                        onSave = { store.observatoryLeastLoadSampling = it },
                    ),
                    textItem(
                        "observatory_least_load_timeout", R.string.set_obs_timeout_title, R.string.set_obs_timeout_sub,
                        rawValue = { store.observatoryLeastLoadTimeout },
                        displayValue = { store.observatoryLeastLoadTimeout },
                        onSave = { store.observatoryLeastLoadTimeout = it },
                    ),
                ),
            ),
            Section(
                "advanced", R.string.set_section_advanced,
                listOf(
                    switchItem(
                        "is_booted", R.string.set_boot_title, R.string.set_boot_sub,
                        isOn = { store.isBooted },
                        onToggle = { store.isBooted = it },
                    ),
                    SettingItem(
                        key = "system_vpn_settings",
                        titleRes = R.string.set_sys_vpn_title,
                        subtitleRes = R.string.set_sys_vpn_sub,
                        kind = Kind.ACTION,
                        displayValue = { "" },
                    ),
                    textItem(
                        "delay_test_url", R.string.set_delay_url_title, R.string.set_delay_url_sub,
                        rawValue = { store.delayTestUrl },
                        displayValue = {
                            SettingsStore.displayOrDefault(
                                store.delayTestUrl, SettingsStore.DISPLAY_DELAY_TEST_URL,
                            )
                        },
                        hint = SettingsStore.DISPLAY_DELAY_TEST_URL,
                        onSave = { store.delayTestUrl = it },
                    ),
                    textItem(
                        "real_ping_concurrency", R.string.set_concurrency_title, R.string.set_concurrency_sub,
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.realPingConcurrency },
                        displayValue = { store.realPingConcurrency },
                        onSave = { store.realPingConcurrency = it },
                    ),
                    textItem(
                        "ip_api_url", R.string.set_ip_api_title, R.string.set_ip_api_sub,
                        rawValue = { store.ipApiUrl },
                        displayValue = {
                            SettingsStore.displayOrDefault(store.ipApiUrl, SettingsStore.DISPLAY_IP_API_URL)
                        },
                        hint = SettingsStore.DISPLAY_IP_API_URL,
                        onSave = { store.ipApiUrl = it },
                    ),
                ),
            ),
            Section(
                "mode", R.string.set_section_mode,
                listOf(
                    listItem(
                        "mode", R.string.set_mode_title, R.string.set_mode_sub,
                        // M2 only implements VPN mode.
                        entries = arrayOf(SettingsStore.MODE_VPN),
                        values = arrayOf(SettingsStore.MODE_VPN),
                        current = { store.mode },
                        onSave = { store.mode = it },
                    ),
                    switchItem(
                        "enable_root_mode", R.string.set_root_mode_title, R.string.set_root_mode_sub,
                        isOn = { store.enableRootMode },
                        onToggle = { store.enableRootMode = it },
                    ),
                    switchItem(
                        "lan_sharing", R.string.set_lan_sharing_title, R.string.set_lan_sharing_sub,
                        isOn = { store.lanSharing },
                        onToggle = { store.lanSharing = it },
                    ),
                ),
            ),
            Section(
                "clash_api", R.string.set_section_clash_api,
                listOf(
                    switchItem(
                        "clash_api_enabled", R.string.set_clash_api_enabled_title, R.string.set_clash_api_enabled_sub,
                        isOn = { store.clashApiEnabled },
                        onToggle = {
                            store.clashApiEnabled = it
                            ClashApiServer.restart(this)
                        },
                    ),
                    textItem(
                        "clash_api_port", R.string.set_clash_api_port_title, R.string.set_clash_api_port_sub,
                        inputType = InputType.TYPE_CLASS_NUMBER,
                        rawValue = { store.clashApiPort },
                        displayValue = { store.clashApiPort },
                        hint = SettingsStore.DEFAULT_CLASH_API_PORT,
                        onSave = {
                            store.clashApiPort = it
                            ClashApiServer.restart(this)
                        },
                    ),
                    textItem(
                        "clash_api_secret", R.string.set_clash_api_secret_title, R.string.set_clash_api_secret_sub,
                        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD,
                        rawValue = { store.clashApiSecret },
                        displayValue = {
                            if (store.clashApiSecret.isBlank()) getString(R.string.set_not_set) else "••••••"
                        },
                        onSave = {
                            store.clashApiSecret = it
                            ClashApiServer.restart(this)
                        },
                    ),
                    switchItem(
                        "clash_api_allow_lan", R.string.set_clash_api_lan_title, R.string.set_clash_api_lan_sub,
                        isOn = { store.clashApiAllowLan },
                        onToggle = {
                            store.clashApiAllowLan = it
                            ClashApiServer.restart(this)
                        },
                    ),
                    listItem(
                        "clash_mode", R.string.set_clash_mode_title, R.string.set_clash_mode_sub,
                        entries = arrayOf("rule", "global", "direct"),
                        values = arrayOf("rule", "global", "direct"),
                        current = { store.clashMode },
                        // Mode dibaca live tiap koneksi oleh resolver —
                        // tidak butuh restart server maupun VPN.
                        onSave = { store.clashMode = it },
                    ),
                ),
            ),
        )
    }

    // ---- Item builders ------------------------------------------------

    private fun switchItem(
        key: String,
        titleRes: Int,
        subtitleRes: Int,
        enabled: () -> Boolean = { true },
        notSupportedM2: Boolean = false,
        isOn: () -> Boolean,
        onToggle: (Boolean) -> Unit,
    ) = SettingItem(
        key = key, titleRes = titleRes, subtitleRes = subtitleRes,
        kind = Kind.SWITCH, enabled = enabled, notSupportedM2 = notSupportedM2,
        displayValue = {
            getString(if (isOn()) R.string.set_on else R.string.set_off)
        },
        isOn = isOn, onToggle = onToggle,
    )

    private fun textItem(
        key: String,
        titleRes: Int,
        subtitleRes: Int,
        enabled: () -> Boolean = { true },
        notSupportedM2: Boolean = false,
        inputType: Int = InputType.TYPE_CLASS_TEXT,
        rawValue: () -> String,
        displayValue: () -> String,
        hint: String? = null,
        onSave: (String) -> Unit,
    ) = SettingItem(
        key = key, titleRes = titleRes, subtitleRes = subtitleRes,
        kind = Kind.TEXT, enabled = enabled, notSupportedM2 = notSupportedM2,
        displayValue = displayValue, rawValue = rawValue,
        inputType = inputType, hint = hint, onSaveText = onSave,
    )

    private fun listItem(
        key: String,
        titleRes: Int,
        subtitleRes: Int,
        entriesRes: Int? = null,
        valuesRes: Int? = null,
        entries: Array<String>? = null,
        values: Array<String>? = null,
        enabled: () -> Boolean = { true },
        current: () -> String,
        onSave: (String) -> Unit,
        afterChange: () -> Unit = {},
    ): SettingItem {
        val entryList = entries ?: resources.getStringArray(entriesRes!!)
        val valueList = values ?: resources.getStringArray(valuesRes!!)
        return SettingItem(
            key = key, titleRes = titleRes, subtitleRes = subtitleRes,
            kind = Kind.LIST, enabled = enabled,
            displayValue = {
                val idx = valueList.indexOf(current())
                if (idx >= 0) entryList[idx] else current()
            },
            listEntries = entryList, listValues = valueList,
            listCurrent = current, onSaveList = onSave, afterChange = afterChange,
        )
    }

    // ---- Interaction ---------------------------------------------------

    private fun onItemTap(item: SettingItem) {
        if (!item.enabled()) return
        when (item.kind) {
            Kind.SWITCH -> {
                item.onToggle(!item.isOn())
                item.afterChange()
                refresh()
            }
            Kind.TEXT -> showEditDialog(item)
            Kind.LIST -> showListDialog(item)
            Kind.ACTION -> {
                if (item.key == "system_vpn_settings") {
                    runCatching {
                        startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                    }
                }
            }
        }
    }

    private fun onItemToggle(item: SettingItem, checked: Boolean) {
        if (!item.enabled()) return
        item.onToggle(checked)
        item.afterChange()
        refresh()
    }

    private fun showEditDialog(item: SettingItem) {
        val input = EditText(this).apply {
            setText(item.rawValue())
            setSelection(text.length)
            inputType = item.inputType
            hint = item.hint
        }
        MaterialAlertDialogBuilder(this)
            .setTitle(item.titleRes)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                item.onSaveText(input.text.toString().trim())
                item.afterChange()
                refresh()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showListDialog(item: SettingItem) {
        val checked = item.listValues.indexOf(item.listCurrent()).coerceAtLeast(0)
        MaterialAlertDialogBuilder(this)
            .setTitle(item.titleRes)
            .setSingleChoiceItems(item.listEntries, checked) { dialog, which ->
                item.onSaveList(item.listValues[which])
                item.afterChange()
                dialog.dismiss()
                refresh()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ---- Adapter ---------------------------------------------------------

    private class SettingsAdapter(
        private val onSectionClick: (Section) -> Unit,
        private val onItemTap: (SettingItem) -> Unit,
        private val onItemToggle: (SettingItem, Boolean) -> Unit,
    ) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

        var rows: List<Row> = emptyList()

        override fun getItemViewType(position: Int): Int =
            when (rows[position]) {
                is Row.Header -> VIEW_SECTION
                is Row.Item -> VIEW_ITEM
            }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val inflater = LayoutInflater.from(parent.context)
            return if (viewType == VIEW_SECTION) {
                SectionHolder(inflater.inflate(R.layout.item_settings_section, parent, false))
            } else {
                ItemHolder(inflater.inflate(R.layout.item_settings_row, parent, false))
            }
        }

        override fun getItemCount(): Int = rows.size

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val row = rows[position]) {
                is Row.Header -> {
                    // Expanded when its items follow it in the row list.
                    val expanded =
                        position + 1 < rows.size && rows[position + 1] is Row.Item
                    (holder as SectionHolder).bind(row.section, expanded, onSectionClick)
                }
                is Row.Item -> (holder as ItemHolder).bind(row.item, onItemTap, onItemToggle)
            }
        }

        private class SectionHolder(view: View) : RecyclerView.ViewHolder(view) {
            private val title: TextView = view.findViewById(R.id.section_title)
            private val arrow: ImageView = view.findViewById(R.id.section_arrow)

            fun bind(section: Section, expanded: Boolean, onClick: (Section) -> Unit) {
                title.setText(section.titleRes)
                arrow.rotation = if (expanded) 180f else 0f
                itemView.setOnClickListener { onClick(section) }
            }
        }

        private class ItemHolder(view: View) : RecyclerView.ViewHolder(view) {
            private val title: TextView = view.findViewById(R.id.item_title)
            private val subtitle: TextView = view.findViewById(R.id.item_subtitle)
            private val switch: SwitchMaterial = view.findViewById(R.id.item_switch)

            fun bind(
                item: SettingItem,
                onTap: (SettingItem) -> Unit,
                onToggle: (SettingItem, Boolean) -> Unit,
            ) {
                val context = itemView.context
                title.setText(item.titleRes)
                subtitle.text = subtitleFor(
                    showValueAsSubtitle =
                        item.kind == Kind.LIST || item.kind == Kind.TEXT,
                    staticSubtitle = context.getString(item.subtitleRes),
                    displayValue = item.displayValue(),
                    notSupportedM2 = item.notSupportedM2,
                    notSupportedLabel = context.getString(R.string.set_not_supported_m2),
                )
                val enabled = item.enabled()
                itemView.alpha = if (enabled) 1f else 0.4f
                if (item.kind == Kind.SWITCH) {
                    switch.visibility = View.VISIBLE
                    switch.setOnCheckedChangeListener(null)
                    switch.isChecked = item.isOn()
                    switch.isEnabled = enabled
                    switch.setOnCheckedChangeListener { _, checked ->
                        if (enabled) onToggle(item, checked)
                    }
                    itemView.setOnClickListener {
                        if (enabled) onTap(item)
                    }
                } else {
                    switch.visibility = View.GONE
                    switch.setOnCheckedChangeListener(null)
                    itemView.setOnClickListener {
                        if (enabled) onTap(item)
                    }
                }
            }
        }

        companion object {
            private const val VIEW_SECTION = 0
            private const val VIEW_ITEM = 1
        }
    }

    companion object {
        private const val KEY_EXPANDED = "expanded_sections"

        /**
         * Hev TUN settings are HIDDEN from the Settings UI (v1.0.5,
         * group A): Hev TUN cannot run in TaptapNG — it needs the
         * native hev-socks5-tunnel library, and this app ships no
         * .so on purpose. The values stay stored (defaults
         * unchanged); only the rows are hidden. [visibleSettingKeys]
         * is the filter buildSections applies; unit-tested in
         * HevTunHiddenTest.
         */
        val HIDDEN_SETTING_KEYS: Set<String> =
            setOf("use_hev_tun", "hev_tun_log_level", "hev_tun_rw_timeout")

        internal fun visibleSettingKeys(keys: List<String>): List<String> =
            keys.filter { it !in HIDDEN_SETTING_KEYS }

        /** Sections expanded on first open, matching v2rayNG. */
        private val DEFAULT_EXPANDED = setOf("ui", "vpn", "core", "advanced", "mode")

        /**
         * Subtitle shown under a setting title (v1.0.27, mirroring
         * v2rayNG's SettingsListItem / SettingsEditItem): LIST and
         * TEXT rows show the current value as the summary, SWITCH
         * and ACTION rows keep the static subtitle. A blank value
         * falls back to the static subtitle; the "not supported"
         * marker is appended whenever it applies. Pure string
         * logic — unit-tested in SettingsSubtitleTest.
         */
        internal fun subtitleFor(
            showValueAsSubtitle: Boolean,
            staticSubtitle: String,
            displayValue: String,
            notSupportedM2: Boolean,
            notSupportedLabel: String,
        ): String {
            val base = if (showValueAsSubtitle && displayValue.isNotBlank()) {
                displayValue
            } else {
                staticSubtitle
            }
            return if (notSupportedM2) "$base • $notSupportedLabel" else base
        }
    }
}
