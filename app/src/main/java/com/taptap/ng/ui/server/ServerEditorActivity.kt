package com.taptap.ng.ui.server

import android.content.Context
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.textfield.TextInputLayout
import com.google.gson.JsonParser
import com.taptap.ng.R
import com.taptap.ng.TaptapNGApp
import com.taptap.ng.core.CertFingerprintFetcher
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import com.taptap.ng.data.SettingsStore

/**
 * Profile editor with Views, mirroring v2rayNG's server activities:
 * (a) Basic -> (b) protocol fields -> (c) Network -> (d) Stream
 * Security (TLS) -> (e) Xray method chips (SlowDNS / Onering /
 * Pemicu) + the SSH method chips (Payload / Enhanced / TLS /
 * SlowDNS / Pemicu, like v2rayNG's ServerSshActivity). v1.0.31: the
 * Xray method section is hidden while editing an SSH entry — SSH
 * gets its Pemicu chip in the SSH method row instead, bound to the
 * same ProfileItem.pemicuEnabled field. Every field is an
 * OUTLINED TextInputLayout; dropdowns are exposed
 * AutoCompleteTextViews. Save lives in the top bar (checkmark).
 *
 * Fields the M2 engine does not use yet are still stored on the
 * profile, so v2rayNG <-> TaptapNG copy round-trips (LinkParser).
 */
class ServerEditorActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_GUID = "guid"
        const val EXTRA_TYPE = "type"

        // Dropdown options, exactly as in v2rayNG.
        private val VMESS_SECURITY = listOf("chacha20-poly1305", "aes-128-gcm", "auto", "none", "zero")
        private val FLOWS = listOf("", "xtls-rprx-vision", "xtls-rprx-vision-udp443")
        private val SS_METHODS = listOf(
            "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
            "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
        )
        private val NETWORKS = listOf("tcp", "kcp", "ws", "httpupgrade", "xhttp", "h2", "grpc")
        private val TCP_HEAD_TYPES = listOf("none", "http")
        private val KCP_HEAD_TYPES = listOf("none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns")
        private val GRPC_MODES = listOf("gun", "multi")
        private val XHTTP_MODES = listOf("auto", "packet-up", "stream-up", "stream-one")
        private val STREAM_SECURITY = listOf("", "tls", "reality")
        private val FINGERPRINTS = listOf(
            "", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
            "random", "randomized",
        )
        private val ALPNS = listOf("", "h3", "h2", "http/1.1", "h3,h2,http/1.1", "h3,h2", "h2,http/1.1")
        private val BROWSER_DIALER_DISPLAYS = listOf("Disable", "OkHttp", "WebView")
        private val BROWSER_DIALER_VALUES = listOf("", "OkHttp", "WebView")
        private val DNSTT_TYPE_DISPLAYS = listOf("TXT", "NULL")
        private val DNSTT_TYPE_VALUES = listOf("txt", "null")
        private val SSH_SNI_VERSION_DISPLAYS = listOf("Default", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
        private val SSH_SNI_VERSION_VALUES = listOf("default", "tls1", "tls1.1", "tls1.2", "tls1.3")

        /**
         * v1.0.31: the Xray method section (SlowDNS / Onering / Pemicu)
         * belongs to VMess/VLESS/Trojan/SS only. SSH entries get their
         * Pemicu chip in the SSH method row instead, so the whole
         * Xray section is hidden while an SSH entry is being edited.
         * Pure so a JVM test can assert the rule.
         */
        fun isXrayMethodVisible(configType: ConfigType): Boolean =
            configType != ConfigType.SSH
    }

    private lateinit var store: ProfileStore
    private var existing: ProfileItem? = null
    private var configType: ConfigType = ConfigType.SSH

    /** Dropdown id -> (display list, value list) for display<->value mapping. */
    private val dropdownOptions = mutableMapOf<Int, Pair<List<String>, List<String>>>()

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(TaptapNGApp.wrapLocale(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_server_editor)

        store = ProfileStore(ProfileStore.defaultFile(filesDir))
        store.load()
        val guid = intent.getStringExtra(EXTRA_GUID)
        existing = guid?.let { store.find(it) }
        configType = existing?.configType
            ?: runCatching { ConfigType.valueOf(intent.getStringExtra(EXTRA_TYPE) ?: "SSH") }
                .getOrDefault(ConfigType.SSH)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        toolbar.title = getString(if (existing == null) R.string.editor_add else R.string.editor_edit)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        bindDropdowns()
        fillFields()
        bindChips()
        bindSwitchRows()
        bindFetchButton()
        updateSections()
    }

    /**
     * "Allow insecure" rows (v1.0.26): the whole row toggles the
     * switch, like v2rayNG's SettingsSwitchItem — the switch itself
     * is not clickable, its label lives in the row (TextView).
     */
    private fun bindSwitchRows() {
        findViewById<View>(R.id.row_insecure).setOnClickListener {
            switch(R.id.switch_insecure).toggle()
        }
        findViewById<View>(R.id.row_ssh_insecure).setOnClickListener {
            switch(R.id.switch_ssh_insecure).toggle()
        }
    }

    // ---- view helpers ----

    private fun text(id: Int): String =
        findViewById<EditText>(id).text?.toString().orEmpty()

    private fun setText(id: Int, value: String) {
        findViewById<EditText>(id).setText(value)
    }

    private fun chip(id: Int): Chip = findViewById(id)

    private fun switch(id: Int): SwitchMaterial = findViewById(id)

    private fun show(id: Int, visible: Boolean) {
        findViewById<View>(id).visibility = if (visible) View.VISIBLE else View.GONE
    }

    private fun bindDropdown(
        id: Int,
        displays: List<String>,
        values: List<String> = displays,
        selected: String = "",
    ) {
        val view = findViewById<AutoCompleteTextView>(id)
        view.setAdapter(ArrayAdapter(this, android.R.layout.simple_list_item_1, displays))
        dropdownOptions[id] = displays to values
        val idx = values.indexOf(selected)
        view.setText(if (idx >= 0) displays[idx] else selected, false)
    }

    /** Current dropdown value (display text mapped back to its value). */
    private fun dropdownValue(id: Int): String {
        val view = findViewById<AutoCompleteTextView>(id)
        val shown = view.text?.toString().orEmpty()
        val (displays, values) = dropdownOptions[id] ?: return shown
        val idx = displays.indexOf(shown)
        return if (idx >= 0) values[idx] else shown
    }

    private fun bindDropdowns() {
        bindDropdown(R.id.input_vmess_security, VMESS_SECURITY, selected = "auto")
        bindDropdown(R.id.input_flow, FLOWS)
        bindDropdown(R.id.input_ss_security, SS_METHODS, selected = "aes-256-gcm")
        bindDropdown(R.id.input_network, NETWORKS, selected = "tcp")
        bindDropdown(R.id.input_header_type, TCP_HEAD_TYPES, selected = "none")
        bindDropdown(R.id.input_grpc_mode, GRPC_MODES, selected = "gun")
        bindDropdown(R.id.input_xhttp_mode, XHTTP_MODES, selected = "auto")
        bindDropdown(R.id.input_browser_dialer, BROWSER_DIALER_DISPLAYS, BROWSER_DIALER_VALUES)
        bindDropdown(R.id.input_stream_security, STREAM_SECURITY)
        bindDropdown(R.id.input_fingerprint, FINGERPRINTS)
        bindDropdown(R.id.input_alpn, ALPNS)
        bindDropdown(R.id.input_dnstt_type, DNSTT_TYPE_DISPLAYS, DNSTT_TYPE_VALUES, selected = "txt")
        bindDropdown(
            R.id.input_ssh_sni_version, SSH_SNI_VERSION_DISPLAYS, SSH_SNI_VERSION_VALUES,
            selected = "default",
        )
        findViewById<AutoCompleteTextView>(R.id.input_network).setOnItemClickListener { _, _, _, _ ->
            updateNetworkSections()
        }
        findViewById<AutoCompleteTextView>(R.id.input_stream_security).setOnItemClickListener { _, _, _, _ ->
            updateTlsSections()
        }
    }

    // ---- fill ----

    private fun fillFields() {
        val item = existing
        if (item == null) {
            // New server: v2rayNG defaults (port 443, 22 for SSH).
            setText(R.id.input_port, if (configType == ConfigType.SSH) "22" else "443")
            setText(R.id.input_pemicu_interval, "15")
            return
        }
        setText(R.id.input_remarks, item.remarks)
        setText(R.id.input_group, item.group)
        setText(R.id.input_address, item.address)
        setText(R.id.input_port, item.port.toString())
        // SSH
        setText(R.id.input_username, item.username)
        setText(R.id.input_password, item.password)
        setText(R.id.input_private_key, item.privateKey)
        setText(R.id.input_ssh_payload, item.sshPayload)
        setText(R.id.input_ssh_remote_proxy, item.sshRemoteProxy)
        setText(R.id.input_ssh_sni, item.sshSni)
        bindDropdown(
            R.id.input_ssh_sni_version, SSH_SNI_VERSION_DISPLAYS, SSH_SNI_VERSION_VALUES,
            selected = item.sshSniVersion,
        )
        switch(R.id.switch_ssh_insecure).isChecked = item.sshInsecure
        // Protocol fields
        setText(R.id.input_uuid, item.uuid)
        bindDropdown(R.id.input_vmess_security, VMESS_SECURITY, selected = item.security.ifBlank { "auto" })
        bindDropdown(R.id.input_flow, FLOWS, selected = item.flow)
        setText(R.id.input_encryption, item.encryption.ifBlank { item.method })
        setText(R.id.input_password_proxy, item.password)
        bindDropdown(
            R.id.input_ss_security, SS_METHODS,
            selected = item.method.ifBlank { "aes-256-gcm" },
        )
        bindDropdown(R.id.input_network, NETWORKS, selected = item.network.ifBlank { "tcp" })
        // gRPC reuses the host/path boxes as authority/serviceName;
        // KCP reuses the path box as the seed (path itself is hidden).
        if (item.network == "grpc") {
            setText(R.id.input_host, item.authority.ifBlank { item.host })
            setText(R.id.input_path, item.serviceName.ifBlank { item.path })
        } else {
            setText(R.id.input_host, item.host)
            setText(R.id.input_path, item.path)
        }
        bindDropdown(
            R.id.input_header_type,
            if (item.network == "kcp") KCP_HEAD_TYPES else TCP_HEAD_TYPES,
            selected = item.headerType.ifBlank { "none" },
        )
        bindDropdown(R.id.input_grpc_mode, GRPC_MODES, selected = item.mode.ifBlank { "gun" })
        bindDropdown(R.id.input_xhttp_mode, XHTTP_MODES, selected = item.xhttpMode.ifBlank { "auto" })
        setText(R.id.input_seed, item.seed)
        setText(R.id.input_kcp_mtu, item.kcpMtu)
        setText(R.id.input_kcp_tti, item.kcpTti)
        setText(R.id.input_xhttp_extra, item.xhttpExtra)
        setText(R.id.input_final_mask, item.finalMask)
        bindDropdown(
            R.id.input_browser_dialer, BROWSER_DIALER_DISPLAYS, BROWSER_DIALER_VALUES,
            selected = item.browserDialerMode,
        )
        bindDropdown(R.id.input_stream_security, STREAM_SECURITY, selected = item.streamSecurity)
        setText(R.id.input_sni, item.sni)
        bindDropdown(R.id.input_fingerprint, FINGERPRINTS, selected = item.fingerprint)
        bindDropdown(R.id.input_alpn, ALPNS, selected = item.alpn)
        switch(R.id.switch_insecure).isChecked = item.insecure
        setText(R.id.input_ech, item.echConfigList)
        setText(R.id.input_vcn, item.verifyPeerCertByName)
        setText(R.id.input_pcs, item.pinnedCA256)
        setText(R.id.input_reality_pbk, item.realityPublicKey)
        setText(R.id.input_reality_sid, item.realityShortId)
        setText(R.id.input_reality_spx, item.realitySpiderX)
        setText(R.id.input_reality_pqv, item.realityMldsa65Verify)
        // Xray method
        bindDropdown(
            R.id.input_dnstt_type, DNSTT_TYPE_DISPLAYS, DNSTT_TYPE_VALUES,
            selected = item.dnsttRecordType.ifBlank { "txt" },
        )
        setText(R.id.input_dnstt_ns, item.dnsttNS)
        setText(R.id.input_dnstt_pubkey, item.dnsttPubkey)
        setText(R.id.input_dnstt_resolver, item.dnsttResolver)
        setText(R.id.input_onering_bug, item.oneringBug)
        setText(R.id.input_pemicu_domain, item.pemicuDomain)
        setText(R.id.input_pemicu_port, item.pemicuPort?.toString() ?: "")
        setText(R.id.input_pemicu_interval, item.pemicuInterval?.toString() ?: "15")
    }

    // ---- chips / sections ----

    private fun bindChips() {
        val protocolChips = mapOf(
            R.id.chip_ssh to ConfigType.SSH,
            R.id.chip_vmess to ConfigType.VMESS,
            R.id.chip_vless to ConfigType.VLESS,
            R.id.chip_trojan to ConfigType.TROJAN,
            R.id.chip_ss to ConfigType.SHADOWSOCKS,
        )
        protocolChips.forEach { (id, type) ->
            val c = chip(id)
            c.isChecked = configType == type
            c.setOnClickListener {
                // Single-selection group: tapping the checked chip would
                // uncheck it and leave no protocol — keep it checked.
                if (!c.isChecked) {
                    c.isChecked = true
                    return@setOnClickListener
                }
                configType = type
                if (existing == null) {
                    val port = text(R.id.input_port)
                    if (port.isBlank() || port == "22" || port == "443") {
                        setText(R.id.input_port, if (type == ConfigType.SSH) "22" else "443")
                    }
                }
                updateSections()
            }
        }
        // SSH method chips toggle their field sections.
        chip(R.id.chip_ssh_payload).setOnCheckedChangeListener { _, _ -> updateSshSections() }
        chip(R.id.chip_ssh_enhanced).setOnCheckedChangeListener { _, _ -> updateSshSections() }
        chip(R.id.chip_ssh_tls).setOnCheckedChangeListener { _, _ -> updateSshSections() }
        chip(R.id.chip_ssh_slowdns).setOnCheckedChangeListener { _, _ -> updateSshSections() }
        // Xray method chips toggle their field sections.
        chip(R.id.chip_slowdns).setOnCheckedChangeListener { _, _ -> updateXraySections() }
        chip(R.id.chip_onering).setOnCheckedChangeListener { _, _ -> updateXraySections() }
        // v1.0.31: the SSH Pemicu chip mirrors the Xray Pemicu chip —
        // one field (ProfileItem.pemicuEnabled), two controls. The
        // Xray chip stays the canonical state holder (save +
        // validation + updateXraySections read it); the SSH chip only
        // writes through it. CompoundButton only notifies on a real
        // value change, so the two-way sync cannot loop.
        chip(R.id.chip_ssh_pemicu).setOnCheckedChangeListener { _, isChecked ->
            chip(R.id.chip_pemicu).isChecked = isChecked
        }
        chip(R.id.chip_pemicu).setOnCheckedChangeListener { _, isChecked ->
            chip(R.id.chip_ssh_pemicu).isChecked = isChecked
            updateXraySections()
        }

        // Restore chip states from the existing profile.
        existing?.let { item ->
            chip(R.id.chip_ssh_payload).isChecked = item.sshUsePayload
            chip(R.id.chip_ssh_enhanced).isChecked = item.sshUseEnhanced
            chip(R.id.chip_ssh_tls).isChecked = item.sshUseTls
            chip(R.id.chip_ssh_slowdns).isChecked = item.sshUseSlowdns
            chip(R.id.chip_slowdns).isChecked = item.dnsttEnabled
            chip(R.id.chip_onering).isChecked = item.oneringEnabled
            chip(R.id.chip_pemicu).isChecked = item.pemicuEnabled
            chip(R.id.chip_ssh_pemicu).isChecked = item.pemicuEnabled
        }
    }

    private fun bindFetchButton() {
        findViewById<MaterialButton>(R.id.button_fetch_fingerprint).setOnClickListener { view ->
            val button = view as MaterialButton
            val address = text(R.id.input_address).trim()
            val port = text(R.id.input_port).toIntOrNull()
            if (address.isBlank() || port == null || port !in 1..65535) {
                Toast.makeText(this, R.string.toast_address_required, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            button.isEnabled = false
            CertFingerprintFetcher.fetch(address, port, text(R.id.input_sni).ifBlank { null }) { fp ->
                runOnUiThread {
                    button.isEnabled = true
                    if (fp != null) {
                        setText(R.id.input_pcs, fp)
                        Toast.makeText(this, R.string.toast_fetch_fp_ok, Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this, R.string.toast_fetch_fp_failed, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    private fun updateSections() {
        val isSsh = configType == ConfigType.SSH
        show(R.id.section_ssh, isSsh)
        show(R.id.section_proxy, !isSsh)
        // v1.0.31: no Xray method section for SSH entries — their
        // Pemicu chip lives in the SSH method row instead.
        show(R.id.label_xray_method, isXrayMethodVisible(configType))
        show(R.id.chip_xray_method, isXrayMethodVisible(configType))
        // UUID only for VMess/VLESS; password only for Trojan/SS.
        show(
            R.id.layout_uuid,
            configType == ConfigType.VMESS || configType == ConfigType.VLESS,
        )
        show(R.id.layout_vmess_security, configType == ConfigType.VMESS)
        show(R.id.layout_flow, configType == ConfigType.VLESS)
        show(R.id.layout_encryption, configType == ConfigType.VLESS)
        show(
            R.id.layout_password_proxy,
            configType == ConfigType.TROJAN || configType == ConfigType.SHADOWSOCKS,
        )
        show(R.id.layout_ss_security, configType == ConfigType.SHADOWSOCKS)
        updateSshSections()
        updateXraySections()
        if (!isSsh) {
            updateNetworkSections()
            updateTlsSections()
        }
    }

    private fun updateNetworkSections() {
        val network = dropdownValue(R.id.input_network).ifBlank { "tcp" }
        val headOptions = if (network == "kcp") KCP_HEAD_TYPES else TCP_HEAD_TYPES
        val currentHead = dropdownValue(R.id.input_header_type)
        bindDropdown(R.id.input_header_type, headOptions, selected = currentHead)
        show(R.id.layout_header_type, network == "tcp" || network == "kcp")
        show(R.id.layout_grpc_mode, network == "grpc")
        show(R.id.layout_xhttp_mode, network == "xhttp")
        // Host label per network (v2rayNG).
        val hostLayout = findViewById<TextInputLayout>(R.id.layout_host)
        hostLayout.hint = getString(
            when (network) {
                "tcp", "httpupgrade", "xhttp", "h2" -> R.string.editor_host_http
                "ws" -> R.string.editor_host_ws
                "grpc" -> R.string.editor_host_grpc
                else -> R.string.editor_host_sni
            }
        )
        // Path: hidden for KCP (seed is used instead); label per network.
        show(R.id.layout_path, network != "kcp")
        val pathLayout = findViewById<TextInputLayout>(R.id.layout_path)
        pathLayout.hint = getString(
            when (network) {
                "ws" -> R.string.editor_path_ws
                "httpupgrade" -> R.string.editor_path_httpupgrade
                "xhttp" -> R.string.editor_path_xhttp
                "h2" -> R.string.editor_path_h2
                "grpc" -> R.string.editor_path_grpc
                else -> R.string.editor_path
            }
        )
        show(R.id.layout_xhttp_extra, network == "xhttp")
        show(R.id.section_kcp, network == "kcp")
        show(R.id.layout_browser_dialer, network == "ws" || network == "xhttp")
    }

    private fun updateTlsSections() {
        val security = dropdownValue(R.id.input_stream_security)
        show(R.id.section_tls_fields, security == "tls" || security == "reality")
        show(R.id.section_tls_only, security == "tls")
        show(R.id.section_reality, security == "reality")
    }

    private fun updateSshSections() {
        val showPayload = chip(R.id.chip_ssh_payload).isChecked || chip(R.id.chip_ssh_enhanced).isChecked
        show(R.id.section_ssh_payload, showPayload)
        show(R.id.section_ssh_tls, chip(R.id.chip_ssh_tls).isChecked)
        // SSH SlowDNS chip shares the DNSTT fields with the Xray chip.
        if (chip(R.id.chip_ssh_slowdns).isChecked) {
            chip(R.id.chip_slowdns).isChecked = true
        }
        updateXraySections()
    }

    private fun updateXraySections() {
        val slowdns = chip(R.id.chip_slowdns).isChecked || chip(R.id.chip_ssh_slowdns).isChecked
        show(R.id.section_dnstt, slowdns)
        show(R.id.section_onering, chip(R.id.chip_onering).isChecked)
        show(R.id.section_pemicu, chip(R.id.chip_pemicu).isChecked)
    }

    // Menu inflated here (see MainActivity): `app:menu` in the layout
    // does not survive setSupportActionBar, and clicks arrive via
    // onOptionsItemSelected, not the Toolbar's own click listener.
    // Without this the save checkmark never appears.
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.editor_toolbar, menu)
        // v2rayNG shows delete only when editing an existing server.
        menu.findItem(R.id.action_delete)?.isVisible = existing != null
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (onToolbarMenu(item)) return true
        return super.onOptionsItemSelected(item)
    }

    private fun onToolbarMenu(item: MenuItem): Boolean {
        if (item.itemId == R.id.action_save) {
            save()
            return true
        }
        if (item.itemId == R.id.action_delete) {
            deleteCurrent()
            return true
        }
        return false
    }

    /** Delete the server being edited (v2rayNG parity; same confirm
     *  rule as the main list's row delete). */
    private fun deleteCurrent() {
        val item = existing ?: return
        val doDelete = {
            store.remove(item.guid)
            finish()
        }
        if (SettingsStore(this).confirmRemove) {
            AlertDialog.Builder(this)
                .setMessage(R.string.confirm_delete_server)
                .setPositiveButton(R.string.action_delete) { _, _ -> doDelete() }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        } else {
            doDelete()
        }
    }

    private fun isValidJson(raw: String): Boolean =
        runCatching { JsonParser.parseString(raw); true }.getOrDefault(false)

    private fun save() {
        if (text(R.id.input_remarks).isBlank()) {
            Toast.makeText(this, R.string.toast_remarks_required, Toast.LENGTH_SHORT).show()
            return
        }
        val address = text(R.id.input_address).trim()
        if (address.isBlank()) {
            Toast.makeText(this, R.string.toast_address_required, Toast.LENGTH_SHORT).show()
            return
        }
        val port = text(R.id.input_port).toIntOrNull()
        if (port == null || port !in 1..65535) {
            Toast.makeText(this, R.string.toast_port_invalid, Toast.LENGTH_SHORT).show()
            return
        }
        val isSsh = configType == ConfigType.SSH
        if (isSsh) {
            if (text(R.id.input_password).isBlank() && text(R.id.input_private_key).isBlank()) {
                Toast.makeText(this, R.string.toast_ssh_auth_required, Toast.LENGTH_SHORT).show()
                return
            }
        } else {
            when (configType) {
                ConfigType.VMESS, ConfigType.VLESS -> {
                    if (text(R.id.input_uuid).isBlank()) {
                        Toast.makeText(this, R.string.toast_uuid_required, Toast.LENGTH_SHORT).show()
                        return
                    }
                }
                ConfigType.TROJAN, ConfigType.SHADOWSOCKS -> {
                    if (text(R.id.input_password_proxy).isBlank()) {
                        Toast.makeText(this, R.string.toast_password_required, Toast.LENGTH_SHORT).show()
                        return
                    }
                }
                else -> Unit
            }
            if (configType == ConfigType.TROJAN && dropdownValue(R.id.input_stream_security).isBlank()) {
                Toast.makeText(this, R.string.toast_tls_required, Toast.LENGTH_SHORT).show()
                return
            }
            if (text(R.id.input_final_mask).isNotBlank() &&
                !isValidJson(text(R.id.input_final_mask))
            ) {
                Toast.makeText(
                    this,
                    getString(R.string.toast_invalid_json, "finalMask"),
                    Toast.LENGTH_SHORT,
                ).show()
                return
            }
            if (text(R.id.input_xhttp_extra).isNotBlank() &&
                !isValidJson(text(R.id.input_xhttp_extra))
            ) {
                Toast.makeText(
                    this,
                    getString(R.string.toast_invalid_json, "xhttpExtra"),
                    Toast.LENGTH_SHORT,
                ).show()
                return
            }
        }
        val usePayload = chip(R.id.chip_ssh_payload).isChecked || chip(R.id.chip_ssh_enhanced).isChecked
        if (usePayload && text(R.id.input_ssh_payload).isBlank()) {
            Toast.makeText(this, R.string.toast_payload_required, Toast.LENGTH_SHORT).show()
            return
        }
        val slowdns = chip(R.id.chip_slowdns).isChecked || chip(R.id.chip_ssh_slowdns).isChecked
        if (slowdns && (text(R.id.input_dnstt_ns).isBlank() || text(R.id.input_dnstt_pubkey).isBlank())) {
            Toast.makeText(this, R.string.toast_slowdns_required, Toast.LENGTH_SHORT).show()
            return
        }
        // v1.0.24 (M5): chip Pemicu nyala tapi Domain pemicu kosong =
        // entry tidak akan pernah di-prime — tolak save seperti
        // SlowDNS (NS + pubkey wajib) supaya tidak ada entry yang
        // "pemicunya nyala" tapi diam-diam tidak di-prime.
        if (chip(R.id.chip_pemicu).isChecked && text(R.id.input_pemicu_domain).isBlank()) {
            Toast.makeText(this, R.string.toast_pemicu_required, Toast.LENGTH_SHORT).show()
            return
        }

        val network = dropdownValue(R.id.input_network).ifBlank { "tcp" }
        val streamSecurity = dropdownValue(R.id.input_stream_security)
        val hostText = text(R.id.input_host)
        val pathText = text(R.id.input_path)
        val isGrpc = network == "grpc"
        val isKcp = network == "kcp"
        val isXhttp = network == "xhttp"

        val item = (existing ?: ProfileItem()).copy(
            remarks = text(R.id.input_remarks),
            group = text(R.id.input_group).trim(),
            configType = configType,
            address = address,
            port = port,
            username = text(R.id.input_username),
            password = if (isSsh) text(R.id.input_password) else text(R.id.input_password_proxy),
            privateKey = text(R.id.input_private_key),
            sshUsePayload = chip(R.id.chip_ssh_payload).isChecked,
            sshPayload = text(R.id.input_ssh_payload),
            sshRemoteProxy = text(R.id.input_ssh_remote_proxy),
            sshUseEnhanced = chip(R.id.chip_ssh_enhanced).isChecked,
            sshUseTls = chip(R.id.chip_ssh_tls).isChecked,
            sshSni = text(R.id.input_ssh_sni),
            sshSniVersion = dropdownValue(R.id.input_ssh_sni_version).ifBlank { "default" },
            sshInsecure = switch(R.id.switch_ssh_insecure).isChecked,
            sshUseSlowdns = chip(R.id.chip_ssh_slowdns).isChecked,
            uuid = text(R.id.input_uuid),
            security = dropdownValue(R.id.input_vmess_security).ifBlank { "auto" },
            method = when (configType) {
                ConfigType.SHADOWSOCKS -> dropdownValue(R.id.input_ss_security).ifBlank { "aes-256-gcm" }
                ConfigType.VLESS -> text(R.id.input_encryption).ifBlank { "none" }
                else -> existing?.method ?: ""
            },
            encryption = if (configType == ConfigType.VLESS) {
                text(R.id.input_encryption).ifBlank { "none" }
            } else {
                existing?.encryption ?: "none"
            },
            flow = dropdownValue(R.id.input_flow),
            network = network,
            headerType = dropdownValue(R.id.input_header_type).ifBlank { "none" },
            mode = if (isGrpc) dropdownValue(R.id.input_grpc_mode) else "",
            xhttpMode = if (isXhttp) dropdownValue(R.id.input_xhttp_mode) else "",
            host = hostText,
            path = if (isKcp) text(R.id.input_seed) else pathText,
            authority = if (isGrpc) hostText else "",
            serviceName = if (isGrpc) pathText else "",
            xhttpExtra = if (isXhttp) text(R.id.input_xhttp_extra) else "",
            seed = if (isKcp) text(R.id.input_seed) else "",
            kcpMtu = if (isKcp) text(R.id.input_kcp_mtu) else "",
            kcpTti = if (isKcp) text(R.id.input_kcp_tti) else "",
            finalMask = text(R.id.input_final_mask),
            browserDialerMode = if (network == "ws" || isXhttp) {
                dropdownValue(R.id.input_browser_dialer)
            } else {
                ""
            },
            streamSecurity = streamSecurity,
            tls = streamSecurity == "tls" || streamSecurity == "reality",
            sni = text(R.id.input_sni),
            fingerprint = dropdownValue(R.id.input_fingerprint),
            alpn = dropdownValue(R.id.input_alpn),
            insecure = switch(R.id.switch_insecure).isChecked,
            echConfigList = text(R.id.input_ech),
            verifyPeerCertByName = text(R.id.input_vcn),
            pinnedCA256 = text(R.id.input_pcs),
            realityPublicKey = text(R.id.input_reality_pbk),
            realityShortId = text(R.id.input_reality_sid),
            realitySpiderX = text(R.id.input_reality_spx),
            realityMldsa65Verify = text(R.id.input_reality_pqv),
            dnsttEnabled = slowdns,
            dnsttRecordType = dropdownValue(R.id.input_dnstt_type).ifBlank { "txt" },
            dnsttNS = text(R.id.input_dnstt_ns),
            dnsttPubkey = text(R.id.input_dnstt_pubkey),
            dnsttResolver = text(R.id.input_dnstt_resolver),
            oneringEnabled = chip(R.id.chip_onering).isChecked,
            oneringBug = text(R.id.input_onering_bug),
            pemicuEnabled = chip(R.id.chip_pemicu).isChecked,
            pemicuDomain = text(R.id.input_pemicu_domain),
            pemicuPort = text(R.id.input_pemicu_port).toIntOrNull(),
            pemicuInterval = text(R.id.input_pemicu_interval).toIntOrNull(),
        )
        if (existing == null) store.add(item) else store.update(item)
        finish()
    }
}
