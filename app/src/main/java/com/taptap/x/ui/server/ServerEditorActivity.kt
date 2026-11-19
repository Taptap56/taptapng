package com.taptap.x.ui.server

import android.content.Context
import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.chip.Chip
import com.google.android.material.textfield.TextInputEditText
import com.taptap.x.R
import com.taptap.x.TaptapXApp
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.data.ProfileStore

/**
 * Profile editor with Views, mirroring v2rayNG's server activities:
 * common fields + protocol fields + the "Xray method" chips
 * (SlowDNS / Onering / Pemicu) + the SSH method chips (Payload /
 * Enhanced / TLS / SlowDNS, like v2rayNG's ServerSshActivity).
 * Save lives in the top bar (checkmark), like v2rayNG.
 */
class ServerEditorActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_GUID = "guid"
        const val EXTRA_TYPE = "type"
    }

    private lateinit var store: ProfileStore
    private var existing: ProfileItem? = null
    private var configType: ConfigType = ConfigType.SSH

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(TaptapXApp.wrapLocale(newBase))
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
        toolbar.setOnMenuItemClickListener { item -> onToolbarMenu(item) }

        val networkSpinner = findViewById<Spinner>(R.id.spinner_network)
        networkSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            resources.getStringArray(R.array.network_entries),
        )

        fillFields()
        bindChips()
        updateSections()
    }

    private fun text(id: Int): String =
        findViewById<TextInputEditText>(id).text?.toString().orEmpty()

    private fun setText(id: Int, value: String) {
        findViewById<TextInputEditText>(id).setText(value)
    }

    private fun chip(id: Int): Chip = findViewById(id)

    private fun fillFields() {
        val item = existing ?: return
        setText(R.id.input_remarks, item.remarks)
        setText(R.id.input_group, item.group)
        setText(R.id.input_address, item.address)
        setText(R.id.input_port, item.port.toString())
        setText(R.id.input_username, item.username)
        setText(R.id.input_password, item.password)
        setText(R.id.input_private_key, item.privateKey)
        setText(R.id.input_uuid, item.uuid)
        setText(R.id.input_password_proxy, item.password)
        setText(R.id.input_method, item.method)
        setText(R.id.input_host, item.host)
        setText(R.id.input_path, item.path)
        setText(R.id.input_sni, item.sni)
        setText(R.id.input_fingerprint, item.fingerprint)
        setText(R.id.input_alpn, item.alpn)
        setText(R.id.input_ssh_payload, item.sshPayload)
        setText(R.id.input_ssh_remote_proxy, item.sshRemoteProxy)
        setText(R.id.input_ssh_sni, item.sshSni)
        setText(R.id.input_dnstt_ns, item.dnsttNS)
        setText(R.id.input_dnstt_pubkey, item.dnsttPubkey)
        setText(R.id.input_dnstt_resolver, item.dnsttResolver)
        setText(R.id.input_onering_bug, item.oneringBug)
        setText(R.id.input_pemicu_domain, item.pemicuDomain)
        setText(R.id.input_pemicu_port, item.pemicuPort?.toString() ?: "")
        setText(R.id.input_pemicu_interval, item.pemicuInterval?.toString() ?: "15")
        findViewById<Spinner>(R.id.spinner_network).setSelection(
            resources.getStringArray(R.array.network_values).indexOf(item.network).coerceAtLeast(0)
        )
        findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_tls).isChecked = item.tls
        findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_insecure).isChecked = item.insecure
        findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_ssh_insecure).isChecked = item.sshInsecure
    }

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
        chip(R.id.chip_pemicu).setOnCheckedChangeListener { _, _ -> updateXraySections() }

        // Restore chip states from the existing profile.
        existing?.let { item ->
            chip(R.id.chip_ssh_payload).isChecked = item.sshUsePayload
            chip(R.id.chip_ssh_enhanced).isChecked = item.sshUseEnhanced
            chip(R.id.chip_ssh_tls).isChecked = item.sshUseTls
            chip(R.id.chip_ssh_slowdns).isChecked = item.sshUseSlowdns
            chip(R.id.chip_slowdns).isChecked = item.dnsttEnabled
            chip(R.id.chip_onering).isChecked = item.oneringEnabled
            chip(R.id.chip_pemicu).isChecked = item.pemicuEnabled
        }
    }

    private fun updateSections() {
        val isSsh = configType == ConfigType.SSH
        findViewById<View>(R.id.section_ssh).visibility = if (isSsh) View.VISIBLE else View.GONE
        findViewById<View>(R.id.section_proxy).visibility = if (isSsh) View.GONE else View.VISIBLE
        // UUID only for VMess/VLESS; password only for Trojan/SS.
        findViewById<View>(R.id.layout_uuid).visibility =
            if (configType == ConfigType.VMESS || configType == ConfigType.VLESS) View.VISIBLE else View.GONE
        findViewById<View>(R.id.layout_password_proxy).visibility =
            if (configType == ConfigType.TROJAN || configType == ConfigType.SHADOWSOCKS) View.VISIBLE else View.GONE
        updateSshSections()
        updateXraySections()
    }

    private fun updateSshSections() {
        val showPayload = chip(R.id.chip_ssh_payload).isChecked || chip(R.id.chip_ssh_enhanced).isChecked
        findViewById<View>(R.id.section_ssh_payload).visibility =
            if (showPayload) View.VISIBLE else View.GONE
        findViewById<View>(R.id.section_ssh_tls).visibility =
            if (chip(R.id.chip_ssh_tls).isChecked) View.VISIBLE else View.GONE
        // SSH SlowDNS chip shares the DNSTT fields with the Xray chip.
        if (chip(R.id.chip_ssh_slowdns).isChecked) {
            chip(R.id.chip_slowdns).isChecked = true
        }
        updateXraySections()
    }

    private fun updateXraySections() {
        val slowdns = chip(R.id.chip_slowdns).isChecked || chip(R.id.chip_ssh_slowdns).isChecked
        findViewById<View>(R.id.section_dnstt).visibility =
            if (slowdns) View.VISIBLE else View.GONE
        findViewById<View>(R.id.section_onering).visibility =
            if (chip(R.id.chip_onering).isChecked) View.VISIBLE else View.GONE
        findViewById<View>(R.id.section_pemicu).visibility =
            if (chip(R.id.chip_pemicu).isChecked) View.VISIBLE else View.GONE
    }

    private fun onToolbarMenu(item: MenuItem): Boolean {
        if (item.itemId == R.id.action_save) {
            save()
            return true
        }
        return false
    }

    private fun save() {
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

        val networkValues = resources.getStringArray(R.array.network_values)
        val network = networkValues.getOrElse(
            findViewById<Spinner>(R.id.spinner_network).selectedItemPosition
        ) { "tcp" }

        val item = (existing ?: ProfileItem()).copy(
            remarks = text(R.id.input_remarks),
            group = text(R.id.input_group).trim(),
            configType = configType,
            address = address,
            port = port,
            username = text(R.id.input_username),
            password = if (configType == ConfigType.SSH) text(R.id.input_password)
            else text(R.id.input_password_proxy),
            privateKey = text(R.id.input_private_key),
            sshUsePayload = chip(R.id.chip_ssh_payload).isChecked,
            sshPayload = text(R.id.input_ssh_payload),
            sshRemoteProxy = text(R.id.input_ssh_remote_proxy),
            sshUseEnhanced = chip(R.id.chip_ssh_enhanced).isChecked,
            sshUseTls = chip(R.id.chip_ssh_tls).isChecked,
            sshSni = text(R.id.input_ssh_sni),
            sshInsecure = findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_ssh_insecure).isChecked,
            sshUseSlowdns = chip(R.id.chip_ssh_slowdns).isChecked,
            uuid = text(R.id.input_uuid),
            method = text(R.id.input_method),
            network = network,
            host = text(R.id.input_host),
            path = text(R.id.input_path),
            tls = findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_tls).isChecked,
            sni = text(R.id.input_sni),
            fingerprint = text(R.id.input_fingerprint),
            alpn = text(R.id.input_alpn),
            insecure = findViewById<com.google.android.material.switchmaterial.SwitchMaterial>(R.id.switch_insecure).isChecked,
            dnsttEnabled = slowdns,
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
