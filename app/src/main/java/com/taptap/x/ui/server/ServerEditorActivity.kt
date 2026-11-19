package com.taptap.x.ui.server

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.taptap.x.R
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.data.ProfileStore
import com.taptap.x.ui.theme.TaptapXTheme

/**
 * Profile editor, mirroring v2rayNG's server editor structure:
 * remarks + protocol + address/port + auth, then the "Xray method"
 * section with the SlowDNS / Onering / Pemicu chips and their fields.
 * Phase 1: SSH is the working protocol; the Xray-method fields are
 * stored on the profile (engines land in later milestones).
 */
class ServerEditorActivity : ComponentActivity() {

    companion object {
        const val EXTRA_GUID = "guid"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val store = ProfileStore(ProfileStore.defaultFile(filesDir))
        store.load()
        val guid = intent.getStringExtra(EXTRA_GUID)
        val existing = guid?.let { store.find(it) }
        setContent {
            TaptapXTheme {
                ServerEditorScreen(
                    existing = existing,
                    onSave = { item ->
                        if (existing == null) store.add(item) else store.update(item)
                        finish()
                    },
                    onCancel = { finish() },
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerEditorScreen(
    existing: ProfileItem?,
    onSave: (ProfileItem) -> Unit,
    onCancel: () -> Unit,
) {
    var remarks by remember { mutableStateOf(existing?.remarks ?: "") }
    var configType by remember { mutableStateOf(existing?.configType ?: ConfigType.SSH) }
    var address by remember { mutableStateOf(existing?.address ?: "") }
    var port by remember { mutableStateOf(existing?.port?.toString() ?: "22") }
    var username by remember { mutableStateOf(existing?.username ?: "") }
    var password by remember { mutableStateOf(existing?.password ?: "") }
    var uuid by remember { mutableStateOf(existing?.uuid ?: "") }
    var network by remember { mutableStateOf(existing?.network ?: "tcp") }
    var host by remember { mutableStateOf(existing?.host ?: "") }
    var path by remember { mutableStateOf(existing?.path ?: "") }
    var tls by remember { mutableStateOf(existing?.tls ?: false) }
    var sni by remember { mutableStateOf(existing?.sni ?: "") }
    // Xray method
    var dnsttEnabled by remember { mutableStateOf(existing?.dnsttEnabled ?: false) }
    var dnsttNS by remember { mutableStateOf(existing?.dnsttNS ?: "") }
    var dnsttPubkey by remember { mutableStateOf(existing?.dnsttPubkey ?: "") }
    var dnsttResolver by remember { mutableStateOf(existing?.dnsttResolver ?: "") }
    var oneringEnabled by remember { mutableStateOf(existing?.oneringEnabled ?: false) }
    var oneringBug by remember { mutableStateOf(existing?.oneringBug ?: "") }
    var pemicuEnabled by remember { mutableStateOf(existing?.pemicuEnabled ?: false) }
    var pemicuDomain by remember { mutableStateOf(existing?.pemicuDomain ?: "") }
    var pemicuPort by remember { mutableStateOf(existing?.pemicuPort?.toString() ?: "") }
    var pemicuInterval by remember { mutableStateOf(existing?.pemicuInterval?.toString() ?: "15") }

    Scaffold(
        topBar = {
            TopAppBar(title = {
                Text(
                    if (existing == null) stringResource(R.string.editor_add)
                    else stringResource(R.string.editor_edit)
                )
            })
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .verticalScroll(rememberScrollState())
        ) {
            OutlinedTextField(
                value = remarks,
                onValueChange = { remarks = it },
                label = { Text(stringResource(R.string.field_remarks)) },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(stringResource(R.string.field_protocol))
            Row {
                ConfigType.entries.forEach { type ->
                    FilterChip(
                        selected = configType == type,
                        onClick = { configType = type },
                        label = { Text(type.name) },
                        modifier = Modifier.padding(end = 4.dp)
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = address,
                onValueChange = { address = it },
                label = { Text(stringResource(R.string.field_address)) },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = port,
                onValueChange = { port = it },
                label = { Text(stringResource(R.string.field_port)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (configType == ConfigType.SSH) {
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text(stringResource(R.string.field_username)) },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(stringResource(R.string.field_password)) },
                    modifier = Modifier.fillMaxWidth()
                )
            } else {
                OutlinedTextField(
                    value = uuid,
                    onValueChange = { uuid = it },
                    label = { Text(stringResource(R.string.field_uuid)) },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text(stringResource(R.string.field_ws_host)) },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = path,
                    onValueChange = { path = it },
                    label = { Text(stringResource(R.string.field_ws_path)) },
                    modifier = Modifier.fillMaxWidth()
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
            // Xray method section (mirrors v2rayNG's XrayMethodFields).
            Text(stringResource(R.string.section_xray_method))
            Spacer(modifier = Modifier.height(8.dp))
            FilterChip(
                selected = dnsttEnabled,
                onClick = { dnsttEnabled = !dnsttEnabled },
                label = { Text("SlowDNS") },
                modifier = Modifier.padding(end = 4.dp)
            )
            FilterChip(
                selected = oneringEnabled,
                onClick = { oneringEnabled = !oneringEnabled },
                label = { Text("Onering") },
                modifier = Modifier.padding(end = 4.dp)
            )
            FilterChip(
                selected = pemicuEnabled,
                onClick = { pemicuEnabled = !pemicuEnabled },
                label = { Text("Pemicu") },
                modifier = Modifier.padding(end = 4.dp)
            )
            if (dnsttEnabled) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = dnsttNS,
                    onValueChange = { dnsttNS = it },
                    label = { Text(stringResource(R.string.field_dnstt_ns)) },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = dnsttPubkey,
                    onValueChange = { dnsttPubkey = it },
                    label = { Text(stringResource(R.string.field_dnstt_pubkey)) },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = dnsttResolver,
                    onValueChange = { dnsttResolver = it },
                    label = { Text(stringResource(R.string.field_dnstt_resolver)) },
                    modifier = Modifier.fillMaxWidth()
                )
            }
            if (oneringEnabled) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = oneringBug,
                    onValueChange = { oneringBug = it },
                    label = { Text(stringResource(R.string.field_onering_bug)) },
                    modifier = Modifier.fillMaxWidth()
                )
            }
            if (pemicuEnabled) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = pemicuDomain,
                    onValueChange = { pemicuDomain = it },
                    label = { Text(stringResource(R.string.field_pemicu_domain)) },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = pemicuPort,
                    onValueChange = { pemicuPort = it },
                    label = { Text(stringResource(R.string.field_pemicu_port)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = pemicuInterval,
                    onValueChange = { pemicuInterval = it },
                    label = { Text(stringResource(R.string.field_pemicu_interval)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth()
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
            Row {
                Button(onClick = {
                    val item = (existing ?: ProfileItem()).copy(
                        remarks = remarks,
                        configType = configType,
                        address = address,
                        port = port.toIntOrNull() ?: 22,
                        username = username,
                        password = password,
                        uuid = uuid,
                        network = network,
                        host = host,
                        path = path,
                        tls = tls,
                        sni = sni,
                        dnsttEnabled = dnsttEnabled,
                        dnsttNS = dnsttNS,
                        dnsttPubkey = dnsttPubkey,
                        dnsttResolver = dnsttResolver,
                        oneringEnabled = oneringEnabled,
                        oneringBug = oneringBug,
                        pemicuEnabled = pemicuEnabled,
                        pemicuDomain = pemicuDomain,
                        pemicuPort = pemicuPort.toIntOrNull(),
                        pemicuInterval = pemicuInterval.toIntOrNull(),
                    )
                    onSave(item)
                }) {
                    Text(stringResource(R.string.action_save))
                }
                Spacer(modifier = Modifier.weight(1f))
                Button(onClick = onCancel) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
