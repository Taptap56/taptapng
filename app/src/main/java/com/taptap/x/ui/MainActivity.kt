package com.taptap.x.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import com.taptap.x.service.TaptapVpnService
import com.taptap.x.ui.log.LogActivity
import com.taptap.x.ui.main.MainScreen
import com.taptap.x.ui.main.MainViewModel
import com.taptap.x.ui.server.ServerEditorActivity
import com.taptap.x.ui.settings.SettingsActivity
import com.taptap.x.ui.theme.TaptapXTheme

/**
 * Main activity, mirroring v2rayNG's MainActivity: Compose host for the
 * server list + drawer + FAB. Owns the VpnService permission request
 * and start/stop intents.
 */
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpn()
        } else {
            viewModel.setRunning(false, "Izin VPN ditolak")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            TaptapXTheme {
                MainScreen(
                    viewModel = viewModel,
                    onAddServer = {
                        startActivity(Intent(this, ServerEditorActivity::class.java))
                    },
                    onEditServer = { guid ->
                        startActivity(
                            Intent(this, ServerEditorActivity::class.java)
                                .putExtra(ServerEditorActivity.EXTRA_GUID, guid)
                        )
                    },
                    onOpenSettings = {
                        startActivity(Intent(this, SettingsActivity::class.java))
                    },
                    onOpenLog = {
                        startActivity(Intent(this, LogActivity::class.java))
                    },
                    onToggleRunning = { toggleRunning() },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.reload()
        viewModel.setRunning(TaptapVpnService.isRunning)
    }

    private fun toggleRunning() {
        if (TaptapVpnService.isRunning) {
            stopVpn()
        } else {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnPermissionLauncher.launch(intent)
            } else {
                startVpn()
            }
        }
    }

    private fun startVpn() {
        val intent = Intent(this, TaptapVpnService::class.java)
            .setAction(TaptapVpnService.ACTION_START)
        startService(intent)
        viewModel.setRunning(true, "TaptapX jalan")
    }

    private fun stopVpn() {
        val intent = Intent(this, TaptapVpnService::class.java)
            .setAction(TaptapVpnService.ACTION_STOP)
        startService(intent)
        viewModel.setRunning(false, "TaptapX berhenti")
    }
}
