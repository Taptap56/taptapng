package com.taptap.x.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.taptap.x.data.SettingsStore

/**
 * Auto-start on boot (Settings > Advanced > "Auto-start on boot").
 * Only starts the tunnel when the VPN permission was already granted
 * (VpnService.prepare returns null); otherwise the user must open
 * the app once to approve it.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!SettingsStore(context).isBooted) return
        if (VpnService.prepare(context) != null) return
        // Plain startService: on API 26+ this throws when the app is in
        // the background, so it is best-effort only until the service
        // gains a foreground notification (M6). Never crash boot.
        runCatching {
            val start = Intent(context, TaptapVpnService::class.java)
                .setAction(TaptapVpnService.ACTION_START)
            context.startService(start)
        }
    }
}
