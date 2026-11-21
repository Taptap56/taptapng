package com.taptap.ng.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.taptap.ng.core.DialLog
import com.taptap.ng.core.RootIptables
import com.taptap.ng.core.RootTunnelController
import com.taptap.ng.core.SuExecutor
import com.taptap.ng.data.SettingsStore

/**
 * Auto-start on boot (Settings > Advanced > "Auto-start on boot").
 * Only starts the tunnel when the VPN permission was already granted
 * (VpnService.prepare returns null); otherwise the user must open
 * the app once to approve it.
 *
 * v1.0.15 (Root mode): SEBELUM apa pun, bila Root mode ON,
 * bersihkan aturan iptables basi dari crash sebelumnya — aturan
 * yang nyangkut = internet mati total sesudah boot. Best-effort:
 * Magisk/su mungkin belum siap saat BOOT_COMPLETED, jadi gagal
 * di sini tidak fatal — start Root mode membersihkan lagi
 * ([RootTunnelController.start] memanggil cleanupStale dulu).
 * Tidak pernah crash boot.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (runCatching { SettingsStore(context).enableRootMode }.getOrDefault(false)) {
            runCatching {
                val failed = RootTunnelController().cleanupStale(
                    SuExecutor(),
                    RootIptables.Config(appUid = android.os.Process.myUid()),
                )
                if (failed.isNotEmpty()) {
                    DialLog.log(
                        "ROOT",
                        "boot: ${failed.size} aturan basi tidak terhapus — " +
                            "coba matikan Root mode lalu nyalakan lagi",
                    )
                } else {
                    DialLog.log("ROOT", "boot: aturan basi dibersihkan")
                }
            }
        }
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
