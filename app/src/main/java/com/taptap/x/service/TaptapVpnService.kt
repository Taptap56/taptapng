package com.taptap.x.service

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.taptap.x.data.SettingsStore
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VpnService skeleton (Phase 1). It owns the TUN interface and the
 * connect/disconnect lifecycle, mirroring v2rayNG's service split:
 * the service manages the tunnel; protocol engines (SSH, later
 * VMess/VLESS/Trojan/SS + SlowDNS + Onering + Pemicu) run as
 * in-app modules and feed the tunnel.
 *
 * Phase 1: establishes the TUN interface and reports running state.
 * Packet forwarding / protocol wiring lands in later milestones.
 */
class TaptapVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.taptap.x.START"
        const val ACTION_STOP = "com.taptap.x.STOP"

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private var tunFd: ParcelFileDescriptor? = null
    private val started = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startTunnel()
            ACTION_STOP -> stopTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel() {
        if (!started.compareAndSet(false, true)) return
        // DNS server comes from Settings (remote DNS), default 8.8.8.8.
        val dns = SettingsStore(this).remoteDns.trim()
            .takeIf { it.isNotBlank() && (it.contains('.') || it.contains(':')) }
            ?: "8.8.8.8"
        val builder = Builder()
            .setSession("TaptapX")
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer(dns)
            .setMtu(1500)
        tunFd = runCatching { builder.establish() }.getOrNull()
        isRunning = tunFd != null
    }

    private fun stopTunnel() {
        if (!started.compareAndSet(true, false)) return
        runCatching { tunFd?.close() }
        tunFd = null
        isRunning = false
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }
}
