package com.taptap.x.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.taptap.x.R
import com.taptap.x.core.proto.ProxyClientFactory
import com.taptap.x.core.proto.Transport
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.data.ProfileStore
import com.taptap.x.data.SettingsStore
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VpnService (M2). It owns the TUN interface and the connect /
 * disconnect lifecycle, mirroring v2rayNG's service split: the
 * service manages the tunnel; protocol engines run as in-app modules
 * and feed it.
 *
 * M2: the selected profile is loaded from [ProfileStore]; a
 * [ProxyClient] (VMess/VLESS/Trojan/SS) is created for it, and a
 * [TunForwarder] relays TCP between the TUN interface and the proxy.
 * SSH profiles cannot ride the tunnel yet (no SOCKS forwarding in
 * SshClient) — starting with an SSH profile selected fails with a
 * clear status instead of blackholing traffic.
 */
class TaptapVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.taptap.x.START"
        const val ACTION_STOP = "com.taptap.x.STOP"

        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "taptapx-vpn"

        @Volatile
        var isRunning: Boolean = false
            private set

        /** Last human-readable status for the main screen. */
        @Volatile
        var statusMessage: String = ""
            private set
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var forwarder: TunForwarder? = null
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
        try {
            startTunnelInner()
        } catch (e: Exception) {
            statusMessage = e.message ?: "Gagal start: $e"
            started.set(false)
            isRunning = false
        }
    }

    private fun startTunnelInner() {
        val store = ProfileStore(ProfileStore.defaultFile(filesDir))
        store.load()
        val item: ProfileItem = store.find(store.selectedGuid ?: "")
            ?: store.profiles.firstOrNull()
            ?: throw IllegalStateException("Tidak ada server — tambah dulu lewat +")
        if (item.configType == ConfigType.SSH) {
            throw IllegalStateException(
                "Entry SSH belum bisa lewat TUN di v1.0.2 — pilih entry VMess/VLESS/Trojan/SS",
            )
        }
        // Create the client BEFORE touching the TUN so a bad profile
        // fails fast instead of blackholing all traffic.
        val client = ProxyClientFactory.create(item)

        // DNS server comes from Settings (remote DNS), default 8.8.8.8.
        // Only an IP literal is accepted here — a hostname would need
        // DNS to resolve, which itself goes through the tunnel.
        val dns = SettingsStore(this).remoteDns.trim()
            .takeIf { it.isNotBlank() && isIpLiteral(it) }
            ?: "8.8.8.8"

        // Dial sockets must bypass our own TUN, or they loop forever.
        Transport.protectSocket = { socket -> protect(socket) }

        val builder = Builder()
            .setSession("TaptapX")
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer(dns)
            .setMtu(1500)
        val fd = builder.establish()
            ?: throw IllegalStateException("Gagal establish TUN (izin VPN ditolak?)")
        tunFd = fd
        try {
            val tunIn = FileInputStream(fd.fileDescriptor)
            val tunOut = FileOutputStream(fd.fileDescriptor)
            val fwd = TunForwarder(
                tunIn = tunIn,
                tunOut = tunOut,
                proxy = client,
                dnsServer = dns,
                protectUdp = { socket -> protect(socket) },
                onStatus = { msg -> statusMessage = "$msg: ${item.displayName()}" },
            )
            forwarder = fwd
            fwd.start()
        } catch (e: Exception) {
            runCatching { fd.close() }
            tunFd = null
            Transport.protectSocket = null
            throw e
        }
        startForegroundNotification(item.displayName())
        statusMessage = "Connecting: ${item.displayName()}…"
        isRunning = true
    }

    private fun stopTunnel() {
        if (!started.compareAndSet(true, false)) return
        runCatching { forwarder?.stop() }
        forwarder = null
        runCatching { tunFd?.close() }
        tunFd = null
        Transport.protectSocket = null
        isRunning = false
        statusMessage = "Stopped"
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        stopSelf()
    }

    private fun startForegroundNotification(remarks: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "TaptapX VPN",
                NotificationManager.IMPORTANCE_LOW,
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TaptapX")
            .setContentText("Connected: $remarks")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun isIpLiteral(s: String): Boolean {
        // IPv4 literal, or IPv6 literal (contains ':'; may be bracketed).
        val v4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(s)
        if (v4) return true
        val v6 = s.removeSurrounding("[", "]")
        return v6.contains(':') && v6.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
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
