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
import com.taptap.x.core.DialLog
import com.taptap.x.core.DnsResolver
import com.taptap.x.core.ServerTester
import com.taptap.x.core.TunnelState
import com.taptap.x.core.proto.DialWatchdog
import com.taptap.x.core.proto.ProbeBody
import com.taptap.x.core.proto.ProxyClient
import com.taptap.x.core.proto.ProxyClientFactory
import com.taptap.x.core.proto.Transport
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import com.taptap.x.data.ProfileStore
import com.taptap.x.data.SettingsStore
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlin.concurrent.thread

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
 *
 * v1.0.6: the start flow is probe-first — the entry is dialled
 * (full protocol handshake) BEFORE the TUN comes up, so a dead
 * entry fails fast with a stage-tagged status instead of leaving a
 * dead VPN up with "Connecting..." forever (v1.0.5 never dialled
 * at startup at all: the first dial only happened when an app sent
 * a SYN). A second start while running restarts with the newly
 * selected entry instead of being silently ignored.
 */
class TaptapVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.taptap.x.START"
        const val ACTION_STOP = "com.taptap.x.STOP"

        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "taptapx-vpn"

        /**
         * Single source of truth for connection state + status text
         * (v1.0.6, fix B). The UI reads [statusMessage] / [isRunning]
         * through these delegating getters — same names as before.
         */
        val connection = VpnConnection()

        /** Last human-readable status for the main screen. */
        val statusMessage: String get() = connection.status

        val isRunning: Boolean get() = connection.isRunning

        /**
         * Profiles that cannot ride the TUN in this version. Start
         * must fail with a clear status instead of blackholing
         * traffic or hanging on "Connecting..." forever. v1.0.4:
         * Onering entries need the M4 engine (the 0xff00 extension
         * is not built yet) and SlowDNS entries need M3 — in M2 both
         * would dial as plain VMess and hang on TLS when the window
         * is closed, with no honest status.
         */
        fun requireStartable(item: ProfileItem) {
            if (item.configType == ConfigType.SSH) {
                throw IllegalStateException(
                    "Entry SSH belum bisa lewat TUN di v1.0.2 — pilih entry VMess/VLESS/Trojan/SS",
                )
            }
            if (item.oneringEnabled) {
                throw IllegalStateException(
                    "Entry Onering belum didukung di v1.0.4 (butuh M4) — pilih entry VMess biasa",
                )
            }
            if (item.dnsttEnabled) {
                throw IllegalStateException(
                    "Entry SlowDNS belum didukung di v1.0.4 (butuh M3) — pilih entry VMess biasa",
                )
            }
        }

        /**
         * Guard + client creation for one start attempt, testable on
         * the JVM (v1.0.6, fix D). The service calls this on EVERY
         * start — including a restart while running — so the guard
         * can never be bypassed by starting with another entry
         * selected first (which is how the Onering entry got dialled
         * in v1.0.5 despite the guard).
         */
        fun prepareStart(item: ProfileItem): PreparedStart {
            try {
                requireStartable(item)
            } catch (e: IllegalStateException) {
                return PreparedStart.Rejected(e.message ?: "Entry tidak bisa dipakai")
            }
            return try {
                PreparedStart.Ready(ProxyClientFactory.create(item), dialLabel(item))
            } catch (e: Exception) {
                PreparedStart.Rejected(e.message ?: "Profil tidak valid: $e")
            }
        }

        /**
         * The TUN interface's IPv4 client address, from the user's
         * interface-address setting (index into v2rayNG's
         * VpnInterfaceAddressConfig: 0 = 10.10.14.x, 1 = 10.1.0.x,
         * 2 = 10.0.0.x, 3 = 172.31.0.x, 4 = 172.20.0.x,
         * 5 = 172.16.0.x, 6 = 192.168.100.x). v1.0.9 hardcoded
         * 172.19.0.1 and ignored this setting entirely — the user
         * could change it in Settings (like in v2rayNG) and nothing
         * happened. The default (index 0) is v2rayNG's default,
         * 10.10.14.1 — the old 172.19.0.1 is not in v2rayNG's list
         * at all, and 172.19.0.0/16 is a range carriers and hotspots
         * use, so a clash there can blackhole TUN traffic.
         */
        fun tunIpv4ClientAddress(index: String?): String {
            val clients = listOf(
                "10.10.14.1", "10.1.0.1", "10.0.0.1", "172.31.0.1",
                "172.20.0.1", "172.16.0.1", "192.168.100.1",
            )
            val i = index?.trim()?.toIntOrNull() ?: 0
            return clients.getOrElse(i) { clients[0] }
        }
    }

    /** Result of [prepareStart]: rejected with a message, or ready to dial. */
    sealed class PreparedStart {
        data class Rejected(val message: String) : PreparedStart()
        data class Ready(val client: ProxyClient, val label: String) : PreparedStart()
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var forwarder: TunForwarder? = null
    private var probeWatchdog: DialWatchdog? = null
    private val tunnelLock = Any()

    /**
     * Generation of the current start. A stop/restart bumps it
     * BEFORE tearing anything down, so an in-flight start thread
     * sees its work is obsolete and never touches the status or the
     * tunnel again. onStartCommand is main-thread serialised, so a
     * plain var is enough.
     */
    @Volatile
    private var startGeneration = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startTunnel()
            ACTION_STOP -> stopTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel() {
        val store = ProfileStore(ProfileStore.defaultFile(filesDir))
        store.load()
        val item: ProfileItem = store.find(store.selectedGuid ?: "")
            ?: store.profiles.firstOrNull()
            ?: run {
                connection.reportFailure("Tidak ada server — tambah dulu lewat +")
                return
            }
        // Guard + client creation run on the main thread, so a
        // rejected entry fails immediately with a clear status —
        // no worker, no foreground notification, no TUN.
        when (val prepared = prepareStart(item)) {
            is PreparedStart.Rejected -> {
                connection.reportFailure("${prepared.message}: ${dialLabel(item)}")
                return
            }
            is PreparedStart.Ready -> {
                val decision = connection.requestStart(prepared.label)
                if (decision == VpnConnection.Decision.ALREADY_RUNNING) {
                    runCatching { prepared.client.close() }
                    return
                }
                // Bump the generation BEFORE tearing down, so an
                // in-flight start thread goes obsolete first.
                val gen = ++startGeneration
                if (decision == VpnConnection.Decision.RESTART) teardownTunnel()
                // Foreground NOW (main thread): the worker below may
                // spend up to the watchdog on the probe dial.
                startForegroundNotification(item.displayName())
                thread(name = "taptapx-start", isDaemon = true) {
                    runStart(prepared.client, item, prepared.label, gen)
                }
            }
        }
    }

    /**
     * Start worker: probe-dial the entry, and only then bring up the
     * TUN. v1.0.5 never dialled at startup — the first dial only
     * happened when an app sent a SYN, so with no traffic the status
     * stayed "Connecting..." forever and no failure was ever
     * reported. The probe is a full protocol dial (transport ladder
     * + protocol handshake) against the entry itself; on failure the
     * tunnel never comes up and the status names the failed stage.
     */
    private fun runStart(client: ProxyClient, item: ProfileItem, label: String, gen: Int) {
        try {
            installProtectHooks()
            probeDial(client, item, label)
            val established = synchronized(tunnelLock) {
                if (!isCurrentStart(gen)) {
                    false
                } else {
                    establishTunnel(client, item)
                    true
                }
            }
            if (!established || !isCurrentStart(gen)) {
                teardownTunnel()
                runCatching { client.close() }
                return
            }
            connection.reportConnected(label)
        } catch (e: Exception) {
            if (isCurrentStart(gen)) {
                DialLog.failure("START", e)
                connection.reportFailure(
                    "${TunForwarder.dialFailureReason(e)}: $label",
                )
                updateNotification(connection.status)
                teardownTunnel()
                runCatching { client.close() }
            } else {
                runCatching { client.close() }
            }
        }
    }

    /** Build the TUN + forwarder. Runs under [tunnelLock] (see runStart). */
    private fun establishTunnel(client: ProxyClient, item: ProfileItem) {
        // DNS server comes from Settings (remote DNS), default 8.8.8.8.
        // Only an IP literal is accepted here — a hostname would need
        // DNS to resolve, which itself goes through the tunnel.
        val settings = SettingsStore(this)
        val dns = settings.remoteDns.trim()
            .takeIf { it.isNotBlank() && isIpLiteral(it) }
            ?: "8.8.8.8"
        // MTU comes from Settings (v2rayNG default 1500); out-of-range
        // values fall back to 1500 instead of breaking establish().
        val mtu = settings.vpnMtu.trim().toIntOrNull()
            ?.takeIf { it in 576..9000 } ?: 1500
        // v1.0.10: the Builder mirrors v2rayNG's CoreVpnService
        // (configureNetworkSettings + configurePlatformFeatures):
        // the TUN address comes from the user's interface-address
        // setting (default 10.10.14.1, v2rayNG's default — NOT the
        // old hardcoded 172.19.0.1); the IPv6 default route is only
        // added when IPv6 is enabled (v2rayNG gates it on
        // PREF_IPV6_ENABLED, default off — v1.0.9 added it always);
        // and the VPN is marked unmetered on API 29+ (v2rayNG
        // setMetered(false)) so Android does not throttle or defer
        // traffic on it.
        val builder = Builder()
            .setSession("TaptapX")
            .addAddress(tunIpv4ClientAddress(settings.vpnInterfaceAddress), 30)
            .addRoute("0.0.0.0", 0)
            .apply {
                if (settings.ipv6Enabled) addRoute("::", 0)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) setMetered(false)
            }
            .addDnsServer(dns)
            .setMtu(mtu)
        // v1.0.9: exclude our own package from the VPN — v2rayNG's
        // CoreVpnService.configurePerAppProxy does exactly this
        // ("if per-app proxy is not enabled, disallow the VPN
        // service's own package"). Our dial/DNS/test sockets are
        // created by this app, so they bypass the TUN at the routing
        // level even when VpnService.protect() returns false — which
        // it does on this phone once the TUN is up (delay test
        // "protect gagal", taptapx-6.txt 04:18; with protect as the
        // only bypass, the forwarder never dialled at all and no app
        // traffic flowed). protect() stays the first layer; the
        // disallow is the second layer that makes a refused protect
        // non-fatal (see TunnelState.appBypass).
        val disallowed = try {
            builder.addDisallowedApplication(packageName)
            true
        } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
            // Own package always exists; if it ever fails, protect()
            // stays the only bypass and a refused protect still fails
            // fast (TunnelState.appBypass stays false).
            false
        }
        val fd = builder.establish()
            ?: throw IllegalStateException("Gagal establish TUN (izin VPN ditolak?)")
        // v1.0.11: the fd from establish() is NON-BLOCKING
        // (O_NONBLOCK) — FileInputStream.read() returns 0 at once
        // when no packet is waiting (EAGAIN), and the reader
        // treated 0 as end-of-stream and exited 1 ms after start
        // (phone log 08:05:09.528–529, "baca TUN selesai (n=0)").
        // Set it blocking so read() waits for the first packet;
        // the reader then only exits on stop() or a real read
        // error. v2rayNG never hits this: it hands the fd to the
        // native core, and xray-core's Android TUN sets the fd
        // non-blocking and waits in the Go poller
        // (tun_android.go: SetNonblock + fdTun.ReadParts) — a
        // naive Java read loop must have a blocking fd instead.
        try {
            android.system.Os.setBlocking(fd.fileDescriptor, true)
        } catch (e: Exception) {
            // If this ever fails, the reader still survives: a 0
            // read is retried, not treated as end-of-stream
            // (see TunForwarder.readLoop).
            DialLog.log(
                "FORWARDER",
                "setBlocking gagal (${e.javaClass.simpleName}) — baca TUN tetap jalan (retry)",
            )
        }
        // The TUN exists from here on: dial/DNS/test sockets must
        // now be protected (TunnelState.up gates enforcement in
        // Transport / DnsResolver / ServerTester). Before this line
        // protect() returns false, so the probe dials direct (v1.0.7).
        TunnelState.up = true
        TunnelState.appBypass = disallowed
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
                onStatus = { msg -> connection.reportDialStatus(msg) },
            )
            forwarder = fwd
            fwd.start()
        } catch (e: Exception) {
            runCatching { fd.close() }
            tunFd = null
            throw e
        }
    }

    private fun isCurrentStart(gen: Int): Boolean =
        gen == startGeneration && connection.state == VpnConnection.State.STARTING

    /**
     * Full protocol dial against the entry itself, under the
     * watchdog (fix A). Target = the entry itself: the server
     * connects to its own port — but a TLS server there sends
     * nothing until spoken to, and the xray-core server only
     * flushes its response header once data flows from the target
     * (v1.0.8, fix B: without [ProbeBody] the probe deadlocks into
     * a 10 s VMess read timeout). The probe body makes the target
     * answer, which unblocks the flush and proves the handshake
     * (including the UUID) end to end.
     */
    private fun probeDial(client: ProxyClient, item: ProfileItem, label: String) {
        val watchdog = DialWatchdog()
        probeWatchdog = watchdog
        Transport.setThreadWatchdog(watchdog)
        try {
            watchdog.start()
            DialLog.log("PROBE", "dial $label")
            val stream = client.dial(item.address, item.port, ProbeBody.forEntry(item))
            runCatching { stream.close() }
            DialLog.log("PROBE", "$label ok")
        } catch (e: Exception) {
            DialLog.failure("PROBE", e)
            throw e
        } finally {
            watchdog.stop()
            Transport.setThreadWatchdog(null)
            if (probeWatchdog === watchdog) probeWatchdog = null
        }
    }

    private fun installProtectHooks() {
        // Dial sockets must bypass our own TUN, or they loop forever
        // — but only once the TUN exists. The hooks are installed
        // before the probe, and enforcement is gated on
        // TunnelState.up inside Transport / DnsResolver /
        // ServerTester: pre-TUN protect() returns false, so the
        // probe dials direct instead of failing instantly (v1.0.7).
        Transport.protectSocket = { socket -> protect(socket) }
        // Same for delay-test sockets (v1.0.4): without this, a test
        // run while the VPN is up dials through the tunnel and
        // reports a false "Timeout" (see ServerTester).
        ServerTester.protectSocket = { socket -> protect(socket) }
        // Same for the direct DNS resolver (v1.0.5): without this,
        // DnsResolver queries go through the TUN and loop in the
        // forwarder's DNS relay instead of reaching 8.8.8.8.
        DnsResolver.protectUdp = { socket -> protect(socket) }
    }

    /**
     * Close TUN/forwarder/hooks. The TUN part takes [tunnelLock]
     * (see runStart); the probe watchdog is cancelled first so an
     * in-flight probe unblocks at once.
     */
    private fun teardownTunnel() {
        // The TUN is going away: from here on there is nothing to
        // bypass again, so protect enforcement switches off first.
        TunnelState.up = false
        TunnelState.appBypass = false
        probeWatchdog?.cancel()
        probeWatchdog = null
        synchronized(tunnelLock) {
            runCatching { forwarder?.stop() }
            forwarder = null
            runCatching { tunFd?.close() }
            tunFd = null
        }
        Transport.protectSocket = null
        ServerTester.protectSocket = null
        DnsResolver.protectUdp = null
    }

    private fun stopTunnel() {
        if (connection.state == VpnConnection.State.IDLE) return
        startGeneration++
        teardownTunnel()
        connection.requestStop()
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

    /** Replace the foreground notification's text (e.g. after a failed probe). */
    private fun updateNotification(text: String) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TaptapX")
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .build()
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        runCatching { manager.notify(NOTIFICATION_ID, notification) }
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
