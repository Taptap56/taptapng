package com.taptap.ng.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.taptap.ng.R
import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsRelayPolicy
import com.taptap.ng.core.DnsResolver
import com.taptap.ng.core.DnsSettings
import com.taptap.ng.core.DohClient
import com.taptap.ng.core.FakeDns
import com.taptap.ng.core.Observatory
import com.taptap.ng.core.ObservatoryRunner
import com.taptap.ng.core.OutboundResolveMethod
import com.taptap.ng.core.PemicuManager
import com.taptap.ng.core.RootIptables
import com.taptap.ng.core.RootTunnelController
import com.taptap.ng.core.RouteEngine
import com.taptap.ng.core.ServerTester
import com.taptap.ng.core.Sniffer
import com.taptap.ng.core.SuExecutor
import com.taptap.ng.core.TunnelState
import com.taptap.ng.core.UrlTestCache
import com.taptap.ng.core.UrlTestLoop
import com.taptap.ng.core.proto.DialWatchdog
import com.taptap.ng.core.proto.MuxConfig
import com.taptap.ng.core.proto.ProbeBody
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyClientFactory
import com.taptap.ng.core.proto.Transport
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import com.taptap.ng.data.SettingsStore
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * VpnService (M2). It owns the TUN interface and the connect /
 * disconnect lifecycle, mirroring v2rayNG's service split: the
 * service manages the tunnel; protocol engines run as in-app modules
 * and feed it.
 *
 * M2: the selected profile is loaded from [ProfileStore]; a
 * [ProxyClient] (VMess/VLESS/Trojan/SS/SSH) is created for it, and a
 * [TunForwarder] relays TCP between the TUN interface and the proxy.
 * v1.0.30: SSH profiles ride the tunnel too ([SshProxyClient] — one
 * shared JSch session, one direct-tcpip channel per dial, payload
 * chain before the SSH handshake); SSH+SlowDNS and SSH+Onering are
 * still rejected (see [requireStartable]).
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
        const val ACTION_START = "com.taptap.ng.START"
        const val ACTION_STOP = "com.taptap.ng.STOP"

        /**
         * v1.0.19 (Issue 2): live switch — move the RUNNING tunnel
         * to another server without stop/start. The guid travels in
         * [EXTRA_GUID]. The UI only sends this while running and
         * for a different server (see [decideLiveSwitch]); the
         * service re-checks both, so a stale intent is harmless.
         */
        const val ACTION_SWITCH = "com.taptap.ng.SWITCH"
        const val EXTRA_GUID = "guid"

        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "taptapng-vpn"

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
         * v1.0.32: true only when the tunnel is actually up
         * (RUNNING) — false while STARTING, FAILED or IDLE.
         * [isRunning] is true from the moment a start is requested,
         * so it cannot gate the dashboard; the dashboard gate reads
         * this instead (see DashboardGate).
         */
        val isConnected: Boolean get() = connection.isConnected

        /**
         * Profiles that cannot ride the TUN in this version. Start
         * must fail with a clear status instead of blackholing
         * traffic or hanging on "Connecting..." forever. v1.0.4:
         * Onering entries need the M4 engine (the 0xff00 extension
         * is not built yet) and SlowDNS entries need M3 — in M2 both
         * would dial as plain VMess and hang on TLS when the window
         * is closed, with no honest status. v1.0.14 (M3): SlowDNS
         * entries ARE startable for VMess/VLESS (the DNSTT tunnel
         * is built in-app); SlowDNS for Trojan/SS/SSH is still
         * rejected — the DNSTT ladder is only plugged into the
         * VMess/VLESS clients. v1.0.23 (M4): Onering entries ARE
         * startable for VMess/VLESS/Trojan with TLS + WS + a bug
         * domain (the 0xff00 extension is built in-app via Bouncy
         * Castle); Onering without TLS/WS/bug, for SS/SSH, or
         * combined with SlowDNS is still rejected with a clear
         * message. v1.0.30: SSH entries ARE startable (the
         * SshProxyClient + payload chain) — the old blanket SSH
         * rejection is gone; SSH+SlowDNS and SSH+Onering are still
         * rejected by the checks below.
         */
        fun requireStartable(item: ProfileItem) {
            if (item.oneringEnabled) {
                if (item.dnsttEnabled) {
                    throw IllegalStateException(
                        "Entry Onering + SlowDNS belum didukung digabung — matikan salah satu",
                    )
                }
                if (item.configType != ConfigType.VMESS &&
                    item.configType != ConfigType.VLESS &&
                    item.configType != ConfigType.TROJAN
                ) {
                    throw IllegalStateException(
                        "Entry Onering baru didukung untuk VMess/VLESS/Trojan di v1.0.23 (M4)",
                    )
                }
                if (!item.tls) {
                    throw IllegalStateException(
                        "Entry Onering butuh TLS — nyalakan TLS di entry ini",
                    )
                }
                if (item.network.lowercase() != "ws") {
                    throw IllegalStateException(
                        "Entry Onering butuh network WS — ganti network ke ws",
                    )
                }
                if (item.oneringBug.isBlank()) {
                    throw IllegalStateException(
                        "Entry Onering butuh Bug domain — isi di Xray method",
                    )
                }
            }
            if (item.dnsttEnabled &&
                item.configType != ConfigType.VMESS &&
                item.configType != ConfigType.VLESS
            ) {
                throw IllegalStateException(
                    "Entry SlowDNS baru didukung untuk VMess/VLESS di v1.0.14 — pilih entry VMess/VLESS",
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
        fun prepareStart(item: ProfileItem, muxConfig: MuxConfig = MuxConfig.DISABLED): PreparedStart {
            try {
                requireStartable(item)
            } catch (e: IllegalStateException) {
                return PreparedStart.Rejected(e.message ?: "Entry tidak bisa dipakai")
            }
            return try {
                PreparedStart.Ready(ProxyClientFactory.create(item, muxConfig), dialLabel(item))
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

        /**
         * Tunnel DNS servers (v1.0.3, XVEON parity). Verified from
         * the XVEON APK (see README-v1.0.3.md): 1.1.1.1 (Primary)
         * and 1.0.0.1 (Secondary) are XVEON's profile DEFAULTS, and
         * its TUN establish sets both via addDnsServer (falling back
         * to 1.1.1.1 when the set is empty). v1.0.5: the primary is
         * now Settings vpnDns ([DnsSettings.effectiveTunnelDns]) —
         * these two constants stay the DEFAULTS (1.1.1.1/1.0.0.1),
         * and the secondary is still always 1.0.0.1.
         * The proxy-host RESOLVER is a different thing and stays
         * 8.8.8.8 (DnsResolver): XVEON resolves the proxy host with
         * the system resolver, never via 1.1.1.1, so there is no
         * evidence for changing it — and the direct-UDP resolver is
         * the v1.0.4 fix for the system resolver hanging while the
         * TUN is up.
         */
        const val PRIMARY_DNS = "1.1.1.1"
        const val SECONDARY_DNS = "1.0.0.1"

        /**
         * The "Initializing Xray Core (...)" line (v1.0.3, XVEON
         * parity), or null for SSH entries. Verified from the XVEON
         * APK: its engine-init method (Ld9.ol()) logs
         * "Initializing Xray Core (<Transport> over <Network>[ +
         * TLS][ + DNSTT])" at entry — the transport/network names
         * come from the profile, " + TLS" is appended when TLS is
         * on, " + DNSTT" when SlowDNS is on. There is no xray-core
         * binary behind it — Ld9 IS XVEON's "Xray Core", a
         * hand-written stream factory — so this line is a LABEL for
         * the in-app engine init, exactly as it is here: the line
         * is logged where the ProxyClient engine is created and
         * the profile validated (runStart, right after "Starting
         * profile"), and no core/library/binary is added.
         * SSH returns null: XVEON's transport enum (Lm8) has no
         * SSH — its SSH path is separate — so an SSH entry must
         * not claim an "Xray Core" init. The "TCP" network label
         * is inferred, not proven from the dex (no standalone
         * "TCP" enum string was found; "WebSocket (WS)" is proven).
         */
        fun initializingLine(item: ProfileItem): String? {
            val transport = when (item.configType) {
                ConfigType.VMESS -> "VMess"
                ConfigType.VLESS -> "VLESS"
                ConfigType.TROJAN -> "Trojan"
                ConfigType.SHADOWSOCKS -> "Shadowsocks"
                ConfigType.SSH -> return null
            }
            val network = when (item.network.ifBlank { "tcp" }.lowercase()) {
                "ws" -> "WebSocket (WS)"
                else -> "TCP"
            }
            val tls = if (item.tls) " + TLS" else ""
            val dnstt = if (item.dnsttEnabled) " + DNSTT" else ""
            return "Initializing Xray Core ($transport over $network$tls$dnstt)"
        }
    }

    /** Result of [prepareStart]: rejected with a message, or ready to dial. */
    sealed class PreparedStart {
        data class Rejected(val message: String) : PreparedStart()
        data class Ready(val client: ProxyClient, val label: String) : PreparedStart()
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var forwarder: TunForwarder? = null
    /**
     * Local SOCKS proxy (v1.0.5, kelompok B): hidup mengikuti tunnel
     * — start sesudah TUN naik, stop saat teardown, hanya bila
     * local proxy efektif (enableLocalProxy, atau useHevTun yang
     * memaksanya — lihat SettingsStore.isLocalProxyEffective).
     * Dial-nya memakai ProxyClient yang sama dengan forwarder.
     */
    private var socksServer: SocksServer? = null
    /**
     * Observatory runner (v1.0.5, kelompok F): probing berkala saat
     * tunnel hidup; dihentikan di teardownTunnel. Hasilnya hanya
     * saran — tidak pernah mencabut tunnel (lihat Observatory).
     */
    private var observatoryRunner: ObservatoryRunner? = null
    private var probeWatchdog: DialWatchdog? = null
    /**
     * The client of the current start (M3): teardown closes it so a
     * SlowDNS client's DNSTT session (KCP/DNS loops) cannot leak
     * after a stop — the old code only closed the client on the
     * error paths in runStart, never on a normal stop.
     */
    private var currentClient: ProxyClient? = null
    /**
     * Root mode (v1.0.15): handle aktif — null bila jalan VpnService.
     * Dihentikan + aturan dibersihkan di [teardownTunnel].
     */
    private var rootHandle: RootModeHandle? = null
    /**
     * M7: cache delay url-test + loop prober-nya (hidup mengikuti
     * tunnel — start di [establishTunnel], stop di [teardownTunnel]).
     */
    private var urlTestCache: UrlTestCache? = null
    private var urlTestLoop: UrlTestLoop? = null
    /**
     * M7: client per guid anggota grup (dibuat sekali per guid
     * lewat [ProxyClientFactory], dipakai ulang tiap koneksi yang
     * diputuskan ke guid itu). Client entry terpilih diisi dulu
     * dengan client tunnel ([currentClient]) supaya konfigurasi
     * default memakai client yang sama persis seperti sebelum M7.
     */
    private val routeClientCache = ConcurrentHashMap<String, ProxyClient>()
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
            ACTION_SWITCH -> switchTunnel(intent.getStringExtra(EXTRA_GUID))
        }
        return START_STICKY
    }

    /**
     * Live switch (v1.0.19, Issue 2): move the RUNNING tunnel to
     * [newGuid] without tearing the TUN or the forwarder down.
     * Order matters — every step that can fail runs BEFORE the
     * routing selection moves, so a failed switch leaves the old
     * server running, selected, and primed:
     * 1. guard: tunnel must be running; entry must exist;
     * 2. validate the new entry exactly like a start
     *    ([prepareStart] — guard + client creation). Rejected =
     *    keep the old selection (ProfileStore selection is
     *    reverted to the old routed guid) + log, tunnel untouched.
     *    The temporary client is closed at once — the forwarder
     *    creates the routed client itself, on demand, per
     *    connection (see [LiveSwitch]);
     * 3. Root mode has no route engine (RootForwarder holds one
     *    client) — it cannot switch live, so it restarts with the
     *    new entry instead (old behaviour, logged);
     * 4. [VpnConnection.switchEntry] moves the "Connected:" label
     *    while staying RUNNING — false while STARTING (the start
     *    worker would overwrite the label), so the switch is
     *    cancelled and the selection reverted;
     * 5. the shared [GroupsStore] selection moves (the step that
     *    actually re-routes NEW connections — see [LiveSwitch]);
     *    a save failure reverts the label to the old entry;
     * 6. notification text follows the new entry, and the Pemicu
     *    loop restarts on the new entry's target (M5 primes only
     *    the connected entry; no target = the loop simply stops —
     *    never a crash). The loop's first tick primes at once
     *    (lastPrime is cleared by stop()), so the new entry's
     *    window is primed in the background while routing has
     *    already moved — the switch itself never blocks on a
     *    prime dial.
     *
     * Runs on the main thread (onStartCommand) and does no
     * network I/O itself: [prepareStart] only constructs the
     * client (dial happens later, per connection).
     */
    private fun switchTunnel(newGuid: String?) {
        if (newGuid.isNullOrBlank()) {
            DialLog.log("SWITCH", "pindah live dibatalkan — guid kosong")
            return
        }
        if (!connection.isRunning) {
            DialLog.log("SWITCH", "pindah live dibatalkan — tunnel tidak jalan")
            return
        }
        val store = ProfileStore(ProfileStore.defaultFile(filesDir))
        store.load()
        val item: ProfileItem = store.find(newGuid) ?: run {
            DialLog.log("SWITCH", "pindah live dibatalkan — server tidak ditemukan")
            return
        }
        val label = dialLabel(item)
        // The routed entry before the switch — the selection to
        // restore when any step below fails.
        val groupsStore = ClashApiRuntime.refreshGroups(filesDir)
        // v1.0.23: the main group BY ID — a renamed main group
        // still yields the routed entry here.
        val oldGuid = groupsStore.mainGroup()
            ?.effectiveSelectedMemberGuid()
            ?: store.selectedGuid
        // Root mode cannot switch live (single-client forwarder,
        // no route engine): restart with the new entry instead.
        // The group selection moves first, so the restarted
        // tunnel and the dashboard agree on the new entry.
        if (rootHandle != null) {
            DialLog.log(
                "SWITCH",
                "Root mode: pindah live tidak didukung — restart tunnel ke '${item.displayName()}'",
            )
            applyLiveSwitchSelection(groupsStore.groups, newGuid, groupsStore.mainGroupId)?.let { updated ->
                updated.firstOrNull { it.id == groupsStore.mainGroup()?.id }
                    ?.let { groupsStore.updateGroup(it) }
            }
            stopTunnel()
            startTunnel()
            return
        }
        // Validate exactly like a start; a rejected entry must not
        // kill the running tunnel or move the selection.
        val muxConfig = MuxConfig.fromSettings(SettingsStore(this))
        when (val prepared = prepareStart(item, muxConfig)) {
            is PreparedStart.Rejected -> {
                DialLog.log(
                    "SWITCH",
                    "pindah live ditolak (${prepared.message}): $label — tetap di entry lama",
                )
                store.setSelectedGuid(oldGuid)
                return
            }
            is PreparedStart.Ready -> runCatching { prepared.client.close() }
        }
        val oldLabel = connection.runningEntry
        if (!connection.switchEntry(label)) {
            DialLog.log(
                "SWITCH",
                "pindah live dibatalkan — tunnel masih starting; ketuk lagi sesudah Connected",
            )
            store.setSelectedGuid(oldGuid)
            return
        }
        try {
            applyLiveSwitchSelection(groupsStore.groups, newGuid, groupsStore.mainGroupId)?.let { updated ->
                updated.firstOrNull { it.id == groupsStore.mainGroup()?.id }
                    ?.let { groupsStore.updateGroup(it) }
            }
        } catch (e: Exception) {
            DialLog.log("SWITCH", "pindah live gagal simpan grup (${e.javaClass.simpleName}) — kembali ke entry lama")
            if (oldLabel != null) connection.switchEntry(oldLabel)
            store.setSelectedGuid(oldGuid)
            return
        }
        DialLog.log("SWITCH", "pindah live ke '${item.displayName()}' (tanpa restart tunnel)")
        updateNotification("Connected: ${connectedLabel(label)}")
        // M5 follows the connected entry: stop the old loop, start
        // the new entry's target (none = loop stays stopped).
        PemicuManager.stop()
        PemicuManager.targetFromProfile(item)?.let { target ->
            PemicuManager.start { listOf(target) }
        }
    }

    private fun startTunnel() {
        val store = ProfileStore(ProfileStore.defaultFile(filesDir))
        store.load()
        // v1.0.5 (kelompok F, Observatory): bila ronde probe
        // sebelumnya menemukan entry terbaik yang berbeda dari
        // pilihan saat ini, SARANKAN saja di log — tunnel tetap
        // memakai pilihan user; tidak ada auto-switch.
        Observatory.bestGuidForNextStart(store.profiles)?.let { bestGuid ->
            val selected = store.find(store.selectedGuid ?: "")
                ?: store.profiles.firstOrNull()
            if (selected != null && bestGuid != selected.guid) {
                val best = store.find(bestGuid)
                if (best != null) {
                    DialLog.log(
                        "OBSERVATORY",
                        "saran entry terbaik: '${best.displayName()}' " +
                            "— ketuk entry itu untuk pindah (tunnel tidak dipindah otomatis)",
                    )
                }
            }
        }
        val item: ProfileItem = store.find(store.selectedGuid ?: "")
            ?: store.profiles.firstOrNull()
            ?: run {
                connection.reportFailure("Tidak ada server — tambah dulu lewat +")
                return
            }
        // Guard + client creation run on the main thread, so a
        // rejected entry fails immediately with a clear status —
        // no worker, no foreground notification, no TUN.
        // v1.0.5 (kelompok D): mux dibaca dari Settings di sini
        // (satu-satunya tempat service menyentuh Settings untuk
        // mux) dan diteruskan ke prepareStart — default OFF, jadi
        // start tanpa mux tidak berubah.
        val muxConfig = MuxConfig.fromSettings(SettingsStore(this))
        when (val prepared = prepareStart(item, muxConfig)) {
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
                thread(name = "taptapng-start", isDaemon = true) {
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
            // v1.0.2 (XVEON order): the connect log opens with the
            // profile line — "Starting profile 'iflix cloudfront'..."
            // — the same first line XVEON logs.
            DialLog.log("START", "Starting profile '${item.displayName()}'...")
            // v1.0.3 (XVEON parity): "Initializing Xray Core
            // (VMess over WebSocket (WS) + TLS)" right after
            // Starting profile and before the outbound dial —
            // the same second line XVEON logs. Label only (see
            // initializingLine); null for SSH entries.
            initializingLine(item)?.let { DialLog.log("START", it) }
            // v1.0.24 (M5): prime dulu, baru probe — prime dial in-app
            // membuka jendela operator, lalu dial utama memakai jendela
            // yang sudah buka. Best-effort: primeNowSync tidak pernah
            // throw dan kegagalannya hanya tercatat di Log (PRIME
            // GAGAL), jadi start tidak pernah gagal karena primenya.
            PemicuManager.primeNowSync(item)
            probeDial(client, item, label)
            val established = synchronized(tunnelLock) {
                if (!isCurrentStart(gen)) {
                    false
                } else if (SettingsStore(this).enableRootMode) {
                    // v1.0.15 (Root mode): tanpa TUN — aturan
                    // iptables + forwarder lokal. true = root jalan;
                    // false = root tidak tersedia → fallback ke
                    // VpnService; install gagal = throw (pesan jelas,
                    // bukan fallback diam-diam — lihat establishRootMode).
                    if (establishRootMode(client, item)) {
                        true
                    } else {
                        DialLog.log(
                            "ROOT",
                            "root tidak tersedia — fallback ke VpnService",
                        )
                        establishTunnel(client, item)
                        true
                    }
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
            // v1.0.4 (zombie loop, review Claude): cek ulang
            // generation SEBELUM start — Stop yang terjadi di antara
            // cek isCurrentStart di atas dan baris ini sudah
            // memanggil PemicuManager.stop(); start() tanpa cek akan
            // menghidupkan loop baru yang jalan tanpa hook protect
            // sampai Stop berikutnya. PemicuManager sendiri punya
            // guard generation, tapi guard itu hanya membunuh loop
            // LAMA — ia tidak tahu start() ini sudah basi. Perhatian:
            // isCurrentStart TIDAK bisa dipakai di sini — state sudah
            // RUNNING sesudah reportConnected, jadi yang dicek hanya
            // generation-nya (startGeneration hanya berubah saat
            // Stop/start baru).
            if (gen == startGeneration) {
                // v1.0.24 (M5): jaga jendela tetap buka selama VPN
                // jalan — auto-prime tiap interval entry. Hanya bila
                // entry ini memang punya target prime (chip nyala +
                // domain terisi); tanpa target tidak ada loop yang jalan.
                PemicuManager.targetFromProfile(item)?.let { target ->
                    PemicuManager.start { listOf(target) }
                }
            }
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

    /**
     * Root mode (v1.0.15): ganti TUN dengan iptables + forwarder
     * lokal. Berjalan di bawah [tunnelLock] (lihat runStart).
     *
     * Urutan: cek root + pasang aturan (controller — rollback
     * otomatis bila gagal) → relay DNS → forwarder lokal.
     * Bila listener gagal bind, aturan di-rollback supaya tidak
     * ada REDIRECT ke port yang tidak didengarkan (internet mati).
     *
     * Mengembalikan true bila root jalan, false bila root TIDAK
     * tersedia (service fallback ke VpnService), dan melempar
     * bila install gagal (pesan jelas di status).
     *
     * TunnelState.up SENGAJA tetap false: tidak ada TUN, dan
     * protect() tidak relevan — dial aplikasi sendiri dikecualikan
     * dari REDIRECT oleh aturan owner UID, bukan oleh protect().
     * Observatory + SOCKS lokal tidak jalan di Root mode v1
     * (keduanya dipasang di establishTunnel).
     */
    private fun establishRootMode(client: ProxyClient, item: ProfileItem): Boolean {
        val settings = SettingsStore(this)
        val config = RootIptables.Config(appUid = android.os.Process.myUid())
        when (val started = RootTunnelController().start(SuExecutor(), config)) {
            is RootTunnelController.StartResult.NoRoot -> {
                DialLog.log("ROOT", started.reason)
                return false
            }
            is RootTunnelController.StartResult.Failed -> {
                throw IllegalStateException("Root mode gagal: ${started.reason}")
            }
            is RootTunnelController.StartResult.Ok -> Unit
        }
        val knownHosts4 = java.util.concurrent.ConcurrentHashMap<Int, String>()
        val knownHosts6 = java.util.concurrent.ConcurrentHashMap<String, String>()
        val dnsRelay = RootDnsRelay(
            proxy = client,
            recordHost = { addr, host ->
                Sniffer.ipv4ToInt(addr)?.let { knownHosts4[it] = host.lowercase() }
                    ?: run {
                        if (addr is java.net.Inet6Address) {
                            knownHosts6[TcpPacket.IpAddr(addr.address).toString()] =
                                host.lowercase()
                        }
                    }
            },
        )
        val forwarder = RootForwarder(
            proxy = client,
            routeOnlyEnabled = settings.routeOnlyEnabled,
            knownHosts4 = knownHosts4,
            knownHosts6 = knownHosts6,
        )
        try {
            dnsRelay.start()
            forwarder.start()
        } catch (e: Exception) {
            runCatching { forwarder.stop() }
            runCatching { dnsRelay.stop() }
            RootTunnelController().stop(SuExecutor(), config)
            throw IllegalStateException(
                "Root mode gagal: listener lokal gagal bind (${e.message}) — aturan dibersihkan",
            )
        }
        rootHandle = RootModeHandle(config, forwarder, dnsRelay)
        currentClient = client
        DialLog.log("ROOT", "ROOT CONNECTED (${item.displayName()} — iptables, tanpa TUN)")
        return true
    }

    /** Handle Root mode aktif (config + forwarder + relay DNS). */
    private class RootModeHandle(
        val config: RootIptables.Config,
        val forwarder: RootForwarder,
        val dnsRelay: RootDnsRelay,
    )

    /** Build the TUN + forwarder. Runs under [tunnelLock] (see runStart). */
    private fun establishTunnel(client: ProxyClient, item: ProfileItem) {
        // v1.0.5 (DNS C): DNS tunnel kini dari Settings
        // ([DnsSettings]) — vpnDns jadi DNS utama (default 1.1.1.1
        // bila kosong/bukan IP), remoteDns (DoH) + domesticDns +
        // dnsHosts + local/fake DNS + metode resolve outbound
        // diteruskan ke resolver + relay. Sebelum v1.0.5 (v1.0.3)
        // tunnel DNS paten PRIMARY_DNS + SECONDARY_DNS dan Remote
        // DNS tidak dipakai tunnel sama sekali. Nilai default TIDAK
        // berubah, jadi log "DNS: Primary DNS set to 1.1.1.1" tetap
        // sama bila user tidak mengubah vpnDns (paritas log XVEON).
        val settings = SettingsStore(this)
        val dnsSettings = DnsSettings(
            vpnDns = settings.vpnDns,
            remoteDns = settings.remoteDns,
            domesticDns = settings.domesticDns,
            dnsHosts = settings.dnsHosts,
            localDnsEnabled = settings.localDnsEnabled,
            fakeDnsEnabled = settings.fakeDnsEnabled,
            outboundResolveMethod = settings.outboundResolveMethod,
        )
        val primaryDns = dnsSettings.effectiveTunnelDns()
        val dohUrl = dnsSettings.remoteDohUrl()
        // Resolver host proxy (dial / delay test / prime): metode
        // dari Settings + pemetaan statis. Default metode "1" =
        // operator-first seperti v1.0.4.
        DnsResolver.resolveMethod = dnsSettings.resolveMethod()
        DnsResolver.staticHosts = dnsSettings.staticHosts()
        DnsResolver.preferIpv6 = settings.preferIpv6
        // FakeDNS hidup hanya bila local + fake sama-sama ON (kunci
        // UI yang sama); bila fake tersimpan ON tapi local OFF,
        // catat sekali supaya tidak diam-diam mati.
        val fakeDns = if (dnsSettings.fakeDnsActive) FakeDns() else null
        if (settings.fakeDnsEnabled && !settings.localDnsEnabled) {
            DialLog.log("DNS", "FakeDNS OFF — butuh local DNS ON")
        }
        val dnsPolicy = DnsRelayPolicy(
            staticHosts = DnsResolver.staticHosts,
            domesticDnsServer = dnsSettings.effectiveDomesticDns(),
            remoteDohUrl = dohUrl,
            localDnsEnabled = settings.localDnsEnabled,
            fakeDns = fakeDns,
            // Resolver lokal = hook operator (jaringan fisik) yang
            // dipasang installProtectHooks — lihat
            // TunForwarder.localResolve.
            localResolve = { host, _ ->
                DnsResolver.operatorResolve?.invoke(host, DnsResolver.DEFAULT_TIMEOUT_MS)
                    ?: emptyList()
            },
            dohClient = dohUrl?.let { DohClient(it) },
        )
        // MTU comes from Settings; out-of-range values fall back
        // to the default instead of breaking establish(). v1.0.21:
        // the default is 9000 (was v2rayNG's 1500) — the writer's
        // ~5000 writes/s ceiling caps throughput at ~55 Mbps with
        // 1460-byte segments, and a 9000 MTU lets the app offer
        // 8960-byte segments (sing-box TUN uses 9000 too). The
        // setting still overrides; the 576..9000 range is unchanged.
        val mtu = settings.vpnMtu.trim().toIntOrNull()
            ?.takeIf { it in 576..9000 } ?: 9000
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
            .setSession("TaptapNG")
            .addAddress(tunIpv4ClientAddress(settings.vpnInterfaceAddress), 30)
            .apply {
                // v1.0.5, group A (v2rayNG "Bypass LAN", stored "1" =
                // default): when on, the TUN gets the public-space
                // routes only — LAN traffic never enters the tunnel
                // and goes out the physical interface. When off, the
                // single catch-all route (v1.0.4 behaviour).
                for (route in LanBypass.tunnelRoutes(settings.vpnBypassLan)) {
                    addRoute(route.address, route.prefixLength)
                }
                if (LanBypass.bypassEnabled(settings.vpnBypassLan)) {
                    DialLog.log("VPN", "Bypass LAN aktif — rute LAN tidak lewat tunnel")
                }
            }
            .apply {
                // v1.0.6 (M6): bila IPv6 nyala, TUN juga mendapat
                // alamat IPv6 (ULA fd00:1:2:3::1/64) + rute ::/0 —
                // tanpa alamat IPv6 di interface, aplikasi tidak
                // punya source address IPv6 dan tidak pernah
                // mengirim paket IPv6 ke TUN. Alamat ini dugaan
                // yang wajar (ULA, tidak bentrok dengan LAN) —
                // verifikasi di HP (lihat README v1.0.6).
                if (settings.ipv6Enabled) {
                    addAddress("fd00:1:2:3::1", 64)
                    addRoute("::", 0)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) setMetered(false)
            }
            .addDnsServer(primaryDns)
            .addDnsServer(SECONDARY_DNS)
            .setMtu(mtu)
        // v1.0.9: exclude our own package from the VPN — v2rayNG's
        // CoreVpnService.configurePerAppProxy does exactly this
        // ("if per-app proxy is not enabled, disallow the VPN
        // service's own package"). Our dial/DNS/test sockets are
        // created by this app, so they bypass the TUN at the routing
        // level even when VpnService.protect() returns false — which
        // it does on this phone once the TUN is up (delay test
        // "protect gagal", taptapng-6.txt 04:18; with protect as the
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
        // v1.0.3 (XVEON parity): the DNS + VPN CONNECTED lines
        // come right after the protocol handshake (the probe) and
        // before reportConnected — the same tail XVEON logs:
        // "DNS: Primary DNS set to 1.1.1.1" /
        // "DNS: Secondary DNS set to 1.0.0.1" /
        // "VPN CONNECTED (1 - 10.11.12.2/30)". The "1" in XVEON's
        // line is the PROFILE NAME — its log opens with
        // "Starting profile '1'..." — so here it is the entry's
        // display name, not a hardcoded 1. The TUN address stays
        // TaptapNG's own (from the interface-address setting,
        // default 10.10.14.1); only the format is XVEON's.
        DialLog.log("DNS", "DNS: Primary DNS set to $primaryDns")
        DialLog.log("DNS", "DNS: Secondary DNS set to $SECONDARY_DNS")
        DialLog.log(
            "VPN",
            "VPN CONNECTED (${item.displayName()} - ${tunIpv4ClientAddress(settings.vpnInterfaceAddress)}/30)",
        )
        // v1.0.11: the fd from establish() is NON-BLOCKING
        // (O_NONBLOCK) — FileInputStream.read() returns 0 at once
        // when no packet is waiting (EAGAIN), and the reader
        // treated 0 as end-of-stream and exited 1 ms after start
        // (phone log 08:05:09.528–529, "baca TUN selesai (n=0)").
        // Set it blocking so read() waits for the first packet;
        // the reader then only exits on stop() or a real read
        // error. (Os has no setBlocking — that lives in hidden
        // libcore.io.IoUtils; fcntlInt is the public API.)
        // v2rayNG never hits this: it hands the fd to the
        // native core, and xray-core's Android TUN sets the fd
        // non-blocking and waits in the Go poller
        // (tun_android.go: SetNonblock + fdTun.ReadParts) — a
        // naive Java read loop must have a blocking fd instead.
        try {
            val flags = android.system.Os.fcntlInt(
                fd.fileDescriptor, android.system.OsConstants.F_GETFL, 0,
            )
            android.system.Os.fcntlInt(
                fd.fileDescriptor, android.system.OsConstants.F_SETFL,
                flags and android.system.OsConstants.O_NONBLOCK.inv(),
            )
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
        currentClient = client
        // M7: routing — grup + aturan dari GroupsStore (default:
        // grup "taptap" SELECT berisi semua profil + FINAL -> taptap,
        // jadi perilaku sama seperti sebelum M7), cache delay
        // url-test (diisi loop berkala, di-seed sekali dari
        // Observatory), dan cache client per guid anggota grup.
        // Client entry terpilih = client tunnel ini sendiri, jadi
        // keputusan default (FINAL -> taptap -> entry terpilih)
        // memakai client yang sama persis seperti sebelum M7.
        // LIVE RELOAD (W3): resolver membaca grup/aturan dari
        // GroupsStore BERSAMA (ClashApiRuntime — dipakai juga oleh
        // API Clash, jadi PUT select dari dashboard langsung
        // berlaku untuk koneksi baru tanpa restart VPN) dan mode
        // Clash dari SettingsStore tiap koneksi; grup/aturan TIDAK
        // lagi dibaca sekali saat tunnel naik.
        val profileStore = ProfileStore(ProfileStore.defaultFile(filesDir)).apply { load() }
        val groupsStore = ClashApiRuntime.ensureGroupsStore(filesDir)
        groupsStore.load(profileStore.profiles, profileStore.selectedGuid)
        // v1.0.19 (live switch): samakan seleksi grup "taptap"
        // dengan entry yang dipilih — lihat [LiveSwitch]: tanpa
        // ini route engine tetap merute koneksi baru ke anggota
        // SELECT lama (seleksi grup tidak pernah disinkron dari
        // ProfileStore sesudah grup default dibuat), jadi "pilih +
        // start" pun tidak benar-benar pindah server.
        // v1.0.23: by main-group id — a renamed main group still
        // syncs here.
        applyLiveSwitchSelection(groupsStore.groups, item.guid, groupsStore.mainGroupId)?.let { updated ->
            updated.firstOrNull { it.id == groupsStore.mainGroup()?.id }
                ?.let { groupsStore.updateGroup(it) }
        }
        val urlCache = UrlTestCache().also { it.seedFromObservatory() }
        urlTestCache = urlCache
        ClashApiRuntime.urlTestCache = urlCache
        routeClientCache[item.guid] = client
        val muxForRoutes = MuxConfig.fromSettings(settings)
        val clientForGuid: (String) -> ProxyClient? = { guid ->
            routeClientCache[guid] ?: run {
                val p = profileStore.find(guid) ?: return@run null
                runCatching { ProxyClientFactory.create(p, muxForRoutes) }
                    .getOrNull()?.also { routeClientCache[guid] = it }
            }
        }
        val testLoop = UrlTestLoop(
            cache = urlCache,
            groupsProvider = { groupsStore.groups.toList() },
            profilesProvider = { profileStore.profiles.toList() },
        )
        urlTestLoop = testLoop
        ClashApiRuntime.urlTestLoop = testLoop
        testLoop.start()
        try {
            val tunIn = FileInputStream(fd.fileDescriptor)
            val tunOut = FileOutputStream(fd.fileDescriptor)
            val fwd = TunForwarder(
                tunIn = tunIn,
                tunOut = tunOut,
                proxy = client,
                // v1.0.3 (XVEON parity): in-tunnel DNS queries
                // (UDP/53 intercepted from apps) are forwarded to
                // the tunnel's PRIMARY DNS — the same server Android
                // was told to use via addDnsServer. v1.0.5: primernya
                // kini dari Settings vpnDns (default 1.1.1.1), dan
                // kebijakan relay (dnsHosts / domestik / DoH /
                // local / FakeDNS) diteruskan lewat dnsPolicy.
                // (v1.0.2 used Settings Remote DNS here; that value
                // no longer drives the tunnel.) v1.0.4: on a primary
                // timeout the forwarder retries the SECONDARY DNS
                // (1.0.0.1) — before, 1.0.0.1 was only in
                // addDnsServer and never used by the forwarder. The
                // proxy-host resolver (DnsResolver, 8.8.8.8) is a
                // different path and is unchanged.
                dnsServer = primaryDns,
                dnsFallbackServer = SECONDARY_DNS,
                dnsPolicy = dnsPolicy,
                protectUdp = { socket -> protect(socket) },
                onStatus = { msg -> connection.reportDialStatus(msg) },
                tunMtu = mtu,
                // v1.0.5 (kelompok F): sniffing + route-only dari Settings.
                sniffingEnabled = settings.sniffingEnabled,
                routeOnlyEnabled = settings.routeOnlyEnabled,
                // M7: routing per koneksi (grup + aturan + delay
                // cache). Resolver membaca grup/aturan/mode LIVE
                // tiap koneksi (lihat atas) — PUT select dari
                // dashboard berlaku tanpa restart VPN. Client per
                // guid diambil dari cache (dibuat sekali per guid).
                routeResolver = { host, ip, port ->
                    RouteEngine.resolve(
                        host, ip, port,
                        groupsStore.groups, groupsStore.rules, urlCache.delays(),
                        mode = SettingsStore(this).clashMode,
                        // v1.0.23: the engine's fallback / global
                        // group follows the main group by id, so a
                        // rename never moves the fallback.
                        mainGroupId = groupsStore.mainGroupId,
                    )
                },
                // v1.0.29 (merge): same decision as routeResolver,
                // plus the record (rule + chain) for GET
                // /connections. The forwarder prefers this when
                // installed. serverNames is rebuilt per connection
                // from the profile store (de-duplicated exactly
                // like ClashApiHandler.displayNames) so a rename
                // is picked up without restarting the tunnel.
                routeRecordResolver = { host, ip, port ->
                    val names = LinkedHashMap<String, String>()
                    val seen = HashMap<String, Int>()
                    for (p in profileStore.profiles) {
                        val base = p.displayName()
                        val n = (seen[base] ?: 0) + 1
                        seen[base] = n
                        names[p.guid] = if (n == 1) base else "$base #$n"
                    }
                    RouteEngine.resolveDetailed(
                        host, ip, port,
                        groupsStore.groups, groupsStore.rules, urlCache.delays(),
                        mode = SettingsStore(this).clashMode,
                        mainGroupId = groupsStore.mainGroupId,
                        serverNames = names,
                    )
                },
                clientProvider = clientForGuid,
            )
            forwarder = fwd
            ClashApiRuntime.forwarder = fwd
            fwd.start()
            // v1.0.5 (B): local SOCKS proxy — hidup mengikuti tunnel.
            // Gagal bind (port sudah dipakai) TIDAK boleh membunuh
            // tunnel: tangkap, catat, tunnel tetap jalan tanpa SOCKS.
            if (settings.isLocalProxyEffective) {
                val socks = SocksServer(
                    config = SocksConfig.fromSettings(settings),
                    dial = { host, port -> client.dial(host, port) },
                    // v1.0.6 (M6): UDP ASSOCIATE lewat jalur UDP proxy
                    // yang sama dengan forwarder TUN.
                    dialUdp = { host, port -> client.dialUdp(host, port) },
                )
                socksServer = socks
                runCatching { socks.start() }.onFailure {
                    DialLog.failure("SOCKS", it)
                    socksServer = null
                }
            }
            // v1.0.5 (kelompok F, Observatory): probing berkala
            // selama tunnel hidup — ronde ping tiap interval
            // least-ping, ronde load tiap interval least-load
            // (metode/sampling/timeout dari Settings). Hasil hanya
            // saran; tunnel tidak pernah dicabut (lihat Observatory).
            val obsConfig = Observatory.Config.fromSettings(
                leastPing = settings.observatoryLeastPing,
                leastLoad = settings.observatoryLeastLoad,
                method = settings.observatoryLeastLoadMethod,
                sampling = settings.observatoryLeastLoadSampling,
                timeout = settings.observatoryLeastLoadTimeout,
                delayTestUrl = settings.delayTestUrl,
            )
            observatoryRunner = ObservatoryRunner(
                config = obsConfig,
                itemsProvider = {
                    ProfileStore(ProfileStore.defaultFile(filesDir))
                        .apply { load() }.profiles.toList()
                },
                isActive = {
                    runCatching {
                        (getSystemService(Context.POWER_SERVICE) as android.os.PowerManager)
                            .isInteractive
                    }.getOrDefault(true)
                },
                onBestChanged = { best, result ->
                    DialLog.log(
                        "OBSERVATORY",
                        "entry terbaik saat ini: '${best.displayName()}' " +
                            "(${result.ms}ms, ${result.method}) — saran untuk " +
                            "koneksi berikutnya, tunnel tidak dicabut",
                    )
                },
            ).also { it.start() }
        } catch (e: Exception) {
            runCatching { fd.close() }
            tunFd = null
            // M7: establish gagal — hentikan loop url-test yang
            // baru dibuat (teardownTunnel belum tentu dipanggil
            // untuk start basi); client tunnel ditutup pemanggil.
            runCatching { urlTestLoop?.stop() }
            urlTestLoop = null
            urlTestCache = null
            ClashApiRuntime.urlTestLoop = null
            ClashApiRuntime.urlTestCache = null
            ClashApiRuntime.forwarder = null
            routeClientCache.values.filter { it !== client }
                .forEach { runCatching { it.close() } }
            routeClientCache.clear()
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
        // v1.0.6 (M6): sama untuk socket UDP (relay SS UDP) —
        // tanpa ini datagram SS masuk TUN dan berputar di forwarder.
        Transport.protectUdpSocket = { socket -> protect(socket) }
        // Same for the prime dials (v1.0.24, M5): a prime socket
        // must bypass the TUN exactly like a probe dial.
        PemicuManager.protectSocket = { socket -> protect(socket) }
        // Same for delay-test sockets (v1.0.4): without this, a test
        // run while the VPN is up dials through the tunnel and
        // reports a false "Timeout" (see ServerTester).
        ServerTester.protectSocket = { socket -> protect(socket) }
        // Same for the direct DNS resolver (v1.0.5): without this,
        // DnsResolver queries go through the TUN and loop in the
        // forwarder's DNS relay instead of reaching 8.8.8.8.
        DnsResolver.protectUdp = { socket -> protect(socket) }
        // Same for the operator resolver (v1.0.4, review Claude):
        // the proxy host is resolved FIRST through the physical
        // (non-VPN) network — the way XVEON resolves it (dex
        // d9.txt:851 Network.getAllByName, fallback InetAddress
        // .getAllByName). Direct UDP 8.8.8.8, then the system
        // resolver, stay as fallbacks. No ConnectivityManager (or
        // no usable network) means no operator path — the hook
        // stays null and resolve behaves exactly like v1.0.3.
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        DnsResolver.operatorResolve = if (cm != null) {
            { host, timeoutMs -> DnsResolver.networkResolveAll(cm, host, timeoutMs) }
        } else {
            null
        }
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
        // v1.0.24 (M5): hentikan loop prime dulu — tidak ada lagi
        // prime dial yang boleh mulai saat TUN dibongkar.
        PemicuManager.stop()
        // v1.0.5 (kelompok F): hentikan probing Observatory — probe
        // butuh tunnel yang hidup.
        runCatching { observatoryRunner?.stop() }
        observatoryRunner = null
        // M7: hentikan loop url-test + tutup client anggota grup
        // yang ter-cache (kecuali client tunnel — ditutup di bawah
        // bersama currentClient).
        runCatching { urlTestLoop?.stop() }
        urlTestLoop = null
        urlTestCache = null
        ClashApiRuntime.urlTestLoop = null
        ClashApiRuntime.urlTestCache = null
        ClashApiRuntime.forwarder = null
        routeClientCache.values.filter { it !== currentClient }
            .forEach { runCatching { it.close() } }
        routeClientCache.clear()
        probeWatchdog?.cancel()
        probeWatchdog = null
        synchronized(tunnelLock) {
            runCatching { socksServer?.stop() }
            socksServer = null
            runCatching { forwarder?.stop() }
            forwarder = null
            runCatching { tunFd?.close() }
            tunFd = null
            // v1.0.15 (Root mode): hentikan forwarder + relay DNS
            // lokal, lalu HAPUS semua aturan iptables. Bila handle
            // null tapi Root mode ON (start gagal di tengah /
            // crash), bersihkan aturan basi best-effort dengan
            // config default — cleanup hanya menyentuh rantai
            // milik TaptapNG, jadi aman dipanggil selalu.
            val root = rootHandle
            rootHandle = null
            if (root != null) {
                runCatching { root.forwarder.stop() }
                runCatching { root.dnsRelay.stop() }
                val failed = runCatching {
                    RootTunnelController().stop(SuExecutor(), root.config)
                }.getOrDefault(listOf("executor gagal"))
                if (failed.isNotEmpty()) {
                    DialLog.log(
                        "ROOT",
                        "cleanup gagal (${failed.size} aturan tertinggal) — " +
                            "pulihkan manual: ${failed.first()}",
                    )
                }
            } else if (runCatching { SettingsStore(this).enableRootMode }.getOrDefault(false)) {
                val stale = runCatching {
                    RootTunnelController().cleanupStale(
                        SuExecutor(),
                        RootIptables.Config(appUid = android.os.Process.myUid()),
                    )
                }.getOrDefault(emptyList())
                if (stale.isNotEmpty()) {
                    DialLog.log("ROOT", "aturan basi tertinggal (${stale.size}) saat teardown")
                }
            }
            // M3: close the client so a SlowDNS session is torn down
            // (idempotent — runStart also closes it on its paths).
            runCatching { currentClient?.close() }
            currentClient = null
        }
        Transport.protectSocket = null
        Transport.protectUdpSocket = null
        PemicuManager.protectSocket = null
        ServerTester.protectSocket = null
        DnsResolver.protectUdp = null
        DnsResolver.operatorResolve = null
        // v1.0.5 (DNS C): reset state DNS per-tunnel — pemetaan
        // statis + metode resolve tidak boleh bocor ke start
        // berikutnya (default = tanpa pemetaan + operator-first).
        DnsResolver.staticHosts = emptyMap()
        DnsResolver.resolveMethod = OutboundResolveMethod.OPERATOR_FIRST
        DnsResolver.preferIpv6 = false
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
                "TaptapNG VPN",
                NotificationManager.IMPORTANCE_LOW,
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TaptapNG")
            .setContentText("Connected: $remarks")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    /** Replace the foreground notification's text (e.g. after a failed probe). */
    private fun updateNotification(text: String) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TaptapNG")
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .build()
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        runCatching { manager.notify(NOTIFICATION_ID, notification) }
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
