package com.taptap.x.core

import com.taptap.x.AppConfig
import com.taptap.x.data.ProfileItem
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.thread

/**
 * Pemicu (built-in primer, M5, v1.0.24): TaptapX itself dials the
 * prime domains of the running entry to keep the operator window
 * open — no root, no separate primer APK.
 *
 * Model (TB v1.0.84 + v2rayNG PemicuManager, both phone-proven):
 * the primer is FULLY SEPARATE from the entry — it only ever reads
 * the entry's own Pemicu fields (chip, domain, port, interval).
 * An empty prime domain means the entry is NOT primed (no fallback
 * to the entry's address); the prime port defaults to 443 (empty or
 * out of range falls back to 443) and never comes from the entry's
 * port; the interval defaults to 15 s and is clamped to 5..300 s.
 * The primer NEVER reads or modifies the entry's address/port or
 * any VMess/proxy config — [targetFromProfile] is the only place
 * the entry is read, and it touches only the pemicu_* fields.
 *
 * The dial is a plain in-app TLS handshake (Java SSLSocket, the
 * same dial pemicu.apk / Hook / v2rayNG use) on a socket the
 * VpnService protects (VpnService.protect(), so the dial bypasses
 * the tunnel and goes direct). The app package is additionally
 * disallowed from the VPN, so the dial bypasses even if protect()
 * returns false (same rule as Transport/DnsResolver). The SNI of
 * the dial is the prime domain itself, never the entry's address.
 * IPv4 is tried first, then IPv6 ([DnsResolver.resolveAll]).
 *
 * Lifecycle (owned by TaptapVpnService): [primeNowSync] runs once
 * BEFORE the probe dial at start (prime first, then the main dial
 * can use the open window); [start] runs the auto-prime loop while
 * the VPN is up (v1.0.25: the loop sleeps until the next prime
 * falls due — ~1 wakeup per interval instead of 1 per second; a
 * host is dialled when its interval has elapsed since its last
 * prime); [stop] ends the loop and closes in-flight dials. A prime
 * failure is only ever logged (PRIME GAGAL) — it NEVER fails the
 * VPN start or connection.
 */
object PemicuManager {

    /** TCP connect timeout for a prime dial (v2rayNG PemicuManager). */
    const val TCP_TIMEOUT_MS = 5_000

    /** TLS handshake read timeout for a prime dial. startHandshake()
     *  must never run without a timeout — pemicu.apk v1.0.0 could
     *  hang on a silent server. */
    const val TLS_TIMEOUT_MS = 10_000

    /** Min sleep of the prime loop (1 s, v1.0.25): the loop never
     *  spins faster than this, even when a target is due at once. */
    private const val MIN_SLEEP_MS = 1_000L

    /** Sleep while the loop has no targets at all (5 s, v1.0.25):
     *  the provider is re-read after this, so editing the entry's
     *  Pemicu fields while the VPN runs takes effect within 5 s. */
    private const val IDLE_SLEEP_MS = 5_000L

    /** One prime host + its interval (seconds). */
    data class PemicuTarget(val host: String, val port: Int, val intervalSec: Int) {
        fun key(): String = "${host.lowercase()}:$port"
    }

    /** Result of one prime dial. */
    sealed class PrimeResult {
        data class Ok(
            val target: PemicuTarget,
            val ip: String,
            val isV4: Boolean,
            val tcpMs: Long,
            val tlsProtocol: String,
            val totalMs: Long,
            val bypassOk: Boolean,
            val localAddr: String,
        ) : PrimeResult()

        data class Failed(val target: PemicuTarget, val error: String) : PrimeResult()
    }

    /**
     * Hook set by [com.taptap.x.service.TaptapVpnService] so prime
     * sockets bypass the TUN (VpnService.protect). Null = direct
     * dial (unit tests, or the VPN is down). Same pattern as
     * [com.taptap.x.core.proto.Transport.protectSocket].
     */
    @Volatile
    var protectSocket: ((Socket) -> Boolean)? = null

    // --- Pure helpers (no Android dependency; unit-tested) ---

    /** Clamp a prime interval to 5..300 s (default 15 when unset). */
    fun clampInterval(v: Int?): Int = when {
        v == null -> AppConfig.PEMICU_DEFAULT_INTERVAL
        v < AppConfig.PEMICU_MIN_INTERVAL -> AppConfig.PEMICU_MIN_INTERVAL
        v > AppConfig.PEMICU_MAX_INTERVAL -> AppConfig.PEMICU_MAX_INTERVAL
        else -> v
    }

    /** Clamp a prime port to 1..65535 (default 443 when unset or out
     *  of range — an empty/invalid editor value arrives here as null,
     *  so it also falls back to 443). */
    fun clampPort(v: Int?): Int = when {
        v == null -> AppConfig.PEMICU_DEFAULT_PORT
        v < 1 || v > 65535 -> AppConfig.PEMICU_DEFAULT_PORT
        else -> v
    }

    /**
     * The prime target of one profile, or null when the profile
     * must not be primed (chip off, or the prime domain blank).
     * Reads ONLY the pemicu_* fields — the entry's address/port
     * are never read for priming (see the test that proves it with
     * a bogus entry address).
     */
    fun targetFromProfile(item: ProfileItem): PemicuTarget? {
        if (!item.pemicuEnabled) return null
        val host = item.pemicuDomain.trim()
        if (host.isEmpty()) return null
        return PemicuTarget(
            host = host,
            port = clampPort(item.pemicuPort),
            intervalSec = clampInterval(item.pemicuInterval),
        )
    }

    /** The merged prime list: every enabled profile's target,
     *  deduplicated by host:port (first profile wins). */
    fun buildTargets(profiles: List<ProfileItem>): List<PemicuTarget> {
        val seen = mutableSetOf<String>()
        val out = mutableListOf<PemicuTarget>()
        for (profile in profiles) {
            val target = targetFromProfile(profile) ?: continue
            if (!seen.add(target.key())) continue
            out.add(target)
        }
        return out
    }

    /** The targets whose interval has elapsed since their last
     *  prime (a host never primed is due at once). */
    fun dueTargets(
        targets: List<PemicuTarget>,
        lastPrime: Map<String, Long>,
        now: Long,
    ): List<PemicuTarget> = targets.filter { target ->
        now - (lastPrime[target.key()] ?: 0L) >= target.intervalSec * 1_000L
    }

    /**
     * Milliseconds until the next prime falls due (v1.0.25): the
     * loop sleeps this long instead of polling every second, so an
     * idle VPN wakes ~1×/interval instead of 1×/s (the #2 idle
     * battery drain in the 2026-11-21 audit). A never-primed
     * target is due at once, so the sleep is at least
     * [MIN_SLEEP_MS] (the loop never busy-spins) and at most the
     * longest target interval; with no targets it is
     * [IDLE_SLEEP_MS]. Pure, unit-tested.
     */
    fun msUntilNextDue(
        targets: List<PemicuTarget>,
        lastPrime: Map<String, Long>,
        now: Long,
    ): Long {
        if (targets.isEmpty()) return IDLE_SLEEP_MS
        var minMs = Long.MAX_VALUE
        var maxIntervalMs = 0L
        for (target in targets) {
            val intervalMs = target.intervalSec * 1_000L
            if (intervalMs > maxIntervalMs) maxIntervalMs = intervalMs
            val last = lastPrime[target.key()]
            val nextDue = if (last == null) 0L else last + intervalMs
            val wait = nextDue - now
            if (wait < minMs) minMs = wait
        }
        return minMs.coerceIn(MIN_SLEEP_MS, maxIntervalMs.coerceAtLeast(MIN_SLEEP_MS))
    }

    /** The log line for a prime result, same short shape as the
     *  task spec: "PRIME OK <host>:<port> <ms>" /
     *  "PRIME GAGAL <host> <alasan>". */
    fun formatPrimeResult(result: PrimeResult): String = when (result) {
        is PrimeResult.Ok ->
            "PRIME OK ${result.target.host}:${result.target.port} ${result.totalMs}ms"
        is PrimeResult.Failed ->
            "PRIME GAGAL ${result.target.host}:${result.target.port} (${result.error})"
    }

    // --- Dial ---

    /**
     * One prime dial: plain in-app TLS handshake to the prime
     * domain (SNI = the prime domain, never the entry's address),
     * IPv4 first then IPv6. The socket is protected before it
     * connects so the dial bypasses the tunnel. Returns the first
     * address that completes a handshake, or the last error.
     * Never throws: every failure is a [PrimeResult.Failed].
     *
     * [tlsHandshake] is the seam that wraps the connected socket in
     * TLS and returns the negotiated protocol; it is a parameter
     * (not inlined) because a real SSLSocket handshake cannot run
     * on loopback in the dev VM or CI (see TlsEngineTest), so tests
     * inject a fake that records the call and returns a protocol.
     * Production always passes [defaultTlsHandshake]. [resolve] is
     * the same kind of seam for the address list (default:
     * [DnsResolver.resolveAll], IPv4 first then IPv6).
     */
    fun primeDial(
        target: PemicuTarget,
        protect: ((Socket) -> Boolean)? = protectSocket,
        resolve: (String, Int) -> List<InetAddress> = { host, port ->
            DnsResolver.resolveAll(host, port)
        },
        tlsHandshake: (Socket, String, Int) -> String = ::defaultTlsHandshake,
    ): PrimeResult {
        val started = System.currentTimeMillis()
        val addresses = try {
            resolve(target.host, target.port)
        } catch (e: Exception) {
            return PrimeResult.Failed(target, "resolve: ${e.message ?: e.javaClass.simpleName}")
        }
        if (addresses.isEmpty()) {
            return PrimeResult.Failed(target, "resolve: no address")
        }
        var lastError = "no address"
        for (address in addresses) {
            val isV4 = address is Inet4Address
            val socket = Socket()
            activeSockets.add(socket)
            try {
                val bypassOk = protectDial(socket, protect)
                val tcpStart = System.currentTimeMillis()
                socket.connect(InetSocketAddress(address, target.port), TCP_TIMEOUT_MS)
                val tcpMs = System.currentTimeMillis() - tcpStart
                val protocol = tlsHandshake(socket, target.host, target.port)
                val localAddr = socket.localAddress?.hostAddress ?: "-"
                val totalMs = System.currentTimeMillis() - started
                return PrimeResult.Ok(
                    target = target,
                    ip = address.hostAddress ?: "-",
                    isV4 = isV4,
                    tcpMs = tcpMs,
                    tlsProtocol = protocol,
                    totalMs = totalMs,
                    bypassOk = bypassOk,
                    localAddr = localAddr,
                )
            } catch (e: Exception) {
                lastError = e.message ?: e.javaClass.simpleName
            } finally {
                activeSockets.remove(socket)
                runCatching { socket.close() }
            }
        }
        return PrimeResult.Failed(target, lastError)
    }

    /**
     * Protect one prime socket before it connects (a connected
     * socket is already routed, so protect() would be too late).
     * Returns whether the socket is known to bypass. Same rule as
     * Transport/DnsResolver: no hook or no TUN yet means a direct
     * dial (protect() returns false before establish()); once the
     * TUN is up a refused protect is fatal UNLESS the app is
     * disallowed from the VPN (then the socket bypasses at the
     * routing level anyway — v2rayNG pattern; on this phone
     * protect() returns false once the TUN is up).
     */
    private fun protectDial(socket: Socket, protect: ((Socket) -> Boolean)?): Boolean {
        if (protect == null || !TunnelState.up) return true
        val ok = try {
            protect(socket)
        } catch (_: Exception) {
            false
        }
        if (ok) return true
        if (TunnelState.appBypass) {
            DialLog.log("PRIME", "protect() gagal — prime lanjut via disallow aplikasi")
            return false
        }
        throw IOException("protect() gagal — prime tidak bisa bypass VPN")
    }

    /** Production TLS handshake: wrap the connected socket in an
     *  SSLSocket with SNI = the prime host, handshake with a hard
     *  timeout, return the negotiated protocol. The socket is closed
     *  here (a prime only needs the handshake, not the stream);
     *  [primeDial] also closes the plain socket in its finally. */
    fun defaultTlsHandshake(socket: Socket, host: String, port: Int): String {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val sslSocket = factory.createSocket(socket, host, port, true) as javax.net.ssl.SSLSocket
        try {
            sslSocket.soTimeout = TLS_TIMEOUT_MS
            sslSocket.startHandshake()
            return sslSocket.session.protocol ?: "TLS?"
        } finally {
            runCatching { sslSocket.close() }
        }
    }

    // --- Loop lifecycle (owned by TaptapVpnService) ---

    private val lock = Any()

    /** Generation of the running loop. A stop/start bumps it, so an
     *  old loop thread that is still exiting can never touch the
     *  new loop's state (its finally only clears state when it is
     *  still the current generation's thread). */
    @Volatile
    private var generation = 0

    private var loopThread: Thread? = null

    private val lastPrime = ConcurrentHashMap<String, Long>()
    private val inFlight = ConcurrentHashMap.newKeySet<String>()

    /** Sockets of the dials currently in flight. Closing them from
     *  stop() interrupts a blocking connect/handshake at once (a
     *  thread interrupt alone cannot interrupt blocking I/O). */
    private val activeSockets = ConcurrentHashMap.newKeySet<Socket>()

    /** True while the prime loop thread is alive (tests / UI). */
    val isLoopRunning: Boolean
        get() = synchronized(lock) { loopThread?.isAlive == true }

    /** Loop iterations so far (tests / battery audit, v1.0.25):
     *  the loop sleeps until the next prime is due, so this grows
     *  ~1×/interval, not 1×/s. */
    val loopTickCount: Long
        get() = loopTicks.get()

    private val loopTicks = java.util.concurrent.atomic.AtomicLong(0)

    /**
     * Start the prime loop (v1.0.25: sleeps until the next prime
     * falls due, ~1 wakeup per interval). Idempotent: a second call
     * while the loop runs restarts it with the new provider, so a
     * core reload / re-entry never spawns a duplicate loop. The
     * provider is re-read on every wake, so editing the entry's
     * Pemicu fields takes effect without restarting the VPN (at
     * the latest when the next prime falls due).
     */
    fun start(targetsProvider: () -> List<PemicuTarget>) {
        val gen: Int
        synchronized(lock) {
            generation++
            gen = generation
            loopThread?.interrupt()
            loopThread = thread(name = "taptapx-pemicu", isDaemon = true) {
                DialLog.log("PRIME", "loop prime jalan")
                try {
                    primeLoop(targetsProvider, gen)
                } finally {
                    synchronized(lock) {
                        if (loopThread === Thread.currentThread()) loopThread = null
                    }
                    DialLog.log("PRIME", "loop prime berhenti")
                }
            }
        }
    }

    /** Stop the prime loop and its in-flight dials. Idempotent.
     *  Safe to call from the main thread: it never joins, it only
     *  interrupts and closes sockets (the sleeping loop thread is
     *  interrupted and exits at once, it does not wait out its
     *  sleep until the next prime). */
    fun stop() {
        synchronized(lock) {
            generation++
            loopThread?.interrupt()
            loopThread = null
        }
        for (socket in activeSockets) {
            runCatching { socket.close() }
        }
        activeSockets.clear()
        inFlight.clear()
        lastPrime.clear()
    }

    private fun primeLoop(targetsProvider: () -> List<PemicuTarget>, gen: Int) {
        while (gen == generation) {
            loopTicks.incrementAndGet()
            var targets: List<PemicuTarget> = emptyList()
            try {
                targets = runCatching { targetsProvider() }.getOrElse { emptyList() }
                val now = System.currentTimeMillis()
                for (target in dueTargets(targets, lastPrime, now)) {
                    if (gen != generation) return
                    if (!inFlight.add(target.key())) continue
                    // Record the prime at launch: a dial (ok or
                    // failed) waits the full interval before it is
                    // retried (v2rayNG pattern).
                    lastPrime[target.key()] = now
                    thread(name = "taptapx-prime-${target.key()}", isDaemon = true) {
                        try {
                            val result = primeDial(target)
                            DialLog.log("PRIME", formatPrimeResult(result))
                        } catch (e: Exception) {
                            // primeDial never throws; this is a safety
                            // net so a loop bug can never kill the
                            // scheduler thread.
                            DialLog.log(
                                "PRIME",
                                "PRIME GAGAL ${target.host}:${target.port} (${e.javaClass.simpleName})",
                            )
                        } finally {
                            inFlight.remove(target.key())
                        }
                    }
                }
            } catch (e: Exception) {
                DialLog.log("PRIME", "loop error (${e.javaClass.simpleName})")
                targets = emptyList()
            }
            // v1.0.25: sleep until the next prime falls due instead
            // of polling every second — an idle VPN wakes ~1× per
            // interval. The sleep is interrupted by start()/stop()
            // (the loop thread is interrupted there), so an entry
            // edit or a stop is still noticed at once.
            val sleepMs = msUntilNextDue(
                targets,
                lastPrime,
                System.currentTimeMillis(),
            )
            try {
                Thread.sleep(sleepMs)
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    /**
     * One-shot prime of one profile on a daemon thread (manual
     * "Prime sekarang" from the UI); the result goes to DialLog.
     * No-op when the profile must not be primed. Never throws.
     */
    fun primeNow(item: ProfileItem) {
        val target = targetFromProfile(item) ?: return
        thread(name = "taptapx-prime-now", isDaemon = true) {
            val result = primeDial(target)
            DialLog.log("PRIME", formatPrimeResult(result))
        }
    }

    /**
     * Synchronous one-shot prime (service start path): prime first,
     * then the probe dial can use the open window. Best-effort —
     * failure is logged, never thrown, and never fails the start.
     * Returns the result, or null when the profile must not be
     * primed.
     */
    fun primeNowSync(item: ProfileItem): PrimeResult? {
        val target = targetFromProfile(item) ?: return null
        val result = primeDial(target)
        DialLog.log("PRIME", formatPrimeResult(result))
        return result
    }
}
