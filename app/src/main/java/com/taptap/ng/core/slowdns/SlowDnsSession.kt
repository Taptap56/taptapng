package com.taptap.ng.core.slowdns

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsResolver
import com.taptap.ng.core.TunnelState
import com.taptap.ng.core.proto.Crypto
import com.taptap.ng.core.proto.Transport
import com.taptap.ng.data.ProfileItem
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * KCP over a [DnsttPacketConn], presented as a byte stream (M3).
 *
 * Mirrors kcp-go's UDPSession in stream mode: a background update
 * loop drives [Kcp.update]/[Kcp.check], a receiver thread feeds
 * incoming segments to [Kcp.input], and [input]/[output] speak the
 * KCP byte stream. The KCP output callback only queues into the
 * packet conn (never blocks, never does I/O) — KCP calls it while
 * flushing, so it must return immediately.
 *
 * [readDeadlineMs] bounds [input] reads (0 = infinite); the session
 * sets 60 s during the Noise handshake (TB's SetDeadline) and clears
 * it once the session is up. A read that hits the deadline throws
 * [SocketTimeoutException], like a socket SO_TIMEOUT.
 */
class KcpStream(
    private val kcp: Kcp,
    private val packetConn: DnsttPacketConn,
) : Closeable {
    @Volatile var readDeadlineMs: Long = 0

    private val closed = AtomicBoolean(false)
    /** Guards ALL KCP calls (kcp-go's raw KCP is not thread-safe; its
     *  UDPSession wraps it in a mutex — this is the same lock). The
     *  output callback only queues into the packet conn, so it never
     *  blocks while the lock is held. */
    private val kcpLock = Object()
    private val readLock = Object()
    // Bytes received from KCP, not yet consumed by the reader.
    private val recvBuf = ArrayDeque<Byte>()
    private var updateThread: Thread? = null
    private var recvThread: Thread? = null

    init {
        updateThread = thread(name = "kcp-update", isDaemon = true) { updateLoop() }
        recvThread = thread(name = "kcp-recv", isDaemon = true) { recvLoop() }
    }

    val input: InputStream = KcpInputStream()
    val output: OutputStream = KcpOutputStream()

    private fun nowMs(): Long = System.currentTimeMillis() and 0xFFFFFFFFL

    private fun kcpIsDead(): Boolean = closed.get() || synchronized(kcpLock) { kcp.isDead }

    private fun updateLoop() {
        while (!closed.get()) {
            try {
                val now = nowMs()
                val delay = synchronized(kcpLock) {
                    kcp.update(now)
                    kcp.check(now)
                }.coerceIn(1, 100)
                Thread.sleep(delay)
            } catch (_: InterruptedException) {
                return
            } catch (_: Exception) {
                if (closed.get()) return
                // KCP update must never kill the loop on a transient
                // error; the session's IsDead check handles a dead KCP.
                try {
                    Thread.sleep(10)
                } catch (_: InterruptedException) {
                    return
                }
            }
        }
    }

    private fun recvLoop() {
        while (!closed.get()) {
            try {
                val seg = packetConn.readFrom()
                synchronized(kcpLock) {
                    kcp.input(seg)
                    kcp.update(nowMs())
                }
                // Never nested with kcpLock: the reader takes readLock
                // and kcpLock in separate steps, so no lock order can
                // invert here.
                synchronized(readLock) { readLock.notifyAll() }
            } catch (_: Exception) {
                if (closed.get()) return
                // Packet conn closed / error: the read side will see
                // the closed flag; do not spin.
                try {
                    Thread.sleep(10)
                } catch (_: InterruptedException) {
                    return
                }
            }
        }
    }

    val isDead: Boolean get() = kcpIsDead()

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            updateThread?.interrupt()
            recvThread?.interrupt()
            synchronized(readLock) { readLock.notifyAll() }
        }
    }

    private inner class KcpInputStream : InputStream() {
        override fun read(): Int {
            val b = ByteArray(1)
            val n = read(b, 0, 1)
            return if (n == -1) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val deadline = readDeadlineMs
            val start = System.currentTimeMillis()
            while (true) {
                // 1. Serve from the buffer (readLock only — never
                //    call kcpIsDead() here: it takes kcpLock, and
                //    the recv thread takes kcpLock then readLock, so
                //    nesting them in the opposite order deadlocks).
                val fromBuf: Int? = synchronized(readLock) {
                    if (recvBuf.isNotEmpty()) {
                        val n = minOf(len, recvBuf.size)
                        repeat(n) { i -> b[off + i] = recvBuf.removeFirst() }
                        n
                    } else {
                        null
                    }
                }
                if (fromBuf != null) return fromBuf
                // 2. Dead check (kcpLock only, readLock released).
                if (closed.get() || kcpIsDead()) return -1
                // 3. Pull whatever KCP has (kcpLock only, never
                //    nested with readLock).
                val chunk = ByteArray(8192)
                val n = synchronized(kcpLock) {
                    try {
                        kcp.recv(chunk)
                    } catch (_: Exception) {
                        -1
                    }
                }
                if (n > 0) {
                    synchronized(readLock) {
                        for (i in 0 until n) recvBuf.addLast(chunk[i])
                    }
                    continue // serve from the buffer at the top
                }
                if (n == -1 && kcpIsDead()) return -1
                // 4. Nothing yet: wait for the receiver thread (or a
                // short poll so a missed notify cannot hang us).
                if (deadline > 0 && System.currentTimeMillis() - start >= deadline) {
                    throw SocketTimeoutException("KCP read timeout ${deadline}ms")
                }
                val waitMs = if (deadline > 0) {
                    minOf(10L, deadline - (System.currentTimeMillis() - start)).coerceAtLeast(1L)
                } else {
                    10L
                }
                val hasData = synchronized(readLock) {
                    // Re-check: a segment may have landed between
                    // steps 1 and 4. (No kcpIsDead() here either —
                    // the dead check runs at the top of the loop.)
                    if (recvBuf.isNotEmpty()) {
                        true
                    } else if (closed.get()) {
                        return -1
                    } else {
                        try {
                            readLock.wait(waitMs)
                        } catch (_: InterruptedException) {
                            if (closed.get()) return -1
                        }
                        false
                    }
                }
                if (hasData) continue // serve from the buffer at the top
                if (deadline > 0 && System.currentTimeMillis() - start >= deadline) {
                    throw SocketTimeoutException("KCP read timeout ${deadline}ms")
                }
            }
        }

        override fun available(): Int = synchronized(readLock) { recvBuf.size }

        override fun close() = runCatching { this@KcpStream.close() }.let {}
    }

    private inner class KcpOutputStream : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()))

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (kcpIsDead()) throw IOException("KCP ditutup")
            if (len == 0) return
            val data = b.copyOfRange(off, off + len)
            val rc = synchronized(kcpLock) {
                val r = kcp.send(data)
                if (r >= 0) kcp.update(nowMs())
                r
            }
            if (rc < 0) throw IOException("KCP send gagal: $rc")
        }

        override fun flush() {
            if (!closed.get()) synchronized(kcpLock) { kcp.update(nowMs()) }
        }

        override fun close() = runCatching { this@KcpStream.close() }.let {}
    }
}

/**
 * One DNSTT tunnel session (M3), ported from TB's Go implementation
 * (singbox-fork/protocol/slowdns/dnstt/session.go).
 *
 * Chain: resolver UDP packet conn -> KCP (stream mode) -> Noise_NK
 * client -> smux v2 client. One session is shared by all streams of
 * one entry (see [SlowDnsSessionPool]); the DNSTT server forwards
 * every stream to ONE fixed TCP target, so the inner VMess/VLESS
 * handshake is spoken on each smux stream.
 *
 * MTU = dnsNameCapacity(domain) - 8 (clientID) - 1 (padding prefix)
 *   - 3 (padding) - 1 (data length prefix); must be >= 80.
 * KCP window = 512 (TB's leaf value, not the DNSTT default 64).
 * Noise handshake deadline 60 s (cleared once the session is up).
 * smux: Version 2, KeepAliveTimeout 2 min, MaxStreamBuffer 1 MB.
 *
 * The resolver UDP socket MUST bypass the TUN (same pattern as
 * [DnsResolver]: the service's protect hook, non-fatal when the app
 * is disallowed from the VPN). A tunnel whose own DNS queries looped
 * back into it would never come up.
 */
class SlowDnsSession private constructor(
    private val packetConn: DnsttPacketConn,
    private val kcpStream: KcpStream,
    private val noiseSocket: NoiseSocket,
    private val smuxSession: SmuxSession,
) : Closeable {
    private val closed = AtomicBoolean(false)

    fun openStream(): SmuxStream {
        if (closed.get() || isDead) throw IOException("SlowDNS session ditutup/mati")
        return smuxSession.openStream()
    }

    val isDead: Boolean get() = closed.get() || smuxSession.isClosed || kcpStream.isDead

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { smuxSession.close() }
            runCatching { noiseSocket.close() }
            runCatching { kcpStream.close() }
            runCatching { packetConn.close() }
        }
    }

    companion object {
        const val HANDSHAKE_DEADLINE_MS = 60_000L
        const val KCP_WINDOW = 512

        /** MTU for a tunnel domain (DNSTT client formula). Throws when < 80. */
        fun mtuForDomain(domain: String): Int {
            val labels = DnsWire.parseDomain(domain)
            var capacity = 255 - 1
            for (label in labels) capacity -= label.length + 1
            capacity = capacity * 63 / 64
            capacity = capacity * 5 / 8
            val mtu = capacity - 8 - 1 - DnsttPacketConn.NUM_PADDING - 1
            require(mtu >= 80) { "Domain $domain hanya memberi MTU $mtu (< 80)" }
            return mtu
        }

        /** Parse a 64-hex-char pubkey into 32 bytes. Throws on bad input. */
        fun parsePubkey(hex: String): ByteArray {
            val clean = hex.trim().lowercase()
            require(clean.length == 64 && clean.all { it in '0'..'9' || it in 'a'..'f' }) {
                "SlowDNS pubkey harus 64 karakter hex"
            }
            return ByteArray(32) { i ->
                ((clean[i * 2].digitToInt(16) shl 4) or clean[i * 2 + 1].digitToInt(16)).toByte()
            }
        }

        fun recordTypeFor(item: ProfileItem): Int {
            return when (item.dnsttRecordType.trim().lowercase()) {
                "", "otomatis", "auto", "txt" -> DnsWire.TYPE_TXT
                "null" -> DnsWire.TYPE_NULL
                else -> throw IllegalArgumentException(
                    "SlowDNS record type tidak didukung: ${item.dnsttRecordType} (txt/null)",
                )
            }
        }

        /** Resolve "host:port" (default port 53) to a socket address. */
        fun resolverAddress(item: ProfileItem): InetSocketAddress {
            val raw = item.dnsttResolver.trim().ifBlank { "8.8.8.8:53" }
            val host: String
            val port: Int
            val colon = raw.lastIndexOf(':')
            if (colon > 0 && raw.indexOf(':') == colon) {
                host = raw.substring(0, colon)
                port = raw.substring(colon + 1).toIntOrNull() ?: 53
            } else {
                host = raw
                port = 53
            }
            require(host.isNotBlank()) { "SlowDNS resolver kosong" }
            val addr = if (com.taptap.ng.core.proto.AddrCodec.isIpLiteral(host)) {
                java.net.InetAddress.getByName(host)
            } else {
                DnsResolver.resolve(host)
            }
            return InetSocketAddress(addr, port)
        }

        /**
         * Build + handshake a session for [item]. Throws (stage-tagged
         * by the caller) on any failure; the caller must not reuse a
         * failed session. The watchdog closeable is armed with the
         * KCP stream during the handshake and cleared on success —
         * the caller (transport) arms the smux stream afterwards.
         * [transportFactory] (test seam) replaces the real UDP socket.
         */
        fun create(
            item: ProfileItem,
            transportFactory: ((InetSocketAddress) -> DnsTransport)? = null,
        ): SlowDnsSession {
            require(item.dnsttNS.isNotBlank()) { "SlowDNS NS kosong — isi NS domain di editor" }
            val pubkey = parsePubkey(item.dnsttPubkey)
            val recordType = recordTypeFor(item)
            val mtu = mtuForDomain(item.dnsttNS)
            val resolverAddr = resolverAddress(item)
            DialLog.log(
                "SlowDNS",
                "NS ${item.dnsttNS} (${if (recordType == DnsWire.TYPE_NULL) "NULL" else "TXT"}) " +
                    "resolver $resolverAddr MTU $mtu",
            )

            // Resolver UDP socket: must bypass the TUN (same pattern
            // as DnsResolver — protect refused is non-fatal only
            // when the app is disallowed from the VPN). A test
            // factory replaces the socket entirely.
            val transport: DnsTransport
            var socket: DatagramSocket? = null
            if (transportFactory != null) {
                transport = transportFactory(resolverAddr)
            } else {
                socket = DatagramSocket()
                try {
                    val protect = DnsResolver.protectUdp
                    if (protect != null && TunnelState.up && !protect(socket)) {
                        if (TunnelState.appBypass) {
                            DialLog.log(
                                "PROTECT",
                                "protect() gagal — query DNSTT lanjut via disallow aplikasi",
                            )
                        } else {
                            throw IOException("protect() gagal — query DNSTT tidak bisa bypass VPN")
                        }
                    }
                } catch (e: Exception) {
                    runCatching { socket.close() }
                    throw e
                }
                transport = UdpDnsTransport(socket)
            }
            val packetConn = DnsttPacketConn(transport, resolverAddr, item.dnsttNS, recordType)
            val convBytes = Crypto.randomBytes(4)
            val conv = ((convBytes[0].toInt() and 0xFF) shl 24) or
                ((convBytes[1].toInt() and 0xFF) shl 16) or
                ((convBytes[2].toInt() and 0xFF) shl 8) or
                (convBytes[3].toInt() and 0xFF)
            val kcp = Kcp(conv) { datagram ->
                packetConn.writeTo(datagram)
            }
            kcp.setStreamMode(true)
            kcp.setNoDelay(0, 0, 0, 1)
            kcp.setWindowSize(KCP_WINDOW, KCP_WINDOW)
            kcp.setMtu(mtu)
            val kcpStream = KcpStream(kcp, packetConn)
            // Arm the watchdog with the KCP stream: a stuck handshake
            // read is killed by closing it (30 s), not by the 60 s
            // KCP deadline alone.
            Transport.armWatchdogCloseable(kcpStream)
            try {
                kcpStream.readDeadlineMs = HANDSHAKE_DEADLINE_MS
                Transport.noteStage("SlowDNS")
                // Noise_NK handshake over the KCP stream (length-
                // prefixed messages, like dnstt noise.go).
                val noiseClient = NoiseNkClient(pubkey)
                val msg1 = noiseClient.writeMessage1()
                writeLengthPrefixed(kcpStream.output, msg1)
                val msg2 = readLengthPrefixed(kcpStream.input)
                val noiseTransport = noiseClient.readMessage2(msg2)
                DialLog.log("SlowDNS", "Noise handshake ok")
                val noiseSocket = NoiseSocket(noiseTransport, kcpStream.input, kcpStream.output)
                kcpStream.readDeadlineMs = 0 // session is up: no deadline
                Transport.noteStage("smux")
                val smux = SmuxSession(
                    noiseSocket.input,
                    noiseSocket.output,
                    SmuxConfig(
                        version = 2,
                        keepAliveTimeoutMs = 120_000,
                        maxStreamBuffer = 1024 * 1024,
                    ),
                )
                Transport.clearWatchdogCloseable()
                DialLog.log("SlowDNS", "smux ok — tunnel naik")
                return SlowDnsSession(packetConn, kcpStream, noiseSocket, smux)
            } catch (e: Exception) {
                Transport.clearWatchdogCloseable()
                runCatching { kcpStream.close() }
                runCatching { packetConn.close() }
                val failure = Transport.preferWatchdogFailure(e)
                DialLog.failure("SlowDNS", failure)
                throw failure
            }
        }

        private fun writeLengthPrefixed(out: OutputStream, msg: ByteArray) {
            require(msg.size <= 0xFFFF) { "Pesan Noise terlalu panjang: ${msg.size}" }
            out.write(byteArrayOf(((msg.size ushr 8) and 0xFF).toByte(), (msg.size and 0xFF).toByte()))
            out.write(msg)
            out.flush()
        }

        private fun readLengthPrefixed(input: InputStream): ByteArray {
            val head = ByteArray(2)
            var filled = 0
            while (filled < 2) {
                val r = input.read(head, filled, 2 - filled)
                if (r == -1) throw IOException("Noise handshake terpotong (EOF)")
                filled += r
            }
            val n = ((head[0].toInt() and 0xFF) shl 8) or (head[1].toInt() and 0xFF)
            val msg = ByteArray(n)
            filled = 0
            while (filled < n) {
                val r = input.read(msg, filled, n - filled)
                if (r == -1) throw IOException("Noise handshake terpotong (EOF)")
                filled += r
            }
            return msg
        }
    }
}

/**
 * One DNSTT session per ProxyClient instance, shared by the probe +
 * all forwarder dials of that client (mirrors TB: one session per
 * outbound). A dead session is dropped and recreated on the next
 * dial (new ClientID + Noise/KCP — TB v1.1.4 fix for "SlowDNS suka
 * timeout, harus restart service baru keluar ping lagi").
 *
 * [transportFactory] is a test seam: when set, the session uses the
 * factory's [DnsTransport] instead of a real UDP socket to the
 * resolver (loopback UDP is blocked in the VM, so the round-trip
 * test drives the tunnel over in-memory queues). Production passes
 * null (real UDP).
 */
class SlowDnsSessionPool(
    private val item: ProfileItem,
    private val transportFactory: ((InetSocketAddress) -> DnsTransport)? = null,
) {
    private val lock = Any()
    private var session: SlowDnsSession? = null
    private val closed = AtomicBoolean(false)

    /** A fresh smux stream from the live session (creating/recreating it as needed). */
    fun stream(): SmuxStream {
        synchronized(lock) {
            if (closed.get()) throw IOException("SlowDNS ditutup")
            var s = session
            if (s == null || s.isDead) {
                if (s != null) {
                    DialLog.log("SlowDNS", "sesi mati — buat sesi baru")
                    runCatching { s.close() }
                }
                s = SlowDnsSession.create(item, transportFactory)
                session = s
            }
            return s.openStream()
        }
    }

    /** Drop the session (e.g. after a dial failure at the session level). */
    fun drop() {
        synchronized(lock) {
            session?.let { runCatching { it.close() } }
            session = null
        }
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            synchronized(lock) {
                session?.let { runCatching { it.close() } }
                session = null
            }
        }
    }
}
