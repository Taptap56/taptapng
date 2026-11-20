package com.taptap.x.core.slowdns

import com.taptap.x.core.DialLog
import com.taptap.x.core.proto.Crypto
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * The actual DNS sender/receiver for a DNSTT tunnel (M3). The
 * [DnsttPacketConn] below handles encoding; this interface is the
 * "some other PacketConn" from the Go code (net.UDPConn there).
 */
interface DnsTransport {
    fun send(data: ByteArray, addr: InetSocketAddress)
    /** Blocks until a datagram arrives; returns its length. Throws on close/error. */
    fun receive(buf: ByteArray): Int
    fun close()
}

/** UDP [DnsTransport] over one [DatagramSocket] (created + protected by the caller). */
class UdpDnsTransport(private val socket: DatagramSocket) : DnsTransport {
    override fun send(data: ByteArray, addr: InetSocketAddress) {
        socket.send(DatagramPacket(data, data.size, addr))
    }

    override fun receive(buf: ByteArray): Int {
        val p = DatagramPacket(buf, buf.size)
        socket.receive(p)
        return p.length
    }

    override fun close() = runCatching { socket.close() }.let {}
}

/**
 * DNSTT packet connection (M3), ported from TB's Go implementation
 * (singbox-fork/protocol/slowdns/dnstt/packetconn.go + queuepacketconn.go
 * — adapted from the public DNSTT library, bamsoftware.com).
 *
 * Wire (see [DnsWire]):
 * - Upstream packet p (< 224 bytes) → [clientID 8B][0xE0+n][n random
 *   bytes][len(p)][p] (n=3, n=8 for empty poll packets) → base32
 *   (no padding, lowercase) → labels of ≤ 63 chars → append tunnel
 *   domain → DNS query (random ID, RD=1, type TXT/NULL, class IN,
 *   EDNS(0) OPT additional, class 4096).
 * - Downstream: response must have QR=1, RCODE=0, exactly 1 answer
 *   whose name is a subdomain of the tunnel domain; TXT → concatenated
 *   character-strings, NULL → raw RDATA. Payload = [u16 BE len][packet]*.
 * - Polling: an empty poll packet is sent when signalled (after
 *   receiving data, up to 16 in a burst) or when the poll timer
 *   expires (initial 500 ms, ×2 up to 10 s, reset on any real send).
 *   A data packet displaces one pending poll.
 * - Queues: 128 packets each way (QueueSize); a full queue drops.
 *
 * Queries and responses are NOT correlated by ID (the Go code
 * ignores the ID on receive) — they are just vehicles for data.
 *
 * One instance serves one DNSTT session; its [readFrom] feeds KCP
 * and its [writeTo] is KCP's output. Both loops run on daemon
 * threads; [close] stops them.
 */
class DnsttPacketConn(
    private val transport: DnsTransport,
    private val resolverAddr: InetSocketAddress,
    domain: String,
    recordType: Int,
    private val clientId: ByteArray = Crypto.randomBytes(8),
) {
    companion object {
        const val QUEUE_SIZE = 128
        const val NUM_PADDING = 3
        const val NUM_PADDING_POLL = 8
        const val INIT_POLL_DELAY_MS = 500L
        const val MAX_POLL_DELAY_MS = 10_000L
        const val POLL_LIMIT = 16
        const val MAX_PACKET = 224
    }

    private val domainLabels: List<String> = DnsWire.parseDomain(domain)
    private val domainLabelBytes: List<ByteArray> =
        domainLabels.map { it.toByteArray(Charsets.US_ASCII) }
    private val qtype: Int = when (recordType) {
        DnsWire.TYPE_NULL -> DnsWire.TYPE_NULL
        else -> DnsWire.TYPE_TXT
    }

    private val recvQueue = LinkedBlockingQueue<ByteArray>(QUEUE_SIZE)
    private val outgoing = LinkedBlockingQueue<ByteArray>(QUEUE_SIZE)
    /** Wakes the send loop when data is queued or a poll permit arrives. */
    private val signalQueue = LinkedBlockingQueue<Unit>()
    private val pollPermits = AtomicInteger(0)
    private val closed = AtomicBoolean(false)

    init {
        require(clientId.size == 8) { "ClientID DNSTT harus 8 byte" }
        thread(name = "dnstt-recv", isDaemon = true) { recvLoop() }
        thread(name = "dnstt-send", isDaemon = true) { sendLoop() }
    }

    /**
     * Queue one upstream packet for sending (KCP's output). Returns
     * the packet size even when the queue is full and the packet is
     * dropped (Go semantics). Throws when the packet is >= 224 bytes
     * — the caller (KCP, bounded by the session MTU) must never do
     * that.
     */
    fun writeTo(packet: ByteArray): Int {
        require(packet.size < MAX_PACKET) { "Paket DNSTT terlalu panjang: ${packet.size}" }
        if (closed.get()) return packet.size
        outgoing.offer(packet) // drop when full, like Go's WriteTo
        signalQueue.offer(Unit)
        return packet.size
    }

    /** Block until one downstream packet arrives. Throws on close. */
    fun readFrom(): ByteArray {
        while (true) {
            if (closed.get()) throw java.io.IOException("DNSTT ditutup")
            val p = recvQueue.poll(100, TimeUnit.MILLISECONDS)
            if (p != null) return p
        }
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { transport.close() }
            signalQueue.offer(Unit)
        }
    }

    val isClosed: Boolean get() = closed.get()

    private fun recvLoop() {
        val buf = ByteArray(4096)
        while (!closed.get()) {
            val n = try {
                transport.receive(buf)
            } catch (_: Exception) {
                if (closed.get()) return
                continue // Go: temporary errors are skipped, not fatal
            }
            val parsed = DnsWire.parseResponse(buf.copyOf(n), domainLabels, qtype)
            if (parsed == null) {
                continue
            }
            val resp = parsed
            val packets = DnsWire.splitPackets(resp.payload)
            var any = false
            for (p in packets) {
                recvQueue.offer(p) // drop when full, like Go's QueueIncoming
                any = true
            }
            if (any) {
                // Permit sendLoop to poll immediately (up to 16 in a
                // burst). KCP's own ACK for this data is effectively a
                // second poll, so the in-flight window grows with the
                // rate data arrives (see packetconn.go recvLoop).
                if (pollPermits.get() < POLL_LIMIT) {
                    pollPermits.incrementAndGet()
                    signalQueue.offer(Unit)
                }
            }
        }
    }

    private fun sendLoop() {
        var pollDelayMs = INIT_POLL_DELAY_MS
        while (!closed.get()) {
            // 1. Real data first.
            val data = outgoing.poll()
            if (data != null) {
                drainOnePermit()
                sendPacket(data)
                pollDelayMs = INIT_POLL_DELAY_MS
                continue
            }
            // 2. A pending poll permit?
            if (tryConsumePermit()) {
                sendPacket(ByteArray(0))
                pollDelayMs = INIT_POLL_DELAY_MS
                continue
            }
            // 3. Wait for a signal (data / permit) or the timer.
            val signaled = signalQueue.poll(pollDelayMs, TimeUnit.MILLISECONDS) != null
            if (!signaled) {
                // Timer expired and nothing arrived: re-check once
                // (data/permit may have landed during the wait),
                // then poll and back off.
                val data2 = outgoing.poll()
                if (data2 != null) {
                    drainOnePermit()
                    sendPacket(data2)
                    pollDelayMs = INIT_POLL_DELAY_MS
                    continue
                }
                if (tryConsumePermit()) {
                    sendPacket(ByteArray(0))
                    pollDelayMs = INIT_POLL_DELAY_MS
                    continue
                }
                if (closed.get()) return
                sendPacket(ByteArray(0))
                pollDelayMs = minOf(pollDelayMs * 2, MAX_POLL_DELAY_MS)
            }
            // Signalled: loop back and pick up the data/permit.
        }
    }

    private fun drainOnePermit() {
        pollPermits.updateAndGet { if (it > 0) it - 1 else 0 }
    }

    private fun tryConsumePermit(): Boolean {
        while (true) {
            val cur = pollPermits.get()
            if (cur <= 0) return false
            if (pollPermits.compareAndSet(cur, cur - 1)) return true
        }
    }

    private fun sendPacket(p: ByteArray) {
        if (closed.get()) return
        try {
            val padding = Crypto.randomBytes(if (p.isEmpty()) NUM_PADDING_POLL else NUM_PADDING)
            val decoded = DnsWire.encodeUpstreamPacket(p, clientId, padding)
            val encoded = Base32.encode(decoded)
            val labels = encoded.toByteArray(Charsets.US_ASCII).chunkedMax(63) + domainLabelBytes
            val idBytes = Crypto.randomBytes(2)
            val id = ((idBytes[0].toInt() and 0xFF) shl 8) or (idBytes[1].toInt() and 0xFF)
            val query = DnsWire.buildQuery(id, labels, qtype)
            transport.send(query, resolverAddr)
        } catch (e: Exception) {
            // Go's sendLoop ignores send errors and carries on.
            DialLog.log("SlowDNS", "kirim query gagal (${e.javaClass.simpleName}) — lanjut")
        }
    }
}
