package com.taptap.ng.core.proto

import java.io.InputStream
import java.util.concurrent.atomic.AtomicLong

/**
 * Per-connection speed instrumentation (v1.0.16).
 *
 * v1.0.15 proved the relay/VMess-chunk layer is NOT the phone
 * bottleneck (Speedtest HP 2026-11-20 12:52: 26,7 Mbps, unchanged
 * from ~30,9 Mbps — while the local in-memory relay measured
 * 98→138 MB/s). The next step is to MEASURE on the phone instead of
 * guessing again: one Speedtest + the exported Log must show WHICH
 * stage is slow. This class accumulates wall-clock time per stage
 * for ONE proxied TCP connection and formats the SPEED lines the
 * forwarder logs (one per 5 s window while transferring + one
 * summary when the session closes).
 *
 * Stage decomposition (download = proxy → TUN, the Speedtest
 * download direction). The stages nest — the forwarder's relay
 * thread reads from the proxy stream, and inside that read the
 * layers run in order:
 *
 *   tls+net: time blocked reading from the transport stream
 *     (TimedInputStream around the TLS socket input / TlsEngine
 *     input / plain TCP input). For the SSLSocket path the TLS
 *     unwrap happens INSIDE the socket read, so unwrap and network
 *     wait cannot be split — the label says so honestly. During a
 *     saturated transfer the socket almost always has data ready,
 *     so this is ≈ TLS unwrap + kernel/socket cost; idle gaps
 *     inflate it (it is wall time, not CPU time).
 *   ws: WebSocket frame parsing only (header, unmask, reassembly
 *     copies) = WsInputStream.read() wall time MINUS the raw-read
 *     time already counted in tls+net.
 *   vmess: VMess AEAD chunk open only (VmessBodyInputStream).
 *   rd: the forwarder relay's total stream.read() wall time —
 *     the cross-check: rd ≈ tls+net + ws + vmess (+ LazyHeader /
 *     stream plumbing overhead, which is the residual).
 *   build: building the TCP segment (buildTcpInto).
 *   tun: enqueueing the segment to the TUN writer thread
 *     (v1.0.18 — was: the fd write itself, incl. any block on the
 *     fd. The fd write moved to a single writer thread, so a small
 *     tun means the relay is no longer stuck behind it; the real
 *     fd-write cost is in the TUNWRITER aggregate line — if the
 *     writer is still the bottleneck, tulisMs there stays large
 *     and blokirMs grows. v1.0.20 splits that cost into a
 *     histogram — cepat/sedang/lambat + tulisMaxUs — so a
 *     blocked-on-full-queue tail can be told apart from a
 *     uniformly expensive write).
 *
 * Upload (TUN → proxy, light): upW = writer thread's write+flush
 * wall time (VMess seal + WS frame + TLS wrap + socket write,
 * combined — the SSLSocket output wraps TLS inline, so wrap and
 * socket write cannot be split); upVmess = the VMess seal part
 * of it (so upW − upVmess ≈ ws + tls + net on the upload side).
 * The TUN read itself is NOT timed per session (the TUN reader
 * thread is shared by all sessions).
 *
 * The relay thread is single-threaded per connection (read →
 * build → enqueue, sequentially), so in a saturated 5 s window the
 * stage times sum to ≈ 5000 ms — the stage with the biggest number
 * IS the bottleneck. All counters are AtomicLong: the relay thread
 * (download) and the writer thread (upload) accumulate into the
 * same object concurrently.
 *
 * Overhead: a handful of System.nanoTime() calls per segment /
 * chunk / frame — negligible next to a 1460-byte segment. When
 * stats is null (probe dials, unit tests) the wrappers are not
 * installed at all, so the hot path is byte-identical to v1.0.15.
 */
class SpeedStats {

    /** Time blocked reading the transport stream (TLS unwrap + net wait). */
    val tlsNetNs = AtomicLong(0)

    /** WebSocket frame parse time (read wall minus raw-read time). */
    val wsNs = AtomicLong(0)

    /** VMess AEAD chunk open time (download). */
    val vmessNs = AtomicLong(0)

    /** TCP segment build time (forwarder). */
    val buildNs = AtomicLong(0)

    /** TUN enqueue time (v1.0.18: enqueue to the writer thread;
     * the fd write itself is on the writer thread — see the
     * TUNWRITER aggregate line). */
    val tunNs = AtomicLong(0)

    /** Forwarder relay total stream.read() wall time (cross-check). */
    val relayReadNs = AtomicLong(0)

    /** Upload: writer thread write+flush wall time (seal+ws+tls+net). */
    val upWriteNs = AtomicLong(0)

    /** Upload: VMess AEAD chunk seal time. */
    val upVmessNs = AtomicLong(0)

    /** Plaintext bytes delivered to the app (download). */
    val downBytes = AtomicLong(0)

    /** App bytes written to the proxy (upload). */
    val upBytes = AtomicLong(0)

    /** WS data frames read. */
    val wsFrames = AtomicLong(0)

    /** VMess response chunks opened. */
    val vmessChunks = AtomicLong(0)

    /** TUN writes (TCP segments sent to the app). */
    val tunWrites = AtomicLong(0)

    data class Snapshot(
        val tlsNetNs: Long,
        val wsNs: Long,
        val vmessNs: Long,
        val buildNs: Long,
        val tunNs: Long,
        val relayReadNs: Long,
        val upWriteNs: Long,
        val upVmessNs: Long,
        val downBytes: Long,
        val upBytes: Long,
        val wsFrames: Long,
        val vmessChunks: Long,
        val tunWrites: Long,
    )

    fun snapshot(): Snapshot = Snapshot(
        tlsNetNs.get(), wsNs.get(), vmessNs.get(),
        buildNs.get(), tunNs.get(), relayReadNs.get(),
        upWriteNs.get(), upVmessNs.get(),
        downBytes.get(), upBytes.get(),
        wsFrames.get(), vmessChunks.get(), tunWrites.get(),
    )

    companion object {
        private fun mb(bytes: Long): String = "%.2f".format(bytes / 1024.0 / 1024.0)
        private fun mbs(bytes: Long, wallMs: Long): String =
            if (wallMs > 0) "%.2f".format(bytes / 1024.0 / 1024.0 / (wallMs / 1000.0)) else "0.00"

        private fun ms(ns: Long): String = "${ns / 1_000_000}ms"
        private fun deltaMs(now: Long, prev: Long): String = ms(now - prev)

        /**
         * One window line (forwarder, every [wallMs] of active
         * transfer): download MB + effective MB/s in the window,
         * then the per-stage wall time spent in the window.
         * Logged as: DialLog.log("SPEED", windowLine(...)).
         */
        fun windowLine(prev: Snapshot, now: Snapshot, dst: String, wallMs: Long): String {
            val down = now.downBytes - prev.downBytes
            return "SPEED $dst down=${mb(down)}MB ${mbs(down, wallMs)}MB/s " +
                "tls+net=${deltaMs(now.tlsNetNs, prev.tlsNetNs)} " +
                "ws=${deltaMs(now.wsNs, prev.wsNs)} " +
                "vmess=${deltaMs(now.vmessNs, prev.vmessNs)} " +
                "rd=${deltaMs(now.relayReadNs, prev.relayReadNs)} " +
                "build=${deltaMs(now.buildNs, prev.buildNs)} " +
                "tun=${deltaMs(now.tunNs, prev.tunNs)}"
        }

        /**
         * One summary line when the session closes: totals over
         * the whole connection (wall time, effective MB/s, per-stage
         * totals, upload totals, frame/chunk/write counts).
         */
        fun totalLine(snap: Snapshot, dst: String, wallMs: Long): String {
            val wallS = "%.1f".format(wallMs / 1000.0)
            return "SPEED $dst TUTUP down=${mb(snap.downBytes)}MB ${wallS}s " +
                "${mbs(snap.downBytes, wallMs)}MB/s " +
                "tls+net=${ms(snap.tlsNetNs)} " +
                "ws=${ms(snap.wsNs)} " +
                "vmess=${ms(snap.vmessNs)} " +
                "rd=${ms(snap.relayReadNs)} " +
                "build=${ms(snap.buildNs)} " +
                "tun=${ms(snap.tunNs)} " +
                "up=${mb(snap.upBytes)}MB upW=${ms(snap.upWriteNs)} " +
                "upVmess=${ms(snap.upVmessNs)} " +
                "frames=${snap.wsFrames} chunks=${snap.vmessChunks} tunW=${snap.tunWrites}"
        }
    }
}

/**
 * InputStream that times every read into [stats].tlsNetNs.
 *
 * Installed by [Transport.open] / SlowDnsTransport.open around the
 * transport stream (TLS socket input, TlsEngine input, or plain TCP
 * / smux input) BEFORE the WS layer reads from it — so every byte
 * the WS / VMess layers pull from the network is timed here, once.
 * Only the read calls are timed; available()/close() delegate
 * untimed. Installed only when stats is non-null.
 */
class TimedInputStream(
    private val rawIn: InputStream,
    private val stats: SpeedStats,
) : InputStream() {

    override fun read(): Int {
        val t0 = System.nanoTime()
        try {
            return rawIn.read()
        } finally {
            stats.tlsNetNs.addAndGet(System.nanoTime() - t0)
        }
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val t0 = System.nanoTime()
        try {
            return rawIn.read(b, off, len)
        } finally {
            stats.tlsNetNs.addAndGet(System.nanoTime() - t0)
        }
    }

    override fun available(): Int = rawIn.available()

    override fun close() {
        runCatching { rawIn.close() }
    }
}
