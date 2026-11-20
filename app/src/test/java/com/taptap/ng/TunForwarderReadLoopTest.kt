package com.taptap.ng

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.SpeedStats
import com.taptap.ng.service.TcpPacket
import com.taptap.ng.service.TunForwarder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.11: the forwarder's TUN read loop exited 1 ms after
 * starting, having read ZERO packets (phone log 2026-11-20
 * 08:05:09.528–529: "FORWARDER mulai — baca TUN" then
 * "FORWARDER baca TUN selesai (n=0)"). The TUN fd from
 * Builder.establish() is non-blocking, so FileInputStream.read()
 * returns 0 at once when no packet is waiting (EAGAIN) — and the
 * loop treated 0 as end-of-stream. These tests fail on v1.0.10
 * code and pass on the fix (blocking fd + 0/EOF handled as
 * "keep waiting" / "error", never as a clean finish).
 */
class TunForwarderReadLoopTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(93, 184, 216, 34)

    /** Proxy stream whose input blocks forever (no server data). */
    private class BlockingStream : ProxyStream {
        override val input: InputStream = PipedInputStream()
        override val output: OutputStream = ByteArrayOutputStream()
        override fun close() {
            runCatching { input.close() }
        }
    }

    private class OkProxy : ProxyClient {
override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream =
            BlockingStream()

        override fun close() = Unit
    }

    /**
     * A TUN input that behaves like a non-blocking fd with no
     * data yet: the first read returns 0 (EAGAIN), the second
     * delivers one packet, later reads block until close() —
     * exactly what the real TUN fd does once set blocking.
     * The block is a sleep-poll on the closed flag (Kotlin's
     * Any has no wait()/notifyAll() to call).
     */
    private class EagainThenPacketIn(private val packet: ByteArray) : InputStream() {
        private val closed = AtomicBoolean(false)
        private var calls = 0

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (closed.get()) return -1
            return when (calls++) {
                0 -> 0 // EAGAIN: no packet waiting yet
                1 -> {
                    val n = minOf(packet.size, len)
                    packet.copyInto(b, off, 0, n)
                    n
                }
                else -> {
                    while (!closed.get()) {
                        try {
                            Thread.sleep(50)
                        } catch (_: InterruptedException) {
                            // Keep waiting until close().
                        }
                    }
                    -1
                }
            }
        }

        override fun read(): Int {
            val one = ByteArray(1)
            val n = read(one, 0, 1)
            return if (n <= 0) n else one[0].toInt() and 0xFF
        }

        override fun close() {
            closed.set(true)
        }
    }

    /** A TUN input that hits EOF at once, while the VPN is up. */
    private class EofTunIn : InputStream() {
        override fun read(b: ByteArray, off: Int, len: Int): Int = -1
        override fun read(): Int = -1
    }

    /** A forwarder wired to a pipe pair; tunOut is drained. */
    private class Harness(proxy: ProxyClient) {
        val tunInRead = PipedInputStream(65536)
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream(65536)
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val statuses = mutableListOf<String>()
        val fwd = TunForwarder(
            tunInRead, tunOutWrite, proxy, "192.0.2.1",
            protectUdp = { true },
            onStatus = { statuses.add(it) },
            dnsTimeoutMs = 200,
        )

        init {
            thread(name = "test-drainer", isDaemon = true) {
                val buf = ByteArray(8192)
                try {
                    while (true) {
                        val n = tunOutRead.read(buf)
                        if (n <= 0) break
                    }
                } catch (_: Exception) {
                    // Pipe closed by stop().
                }
            }
        }

        fun stop() {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
        }
    }

    private fun waitFor(
        timeoutMs: Long = 5_000,
        what: String,
        condition: () -> Boolean,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(25)
        }
        return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
    }

    private fun syn(): ByteArray =
        TcpPacket.buildTcp(
            clientIp, serverIp, 12345, 443,
            1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = 1460,
        )

    @Test
    fun `zero read does not kill the reader — packet after it is delivered`() {
        // v1.0.10: the first read returns 0 and the loop logs
        // "baca TUN selesai (n=0)" and exits — the packet that
        // arrives right after is never seen (no TUN TCP line).
        val before = DialLog.lines().size
        val tunIn = EagainThenPacketIn(syn())
        val fwd = TunForwarder(
            tunIn, ByteArrayOutputStream(), OkProxy(), "192.0.2.1",
            protectUdp = { true }, onStatus = {}, dnsTimeoutMs = 200,
        )
        fwd.start()
        assertTrue(waitFor(what = "loop baca TUN jalan") {
            DialLog.lines().drop(before).any { it.contains("loop baca TUN jalan") }
        })
        assertTrue(waitFor(what = "TUN TCP line after zero read") {
            DialLog.lines().drop(before).any { it.contains("TUN TCP") }
        })
        // The reader is still alive waiting for more packets —
        // no "selesai" while the VPN is up.
        val lines = DialLog.lines().drop(before)
        assertTrue(lines.none { it.contains("baca TUN selesai") })
        fwd.stop()
    }

    @Test
    fun `eof while running is logged as failure not clean selesai`() {
        // v1.0.10: a -1 read logs "baca TUN selesai (n=-1)" and
        // exits silently, as if the VPN had stopped cleanly.
        val before = DialLog.lines().size
        val fwd = TunForwarder(
            EofTunIn(), ByteArrayOutputStream(), OkProxy(), "192.0.2.1",
            protectUdp = { true }, onStatus = {}, dnsTimeoutMs = 200,
        )
        fwd.start()
        assertTrue(waitFor(what = "FORWARDER baca TUN GAGAL line") {
            DialLog.lines().drop(before).any { it.contains("FORWARDER baca TUN GAGAL") }
        })
        val lines = DialLog.lines().drop(before)
        assertTrue(lines.none { it.contains("baca TUN selesai") })
        fwd.stop()
    }

    @Test
    fun `stop after packets logs selesai with the packet count`() {
        // "selesai" belongs to a real teardown only. v1.0.10
        // never logged it on the stop path at all (the blocked
        // read throws, the catch exits quietly) — so a phone log
        // could not tell a clean stop from a dead reader.
        val before = DialLog.lines().size
        val h = Harness(OkProxy())
        h.fwd.start()
        h.tunInWrite.write(syn())
        h.tunInWrite.flush()
        assertTrue(waitFor(what = "TUN TCP line") {
            DialLog.lines().drop(before).any { it.contains("TUN TCP") }
        })
        h.stop()
        assertTrue(waitFor(what = "baca TUN selesai line") {
            DialLog.lines().drop(before).any { it.contains("baca TUN selesai (paket: 1)") }
        })
        val lines = DialLog.lines().drop(before).joinToString("\n")
        assertEquals(1, lines.split("TUN TCP").size - 1)
    }
}
