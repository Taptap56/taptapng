package com.taptap.x

import com.taptap.x.core.DialLog
import com.taptap.x.core.proto.ProxyClient
import com.taptap.x.core.proto.ProxyStream
import com.taptap.x.core.proto.SpeedStats
import com.taptap.x.service.TcpPacket
import com.taptap.x.service.TunForwarder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.util.Collections
import javax.net.ssl.SSLException
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.3 phone report (2026-11-20 01:06):
 * with an Onering entry selected the status stuck on "Connecting:
 * Zoom onering..." forever while every proxy dial failed (closed
 * window, no priming) — the forwarder RST-ed each dial silently and
 * the service only reported status on the first SUCCESSFUL dial.
 *
 * v1.0.4: the first dial failure (then at most one per 10 s) is
 * reported as "Konek gagal (<reason>)" so the user sees what is
 * wrong instead of a stuck "Connecting...".
 */
class TunForwarderDialFailureTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 0, 0, 2)
    private val serverIp = TcpPacket.ipFromBytes(1, 2, 3, 4)

    private class FailingProxy(private val error: Exception) : ProxyClient {
override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats? = null,
        ): ProxyStream {
            throw error
        }

        override fun close() = Unit
    }

    /** Proxy that always succeeds: input blocks forever (no server
     * data), output is discarded — enough for the dial + SYN-ACK
     * path; the relay thread just waits. */
    private class OkProxy : ProxyClient {
override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats? = null,
        ): ProxyStream {
            val input = PipedInputStream()
            return object : ProxyStream {
                override val input: InputStream = input
                override val output: OutputStream = ByteArrayOutputStream()
                override fun close() {
                    runCatching { input.close() }
                }
            }
        }

        override fun close() = Unit
    }

    @Test
    fun `dial failure reason maps common exceptions to short text`() {
        assertEquals("timeout", TunForwarder.dialFailureReason(SocketTimeoutException()))
        assertEquals("TLS gagal", TunForwarder.dialFailureReason(SSLException("handshake")))
        assertEquals("TCP gagal", TunForwarder.dialFailureReason(ConnectException()))
        assertEquals("boom", TunForwarder.dialFailureReason(RuntimeException("boom")))
    }

    @Test
    fun `dial failure reason keeps stage tags on timeouts`() {
        // v1.0.5: Transport/VmessClient tag the stage in the message
        // ("TCP gagal: ...") — the status must show WHERE the dial
        // died instead of a bare "timeout".
        assertEquals(
            "TCP gagal: Read timed out",
            TunForwarder.dialFailureReason(SocketTimeoutException("TCP gagal: Read timed out")),
        )
        assertEquals(
            "VMess gagal: Read timed out",
            TunForwarder.dialFailureReason(SocketTimeoutException("VMess gagal: Read timed out")),
        )
        // A raw timeout without our tag keeps the plain word.
        assertEquals(
            "timeout",
            TunForwarder.dialFailureReason(SocketTimeoutException("Read timed out")),
        )
        assertEquals("timeout", TunForwarder.dialFailureReason(SocketTimeoutException()))
    }

    @Test
    fun `successful dial logs DIAL start and ok lines`() {
        // v1.0.9: taptapx-6.txt (2026-11-20 04:17) stopped at
        // "PROBE ok" with no forwarder lines at all — every attempt
        // must be logged, not just failures, so the next phone log
        // shows whether a dial was even attempted once the TUN is
        // up. Fails on v1.0.8 code (no DIAL lines on success).
        val statuses = Collections.synchronizedList(mutableListOf<String>())
        val tunInRead = PipedInputStream()
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream()
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        val drainer = thread(name = "tun-test-drain", isDaemon = true) {
            runCatching { tunOutRead.copyTo(drained) }
        }
        val fwd = TunForwarder(
            tunIn = tunInRead,
            tunOut = tunOutWrite,
            proxy = OkProxy(),
            dnsServer = "8.8.8.8",
            protectUdp = { true },
            onStatus = { statuses.add(it) },
        )
        val before = DialLog.lines().size
        try {
            fwd.start()
            val syn = TcpPacket.buildTcp(
                clientIp, serverIp, 12345, 443,
                1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
                mss = TcpPacket.TCP_MSS,
            )
            tunInWrite.write(syn)
            tunInWrite.flush()
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline && statuses.isEmpty()) {
                Thread.sleep(50)
            }
            assertTrue(statuses.contains("Connected"), "expected Connected, got $statuses")
            val lines = DialLog.lines().drop(before)
            assertTrue(
                lines.any { it.contains("DIAL 1.2.3.4:443") && !it.contains(" ok") },
                "expected a DIAL start line, got: $lines",
            )
            assertTrue(
                lines.any { it.contains("DIAL 1.2.3.4:443 ok") },
                "expected a DIAL ok line, got: $lines",
            )
        } finally {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
            drainer.join(1000)
        }
    }

    @Test
    fun `failed dial logs a DIAL GAGAL line`() {
        // Guard (already true on v1.0.8): the failure path logs to
        // DialLog as well as reporting the status — the log must
        // keep naming the failed target.
        val statuses = Collections.synchronizedList(mutableListOf<String>())
        val tunInRead = PipedInputStream()
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream()
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        val drainer = thread(name = "tun-test-drain", isDaemon = true) {
            runCatching { tunOutRead.copyTo(drained) }
        }
        val fwd = TunForwarder(
            tunIn = tunInRead,
            tunOut = tunOutWrite,
            proxy = FailingProxy(SocketTimeoutException("Read timed out")),
            dnsServer = "8.8.8.8",
            protectUdp = { true },
            onStatus = { statuses.add(it) },
        )
        val before = DialLog.lines().size
        try {
            fwd.start()
            val syn = TcpPacket.buildTcp(
                clientIp, serverIp, 12345, 443,
                1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
                mss = TcpPacket.TCP_MSS,
            )
            tunInWrite.write(syn)
            tunInWrite.flush()
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline && statuses.isEmpty()) {
                Thread.sleep(50)
            }
            assertTrue(statuses.isNotEmpty(), "expected a dial-failure status, got none")
            val lines = DialLog.lines().drop(before)
            assertTrue(
                lines.any { it.contains("DIAL 1.2.3.4:443 GAGAL") },
                "expected a DIAL GAGAL line, got: $lines",
            )
        } finally {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
            drainer.join(1000)
        }
    }

    @Test
    fun `timed out dial reports Konek gagal instead of staying silent`() {
        val statuses = Collections.synchronizedList(mutableListOf<String>())
        val tunInRead = PipedInputStream()
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream()
        val tunOutWrite = PipedOutputStream(tunOutRead)
        // Drain the forwarder's output (RST packets) so its writes
        // never block on a full pipe.
        val drained = ByteArrayOutputStream()
        val drainer = thread(name = "tun-test-drain", isDaemon = true) {
            runCatching { tunOutRead.copyTo(drained) }
        }
        val fwd = TunForwarder(
            tunIn = tunInRead,
            tunOut = tunOutWrite,
            proxy = FailingProxy(SocketTimeoutException("Read timed out")),
            dnsServer = "8.8.8.8",
            protectUdp = { true },
            onStatus = { statuses.add(it) },
        )
        try {
            fwd.start()
            val syn = TcpPacket.buildTcp(
                clientIp, serverIp, 12345, 443,
                1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
                mss = TcpPacket.TCP_MSS,
            )
            tunInWrite.write(syn)
            tunInWrite.flush()
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline && statuses.isEmpty()) {
                Thread.sleep(50)
            }
            assertTrue(statuses.isNotEmpty(), "expected a dial-failure status, got none")
            assertEquals("Konek gagal (timeout)", statuses.first())
            assertFalse(statuses.any { it == "Connected" }, "a failed dial must not report Connected")
        } finally {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
            drainer.join(1000)
        }
    }
}
