package com.taptap.x

import com.taptap.x.core.proto.ProxyClient
import com.taptap.x.core.proto.ProxyStream
import com.taptap.x.service.TcpPacket
import com.taptap.x.service.TunForwarder
import java.io.ByteArrayOutputStream
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
        override fun dial(targetHost: String, targetPort: Int): ProxyStream {
            throw error
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
