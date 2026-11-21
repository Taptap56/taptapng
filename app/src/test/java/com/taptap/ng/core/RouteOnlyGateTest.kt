package com.taptap.ng.core

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
import java.util.Collections
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RouteOnlyGateTest {

    private val serverIp = TcpPacket.ipFromBytes(1, 2, 3, 4)

    @Test
    fun `route only off proxies everything`() {
        assertEquals(
            RouteOnlyGate.Decision.PROXY,
            RouteOnlyGate.decide(false, serverIp, emptyMap()),
        )
    }

    @Test
    fun `route only on proxies a known destination and refuses an unknown one`() {
        val known = mapOf(serverIp to "example.com")
        assertEquals(
            RouteOnlyGate.Decision.PROXY,
            RouteOnlyGate.decide(true, serverIp, known),
        )
        assertEquals(
            RouteOnlyGate.Decision.REFUSE,
            RouteOnlyGate.decide(
                true,
                TcpPacket.ipFromBytes(9, 9, 9, 9),
                known,
            ),
        )
    }

    /** Proxy that always succeeds: input blocks forever (a CONNECTED
     * pipe whose sink never writes — an unconnected PipedInputStream
     * throws on read at once, which kills the relay thread and
     * closes the session before the test's ACK/data arrive),
     * output is discarded. */
    private class OkProxy : ProxyClient {
        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream {
            val sink = PipedOutputStream()
            val input = PipedInputStream(sink)
            return object : ProxyStream {
                override val input: InputStream = input
                override val output: OutputStream = ByteArrayOutputStream()
                override fun close() {
                    runCatching { input.close() }
                    runCatching { sink.close() }
                }
            }
        }

        override fun close() = Unit
    }

    private fun harness(routeOnly: Boolean, known: Map<Int, String>): Triple<TunForwarder, PipedOutputStream, ByteArrayOutputStream> {
        val tunInRead = PipedInputStream()
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream()
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        thread(name = "tun-test-drain", isDaemon = true) {
            runCatching { tunOutRead.copyTo(drained) }
        }
        val fwd = TunForwarder(
            tunIn = tunInRead,
            tunOut = tunOutWrite,
            proxy = OkProxy(),
            dnsServer = "8.8.8.8",
            protectUdp = { true },
            onStatus = {},
            routeOnlyEnabled = routeOnly,
            knownHosts = Collections.synchronizedMap(HashMap(known)),
        )
        return Triple(fwd, tunInWrite, drained)
    }

    private fun sendSyn(tunInWrite: PipedOutputStream, dstIp: Int) {
        val syn = TcpPacket.buildTcp(
            TcpPacket.ipFromBytes(10, 0, 0, 2), dstIp, 12345, 443,
            1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
            mss = TcpPacket.TCP_MSS,
        )
        tunInWrite.write(syn)
        tunInWrite.flush()
    }

    /** Parse the first IP packet in `bytes` and return its TCP flags, or -1. */
    private fun firstTcpFlags(bytes: ByteArray): Int {
        if (bytes.isEmpty()) return -1
        val ipH = TcpPacket.parseIpHeader(bytes, bytes.size) ?: return -1
        val tcp = TcpPacket.parseTcpSegment(bytes, ipH.payloadOff, ipH.payloadLen) ?: return -1
        return tcp.flags
    }

    @Test
    fun `route only refuses an unknown destination with rst and no session`() {
        val (fwd, tunInWrite, drained) = harness(
            routeOnly = true,
            known = emptyMap(),
        )
        try {
            fwd.start()
            sendSyn(tunInWrite, serverIp)
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline && drained.size() == 0) {
                Thread.sleep(50)
            }
            assertEquals(0, fwd.sessionCount())
            val flags = firstTcpFlags(drained.toByteArray())
            assertTrue(flags and TcpPacket.FLAG_RST != 0, "expected RST, got flags=$flags")
            assertTrue(
                // DialLog.log does NOT render the stage/tag (v1.0.3
                // XVEON parity) — assert on the message text.
                DialLog.lines().any { it.contains("tujuan tidak dikenal") },
                "expected a route-only refusal log line",
            )
        } finally {
            fwd.stop()
            runCatching { tunInWrite.close() }
        }
    }

    @Test
    fun `route only dials a known destination`() {
        val statuses = Collections.synchronizedList(mutableListOf<String>())
        val tunInRead = PipedInputStream()
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream()
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        thread(name = "tun-test-drain", isDaemon = true) {
            runCatching { tunOutRead.copyTo(drained) }
        }
        val fwd = TunForwarder(
            tunIn = tunInRead,
            tunOut = tunOutWrite,
            proxy = OkProxy(),
            dnsServer = "8.8.8.8",
            protectUdp = { true },
            onStatus = { statuses.add(it) },
            routeOnlyEnabled = true,
            knownHosts = Collections.synchronizedMap(
                HashMap(mapOf(serverIp to "example.com")),
            ),
        )
        try {
            fwd.start()
            sendSyn(tunInWrite, serverIp)
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline && statuses.isEmpty()) {
                Thread.sleep(50)
            }
            assertTrue(statuses.contains("Connected"), "expected Connected, got $statuses")
            assertEquals(1, fwd.sessionCount())
        } finally {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
        }
    }

    /** Complete the handshake deterministically: wait for the
     * SYN-ACK in `drained`, parse its sequence number, and ACK it.
     * Returns the server sequence number + 1 (our ack number). */
    private fun establishSession(
        tunInWrite: PipedOutputStream,
        drained: ByteArrayOutputStream,
    ): Long {
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline && drained.size() == 0) {
            Thread.sleep(50)
        }
        val bytes = drained.toByteArray()
        val ipH = TcpPacket.parseIpHeader(bytes, bytes.size)
            ?: throw AssertionError("no SYN-ACK in drained output")
        val synAck = TcpPacket.parseTcpSegment(bytes, ipH.payloadOff, ipH.payloadLen)
            ?: throw AssertionError("no TCP segment in drained output")
        assertTrue(synAck.flags and TcpPacket.FLAG_SYN != 0, "expected SYN-ACK, got ${synAck.flags}")
        val serverSeqPlus1 = (synAck.seq + 1) and 0xFFFFFFFFL
        val ack = TcpPacket.buildTcp(
            TcpPacket.ipFromBytes(10, 0, 0, 2), serverIp, 12345, 443,
            1001L, serverSeqPlus1, TcpPacket.FLAG_ACK, ByteArray(0),
        )
        tunInWrite.write(ack)
        tunInWrite.flush()
        Thread.sleep(200)
        return serverSeqPlus1
    }

    private fun sendData(tunInWrite: PipedOutputStream, serverAck: Long, payload: ByteArray) {
        val data = TcpPacket.buildTcp(
            TcpPacket.ipFromBytes(10, 0, 0, 2), serverIp, 12345, 443,
            1001L, serverAck, TcpPacket.FLAG_PSH or TcpPacket.FLAG_ACK, payload,
        )
        tunInWrite.write(data)
        tunInWrite.flush()
    }

    @Test
    fun `sniffed host on first data lands in known hosts`() {
        // An HTTP request as the first data chunk: the forwarder
        // records its Host, so the NEXT connection to the same IP
        // is known to route-only (same code path as SNI).
        val tunInRead = PipedInputStream()
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream()
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        thread(name = "tun-test-drain", isDaemon = true) {
            runCatching { tunOutRead.copyTo(drained) }
        }
        val fwd = TunForwarder(
            tunIn = tunInRead,
            tunOut = tunOutWrite,
            proxy = OkProxy(),
            dnsServer = "8.8.8.8",
            protectUdp = { true },
            onStatus = {},
            sniffingEnabled = true,
        )
        try {
            fwd.start()
            sendSyn(tunInWrite, serverIp)
            val serverAck = establishSession(tunInWrite, drained)
            val req = "GET / HTTP/1.1\r\nHost: sniffed.example\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            sendData(tunInWrite, serverAck, req)
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline &&
                fwd.knownHostsSnapshot()[serverIp] == null
            ) {
                Thread.sleep(50)
            }
            assertEquals("sniffed.example", fwd.knownHostsSnapshot()[serverIp])
        } finally {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
        }
    }

    @Test
    fun `sniffing off leaves known hosts empty`() {
        val tunInRead = PipedInputStream()
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream()
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val drained = ByteArrayOutputStream()
        thread(name = "tun-test-drain", isDaemon = true) {
            runCatching { tunOutRead.copyTo(drained) }
        }
        val fwd = TunForwarder(
            tunIn = tunInRead,
            tunOut = tunOutWrite,
            proxy = OkProxy(),
            dnsServer = "8.8.8.8",
            protectUdp = { true },
            onStatus = {},
            sniffingEnabled = false,
        )
        try {
            fwd.start()
            sendSyn(tunInWrite, serverIp)
            val serverAck = establishSession(tunInWrite, drained)
            val req = "GET / HTTP/1.1\r\nHost: sniffed.example\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            sendData(tunInWrite, serverAck, req)
            Thread.sleep(500)
            assertFalse(fwd.knownHostsSnapshot().containsKey(serverIp))
        } finally {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
        }
    }
}
