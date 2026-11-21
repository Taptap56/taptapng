package com.taptap.ng

import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.ProxyUdpSession
import com.taptap.ng.core.proto.SpeedStats
import com.taptap.ng.service.TcpPacket
import com.taptap.ng.service.TunForwarder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.6 (M6): UDP non-DNS dari TUN diteruskan lewat proxy dan
 * balasannya kembali ke TUN. DNS port 53 TIDAK lewat jalur ini
 * (sudah dikunci TunForwarderDnsTest — relay langsung).
 */
@Timeout(30)
class TunForwarderUdpTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(8, 8, 8, 8)

    private class EchoUdpSession : ProxyUdpSession {
        val sent = LinkedBlockingQueue<ByteArray>()
        private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

        override fun send(datagram: ByteArray) {
            sent.add(datagram)
        }

        override fun receive(timeoutMs: Long): ByteArray? {
            // Echo: blokir sampai ada datagram / sesi ditutup —
            // seperti sesi stream (timeoutMs tidak dihonor).
            while (!closed.get()) {
                sent.poll(100, TimeUnit.MILLISECONDS)?.let { return it }
            }
            return null
        }

        override fun close() {
            closed.set(true)
        }
    }

    private class EchoProxy : ProxyClient {
        val udpDialed = mutableListOf<Pair<String, Int>>()
        val sessions = mutableListOf<EchoUdpSession>()

        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream = throw UnsupportedOperationException("tes ini hanya UDP")

        override fun dialUdp(targetHost: String, targetPort: Int, stats: SpeedStats?): ProxyUdpSession {
            udpDialed += targetHost to targetPort
            return EchoUdpSession().also { sessions += it }
        }

        override fun close() = Unit
    }

    private class NoUdpProxy : ProxyClient {
        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream = throw UnsupportedOperationException("tes ini hanya UDP")

        override fun close() = Unit
        // dialUdp default: UnsupportedOperationException (seperti SSH).
    }

    /** Kumpulkan paket IPv4 utuh dari byte stream (framing total-length). */
    private class PacketCollector(input: InputStream) {
        private val packets = mutableListOf<ByteArray>()
        private val buf = mutableListOf<Byte>()
        private var seen = 0

        init {
            Thread({
                val tmp = ByteArray(8192)
                try {
                    while (true) {
                        val n = input.read(tmp)
                        if (n <= 0) break
                        synchronized(packets) {
                            for (i in 0 until n) buf += tmp[i]
                            while (buf.size >= 20) {
                                val total = ((buf[2].toInt() and 0xFF) shl 8) or
                                    (buf[3].toInt() and 0xFF)
                                if (total <= 0 || buf.size < total) break
                                val pkt = ByteArray(total)
                                for (i in 0 until total) pkt[i] = buf[i]
                                repeat(total) { buf.removeAt(0) }
                                packets.add(pkt)
                                (packets as Object).notifyAll()
                            }
                        }
                    }
                } catch (_: Exception) {
                    // Stream ditutup saat stop(): akhir normal.
                }
            }, "udp-test-collector").apply { isDaemon = true; start() }
        }

        fun waitForPacket(timeoutMs: Long): ByteArray? {
            val deadline = System.currentTimeMillis() + timeoutMs
            synchronized(packets) {
                while (packets.size <= seen && System.currentTimeMillis() < deadline) {
                    (packets as Object).wait(50)
                }
                return if (packets.size > seen) packets[seen++] else null
            }
        }

        fun packetCount(): Int = synchronized(packets) { packets.size }
    }

    private class Harness(proxy: ProxyClient) {
        val tunWrite = PipedOutputStream()
        val tunIn = PipedInputStream(tunWrite, 65536)
        val tunOut = PipedOutputStream()
        val tunRead = PipedInputStream(tunOut, 65536)
        val collector = PacketCollector(tunRead)
        val forwarder = TunForwarder(
            tunIn = tunIn,
            tunOut = tunOut,
            proxy = proxy,
            dnsServer = "1.1.1.1",
            protectUdp = { true },
            onStatus = {},
        )

        fun start() = forwarder.start()
        fun stop() {
            runCatching { forwarder.stop() }
            runCatching { tunWrite.close() }
            runCatching { tunOut.close() }
        }
    }

    @Test
    fun `UDP non-DNS di-echo lewat proxy dan kembali ke TUN`() {
        val proxy = EchoProxy()
        val h = Harness(proxy)
        h.start()
        try {
            val payload = "quic-ping".toByteArray()
            val pkt = TcpPacket.buildUdp(clientIp, serverIp, 5000, 443, payload)
            h.tunWrite.write(pkt)
            h.tunWrite.flush()
            val reply = h.collector.waitForPacket(5000)
                ?: throw AssertionError("tidak ada balasan UDP dari forwarder")
            val ip = TcpPacket.parseIp(reply, reply.size)!!
            assertEquals(serverIp, ip.src)
            assertEquals(clientIp, ip.dst)
            assertEquals(TcpPacket.PROTO_UDP, ip.protocol)
            val udp = TcpPacket.parseUdp(ip.payload)!!
            assertEquals(443, udp.srcPort)
            assertEquals(5000, udp.dstPort)
            assertEquals(payload.toList(), udp.payload.toList())
            assertEquals(listOf("8.8.8.8" to 443), proxy.udpDialed)
            assertEquals(1, h.forwarder.udpSessionCount())
        } finally {
            h.stop()
        }
    }

    @Test
    fun `dua datagram 4-tuple sama memakai satu sesi`() {
        val proxy = EchoProxy()
        val h = Harness(proxy)
        h.start()
        try {
            for (i in 1..2) {
                val pkt = TcpPacket.buildUdp(clientIp, serverIp, 5000, 443, "d$i".toByteArray())
                h.tunWrite.write(pkt)
                h.tunWrite.flush()
                h.collector.waitForPacket(5000)
                    ?: throw AssertionError("tidak ada balasan untuk datagram $i")
            }
            assertEquals(1, proxy.udpDialed.size)
            assertEquals(1, h.forwarder.udpSessionCount())
        } finally {
            h.stop()
        }
    }

    @Test
    fun `entry tanpa UDP membuang datagram tanpa membunuh reader`() {
        val proxy = NoUdpProxy()
        val h = Harness(proxy)
        h.start()
        try {
            val pkt = TcpPacket.buildUdp(clientIp, serverIp, 5000, 443, "drop-me".toByteArray())
            h.tunWrite.write(pkt)
            h.tunWrite.flush()
            Thread.sleep(500)
            assertEquals(0, h.collector.packetCount())
            assertEquals(0, h.forwarder.udpSessionCount())
            // Reader masih hidup: datagram kedua juga diproses (dibuang lagi).
            h.tunWrite.write(pkt)
            h.tunWrite.flush()
            Thread.sleep(500)
            assertEquals(0, h.collector.packetCount())
        } finally {
            h.stop()
        }
    }
}
