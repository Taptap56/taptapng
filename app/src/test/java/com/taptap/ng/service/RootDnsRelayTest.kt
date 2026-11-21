package com.taptap.ng.service

import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.ProxyUdpSession
import com.taptap.ng.core.proto.SpeedStats
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.15: relay DNS Root mode — query UDP diteruskan lewat
 * dialUdp proxy ke upstream, jawaban dikembalikan ke pengirim.
 * Sesi dialUdp di-fake sebagai echo (jawaban = query); yang
 * diuji: query sampai ke sesi, jawaban sampai balik ke pengirim,
 * dan upstream yang dipakai adalah 8.8.8.8:53.
 */
@Timeout(30)
class RootDnsRelayTest {

    private class EchoUdpSession : ProxyUdpSession {
        val sent = LinkedBlockingQueue<ByteArray>()
        val sentAll = mutableListOf<ByteArray>()
        private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

        override fun send(datagram: ByteArray) {
            sent.add(datagram)
            synchronized(sentAll) { sentAll += datagram }
        }

        override fun receive(timeoutMs: Long): ByteArray? {
            while (!closed.get()) {
                sent.poll(100, TimeUnit.MILLISECONDS)?.let { return it }
            }
            return null
        }

        override fun close() {
            closed.set(true)
        }
    }

    private class FakeProxy : ProxyClient {
        val udpDialed = mutableListOf<Pair<String, Int>>()
        var lastUdp: EchoUdpSession? = null

        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream = throw UnsupportedOperationException("TCP tidak dipakai tes ini")

        override fun dialUdp(targetHost: String, targetPort: Int, stats: SpeedStats?): ProxyUdpSession {
            udpDialed += targetHost to targetPort
            return EchoUdpSession().also { lastUdp = it }
        }

        override fun close() = Unit
    }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    /** Query DNS minimal: id 0x1234, RD, 1 pertanyaan A example.com. */
    private fun dnsQuery(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        for (label in listOf("example", "com")) {
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0)
        out.write(byteArrayOf(0x00, 0x01, 0x00, 0x01)) // QTYPE A, QCLASS IN
        return out.toByteArray()
    }

    @Test
    fun `query diteruskan lewat proxy dan jawaban kembali ke pengirim`() {
        val proxy = FakeProxy()
        val port = freePort()
        val relay = RootDnsRelay(proxy = proxy, port = port)
        relay.start()
        try {
            val query = dnsQuery()
            DatagramSocket().use { client ->
                client.soTimeout = 5000
                client.send(DatagramPacket(query, query.size, InetAddress.getByName("127.0.0.1"), port))
                val buf = ByteArray(2048)
                val reply = DatagramPacket(buf, buf.size)
                client.receive(reply)
                assertArrayEquals(query, reply.data.copyOfRange(0, reply.length))
            }
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline && proxy.udpDialed.isEmpty()) {
                Thread.sleep(25)
            }
            assertEquals(listOf("8.8.8.8" to 53), proxy.udpDialed)
            // receive() mengonsumsi antrean `sent` (poll) — isi
            // yang dikirim dicek dari salinan `sentAll`.
            assertEquals(1, proxy.lastUdp!!.sentAll.size)
            assertArrayEquals(query, proxy.lastUdp!!.sentAll[0])
        } finally {
            relay.stop()
        }
    }

    @Test
    fun `relay berhenti dan tidak lagi menjawab`() {
        val proxy = FakeProxy()
        val port = freePort()
        val relay = RootDnsRelay(proxy = proxy, port = port)
        relay.start()
        assertTrue(relay.isRunning())
        relay.stop()
        assertTrue(!relay.isRunning())
    }
}
