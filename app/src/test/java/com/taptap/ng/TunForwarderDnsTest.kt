package com.taptap.ng

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsResolver
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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.4 DNS relay tests (review Claude atas v1.0.3):
 * (3a) fallback ke 1.0.0.1 saat 1.1.1.1 timeout — sebelumnya
 * 1.0.0.1 hanya dipasang di addDnsServer dan tidak pernah dipakai
 * forwarder; (3b) pool DNS berbatas (bukan satu thread per query
 * tanpa batas); (3d) dnsLogged naik sekali per query, jadi batas
 * "5 query pertama" benar-benar 5 query, bukan ~2–3.
 *
 * Server DNS primer/fallback adalah socket lokal di dua IP loopback
 * yang sama port-nya (127.0.0.2 = primer, 127.0.0.1 = fallback) —
 * forwarder hanya punya satu dnsPort untuk keduanya. Query ditulis
 * ke TUN satu per satu (pipe bisa menggabungkan dua write menjadi
 * satu read, dan forwarder hanya memproses satu paket per read).
 */
class TunForwarderDnsTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(8, 8, 8, 8)

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
        ): ProxyStream = BlockingStream()

        override fun close() = Unit
    }

    /** Collects whole IPv4 packets from a byte stream, framing by
     *  the IPv4 total-length field (a pipe read may split packets). */
    private class PacketCollector(input: InputStream) {
        private val packets = mutableListOf<ByteArray>()
        private val buf = mutableListOf<Byte>()

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
                                packets += pkt
                                repeat(total) { buf.removeAt(0) }
                            }
                        }
                    }
                } catch (_: Exception) {
                    // Input ditutup stop().
                }
            }, "test-dns-collector").apply { isDaemon = true; start() }
        }

        fun snapshot(): List<ByteArray> = synchronized(packets) { packets.toList() }
    }

    private class Harness(
        dnsServer: String,
        dnsFallbackServer: String,
        dnsPort: Int,
    ) {
        val tunInRead = PipedInputStream(65536)
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream(65536)
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val collector = PacketCollector(tunOutRead)
        val fwd = TunForwarder(
            tunInRead, tunOutWrite, OkProxy(), dnsServer,
            protectUdp = { true },
            onStatus = {},
            dnsTimeoutMs = 200,
            dnsFallbackServer = dnsFallbackServer,
            dnsPort = dnsPort,
        )

        fun start() = fwd.start()

        fun stop() {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
        }
    }

    private fun dnsQueryPacket(srcPort: Int): ByteArray {
        val query = DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_A)
        return TcpPacket.buildUdp(clientIp, serverIp, srcPort, 53, query)
    }

    private fun waitForPackets(
        h: Harness,
        count: Int,
        timeoutMs: Long = 5_000,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (h.collector.snapshot().size >= count) return true
            Thread.sleep(25)
        }
        return h.collector.snapshot().size >= count
    }

    private fun udpPayload(packet: ByteArray): TcpPacket.UdpDatagram? {
        val ip = TcpPacket.parseIp(packet, packet.size) ?: return null
        return TcpPacket.parseUdp(ip.payload)
    }

    @Test
    fun `fallback answers when the primary stays silent`() {
        // Primer (127.0.0.2) diam — tidak pernah membaca; fallback
        // (127.0.0.1) menjawab dengan marker. Gagal pada kode v1.0.3
        // (query dibuang sesudah timeout primer, tanpa jawaban).
        val fallback = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val port = fallback.localPort
        val primary = DatagramSocket(port, InetAddress.getByName("127.0.0.2"))
        val marker = "FALLBACK-ANSWER".toByteArray(Charsets.US_ASCII)
        val fallbackThread = Thread({
            try {
                val buf = ByteArray(2048)
                val pkt = DatagramPacket(buf, buf.size)
                fallback.receive(pkt)
                fallback.send(DatagramPacket(marker, marker.size, pkt.address, pkt.port))
            } catch (_: Exception) {
                // Socket ditutup.
            }
        }, "test-dns-fallback").apply { isDaemon = true; start() }
        val before = DialLog.lines().size
        val h = Harness("127.0.0.2", "127.0.0.1", port)
        try {
            h.start()
            val query = DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_A)
            h.tunInWrite.write(dnsQueryPacket(40000))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban dari fallback")
            val reply = udpPayload(h.collector.snapshot()[0])
            assertEquals(53, reply?.srcPort)
            assertEquals(40000, reply?.dstPort)
            assertTrue(
                reply?.payload?.contentEquals(marker) == true,
                "jawaban harus dari fallback, bukan primer",
            )
            // Primer tetap dicoba dulu (query-nya antre di socket diam).
            primary.soTimeout = 500
            val got = DatagramPacket(ByteArray(2048), 2048)
            primary.receive(got)
            assertTrue(
                got.data.copyOf(got.length).contentEquals(query),
                "primer harus menerima query dulu sebelum fallback",
            )
            // Baris log-nya menyebut timeout primer + coba fallback.
            assertTrue(
                DialLog.lines().drop(before).any {
                    it.contains("timeout 127.0.0.2 untuk query #1 — coba 127.0.0.1")
                },
                "log: ${DialLog.lines().drop(before)}",
            )
        } finally {
            h.stop()
            fallback.close()
            primary.close()
        }
    }

    @Test
    fun `both silent logs a timeout and sends no reply`() {
        val fallback = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val port = fallback.localPort
        val primary = DatagramSocket(port, InetAddress.getByName("127.0.0.2"))
        val before = DialLog.lines().size
        val h = Harness("127.0.0.2", "127.0.0.1", port)
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket(40001))
            h.tunInWrite.flush()
            Thread.sleep(1500)
            assertEquals(
                0, h.collector.snapshot().size,
                "tidak boleh ada jawaban bila kedua server diam",
            )
            assertTrue(
                DialLog.lines().drop(before).any {
                    it.contains("timeout 127.0.0.1 untuk query #1")
                },
                "log harus ada timeout fallback: ${DialLog.lines().drop(before)}",
            )
        } finally {
            h.stop()
            fallback.close()
            primary.close()
        }
    }

    @Test
    fun `first five queries each get a query and an answer detail line`() {
        // v1.0.4 (3d): dnsLogged naik dua kali per query (baris
        // query + baris jawab), jadi batas "5 pertama" sebenarnya
        // ~2–3 query. Sesudah perbaikan: 5 query → 5 baris query +
        // 5 baris jawab. Primer diam (timeout 200 ms), fallback
        // menggemakan query.
        val fallback = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val port = fallback.localPort
        val primary = DatagramSocket(port, InetAddress.getByName("127.0.0.2"))
        val fallbackThread = Thread({
            try {
                repeat(5) {
                    val buf = ByteArray(2048)
                    val pkt = DatagramPacket(buf, buf.size)
                    fallback.receive(pkt)
                    val bytes = pkt.data.copyOf(pkt.length)
                    fallback.send(DatagramPacket(bytes, bytes.size, pkt.address, pkt.port))
                }
            } catch (_: Exception) {
                // Socket ditutup.
            }
        }, "test-dns-echo").apply { isDaemon = true; start() }
        val before = DialLog.lines().size
        val h = Harness("127.0.0.2", "127.0.0.1", port)
        try {
            h.start()
            for (i in 0 until 5) {
                h.tunInWrite.write(dnsQueryPacket(40100 + i))
                h.tunInWrite.flush()
                assertTrue(
                    waitForPackets(h, i + 1),
                    "jawaban ke-${i + 1} tidak datang",
                )
            }
            val lines = DialLog.lines().drop(before)
            assertEquals(
                5, lines.count { it.contains("query 8.8.8.8") },
                "harus 5 baris detail query: $lines",
            )
            assertEquals(
                5, lines.count { it.contains("jawab 8.8.8.8") },
                "harus 5 baris detail jawab: $lines",
            )
        } finally {
            h.stop()
            fallback.close()
            primary.close()
        }
    }

    @Test
    fun `dns executor is bounded`() {
        val h = Harness("127.0.0.1", "127.0.0.1", 1)
        try {
            assertEquals(2, h.fwd.dnsExecutor.corePoolSize)
            assertEquals(16, h.fwd.dnsExecutor.maximumPoolSize)
            assertEquals(128, h.fwd.dnsExecutor.queue.remainingCapacity())
            assertTrue(!h.fwd.dnsExecutor.isShutdown)
        } finally {
            h.fwd.dnsExecutor.shutdownNow()
        }
    }
}
