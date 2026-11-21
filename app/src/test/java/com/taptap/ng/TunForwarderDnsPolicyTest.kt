package com.taptap.ng

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsExchange
import com.taptap.ng.core.DnsRelayPolicy
import com.taptap.ng.core.DnsResolver
import com.taptap.ng.core.DohClient
import com.taptap.ng.core.FakeDns
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
import java.net.InetAddress
import java.util.Collections
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for the v1.0.5 DNS relay policy (kelompok C): vpnDns as
 * tunnel upstream, dnsHosts, FakeDNS (+ dial reverse-map), local
 * DNS, domestic split, and DoH — all through the real
 * [TunForwarder] with IN-MEMORY stub transports (no loopback
 * sockets, no real network): the TUN is pipes, the UDP upstream is
 * a [DnsExchange] stub, DoH is a [DohClient.Exchange] stub, and the
 * local resolver is a lambda stub.
 */
class TunForwarderDnsPolicyTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 10, 14, 2)
    private val serverIp = TcpPacket.ipFromBytes(8, 8, 8, 8)

    private class BlockingStream : ProxyStream {
        override val input: InputStream = PipedInputStream()
        override val output: OutputStream = ByteArrayOutputStream()
        override fun close() {
            runCatching { input.close() }
        }
    }

    /** Proxy that records every dial target (for the FakeDNS test). */
    private class RecordingProxy : ProxyClient {
        val dials = Collections.synchronizedList(mutableListOf<Pair<String, Int>>())

        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream {
            dials += targetHost to targetPort
            return BlockingStream()
        }

        override fun close() = Unit
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
            }, "test-dns-policy-collector").apply { isDaemon = true; start() }
        }

        fun snapshot(): List<ByteArray> = synchronized(packets) { packets.toList() }
    }

    private class Harness(
        dnsServer: String,
        dnsFallbackServer: String = "1.0.0.1",
        policy: DnsRelayPolicy = DnsRelayPolicy.DEFAULT,
        proxy: ProxyClient = OkProxy(),
    ) {
        val tunInRead = PipedInputStream(65536)
        val tunInWrite = PipedOutputStream(tunInRead)
        val tunOutRead = PipedInputStream(65536)
        val tunOutWrite = PipedOutputStream(tunOutRead)
        val collector = PacketCollector(tunOutRead)
        val fwd = TunForwarder(
            tunInRead, tunOutWrite, proxy, dnsServer,
            protectUdp = { true },
            onStatus = {},
            dnsTimeoutMs = 200,
            dnsFallbackServer = dnsFallbackServer,
            dnsPolicy = policy,
        )

        fun start() = fwd.start()

        fun stop() {
            fwd.stop()
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
        }
    }

    /** Stub UDP upstream: jawab setiap query dengan A [answerIp]; catat server yang dituju. */
    private class StubUdp(private val answerIp: String = "93.184.216.34") : DnsExchange {
        val servers = Collections.synchronizedList(mutableListOf<String>())
        var calls = 0

        override fun exchange(
            query: ByteArray,
            server: String,
            port: Int,
            timeoutMs: Int,
        ): ByteArray {
            calls++
            servers += server
            return DnsResolver.buildResponse(
                query,
                listOf(InetAddress.getByName(answerIp)),
            ) ?: throw IllegalStateException("stub tidak bisa membangun jawaban")
        }
    }

    /** Stub DoH: jawab setiap query dengan A [answerIp]; catat pemakaian + metode. */
    private class StubDoh(
        private val answerIp: String = "93.184.216.34",
        private val fail: Boolean = false,
    ) : DohClient.Exchange {
        var calls = 0
        var lastUseGet: Boolean? = null

        override fun exchange(
            url: String,
            query: ByteArray,
            useGet: Boolean,
            timeoutMs: Int,
        ): ByteArray {
            calls++
            lastUseGet = useGet
            if (fail) throw java.io.IOException("stub DoH mati")
            return DnsResolver.buildResponse(
                query,
                listOf(InetAddress.getByName(answerIp)),
            ) ?: throw IllegalStateException("stub tidak bisa membangun jawaban")
        }
    }

    private fun dnsQueryPacket(host: String, srcPort: Int): ByteArray {
        val query = DnsResolver.buildQuery(host, 0x1234, DnsResolver.TYPE_A)
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

    private fun replyAddresses(h: Harness, index: Int = 0): List<String> {
        val reply = udpPayload(h.collector.snapshot()[index])!!
        return DnsResolver.parseAnswers(reply.payload, 0x1234).map { it.hostAddress }
    }

    @Test
    fun `vpnDns menjadi upstream tunnel`() {
        // Ganti setting -> upstream berubah (bukti item 1, ujung ke
        // ujung lewat forwarder): query harus sampai ke 8.8.4.4,
        // bukan ke 1.1.1.1 paten v1.0.4.
        val udp = StubUdp()
        val h = Harness("8.8.4.4", policy = DnsRelayPolicy(dnsExchange = udp))
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("example.com", 40000))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban relay")
            assertEquals(listOf("8.8.4.4"), udp.servers)
            assertEquals(listOf("93.184.216.34"), replyAddresses(h))
            val reply = udpPayload(h.collector.snapshot()[0])
            assertEquals(53, reply?.srcPort)
            assertEquals(40000, reply?.dstPort)
        } finally {
            h.stop()
        }
    }

    @Test
    fun `static host dijawab lokal tanpa upstream`() {
        val udp = StubUdp()
        val policy = DnsRelayPolicy(
            staticHosts = mapOf("example.com" to InetAddress.getByName("10.9.9.9")),
            dnsExchange = udp,
        )
        val h = Harness("8.8.4.4", policy = policy)
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("example.com", 40001))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban statis")
            assertEquals(0, udp.calls)
            assertEquals(listOf("10.9.9.9"), replyAddresses(h))
            // Subdomain ikut terpetakan.
            h.tunInWrite.write(dnsQueryPacket("sub.example.com", 40002))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 2), "tidak ada jawaban subdomain statis")
            assertEquals(0, udp.calls)
            assertEquals(listOf("10.9.9.9"), replyAddresses(h, 1))
        } finally {
            h.stop()
        }
    }

    @Test
    fun `fake DNS mengalokasi IP dan dial memetakan balik ke hostname`() {
        val udp = StubUdp()
        val fake = FakeDns()
        val proxy = RecordingProxy()
        val policy = DnsRelayPolicy(fakeDns = fake, dnsExchange = udp)
        val h = Harness("8.8.4.4", policy = policy, proxy = proxy)
        val before = DialLog.lines().size
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("fake.example", 40003))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban fake")
            assertEquals(0, udp.calls)
            assertEquals(listOf("198.18.0.1"), replyAddresses(h))
            // App lalu SYN ke IP fake: dial harus membawa hostname,
            // bukan IP fake.
            val fakeBytes = InetAddress.getByName("198.18.0.1").address
            val fakeIp = TcpPacket.ipFromBytes(
                fakeBytes[0].toInt() and 0xFF,
                fakeBytes[1].toInt() and 0xFF,
                fakeBytes[2].toInt() and 0xFF,
                fakeBytes[3].toInt() and 0xFF,
            )
            val syn = TcpPacket.buildTcp(
                clientIp, fakeIp, 40010, 443,
                1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
                mss = TcpPacket.TCP_MSS,
            )
            h.tunInWrite.write(syn)
            h.tunInWrite.flush()
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline && proxy.dials.isEmpty()) {
                Thread.sleep(25)
            }
            assertEquals(
                listOf("fake.example" to 443),
                proxy.dials.toList(),
                "dial harus membawa hostname asli, bukan IP fake",
            )
            assertTrue(
                DialLog.lines().drop(before).any {
                    it.contains("fake 198.18.0.1:443 -> fake.example")
                },
                "log: ${DialLog.lines().drop(before)}",
            )
        } finally {
            h.stop()
        }
    }

    @Test
    fun `local DNS memakai resolver lokal bukan upstream`() {
        val udp = StubUdp()
        val policy = DnsRelayPolicy(
            localDnsEnabled = true,
            localResolve = { host, _ ->
                if (host == "example.com") {
                    listOf(InetAddress.getByName("10.7.7.7"))
                } else {
                    emptyList()
                }
            },
            dnsExchange = udp,
        )
        val h = Harness("8.8.4.4", policy = policy)
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("example.com", 40004))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban lokal")
            assertEquals(0, udp.calls)
            assertEquals(listOf("10.7.7.7"), replyAddresses(h))
        } finally {
            h.stop()
        }
    }

    @Test
    fun `local DNS kosong fallback ke UDP utama`() {
        val udp = StubUdp()
        val policy = DnsRelayPolicy(
            localDnsEnabled = true,
            localResolve = { _, _ -> emptyList() },
            dnsExchange = udp,
        )
        val h = Harness("8.8.4.4", policy = policy)
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("example.com", 40005))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban fallback")
            assertEquals(listOf("8.8.4.4"), udp.servers)
            assertEquals(listOf("93.184.216.34"), replyAddresses(h))
        } finally {
            h.stop()
        }
    }

    @Test
    fun `domain id dirutekan ke DNS domestik`() {
        val udp = StubUdp()
        val h = Harness("8.8.4.4", policy = DnsRelayPolicy(dnsExchange = udp))
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("example.id", 40006))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban domestik")
            assertEquals(listOf("223.5.5.5"), udp.servers)
            assertEquals(listOf("93.184.216.34"), replyAddresses(h))
            // Domain non-id tetap ke remote (UDP utama).
            h.tunInWrite.write(dnsQueryPacket("example.com", 40007))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 2), "tidak ada jawaban remote")
            assertEquals(listOf("223.5.5.5", "8.8.4.4"), udp.servers)
        } finally {
            h.stop()
        }
    }

    @Test
    fun `query remote memakai DoH bukan UDP`() {
        val udp = StubUdp()
        val doh = StubDoh()
        val dohUrl = "https://cloudflare-dns.com/dns-query"
        val policy = DnsRelayPolicy(
            remoteDohUrl = dohUrl,
            dohClient = DohClient(dohUrl, doh),
            dnsExchange = udp,
        )
        val h = Harness("8.8.4.4", policy = policy)
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("example.com", 40008))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban DoH")
            assertEquals(1, doh.calls)
            assertEquals(false, doh.lastUseGet)
            assertEquals(0, udp.calls)
            assertEquals(listOf("93.184.216.34"), replyAddresses(h))
        } finally {
            h.stop()
        }
    }

    @Test
    fun `DoH gagal fallback ke UDP utama`() {
        val udp = StubUdp()
        val doh = StubDoh(fail = true)
        val dohUrl = "https://cloudflare-dns.com/dns-query"
        val policy = DnsRelayPolicy(
            remoteDohUrl = dohUrl,
            dohClient = DohClient(dohUrl, doh),
            dnsExchange = udp,
        )
        val h = Harness("8.8.4.4", policy = policy)
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("example.com", 40009))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban fallback DoH")
            assertEquals(1, doh.calls)
            assertEquals(listOf("8.8.4.4"), udp.servers)
            assertEquals(listOf("93.184.216.34"), replyAddresses(h))
        } finally {
            h.stop()
        }
    }

    @Test
    fun `host DoH sendiri di-resolve lewat UDP bukan DoH`() {
        // Pengecualian loop: query untuk cloudflare-dns.com tidak
        // boleh masuk DoH (DoH akan memanggil dirinya sendiri).
        val udp = StubUdp()
        val doh = StubDoh()
        val dohUrl = "https://cloudflare-dns.com/dns-query"
        val policy = DnsRelayPolicy(
            remoteDohUrl = dohUrl,
            dohClient = DohClient(dohUrl, doh),
            dnsExchange = udp,
        )
        val h = Harness("8.8.4.4", policy = policy)
        try {
            h.start()
            h.tunInWrite.write(dnsQueryPacket("cloudflare-dns.com", 40010))
            h.tunInWrite.flush()
            assertTrue(waitForPackets(h, 1), "tidak ada jawaban host DoH")
            assertEquals(0, doh.calls)
            assertEquals(listOf("8.8.4.4"), udp.servers)
            assertEquals(listOf("93.184.216.34"), replyAddresses(h))
        } finally {
            h.stop()
        }
    }
}
