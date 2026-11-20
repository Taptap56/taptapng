package com.taptap.x.core.slowdns

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * DnsttPacketConn tests (M3) with an in-memory fake DNS transport
 * (loopback UDP is blocked in the VM, so no real sockets here).
 * Each test FAILS on a packet encoding that does not match TB's Go
 * DNSTT client, and PASSES on the port.
 */
class DnsttPacketConnTest {

    /** Fake DNS transport: sent queries land in [sent]; receive() returns queued responses. */
    private class FakeTransport : DnsTransport {
        val sent = LinkedBlockingQueue<ByteArray>()
        val toReceive = LinkedBlockingQueue<ByteArray>()
        @Volatile var closed = false

        override fun send(data: ByteArray, addr: InetSocketAddress) {
            sent.offer(data.copyOf())
        }

        override fun receive(buf: ByteArray): Int {
            while (!closed) {
                val d = toReceive.poll(100, TimeUnit.MILLISECONDS)
                if (d != null) {
                    d.copyInto(buf, 0, 0, minOf(d.size, buf.size))
                    return minOf(d.size, buf.size)
                }
            }
            throw java.io.IOException("transport ditutup")
        }

        override fun close() {
            closed = true
        }
    }

    private val resolver = InetSocketAddress("8.8.8.8", 53)
    private val domain = "example.com"

    private fun u16(v: Int): ByteArray =
        byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun writeName(out: MutableList<Byte>, labels: List<String>) {
        for (label in labels) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.add(b.size.toByte())
            out.addAll(b.toList())
        }
        out.add(0)
    }

    /** Build a DNS response carrying [payload] as one TXT answer for [qnameLabels]. */
    private fun buildTxtResponse(qnameLabels: List<String>, payload: ByteArray): ByteArray {
        val out = mutableListOf<Byte>()
        out.addAll(u16(0x1111).toList())
        out.addAll(u16(0x8100).toList())
        out.addAll(u16(1).toList())
        out.addAll(u16(1).toList())
        out.addAll(u16(0).toList())
        out.addAll(u16(0).toList())
        writeName(out, qnameLabels)
        out.addAll(u16(DnsWire.TYPE_TXT).toList())
        out.addAll(u16(1).toList())
        writeName(out, qnameLabels)
        out.addAll(u16(DnsWire.TYPE_TXT).toList())
        out.addAll(u16(1).toList())
        out.addAll(byteArrayOf(0, 0, 0, 60).toList())
        val rdata = DnsWire.encodeRDataTxt(payload)
        out.addAll(u16(rdata.size).toList())
        out.addAll(rdata.toList())
        return out.toByteArray()
    }

    /** Decode a client query: returns (question name labels, qtype). */
    private fun parseQuery(q: ByteArray): Pair<List<String>, Int> {
        val (labels, afterName) = DnsWire.readName(q, 12)!!
        val qtype = ((q[afterName].toInt() and 0xFF) shl 8) or (q[afterName + 1].toInt() and 0xFF)
        return labels.map { it.toString(Charsets.US_ASCII) } to qtype
    }

    /** Extract the upstream packet from a client query's QNAME. */
    private fun upstreamPacketFromQuery(q: ByteArray): ByteArray {
        val (labels, _) = parseQuery(q)
        // QNAME = base32 labels + domain labels; strip the domain.
        val b32 = labels.dropLast(2).joinToString("")
        val decoded = Base32.decode(b32)
        // Strip the 8-byte clientID.
        val body = decoded.copyOfRange(8, decoded.size)
        return DnsWire.decodeUpstreamPacket(body)!!
    }

    @Test
    fun `writeTo sends a TXT query carrying the packet`() {
        val transport = FakeTransport()
        val conn = DnsttPacketConn(transport, resolver, domain, DnsWire.TYPE_TXT)
        try {
            val packet = "kcp-segment".toByteArray(Charsets.US_ASCII)
            conn.writeTo(packet)
            val query = transport.sent.poll(3, TimeUnit.SECONDS)
            assertTrue(query != null, "Tidak ada query DNS yang dikirim")
            val (labels, qtype) = parseQuery(query!!)
            assertEquals(DnsWire.TYPE_TXT, qtype)
            // QNAME ends with the tunnel domain.
            assertEquals(listOf("example", "com"), labels.takeLast(2))
            assertEquals(packet.toString(Charsets.US_ASCII), upstreamPacketFromQuery(query).toString(Charsets.US_ASCII))
            // Flags: RD=1.
            assertEquals(0x01, query[2].toInt() and 0xFF)
        } finally {
            conn.close()
        }
    }

    @Test
    fun `writeTo with NULL sends a NULL query`() {
        val transport = FakeTransport()
        val conn = DnsttPacketConn(transport, resolver, domain, DnsWire.TYPE_NULL)
        try {
            conn.writeTo(byteArrayOf(1, 2, 3))
            val query = transport.sent.poll(3, TimeUnit.SECONDS)
            assertTrue(query != null)
            val (_, qtype) = parseQuery(query!!)
            assertEquals(DnsWire.TYPE_NULL, qtype)
        } finally {
            conn.close()
        }
    }

    @Test
    fun `readFrom returns packets from a TXT response`() {
        val transport = FakeTransport()
        val conn = DnsttPacketConn(transport, resolver, domain, DnsWire.TYPE_TXT)
        try {
            val payload = byteArrayOf(0, 3) + "abc".toByteArray() + byteArrayOf(0, 2) + "de".toByteArray()
            val resp = buildTxtResponse(listOf("q", "example", "com"), payload)
            transport.toReceive.offer(resp)
            val p1 = conn.readFrom()
            assertEquals("abc", p1.toString(Charsets.US_ASCII))
            // The second packet is queued too: feed another response is
            // NOT needed — readFrom returns the next queued packet.
            val p2 = conn.readFrom()
            assertEquals("de", p2.toString(Charsets.US_ASCII))
        } finally {
            conn.close()
        }
    }

    @Test
    fun `response with a foreign answer name is dropped`() {
        val transport = FakeTransport()
        val conn = DnsttPacketConn(transport, resolver, domain, DnsWire.TYPE_TXT)
        try {
            val payload = byteArrayOf(0, 1, 7)
            val resp = buildTxtResponse(listOf("q", "other", "net"), payload)
            transport.toReceive.offer(resp)
            // readFrom must NOT return the dropped packet: run it on a
            // thread and assert it is still waiting after 400 ms.
            var returned: ByteArray? = null
            val t = thread(isDaemon = true) {
                runCatching { returned = conn.readFrom() }
            }
            Thread.sleep(400)
            assertTrue(returned == null, "Paket dari nama asing seharusnya dibuang")
            assertTrue(t.isAlive)
            conn.close()
            t.join(2000)
        } finally {
            conn.close()
        }
    }

    @Test
    fun `idle connection polls with an empty packet`() {
        val transport = FakeTransport()
        val conn = DnsttPacketConn(transport, resolver, domain, DnsWire.TYPE_TXT)
        try {
            // No data written: the poll timer (500 ms) must still send
            // an empty poll query.
            val query = transport.sent.poll(3, TimeUnit.SECONDS)
            assertTrue(query != null, "Tidak ada poll query saat idle")
            val packet = upstreamPacketFromQuery(query!!)
            assertEquals(0, packet.size)
        } finally {
            conn.close()
        }
    }
}
