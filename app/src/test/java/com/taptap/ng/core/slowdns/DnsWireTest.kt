package com.taptap.ng.core.slowdns

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * DnsWire tests (M3). Every test FAILS on a wire format that does not
 * match TB's Go DNSTT implementation, and PASSES on the port.
 */
class DnsWireTest {

    private fun u16(v: Int): ByteArray =
        byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun u32(v: Long): ByteArray = byteArrayOf(
        ((v ushr 24) and 0xFF).toByte(), ((v ushr 16) and 0xFF).toByte(),
        ((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte(),
    )

    private fun writeName(out: MutableList<Byte>, labels: List<String>) {
        for (label in labels) {
            val b = label.toByteArray(Charsets.US_ASCII)
            out.add(b.size.toByte())
            out.addAll(b.toList())
        }
        out.add(0)
    }

    /** Build a minimal DNS response: header + question echo + one answer. */
    private fun buildResponse(
        qnameLabels: List<String>,
        qtype: Int,
        answerNameLabels: List<String>,
        answerType: Int,
        rdata: ByteArray,
        flags: Int = 0x8100,
        anCount: Int = 1,
    ): ByteArray {
        val out = mutableListOf<Byte>()
        out.addAll(u16(0x1234).toList())
        out.addAll(u16(flags).toList())
        out.addAll(u16(1).toList()) // QDCOUNT
        out.addAll(u16(anCount).toList())
        out.addAll(u16(0).toList())
        out.addAll(u16(0).toList())
        writeName(out, qnameLabels)
        out.addAll(u16(qtype).toList())
        out.addAll(u16(1).toList())
        repeat(anCount) {
            writeName(out, answerNameLabels)
            out.addAll(u16(answerType).toList())
            out.addAll(u16(1).toList())
            out.addAll(u32(60).toList())
            out.addAll(u16(rdata.size).toList())
            out.addAll(rdata.toList())
        }
        return out.toByteArray()
    }

    @Test
    fun `buildQuery has RD flag, one question, TXT type and EDNS OPT`() {
        val labels = listOf("abc".toByteArray(), "def".toByteArray())
        val q = DnsWire.buildQuery(0xABCD, labels, DnsWire.TYPE_TXT)
        // Header: ID, flags=0x0100, QD=1, AN=0, NS=0, AR=1.
        assertEquals(0xAB, q[0].toInt() and 0xFF)
        assertEquals(0xCD, q[1].toInt() and 0xFF)
        assertEquals(0x01, q[2].toInt() and 0xFF)
        assertEquals(0x00, q[3].toInt() and 0xFF)
        assertEquals(1, (q[4].toInt() and 0xFF shl 8) or (q[5].toInt() and 0xFF))
        assertEquals(1, (q[10].toInt() and 0xFF shl 8) or (q[11].toInt() and 0xFF))
        // Question name: 3 "abc", 3 "def", 0.
        assertEquals(3, q[12].toInt())
        assertEquals("abc", q.copyOfRange(13, 16).toString(Charsets.US_ASCII))
        assertEquals(3, q[16].toInt())
        assertEquals("def", q.copyOfRange(17, 20).toString(Charsets.US_ASCII))
        assertEquals(0, q[20].toInt())
        // QTYPE=TXT(16), QCLASS=IN(1).
        assertEquals(16, (q[21].toInt() and 0xFF shl 8) or (q[22].toInt() and 0xFF))
        assertEquals(1, (q[23].toInt() and 0xFF shl 8) or (q[24].toInt() and 0xFF))
        // EDNS OPT: root name, type 41, class 4096, TTL 0, rdlen 0.
        assertEquals(0, q[25].toInt())
        assertEquals(41, (q[26].toInt() and 0xFF shl 8) or (q[27].toInt() and 0xFF))
        assertEquals(4096, (q[28].toInt() and 0xFF shl 8) or (q[29].toInt() and 0xFF))
        assertEquals(0, q.size - 36)
    }

    @Test
    fun `buildQuery rejects NULL type mismatch and bad labels`() {
        assertThrows<IllegalArgumentException> {
            DnsWire.buildQuery(1, listOf("a".toByteArray()), 1)
        }
        assertThrows<IllegalArgumentException> {
            DnsWire.buildQuery(1, listOf(ByteArray(64) { 'a'.code.toByte() }), DnsWire.TYPE_TXT)
        }
    }

    @Test
    fun `parseResponse extracts TXT payload`() {
        val payload = byteArrayOf(0, 3) + "abc".toByteArray() + byteArrayOf(0, 2) + "de".toByteArray()
        val rdata = DnsWire.encodeRDataTxt(payload)
        val resp = buildResponse(
            qnameLabels = listOf("x", "example", "com"),
            qtype = DnsWire.TYPE_TXT,
            answerNameLabels = listOf("x", "example", "com"),
            answerType = DnsWire.TYPE_TXT,
            rdata = rdata,
        )
        val parsed = DnsWire.parseResponse(resp, listOf("example", "com"), DnsWire.TYPE_TXT)
        assertNotNull(parsed)
        assertTrue(parsed!!.payload.contentEquals(payload))
        assertEquals(2, DnsWire.splitPackets(parsed.payload).size)
        assertEquals("abc", DnsWire.splitPackets(parsed.payload)[0].toString(Charsets.US_ASCII))
    }

    @Test
    fun `parseResponse extracts NULL raw rdata`() {
        val payload = byteArrayOf(0, 2, 9, 9)
        val resp = buildResponse(
            qnameLabels = listOf("x", "example", "com"),
            qtype = DnsWire.TYPE_NULL,
            answerNameLabels = listOf("x", "example", "com"),
            answerType = DnsWire.TYPE_NULL,
            rdata = payload,
        )
        val parsed = DnsWire.parseResponse(resp, listOf("example", "com"), DnsWire.TYPE_NULL)
        assertNotNull(parsed)
        assertTrue(parsed!!.payload.contentEquals(payload))
    }

    @Test
    fun `parseResponse rejects bad messages`() {
        val good = buildResponse(
            listOf("x", "example", "com"), DnsWire.TYPE_TXT,
            listOf("x", "example", "com"), DnsWire.TYPE_TXT,
            DnsWire.encodeRDataTxt(byteArrayOf(0, 1, 7)),
        )
        // QR=0 (query, not response).
        assertNull(DnsWire.parseResponse(buildResponse(
            listOf("x", "example", "com"), DnsWire.TYPE_TXT,
            listOf("x", "example", "com"), DnsWire.TYPE_TXT,
            DnsWire.encodeRDataTxt(byteArrayOf(0, 1, 7)), flags = 0x0100,
        ), listOf("example", "com"), DnsWire.TYPE_TXT))
        // RCODE != 0.
        assertNull(DnsWire.parseResponse(buildResponse(
            listOf("x", "example", "com"), DnsWire.TYPE_TXT,
            listOf("x", "example", "com"), DnsWire.TYPE_TXT,
            DnsWire.encodeRDataTxt(byteArrayOf(0, 1, 7)), flags = 0x8103,
        ), listOf("example", "com"), DnsWire.TYPE_TXT))
        // Answer name not a subdomain of the tunnel domain.
        assertNull(DnsWire.parseResponse(buildResponse(
            listOf("x", "example", "com"), DnsWire.TYPE_TXT,
            listOf("x", "other", "net"), DnsWire.TYPE_TXT,
            DnsWire.encodeRDataTxt(byteArrayOf(0, 1, 7)),
        ), listOf("example", "com"), DnsWire.TYPE_TXT))
        // Answer type mismatch (NULL expected, TXT given).
        assertNull(DnsWire.parseResponse(good, listOf("example", "com"), DnsWire.TYPE_NULL))
        // Truncated message.
        assertNull(DnsWire.parseResponse(good.copyOf(10), listOf("example", "com"), DnsWire.TYPE_TXT))
    }

    @Test
    fun `parseResponse handles compressed answer names`() {
        // Response where the answer name is a compression pointer to the
        // question name (offset 12). Built by hand.
        val out = mutableListOf<Byte>()
        out.addAll(u16(0x1234).toList())
        out.addAll(u16(0x8100).toList())
        out.addAll(u16(1).toList())
        out.addAll(u16(1).toList())
        out.addAll(u16(0).toList())
        out.addAll(u16(0).toList())
        writeName(out, listOf("x", "example", "com"))
        out.addAll(u16(DnsWire.TYPE_TXT).toList())
        out.addAll(u16(1).toList())
        // Answer name = pointer 0xC00C.
        out.add(0xC0.toByte())
        out.add(12)
        out.addAll(u16(DnsWire.TYPE_TXT).toList())
        out.addAll(u16(1).toList())
        out.addAll(u32(60).toList())
        val rdata = DnsWire.encodeRDataTxt(byteArrayOf(0, 1, 42))
        out.addAll(u16(rdata.size).toList())
        out.addAll(rdata.toList())
        val parsed = DnsWire.parseResponse(out.toByteArray(), listOf("example", "com"), DnsWire.TYPE_TXT)
        assertNotNull(parsed)
        assertEquals(1, DnsWire.splitPackets(parsed!!.payload).size)
        assertEquals(42, DnsWire.splitPackets(parsed.payload)[0][0].toInt())
    }

    @Test
    fun `splitPackets drops truncated tail`() {
        val payload = byteArrayOf(0, 3) + "abc".toByteArray() + byteArrayOf(0, 5, 1, 2)
        val packets = DnsWire.splitPackets(payload)
        assertEquals(1, packets.size)
        assertEquals("abc", packets[0].toString(Charsets.US_ASCII))
    }

    @Test
    fun `upstream packet encode decode round trip`() {
        val clientId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val packet = "hello-dnstt".toByteArray()
        val encoded = DnsWire.encodeUpstreamPacket(packet, clientId, byteArrayOf(9, 9, 9))
        // [clientID 8][0xE3][3 padding][len][packet]
        assertEquals(8 + 1 + 3 + 1 + packet.size, encoded.size)
        assertEquals(0xE3, encoded[8].toInt() and 0xFF)
        assertEquals(packet.size, encoded[12].toInt() and 0xFF)
        val body = encoded.copyOfRange(8, encoded.size)
        val decoded = DnsWire.decodeUpstreamPacket(body)
        assertNotNull(decoded)
        assertTrue(decoded!!.contentEquals(packet))
        // Poll packet (empty): prefix 0xE8 + 8 padding, no length byte.
        val poll = DnsWire.encodeUpstreamPacket(ByteArray(0), clientId, ByteArray(8) { 5 })
        assertEquals(0xE8, poll[8].toInt() and 0xFF)
        assertEquals(0, DnsWire.decodeUpstreamPacket(poll.copyOfRange(8, poll.size))!!.size)
    }

    @Test
    fun `base32 encode decode round trip and known vectors`() {
        // RFC 4648 (without padding, lowercase): "f" -> "my", "foobar" -> "mzxw6ytboi".
        assertEquals("my", Base32.encode("f".toByteArray(Charsets.US_ASCII)))
        assertEquals("mzxw6ytboi", Base32.encode("foobar".toByteArray(Charsets.US_ASCII)))
        assertEquals("", Base32.encode(ByteArray(0)))
        val data = ByteArray(100) { (it * 7 + 3).toByte() }
        assertTrue(Base32.decode(Base32.encode(data)).contentEquals(data))
        assertTrue(Base32.decode("MZXW6YTBOI").contentEquals("foobar".toByteArray(Charsets.US_ASCII)))
    }

    @Test
    fun `txt rdata encode decode round trip`() {
        val data = ByteArray(600) { (it % 251).toByte() }
        val encoded = DnsWire.encodeRDataTxt(data)
        val decoded = DnsWire.decodeRDataTxt(encoded)
        assertNotNull(decoded)
        assertTrue(decoded!!.contentEquals(data))
        assertNull(DnsWire.decodeRDataTxt(ByteArray(0)))
        assertNull(DnsWire.decodeRDataTxt(byteArrayOf(5, 1, 2))) // truncated character-string
    }

    @Test
    fun `parseDomain validates labels`() {
        assertEquals(listOf("dnsv", "sshvpn", "web", "id"), DnsWire.parseDomain("dnsv.sshvpn.web.id"))
        assertEquals(listOf("a", "b"), DnsWire.parseDomain("a.b."))
        assertThrows<IllegalArgumentException> { DnsWire.parseDomain("") }
        assertThrows<IllegalArgumentException> { DnsWire.parseDomain("a..b") }
        assertThrows<IllegalArgumentException> { DnsWire.parseDomain("a_b.com") }
    }

    @Test
    fun `isSubdomainOf matches case-insensitively`() {
        val name = listOf("x".toByteArray(), "Example".toByteArray(), "COM".toByteArray())
        assertTrue(DnsWire.isSubdomainOf(name, listOf("example", "com")))
        assertTrue(!DnsWire.isSubdomainOf(name, listOf("other", "com")))
        assertTrue(!DnsWire.isSubdomainOf(listOf("example".toByteArray()), listOf("example", "com")))
    }
}
