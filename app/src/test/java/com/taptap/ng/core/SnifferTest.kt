package com.taptap.ng.core

import java.io.ByteArrayOutputStream
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SnifferTest {

    /** Minimal well-formed TLS ClientHello carrying SNI `host`. */
    private fun clientHello(host: String, includeSni: Boolean = true): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val exts = ByteArrayOutputStream()
        if (includeSni) {
            val sniList = ByteArrayOutputStream()
            sniList.write(0)
            sniList.write(hostBytes.size shr 8)
            sniList.write(hostBytes.size and 0xFF)
            sniList.write(hostBytes)
            val sniListBytes = sniList.toByteArray()
            val sniBody = ByteArrayOutputStream()
            sniBody.write(sniListBytes.size shr 8)
            sniBody.write(sniListBytes.size and 0xFF)
            sniBody.write(sniListBytes)
            val sniBodyBytes = sniBody.toByteArray()
            exts.write(0)
            exts.write(0) // extension type server_name
            exts.write(sniBodyBytes.size shr 8)
            exts.write(sniBodyBytes.size and 0xFF)
            exts.write(sniBodyBytes)
        }
        // A second extension after SNI (ALPN-like) — the parser must skip it.
        exts.write(0x00)
        exts.write(0x10)
        exts.write(0)
        exts.write(2)
        exts.write(0)
        exts.write(0)
        val extBytes = exts.toByteArray()

        val body = ByteArrayOutputStream()
        body.write(0x03)
        body.write(0x03) // TLS 1.2
        body.write(ByteArray(32)) // random
        body.write(0) // session id len
        body.write(0)
        body.write(2) // cipher suites len
        body.write(0x13)
        body.write(0x01)
        body.write(1) // compression len
        body.write(0) // null compression
        body.write(extBytes.size shr 8)
        body.write(extBytes.size and 0xFF)
        body.write(extBytes)
        val bodyBytes = body.toByteArray()

        val hs = ByteArrayOutputStream()
        hs.write(0x01) // ClientHello
        hs.write(bodyBytes.size shr 16)
        hs.write(bodyBytes.size shr 8)
        hs.write(bodyBytes.size and 0xFF)
        hs.write(bodyBytes)
        val hsBytes = hs.toByteArray()

        val rec = ByteArrayOutputStream()
        rec.write(0x16) // handshake record
        rec.write(0x03)
        rec.write(0x01)
        rec.write(hsBytes.size shr 8)
        rec.write(hsBytes.size and 0xFF)
        rec.write(hsBytes)
        return rec.toByteArray()
    }

    @Test
    fun `sni extracted from a minimal client hello`() {
        assertEquals("example.com", Sniffer.extractSni(clientHello("example.com")))
    }

    @Test
    fun `extract prefers sni over http host`() {
        val found = Sniffer.extract(clientHello("tls.example.com"))
        assertEquals("tls.example.com", found?.host)
        assertEquals(Sniffer.Kind.TLS_SNI, found?.kind)
    }

    @Test
    fun `client hello without sni returns null`() {
        assertNull(Sniffer.extractSni(clientHello("example.com", includeSni = false)))
    }

    @Test
    fun `truncated client hello returns null instead of throwing`() {
        val full = clientHello("example.com")
        assertNull(Sniffer.extractSni(full.copyOf(full.size / 2)))
        assertNull(Sniffer.extractSni(full.copyOf(4)))
        assertNull(Sniffer.extractSni(ByteArray(0)))
    }

    @Test
    fun `non tls bytes do not parse as sni`() {
        assertNull(Sniffer.extractSni("GET / HTTP/1.1\r\nHost: x\r\n\r\n".toByteArray()))
        assertNull(Sniffer.extractSni(ByteArray(64) { 0x42 }))
        // ServerHello (handshake type 0x02) is not a ClientHello.
        val hello = clientHello("example.com")
        hello[5] = 0x02
        assertNull(Sniffer.extractSni(hello))
    }

    @Test
    fun `http host extracted from get request`() {
        val req = "GET /index HTTP/1.1\r\nHost: Example.COM:8080\r\nUser-Agent: t\r\n\r\n"
        assertEquals("example.com", Sniffer.extractHttpHost(req.toByteArray(Charsets.US_ASCII)))
        val found = Sniffer.extract(req.toByteArray(Charsets.US_ASCII))
        assertEquals("example.com", found?.host)
        assertEquals(Sniffer.Kind.HTTP_HOST, found?.kind)
    }

    @Test
    fun `http host header is case insensitive and post works too`() {
        val req = "POST /x HTTP/1.1\r\nhOsT: api.example.org\r\nContent-Length: 0\r\n\r\n"
        assertEquals("api.example.org", Sniffer.extractHttpHost(req.toByteArray(Charsets.US_ASCII)))
    }

    @Test
    fun `http without host or with unknown method returns null`() {
        assertNull(
            Sniffer.extractHttpHost(
                "GET / HTTP/1.1\r\nUser-Agent: t\r\n\r\n".toByteArray(Charsets.US_ASCII),
            ),
        )
        assertNull(
            Sniffer.extractHttpHost(
                "BOGUS / HTTP/1.1\r\nHost: x.example\r\n\r\n".toByteArray(Charsets.US_ASCII),
            ),
        )
        assertNull(Sniffer.extractHttpHost("not http at all".toByteArray(Charsets.US_ASCII)))
    }

    @Test
    fun `dns query name parsed from a built query`() {
        val query = DnsResolver.buildQuery("www.example.com", 0x1234, DnsResolver.TYPE_A)
        assertEquals("www.example.com", Sniffer.parseDnsQueryName(query))
        assertNull(Sniffer.parseDnsQueryName(ByteArray(0)))
        assertNull(Sniffer.parseDnsQueryName(ByteArray(20)))
    }

    @Test
    fun `ipv4 to int round trips through the forwarder key`() {
        val addr = java.net.InetAddress.getByName("1.2.3.4")
        assertEquals(0x01020304, Sniffer.ipv4ToInt(addr))
        assertNull(Sniffer.ipv4ToInt(java.net.InetAddress.getByName("::1")))
    }
}
