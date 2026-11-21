package com.taptap.ng.core

import java.io.IOException
import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for [DohClient] (v1.0.5, kelompok C). Transport HTTP
 * di-inject sebagai stub in-memory — tanpa jaringan, tanpa socket.
 * Satu-satunya yang dites di sini adalah klien DoH-nya (wire format
 * GET/POST + parse jawaban); transport HTTP aslinya (HttpsURLConnection)
 * hanya jalan di HP.
 */
class DohClientTest {

    private val dohUrl = "https://cloudflare-dns.com/dns-query"

    /** Stub exchange: jawab setiap query dengan A 93.184.216.34. */
    private class StubExchange(
        private val answerIp: String = "93.184.216.34",
        private val fail: Boolean = false,
    ) : DohClient.Exchange {
        var calls = 0
        var lastUrl: String? = null
        var lastQuery: ByteArray? = null
        var lastUseGet: Boolean? = null

        override fun exchange(
            url: String,
            query: ByteArray,
            useGet: Boolean,
            timeoutMs: Int,
        ): ByteArray {
            calls++
            lastUrl = url
            lastQuery = query
            lastUseGet = useGet
            if (fail) throw IOException("stub DoH mati")
            val id = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
            return DnsResolver.buildResponse(
                query,
                listOf(InetAddress.getByName(answerIp)),
            ) ?: throw IOException("stub tidak bisa membangun jawaban (id=$id)")
        }
    }

    @Test
    fun `query POST mengembalikan alamat dari jawaban stub`() {
        val stub = StubExchange()
        val client = DohClient(dohUrl, stub)
        val addrs = client.query("example.com")
        assertEquals(listOf("93.184.216.34"), addrs.map { it.hostAddress })
        assertEquals(1, stub.calls)
        assertEquals(dohUrl, stub.lastUrl)
        assertEquals(false, stub.lastUseGet)
        // Body POST = pesan DNS wire (ID + pertanyaan example.com).
        val sent = stub.lastQuery!!
        assertEquals("example.com", DnsResolver.parseQuery(sent)?.name)
        assertEquals(DnsResolver.TYPE_A, DnsResolver.parseQuery(sent)?.qtype)
    }

    @Test
    fun `queryViaGet memakai URL dns dan query yang sama`() {
        val stub = StubExchange()
        val client = DohClient(dohUrl, stub)
        val addrs = client.queryViaGet("example.com")
        assertEquals(listOf("93.184.216.34"), addrs.map { it.hostAddress })
        assertEquals(1, stub.calls)
        assertEquals(true, stub.lastUseGet)
        assertEquals(dohUrl, stub.lastUrl)
        // URL GET membawa pesan yang sama (base64url, tanpa padding).
        val expected = DohClient.buildGetUrl(dohUrl, stub.lastQuery!!)
        assertTrue(expected.startsWith("$dohUrl?dns="))
        assertFalse(expected.substringAfter("dns=").contains('='))
    }

    @Test
    fun `buildGetUrl memakai ampersand bila basis sudah punya query`() {
        val q = DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_A)
        val url = DohClient.buildGetUrl("https://dns.example/dns-query?x=1", q)
        assertTrue(url.startsWith("https://dns.example/dns-query?x=1&dns="))
        // Base64url hasil decode kembali = query asli.
        val encoded = url.substringAfter("dns=")
        assertTrue(DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_A)
            .contentEquals(Base64Util.decode(encoded)!!))
    }

    @Test
    fun `query AAAA memakai qtype 28`() {
        val stub = StubExchange(answerIp = "2001:db8::1")
        val client = DohClient(dohUrl, stub)
        val addrs = client.query("example.com", DnsResolver.TYPE_AAAA)
        assertEquals(listOf("2001:db8::1"), addrs.map { it.hostAddress })
        assertEquals(DnsResolver.TYPE_AAAA, DnsResolver.parseQuery(stub.lastQuery!!)?.qtype)
    }

    @Test
    fun `query gagal bila exchange melempar`() {
        val stub = StubExchange(fail = true)
        val client = DohClient(dohUrl, stub)
        assertThrows(IOException::class.java) { client.query("example.com") }
    }

    @Test
    fun `query gagal bila jawaban kosong`() {
        val empty = DohClient.Exchange { _, query, _, _ ->
            // Jawaban NOERROR tanpa record.
            val out = mutableListOf<Byte>()
            fun u16(v: Int) {
                out += ((v ushr 8) and 0xFF).toByte()
                out += (v and 0xFF).toByte()
            }
            val id = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
            u16(id); u16(0x8180); u16(1); u16(0); u16(0); u16(0)
            out += query.copyOfRange(12, query.size).toList()
            out.toByteArray()
        }
        val client = DohClient(dohUrl, empty)
        val e = assertThrows(IOException::class.java) { client.query("example.com") }
        assertTrue(e.message!!.contains("tanpa jawaban"), "pesan: ${e.message}")
    }

    @Test
    fun `URL DoH bukan https ditolak`() {
        assertThrows(IllegalArgumentException::class.java) {
            DohClient("http://cloudflare-dns.com/dns-query", StubExchange())
        }
        assertThrows(IllegalArgumentException::class.java) {
            DohClient("https://", StubExchange())
        }
        assertThrows(IllegalArgumentException::class.java) {
            DohClient("cloudflare-dns.com/dns-query", StubExchange())
        }
    }

    @Test
    fun `hostOf mengambil host DoH untuk pengecualian loop`() {
        assertEquals("cloudflare-dns.com", DohClient.hostOf(dohUrl))
        assertEquals("dns.example.org", DohClient.hostOf("https://dns.example.org/dns-query?x=1"))
        assertEquals("dns.example.org", DohClient.hostOf("https://dns.example.org:8443/dns-query"))
        assertNull(DohClient.hostOf("http://cloudflare-dns.com/dns-query"))
        assertNull(DohClient.hostOf("https://"))
    }
}
