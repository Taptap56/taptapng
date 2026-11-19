package com.taptap.x.core

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for [DnsResolver]. Query building / answer parsing run
 * without any network; the end-to-end resolve test talks to a fake
 * DNS server on localhost, so no real internet is needed.
 */
class DnsResolverTest {

    @Test
    fun `buildQuery encodes a standard A query`() {
        val q = DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_A)
        // header 12 + (1+7) + (1+3) + 1 root + 4 QTYPE/QCLASS = 29
        assertEquals(29, q.size)
        assertEquals(0x12, q[0].toInt() and 0xFF)
        assertEquals(0x34, q[1].toInt() and 0xFF)
        assertEquals(0x01, q[2].toInt() and 0xFF) // RD=1
        assertEquals(0x00, q[3].toInt() and 0xFF)
        assertEquals(1, (q[4].toInt() and 0xFF shl 8) or (q[5].toInt() and 0xFF)) // QDCOUNT
        // QNAME: 7 "example", 3 "com", 0
        assertEquals(7, q[12].toInt() and 0xFF)
        assertEquals("example", String(q, 13, 7, Charsets.US_ASCII))
        assertEquals(3, q[20].toInt() and 0xFF)
        assertEquals("com", String(q, 21, 3, Charsets.US_ASCII))
        assertEquals(0, q[24].toInt() and 0xFF)
        assertEquals(1, (q[25].toInt() and 0xFF shl 8) or (q[26].toInt() and 0xFF)) // QTYPE A
        assertEquals(1, (q[27].toInt() and 0xFF shl 8) or (q[28].toInt() and 0xFF)) // QCLASS IN
    }

    @Test
    fun `buildQuery encodes AAAA type`() {
        val q = DnsResolver.buildQuery("example.com", 1, DnsResolver.TYPE_AAAA)
        assertEquals(28, (q[25].toInt() and 0xFF shl 8) or (q[26].toInt() and 0xFF))
    }

    /** Hand-built response: question echo + A + AAAA, names compressed (0xC00C). */
    private fun cannedResponse(id: Int, anCount: Int = 2, flags: Int = 0x8180): ByteArray {
        val out = mutableListOf<Byte>()
        fun u16(v: Int) {
            out += ((v ushr 8) and 0xFF).toByte()
            out += (v and 0xFF).toByte()
        }
        fun u32(v: Long) {
            out += ((v ushr 24) and 0xFF).toByte()
            out += ((v ushr 16) and 0xFF).toByte()
            out += ((v ushr 8) and 0xFF).toByte()
            out += (v and 0xFF).toByte()
        }
        u16(id); u16(flags); u16(1); u16(anCount); u16(0); u16(0)
        // Question: example.com, A, IN
        out += 7.toByte()
        out += "example".toByteArray(Charsets.US_ASCII).toList()
        out += 3.toByte()
        out += "com".toByteArray(Charsets.US_ASCII).toList()
        out += 0.toByte()
        u16(1); u16(1)
        if (anCount >= 1) {
            // A 93.184.216.34, nama = pointer ke offset 12 (0xC00C)
            out += 0xC0.toByte(); out += 0x0C.toByte()
            u16(1); u16(1); u32(60); u16(4)
            out += listOf(93.toByte(), 184.toByte(), 216.toByte(), 34.toByte())
        }
        if (anCount >= 2) {
            // AAAA ::1
            out += 0xC0.toByte(); out += 0x0C.toByte()
            u16(28); u16(1); u32(60); u16(16)
            out += ByteArray(15).toList() + listOf(1.toByte())
        }
        return out.toByteArray()
    }

    @Test
    fun `parseAnswers reads A and AAAA with compressed names, A first`() {
        val addrs = DnsResolver.parseAnswers(cannedResponse(0x1234), 0x1234)
        assertEquals(2, addrs.size)
        assertEquals("93.184.216.34", addrs[0].hostAddress)
        assertEquals("0:0:0:0:0:0:0:1", addrs[1].hostAddress)
    }

    @Test
    fun `parseAnswers rejects wrong id, non-response and truncation`() {
        assertTrue(DnsResolver.parseAnswers(cannedResponse(0x1234), 0x9999).isEmpty())
        assertTrue(DnsResolver.parseAnswers(cannedResponse(0x1234, flags = 0x0100), 0x1234).isEmpty())
        assertTrue(DnsResolver.parseAnswers(cannedResponse(0x1234).copyOf(10), 0x1234).isEmpty())
        assertTrue(DnsResolver.parseAnswers(cannedResponse(0x1234, anCount = 0), 0x1234).isEmpty())
        assertTrue(DnsResolver.parseAnswers(ByteArray(0)).isEmpty())
    }

    @Test
    fun `resolve answers from a fake local DNS server`() {
        // Server DNS palsu: jawab setiap query dengan A 93.184.216.34,
        // echo pertanyaan + ID dari query.
        val server = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val running = AtomicBoolean(true)
        val serverThread = Thread {
            val buf = ByteArray(2048)
            while (running.get()) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    server.receive(pkt)
                    val query = pkt.data.copyOf(pkt.length)
                    val id = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
                    val question = query.copyOfRange(12, query.size)
                    // Bangun jawaban dengan ID + question dari query asli.
                    val out = mutableListOf<Byte>()
                    fun u16(v: Int) {
                        out += ((v ushr 8) and 0xFF).toByte()
                        out += (v and 0xFF).toByte()
                    }
                    fun u32(v: Long) {
                        out += ((v ushr 24) and 0xFF).toByte()
                        out += ((v ushr 16) and 0xFF).toByte()
                        out += ((v ushr 8) and 0xFF).toByte()
                        out += (v and 0xFF).toByte()
                    }
                    u16(id); u16(0x8180); u16(1); u16(1); u16(0); u16(0)
                    out += question.toList()
                    out += 0xC0.toByte(); out += 0x0C.toByte()
                    u16(1); u16(1); u32(60); u16(4)
                    out += listOf(93.toByte(), 184.toByte(), 216.toByte(), 34.toByte())
                    val bytes = out.toByteArray()
                    server.send(DatagramPacket(bytes, bytes.size, pkt.address, pkt.port))
                } catch (_: Exception) {
                    if (!running.get()) return@Thread
                }
            }
        }.apply { isDaemon = true; start() }
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        try {
            DnsResolver.dnsServer = "127.0.0.1"
            DnsResolver.dnsPort = server.localPort
            val addr = DnsResolver.resolve("example.com", timeoutMs = 2000)
            assertEquals("93.184.216.34", addr.hostAddress)
        } finally {
            DnsResolver.dnsServer = oldServer
            DnsResolver.dnsPort = oldPort
            running.set(false)
            server.close()
            serverThread.join(1000)
        }
    }

    @Test
    fun `resolve returns IP literals without any network`() {
        // Server DNS diarahkan ke port mati: bila literal ikut lookup,
        // tes ini akan timeout — membuktikan literal tidak lookup.
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        try {
            DnsResolver.dnsServer = "127.0.0.1"
            DnsResolver.dnsPort = 1
            assertEquals("127.0.0.1", DnsResolver.resolve("127.0.0.1").hostAddress)
        } finally {
            DnsResolver.dnsServer = oldServer
            DnsResolver.dnsPort = oldPort
        }
    }

    @Test
    fun `resolve times out with a clear message when the server stays silent`() {
        // Socket ter-bind tapi tidak pernah membaca: paket masuk
        // antrean kernel, tidak ada balasan — receive harus timeout.
        val silent = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        try {
            DnsResolver.dnsServer = "127.0.0.1"
            DnsResolver.dnsPort = silent.localPort
            val start = System.nanoTime()
            val e = assertThrows(IOException::class.java) {
                DnsResolver.resolve("example.com", timeoutMs = 500)
            }
            val elapsedMs = (System.nanoTime() - start) / 1_000_000
            assertTrue(e.message!!.contains("timeout"), "pesan: ${e.message}")
            assertTrue(e.message!!.contains("example.com"), "pesan: ${e.message}")
            assertTrue(elapsedMs < 5000, "resolve menggantung $elapsedMs ms")
        } finally {
            DnsResolver.dnsServer = oldServer
            DnsResolver.dnsPort = oldPort
            silent.close()
        }
    }

    @Test
    fun `resolveWithSystemFallback fails fast on an unresolvable host`() {
        val start = System.nanoTime()
        assertThrows(IOException::class.java) {
            DnsResolver.resolveWithSystemFallback("tidak-ada.invalid", 443, timeoutMs = 500)
        }
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertTrue(elapsedMs < 10_000, "fallback menggantung $elapsedMs ms")
    }
}
