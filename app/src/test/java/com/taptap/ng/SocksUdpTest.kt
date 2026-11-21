package com.taptap.ng

import com.taptap.ng.core.proto.ProxyUdpSession
import com.taptap.ng.service.SocksConfig
import com.taptap.ng.service.SocksServer
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.6 (M6): SOCKS5 UDP ASSOCIATE beneran — balasan sukses +
 * datagram diteruskan lewat [ProxyUdpSession] dan kembali ke klien.
 * Tanpa dialUdp (SSH) atau bila setting OFF, tetap REP 0x07.
 */
@Timeout(30)
class SocksUdpTest {

    private class EchoUdpSession : ProxyUdpSession {
        val sent = LinkedBlockingQueue<ByteArray>()
        private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

        override fun send(datagram: ByteArray) {
            sent.add(datagram)
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

    private class Harness(
        config: SocksConfig = SocksConfig(),
        dialUdp: ((String, Int) -> ProxyUdpSession)? = null,
    ) {
        val udpDialed = mutableListOf<Pair<String, Int>>()
        val server = SocksServer(
            config,
            { _, _ -> throw UnsupportedOperationException("tes ini hanya UDP") },
            dialUdp = dialUdp?.let { fn ->
                { h: String, p: Int ->
                    udpDialed += h to p
                    fn(h, p)
                }
            },
        )
        private val clientOut = PipedOutputStream()
        private val serverIn = PipedInputStream(clientOut, 8192)
        private val serverOut = PipedOutputStream()
        private val clientIn = PipedInputStream(serverOut, 8192)
        val handlerThread = thread(name = "socks-udp-test-handler", isDaemon = true) {
            runCatching { server.handleConnection(serverIn, serverOut) }
        }

        fun write(vararg bytes: Int) {
            clientOut.write(bytes.map { it.toByte() }.toByteArray())
            clientOut.flush()
        }

        fun write(bytes: ByteArray) {
            clientOut.write(bytes)
            clientOut.flush()
        }

        fun readExact(n: Int): ByteArray {
            val out = ByteArray(n)
            var filled = 0
            while (filled < n) {
                val r = clientIn.read(out, filled, n - filled)
                if (r == -1) throw java.io.EOFException("klien EOF, dapat $filled dari $n")
                filled += r
            }
            return out
        }

        fun closeClient() {
            runCatching { clientOut.close() }
        }

        fun joinHandler(timeoutMs: Long = 5000) {
            handlerThread.join(timeoutMs)
            assertFalse(handlerThread.isAlive, "handler tidak selesai sesudah klien tutup")
        }
    }

    /** Greeting tanpa auth + request UDP ASSOCIATE. Mengembalikan balasan 10 byte. */
    private fun Harness.associate(): ByteArray {
        write(0x05, 0x01, 0x00)
        assertEquals(byteArrayOf(0x05, 0x00).toList(), readExact(2).toList())
        write(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
        return readExact(10)
    }

    @Test
    fun `ASSOCIATE diterima dan datagram di-echo`() {
        val h = Harness(dialUdp = { _, _ -> EchoUdpSession() })
        val reply = h.associate()
        assertEquals(0x00, reply[1].toInt() and 0xFF)
        val bndPort = ((reply[8].toInt() and 0xFF) shl 8) or (reply[9].toInt() and 0xFF)
        assertTrue(bndPort > 0, "BND port harus terisi, dapat $bndPort")
        // Kirim datagram SOCKS UDP ke listener: RSV/FRAG/ATYP IPv4 8.8.8.8:53 + payload.
        val payload = "socks-udp-ping".toByteArray()
        val packet = ByteArrayOutputStream().apply {
            write(0); write(0); write(0); write(0x01)
            write(8); write(8); write(8); write(8)
            write(0); write(53)
            write(payload)
        }.toByteArray()
        val sock = DatagramSocket()
        try {
            sock.soTimeout = 5000
            sock.send(
                DatagramPacket(packet, packet.size, InetAddress.getByName("127.0.0.1"), bndPort),
            )
            val buf = ByteArray(65535)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            val parsed = h.server.parseSocksUdpPacket(resp.data, resp.length)
                ?: throw AssertionError("balasan SOCKS UDP tidak ter-parse")
            assertEquals("8.8.8.8", parsed.first)
            assertEquals(53, parsed.second)
            assertArrayEquals(payload, parsed.third)
            assertEquals(listOf("8.8.8.8" to 53), h.udpDialed)
        } finally {
            runCatching { sock.close() }
            h.closeClient()
            h.joinHandler()
        }
    }

    @Test
    fun `ASSOCIATE ditolak 0x07 bila dialUdp null (entry tanpa UDP)`() {
        val h = Harness(dialUdp = null)
        val reply = h.associate()
        assertEquals(0x07, reply[1].toInt() and 0xFF)
        h.joinHandler()
    }

    @Test
    fun `ASSOCIATE ditolak 0x07 bila setting socksEnableUdp OFF`() {
        val h = Harness(
            config = SocksConfig(socksEnableUdp = false),
            dialUdp = { _, _ -> EchoUdpSession() },
        )
        val reply = h.associate()
        assertEquals(0x07, reply[1].toInt() and 0xFF)
        assertTrue(h.udpDialed.isEmpty())
        h.joinHandler()
    }

    @Test
    fun `parse dan wrap paket SOCKS UDP round trip`() {
        val server = SocksServer(SocksConfig(), { _, _ -> throw UnsupportedOperationException() })
        val payload = "abc".toByteArray()
        val wrapped = server.wrapSocksUdpPacket("example.com", 443, payload)
        val parsed = server.parseSocksUdpPacket(wrapped, wrapped.size)!!
        assertEquals("example.com", parsed.first)
        assertEquals(443, parsed.second)
        assertArrayEquals(payload, parsed.third)
        // FRAG != 0 ditolak.
        val fragged = wrapped.copyOf().also { it[2] = 1 }
        assertEquals(null, server.parseSocksUdpPacket(fragged, fragged.size))
    }
}
