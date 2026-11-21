package com.taptap.ng

import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.SpeedStats
import com.taptap.ng.service.SocksConfig
import com.taptap.ng.service.SocksConnection
import com.taptap.ng.service.SocksListener
import com.taptap.ng.service.SocksServer
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.InetAddress
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.5 (kelompok B): SOCKS5 lokal in-app. Semua tes in-memory —
 * handler dijalankan di atas pipe pair, tanpa socket loopback
 * (Gradle diblokir di VM dan loopback JVM di-intercept; loopback
 * jalan normal di CI). Tes ini gagal pada kode tanpa SocksServer
 * (tidak ada handler / config / listener sama sekali).
 */
class SocksServerTest {

    // ---- Stub upstream (ProxyClient) ----

    private class StubStream(
        override val input: InputStream,
        override val output: OutputStream,
        /**
         * Sisi TULIS dari pipe [input]: menutupnya yang membangunkan
         * read yang sedang blok di sisi baca. PipedInputStream.close()
         * di sisi baca TIDAK membangunkan read yang macet (beda dengan
         * Socket.close() di produksi, yang membangunkan) — tanpa ini
         * relay thread tidak pernah selesai dan handler menggantung.
         */
        private val inputWriteSide: OutputStream? = null,
    ) : ProxyStream {
        override fun close() {
            runCatching { inputWriteSide?.close() }
            runCatching { input.close() }
            runCatching { output.close() }
        }
    }

    private class StubProxy(
        var failDial: Boolean = false,
    ) : ProxyClient {
        val dialed = mutableListOf<Pair<String, Int>>()
        /** Byte yang diteruskan server ke upstream. */
        val received = ByteArrayOutputStream()
        /** Test menulis ke sini = data dari upstream ke klien. */
        val feedOut = PipedOutputStream()
        val feedIn = PipedInputStream(feedOut, 8192)

        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream {
            if (failDial) throw IOException("dial gagal")
            dialed += targetHost to targetPort
            return StubStream(feedIn, received, feedOut)
        }

        override fun close() = Unit
    }

    // ---- Harness klien <-> handler (pipe pair) ----

    private class Harness(
        config: SocksConfig = SocksConfig(),
        proxy: ProxyClient,
    ) {
        val server = SocksServer(config, { h, p -> proxy.dial(h, p) })
        private val clientOut = PipedOutputStream()
        private val serverIn = PipedInputStream(clientOut, 8192)
        private val serverOut = PipedOutputStream()
        private val clientIn = PipedInputStream(serverOut, 8192)

        val handlerThread = thread(name = "socks-test-handler", isDaemon = true) {
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

        fun writeText(text: String) = write(text.toByteArray(Charsets.US_ASCII))

        fun readByte(): Int = clientIn.read()

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

        fun readText(n: Int): String = readExact(n).toString(Charsets.US_ASCII)

        fun available(): Int = clientIn.available()

        fun closeClient() {
            runCatching { clientOut.close() }
        }

        fun joinHandler(timeoutMs: Long = 5000) {
            handlerThread.join(timeoutMs)
            assertFalse(handlerThread.isAlive, "handler tidak selesai sesudah klien tutup")
        }
    }

    /** Greeting + CONNECT domain, tanpa auth. Mengembalikan byte balasan CONNECT. */
    private fun Harness.connectDomain(
        host: String = "example.com",
        port: Int = 80,
    ): ByteArray {
        write(0x05, 0x01, 0x00)
        assertEquals(byteArrayOf(0x05, 0x00).toList(), readExact(2).toList())
        return connectRequest(host, port)
    }

    /** Hanya request CONNECT (dipakai sesudah auth — greeting sudah terkirim). */
    private fun Harness.connectRequest(
        host: String = "example.com",
        port: Int = 80,
    ): ByteArray {
        val hostBytes = host.toByteArray(Charsets.UTF_8)
        val req = ByteArrayOutputStream().apply {
            write(0x05); write(0x01); write(0x00); write(0x03)
            write(hostBytes.size); write(hostBytes)
            write((port shr 8) and 0xFF); write(port and 0xFF)
        }
        write(req.toByteArray())
        return readExact(10)
    }

    private fun pollUntil(timeoutMs: Long = 2000, cond: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (!cond()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError("kondisi tak tercapai")
            Thread.sleep(10)
        }
    }

    // ---- Handshake + CONNECT ----

    @Test
    fun `handshake tanpa auth lalu CONNECT meneruskan byte dua arah`() {
        val proxy = StubProxy()
        val h = Harness(proxy = proxy)
        val reply = h.connectDomain("example.com", 80)
        assertEquals(0x00, reply[1].toInt() and 0xFF)
        assertEquals(listOf("example.com" to 80), proxy.dialed)
        h.writeText("hello")
        pollUntil { proxy.received.size() == 5 }
        assertEquals("hello", proxy.received.toString(Charsets.UTF_8.name()))
        proxy.feedOut.write("world".toByteArray(Charsets.UTF_8))
        proxy.feedOut.flush()
        assertEquals("world", h.readText(5))
        h.closeClient()
        h.joinHandler()
    }

    @Test
    fun `auth benar diterima lalu CONNECT jalan`() {
        val proxy = StubProxy()
        val h = Harness(
            config = SocksConfig(socksUsername = "user", socksPassword = "pass"),
            proxy = proxy,
        )
        h.write(0x05, 0x01, 0x02)
        assertEquals(byteArrayOf(0x05, 0x02).toList(), h.readExact(2).toList())
        val user = "user".toByteArray(Charsets.UTF_8)
        val pass = "pass".toByteArray(Charsets.UTF_8)
        val sub = ByteArrayOutputStream().apply {
            write(0x01); write(user.size); write(user); write(pass.size); write(pass)
        }
        h.write(sub.toByteArray())
        assertEquals(byteArrayOf(0x01, 0x00).toList(), h.readExact(2).toList())
        val reply = h.connectRequest("example.com", 443)
        assertEquals(0x00, reply[1].toInt() and 0xFF)
        h.closeClient()
        h.joinHandler()
    }

    @Test
    fun `auth salah ditolak dan koneksi ditutup`() {
        val proxy = StubProxy()
        val h = Harness(
            config = SocksConfig(socksUsername = "user", socksPassword = "pass"),
            proxy = proxy,
        )
        h.write(0x05, 0x01, 0x02)
        assertEquals(byteArrayOf(0x05, 0x02).toList(), h.readExact(2).toList())
        val user = "user".toByteArray(Charsets.UTF_8)
        val wrong = "salah".toByteArray(Charsets.UTF_8)
        val sub = ByteArrayOutputStream().apply {
            write(0x01); write(user.size); write(user); write(wrong.size); write(wrong)
        }
        h.write(sub.toByteArray())
        assertEquals(byteArrayOf(0x01, 0x01).toList(), h.readExact(2).toList())
        assertTrue(proxy.dialed.isEmpty())
        h.joinHandler()
    }

    @Test
    fun `auth wajib tapi klien hanya tawar no-auth ditolak 0xFF`() {
        val proxy = StubProxy()
        val h = Harness(
            config = SocksConfig(socksUsername = "user", socksPassword = "pass"),
            proxy = proxy,
        )
        h.write(0x05, 0x01, 0x00)
        assertEquals(byteArrayOf(0x05, 0xFF.toByte()).toList(), h.readExact(2).toList())
        assertTrue(proxy.dialed.isEmpty())
        h.joinHandler()
    }

    @Test
    fun `tanpa auth klien tawar userpass saja ditolak 0xFF`() {
        val proxy = StubProxy()
        val h = Harness(proxy = proxy)
        h.write(0x05, 0x01, 0x02)
        assertEquals(byteArrayOf(0x05, 0xFF.toByte()).toList(), h.readExact(2).toList())
        h.joinHandler()
    }

    @Test
    fun `dial gagal dibalas REP 5 dan tidak ada relay`() {
        val proxy = StubProxy(failDial = true)
        val h = Harness(proxy = proxy)
        val reply = h.connectDomain("example.com", 80)
        assertEquals(0x05, reply[1].toInt() and 0xFF)
        h.joinHandler()
    }

    @Test
    fun `UDP ASSOCIATE ditolak dengan REP 7`() {
        val proxy = StubProxy()
        val h = Harness(proxy = proxy)
        h.write(0x05, 0x01, 0x00)
        assertEquals(byteArrayOf(0x05, 0x00).toList(), h.readExact(2).toList())
        // CMD=0x03 UDP ASSOCIATE, ATYP IPv4 0.0.0.0:0
        h.write(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
        val reply = h.readExact(10)
        assertEquals(0x07, reply[1].toInt() and 0xFF)
        assertTrue(proxy.dialed.isEmpty(), "UDP tidak boleh dial — tidak ada jalur UDP di M2")
        h.joinHandler()
    }

    @Test
    fun `BIND ditolak dengan REP 7`() {
        val proxy = StubProxy()
        val h = Harness(proxy = proxy)
        h.write(0x05, 0x01, 0x00)
        assertEquals(byteArrayOf(0x05, 0x00).toList(), h.readExact(2).toList())
        h.write(0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
        val reply = h.readExact(10)
        assertEquals(0x07, reply[1].toInt() and 0xFF)
        h.joinHandler()
    }

    // ---- HTTP CONNECT (appendHttpProxy, listener yang sama) ----

    @Test
    fun `HTTP CONNECT meneruskan byte dua arah`() {
        val proxy = StubProxy()
        val h = Harness(config = SocksConfig(appendHttpProxy = true), proxy = proxy)
        h.writeText("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        val head = h.readText("HTTP/1.1 200 Connection Established\r\n\r\n".length)
        assertEquals("HTTP/1.1 200 Connection Established\r\n\r\n", head)
        assertEquals(listOf("example.com" to 443), proxy.dialed)
        h.writeText("hello")
        pollUntil { proxy.received.size() == 5 }
        proxy.feedOut.write("world".toByteArray(Charsets.UTF_8))
        proxy.feedOut.flush()
        assertEquals("world", h.readText(5))
        h.closeClient()
        h.joinHandler()
    }

    @Test
    fun `HTTP CONNECT tanpa auth saat auth wajib ditolak 407`() {
        val proxy = StubProxy()
        val h = Harness(
            config = SocksConfig(
                socksUsername = "user",
                socksPassword = "pass",
                appendHttpProxy = true,
            ),
            proxy = proxy,
        )
        h.writeText("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        val head = h.readText("HTTP/1.1 407 Proxy Authentication Required\r\n".length)
        assertTrue(head.startsWith("HTTP/1.1 407"))
        assertTrue(proxy.dialed.isEmpty())
        h.joinHandler()
    }

    @Test
    fun `HTTP CONNECT ditutup tanpa balasan bila appendHttpProxy mati`() {
        val proxy = StubProxy()
        val h = Harness(config = SocksConfig(appendHttpProxy = false), proxy = proxy)
        h.writeText("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        h.joinHandler()
        assertEquals(0, h.available())
        assertTrue(proxy.dialed.isEmpty())
    }

    // ---- Resolusi config murni ----

    @Test
    fun `bind address mengikuti proxySharing dan lanSharing`() {
        assertEquals("127.0.0.1", SocksConfig().bindAddress().hostAddress)
        assertEquals("0.0.0.0", SocksConfig(proxySharing = true).bindAddress().hostAddress)
        assertEquals("0.0.0.0", SocksConfig(lanSharing = true).bindAddress().hostAddress)
    }

    @Test
    fun `port statis kosong atau rusak pakai 10808`() {
        assertEquals(10808, SocksConfig(socksPort = "").requestedPort())
        assertEquals(10808, SocksConfig(socksPort = "abc").requestedPort())
        assertEquals(10808, SocksConfig(socksPort = "0").requestedPort())
        assertEquals(10808, SocksConfig(socksPort = "70000").requestedPort())
        assertEquals(10809, SocksConfig(socksPort = "10809").requestedPort())
    }

    @Test
    fun `dynamic port minta 0 ke OS`() {
        assertEquals(0, SocksConfig(dynamicSocksPort = true, socksPort = "10809").requestedPort())
    }

    @Test
    fun `auth hanya wajib bila username dan password sama-sama terisi`() {
        assertFalse(SocksConfig().requireAuth)
        assertFalse(SocksConfig(socksUsername = "user").requireAuth)
        assertFalse(SocksConfig(socksPassword = "pass").requireAuth)
        assertTrue(SocksConfig(socksUsername = "user", socksPassword = "pass").requireAuth)
    }

    // ---- Lifecycle start/stop dengan listener fake ----

    private class FakeListener(
        override val localAddress: InetAddress,
        val requestedPort: Int,
        private val fixedPort: Int = 54321,
    ) : SocksListener {
        override val localPort: Int get() = fixedPort
        var closed = false
        private val lock = Object()

        override fun accept(): SocksConnection {
            synchronized(lock) { lock.wait() }
            throw IOException("listener ditutup")
        }

        override fun close() {
            closed = true
            synchronized(lock) { lock.notifyAll() }
        }
    }

    @Test
    fun `start dynamic melaporkan port pilihan dan stop menutup listener`() {
        var seenAddr: InetAddress? = null
        var seenPort: Int? = null
        var fake: FakeListener? = null
        val server = SocksServer(
            config = SocksConfig(dynamicSocksPort = true),
            dial = { _, _ -> throw IOException("tidak dipakai") },
            listenerFactory = { addr, port ->
                seenAddr = addr
                seenPort = port
                FakeListener(addr, port).also { fake = it }
            },
        )
        server.start()
        assertEquals("127.0.0.1", seenAddr?.hostAddress)
        assertEquals(0, seenPort)
        assertEquals(54321, server.actualPort)
        assertTrue(server.isRunning)
        server.stop()
        assertFalse(server.isRunning)
        assertTrue(fake?.closed == true)
    }

    @Test
    fun `start dengan proxySharing bind 0_0_0_0`() {
        var seenAddr: InetAddress? = null
        val server = SocksServer(
            config = SocksConfig(proxySharing = true, socksPort = "10808"),
            dial = { _, _ -> throw IOException("tidak dipakai") },
            listenerFactory = { addr, port ->
                seenAddr = addr
                FakeListener(addr, port)
            },
        )
        server.start()
        assertEquals("0.0.0.0", seenAddr?.hostAddress)
        assertEquals(54321, server.actualPort)
        server.stop()
    }
}
