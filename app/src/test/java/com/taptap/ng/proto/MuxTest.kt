package com.taptap.ng.proto

import com.taptap.ng.core.proto.*
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * Mux in-app vs stub server in-memory (v1.0.5, kelompok D).
 *
 * Transport in-memory (Piped streams, BUKAN loopback socket —
 * loopback JVM di-intercept di VM ini). Stub server di sini
 * mengimplementasikan framing mux SECARA INDEPENDEN (rakit/urai
 * byte manual, TIDAK memakai [Mux.encodeMeta]/[Mux.decodeMeta])
 * supaya bug di codec produksi tidak lolos karena kedua sisi
 * memakai kode yang sama salahnya. Satu-satunya yang dibagi
 * adalah [AddrCodec] (format address VMess/VLESS yang sama).
 */
class MuxTest {

    // ---- frame codec: byte-exact vs spesifikasi xray-core ----

    @Test
    fun `frame new domain byte-exact sesuai frame dot go`() {
        // meta = sid(2) + status(1) + option(1) + network(1) +
        // port(2) + atyp(1) + len(1) + "example.com"(11) = 20 byte.
        val expected = byteArrayOf(
            0x00, 0x14, // metaLen = 20
            0x00, 0x01, // session id 1
            0x01, // New
            0x01, // OptionData
            0x01, // TCP
            0x01, 0xBB.toByte(), // port 443
            0x02, 0x0B, // domain, len 11
        ) + "example.com".toByteArray(Charsets.UTF_8)
        assertArrayEquals(
            expected,
            Mux.encodeMeta(1, Mux.STATUS_NEW, Mux.OPTION_DATA, "example.com", 443),
        )
        val meta = Mux.decodeMeta(expected.inputStream())
        assertEquals(1, meta.sessionId)
        assertEquals(Mux.STATUS_NEW, meta.status)
        assertEquals(Mux.OPTION_DATA, meta.option)
        assertEquals("example.com", meta.target?.host)
        assertEquals(443, meta.target?.port)
        assertEquals(Mux.TARGET_NETWORK_TCP, meta.targetNetwork)
    }

    @Test
    fun `frame keep tanpa target byte-exact`() {
        val expected = byteArrayOf(
            0x00, 0x04, // metaLen = 4
            0x01, 0x02, // session id 0x0102
            0x02, // Keep
            0x01, // OptionData
        )
        assertArrayEquals(expected, Mux.encodeMeta(0x0102, Mux.STATUS_KEEP, Mux.OPTION_DATA))
        val meta = Mux.decodeMeta(expected.inputStream())
        assertEquals(0x0102, meta.sessionId)
        assertEquals(Mux.STATUS_KEEP, meta.status)
        assertNull(meta.target)
    }

    @Test
    fun `frame new ipv4 dan ipv6 round trip`() {
        for ((host, port) in listOf("1.2.3.4" to 80, "2001:db8::1" to 443)) {
            val bytes = Mux.encodeMeta(7, Mux.STATUS_NEW, 0, host, port)
            val meta = Mux.decodeMeta(bytes.inputStream())
            assertEquals(7, meta.sessionId)
            assertEquals(port, meta.target?.port)
            if (host.contains(':')) {
                assertArrayEquals(
                    java.net.InetAddress.getByName(host).address,
                    java.net.InetAddress.getByName(meta.target?.host).address,
                )
            } else {
                assertEquals(host, meta.target?.host)
            }
        }
    }

    @Test
    fun `metaLen di atas 512 ditolak`() {
        val bad = byteArrayOf(0x02, 0x01) // metaLen 513
        assertThrows(IOException::class.java) { Mux.decodeMeta(bad.inputStream()) }
    }

    @Test
    fun `metaLen di bawah 4 ditolak`() {
        val bad = byteArrayOf(0x00, 0x03, 0x00, 0x01, 0x02)
        assertThrows(IOException::class.java) { Mux.decodeMeta(bad.inputStream()) }
    }

    // ---- stub server independen ----

    /** Satu frame yang dibaca stub (parse manual, tanpa Mux.*). */
    private data class TestFrame(
        val id: Int,
        val status: Int,
        val option: Int,
        val targetHost: String?,
        val targetPort: Int,
        val data: ByteArray?,
    )

    private fun readTestFrame(input: InputStream): TestFrame {
        val lenBytes = input.readExactBytes(2)
        val metaLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        if (metaLen < 4 || metaLen > 512) throw IOException("stub: metaLen tidak valid: $metaLen")
        val meta = input.readExactBytes(metaLen)
        val id = ((meta[0].toInt() and 0xFF) shl 8) or (meta[1].toInt() and 0xFF)
        val status = meta[2].toInt() and 0xFF
        val option = meta[3].toInt() and 0xFF
        var host: String? = null
        var port = 0
        if (status == Mux.STATUS_NEW) {
            val (t, _) = AddrCodec.parseVmessTarget(meta, 5)
            host = t.host
            port = t.port
        }
        val data = if ((option and Mux.OPTION_DATA) != 0) {
            val dl = input.readExactBytes(2)
            val n = ((dl[0].toInt() and 0xFF) shl 8) or (dl[1].toInt() and 0xFF)
            input.readExactBytes(n)
        } else {
            null
        }
        return TestFrame(id, status, option, host, port, data)
    }

    private fun writeTestFrame(
        output: OutputStream,
        id: Int,
        status: Int,
        option: Int,
        data: ByteArray?,
    ) {
        val meta = byteArrayOf(
            ((id ushr 8) and 0xFF).toByte(), (id and 0xFF).toByte(),
            status.toByte(), option.toByte(),
        )
        output.write(byteArrayOf(((meta.size ushr 8) and 0xFF).toByte(), (meta.size and 0xFF).toByte()))
        output.write(meta)
        if (data != null) {
            output.write(byteArrayOf(((data.size ushr 8) and 0xFF).toByte(), (data.size and 0xFF).toByte()))
            output.write(data)
        }
        output.flush()
    }

    /** Sepasang pipa dua arah (klien <-> stub). */
    private class PipePair(pipeSize: Int = 65536) {
        val clientOut = PipedOutputStream()
        val serverIn = PipedInputStream(clientOut, pipeSize)
        val serverOut = PipedOutputStream()
        val clientIn = PipedInputStream(serverOut, pipeSize)
    }

    /**
     * Stub server echo: tiap frame data dibalas dengan payload yang
     * sama ke session yang sama; End dicatat (dan dibalas End).
     * [onFrame] dipanggil untuk tiap frame (tes bisa bereaksi,
     * mis. mengirim End aktif).
     */
    private class EchoStub(
        val pipes: PipePair,
        val onFrame: (TestFrame) -> Unit = {},
    ) {
        val frames = java.util.Collections.synchronizedList(mutableListOf<TestFrame>())
        val ends = java.util.Collections.synchronizedList(mutableListOf<Int>())
        @Volatile var error: Throwable? = null
        val thread = Thread({
            try {
                while (true) {
                    val f = readTestFrame(pipes.serverIn)
                    frames.add(f)
                    onFrame(f)
                    when (f.status) {
                        Mux.STATUS_NEW, Mux.STATUS_KEEP -> {
                            if (f.data != null) {
                                writeTestFrame(
                                    pipes.serverOut, f.id, Mux.STATUS_KEEP,
                                    Mux.OPTION_DATA, f.data,
                                )
                            }
                        }
                        Mux.STATUS_END -> {
                            ends.add(f.id)
                            writeTestFrame(pipes.serverOut, f.id, Mux.STATUS_END, f.option, null)
                        }
                    }
                }
            } catch (e: EOFException) {
                // Pipa ditutup: akhir normal.
            } catch (e: Throwable) {
                error = e
            }
        }, "mux-stub").apply { isDaemon = true }
    }

    private fun readFully(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var filled = 0
        while (filled < n) {
            val r = input.read(out, filled, n - filled)
            if (r == -1) throw EOFException("stub: EOF, dapat $filled dari $n")
            filled += r
        }
        return out
    }

    private fun newConnection(
        pipes: PipePair,
        maxConcurrency: Int = 8,
    ): MuxConnection = MuxConnection(pipes.clientIn, pipes.clientOut, onClose = {}, maxConcurrency)

    // ---- perilaku session ----

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `beberapa session bersamaan saling kirim dua arah`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes)
        stub.thread.start()
        val conn = newConnection(pipes)
        try {
            val s1 = conn.tryOpenSession("a.example.com", 80)!!
            val s2 = conn.tryOpenSession("b.example.com", 443)!!
            val s3 = conn.tryOpenSession("1.2.3.4", 8080)!!
            s1.output.write("satu".toByteArray())
            s2.output.write("dua-dua".toByteArray())
            s3.output.write("tiga-tiga-tiga".toByteArray())
            s1.output.flush()
            s2.output.flush()
            s3.output.flush()
            assertArrayEquals("satu".toByteArray(), readFully(s1.input, 4))
            assertArrayEquals("dua-dua".toByteArray(), readFully(s2.input, 7))
            assertArrayEquals("tiga-tiga-tiga".toByteArray(), readFully(s3.input, 13))
            // Server melihat target tiap session di frame New-nya.
            val news = stub.frames.filter { it.status == Mux.STATUS_NEW }
            assertEquals(3, news.size)
            assertEquals("a.example.com", news.find { it.data?.contentEquals("satu".toByteArray()) == true }?.targetHost)
            assertEquals("b.example.com", news.find { it.data?.contentEquals("dua-dua".toByteArray()) == true }?.targetHost)
            assertEquals("1.2.3.4", news.find { it.data?.contentEquals("tiga-tiga-tiga".toByteArray()) == true }?.targetHost)
            assertEquals(8080, news.find { it.targetHost == "1.2.3.4" }?.targetPort)
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `tutup satu session tanpa merusak yang lain`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes)
        stub.thread.start()
        val conn = newConnection(pipes)
        try {
            val s1 = conn.tryOpenSession("a.example.com", 80)!!
            val s2 = conn.tryOpenSession("b.example.com", 443)!!
            s1.output.write("satu".toByteArray())
            s2.output.write("dua".toByteArray())
            assertArrayEquals("satu".toByteArray(), readFully(s1.input, 4))
            assertArrayEquals("dua".toByteArray(), readFully(s2.input, 3))
            val s1Id = s1.id
            s1.close()
            // Server menerima End hanya untuk s1.
            val deadline = System.currentTimeMillis() + 5_000
            while (!stub.ends.contains(s1Id) && System.currentTimeMillis() < deadline) {
                Thread.sleep(10)
            }
            assertTrue(stub.ends.contains(s1Id), "server harus menerima End s1: ${stub.ends}")
            assertFalse(stub.ends.contains(s2.id), "server tidak boleh menerima End s2: ${stub.ends}")
            // s2 tetap jalan sesudah s1 ditutup.
            s2.output.write("dua-lagi".toByteArray())
            assertArrayEquals("dua-lagi".toByteArray(), readFully(s2.input, 8))
            assertEquals(1, conn.activeSessions)
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `end dari server menutup input session itu saja`() {
        val pipes = PipePair()
        val endLatch = CountDownLatch(1)
        var victimId = -1
        val stub = EchoStub(pipes) { f ->
            // Sesudah data pertama session kedua, server menutupnya.
            if (f.status == Mux.STATUS_KEEP && f.data?.contentEquals("dua".toByteArray()) == true) {
                victimId = f.id
                writeTestFrame(pipes.serverOut, f.id, Mux.STATUS_END, 0, null)
                endLatch.countDown()
            }
        }
        stub.thread.start()
        val conn = newConnection(pipes)
        try {
            val s1 = conn.tryOpenSession("a.example.com", 80)!!
            val s2 = conn.tryOpenSession("b.example.com", 443)!!
            s1.output.write("satu".toByteArray())
            s2.output.write("dua".toByteArray())
            assertArrayEquals("satu".toByteArray(), readFully(s1.input, 4))
            assertTrue(endLatch.await(5, TimeUnit.SECONDS), "server tidak mengirim End")
            assertEquals(victimId, s2.id)
            assertEquals(-1, s2.input.read())
            // s1 tetap jalan.
            s1.output.write("satu-lagi".toByteArray())
            assertArrayEquals("satu-lagi".toByteArray(), readFully(s1.input, 9))
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `end error dari server membuat read melempar`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes) { f ->
            if (f.status == Mux.STATUS_NEW) {
                writeTestFrame(pipes.serverOut, f.id, Mux.STATUS_END, Mux.OPTION_ERROR, null)
            }
        }
        stub.thread.start()
        val conn = newConnection(pipes)
        try {
            val s = conn.tryOpenSession("a.example.com", 80)!!
            s.output.write("data".toByteArray())
            assertThrows(IOException::class.java) { s.input.read() }
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `frame data dipecah max 8 KiB per frame`() {
        val pipes = PipePair()
        val sizes = java.util.Collections.synchronizedList(mutableListOf<Int>())
        val stub = EchoStub(pipes) { f ->
            if (f.data != null) sizes.add(f.data.size)
        }
        stub.thread.start()
        val conn = newConnection(pipes)
        try {
            val s = conn.tryOpenSession("a.example.com", 80)!!
            val total = 20_000
            val data = ByteArray(total) { (it % 251).toByte() }
            s.output.write(data)
            s.output.flush()
            val echo = readFully(s.input, total)
            assertArrayEquals(data, echo)
            assertEquals(listOf(8192, 8192, 3616), sizes)
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `keepalive dan frame session tak dikenal diabaikan`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes)
        stub.thread.start()
        val conn = newConnection(pipes)
        try {
            val s = conn.tryOpenSession("a.example.com", 80)!!
            s.output.write("data".toByteArray())
            assertArrayEquals("data".toByteArray(), readFully(s.input, 4))
            // Server mengirim KeepAlive (id 0) + Keep untuk session
            // yang tidak ada — klien harus mengabaikan, bukan mati.
            writeTestFrame(pipes.serverOut, 0, Mux.STATUS_KEEP_ALIVE, 0, null)
            writeTestFrame(pipes.serverOut, 999, Mux.STATUS_KEEP, Mux.OPTION_DATA, "hantu".toByteArray())
            writeTestFrame(pipes.serverOut, 999, Mux.STATUS_END, 0, null)
            Thread.sleep(300)
            assertFalse(conn.isClosed, "koneksi tidak boleh mati karena frame asing")
            s.output.write("lagi".toByteArray())
            assertArrayEquals("lagi".toByteArray(), readFully(s.input, 4))
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `koneksi mati menutup semua session`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes)
        stub.thread.start()
        val conn = newConnection(pipes)
        val s1 = conn.tryOpenSession("a.example.com", 80)!!
        val s2 = conn.tryOpenSession("b.example.com", 443)!!
        s1.output.write("satu".toByteArray())
        assertArrayEquals("satu".toByteArray(), readFully(s1.input, 4))
        // Stub mati: tutup pipa server.
        runCatching { pipes.serverOut.close() }
        runCatching { pipes.serverIn.close() }
        val deadline = System.currentTimeMillis() + 5_000
        while (!conn.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertTrue(conn.isClosed, "koneksi harus terdeteksi mati")
        assertEquals(-1, s1.input.read())
        assertEquals(-1, s2.input.read())
        stub.thread.join(5_000)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `session id tidak pernah nol dan tidak dipakai ulang selagi aktif`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes)
        stub.thread.start()
        val conn = newConnection(pipes, maxConcurrency = 64)
        try {
            val ids = (1..10).map { conn.tryOpenSession("a.example.com", 80)!!.id }
            assertEquals(10, ids.toSet().size)
            assertTrue(ids.none { it == 0 }, "id 0 tidak boleh dipakai: $ids")
            assertTrue(ids.all { it in 1..0xFFFF }, "id di luar 1..65535: $ids")
            // Id yang sudah ditutup boleh dipakai ulang: buka +
            // tutup satu session lagi tidak boleh melempar.
            conn.tryOpenSession("x.example.com", 80)!!.close()
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    // ---- pool: batas concurrency ----

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `batas concurrency dihormati pool membuat koneksi baru`() {
        val created = AtomicInteger(0)
        val stubs = java.util.Collections.synchronizedList(mutableListOf<EchoStub>())
        val pool = MuxConnectionPool(2) {
            val pipes = PipePair()
            val stub = EchoStub(pipes)
            stub.thread.start()
            stubs.add(stub)
            created.incrementAndGet()
            MuxConnection(pipes.clientIn, pipes.clientOut, onClose = {}, 2)
        }
        try {
            val (c1, s1) = pool.openSession("a.example.com", 80)
            val (c1b, s2) = pool.openSession("b.example.com", 443)
            assertEquals(c1, c1b, "dua session pertama harus berbagi satu koneksi")
            val (c2, s3) = pool.openSession("c.example.com", 80)
            assertNotEquals(c1, c2, "session ketiga harus memakai koneksi baru (penuh)")
            assertEquals(2, pool.connectionCount())
            assertEquals(2, created.get())
            // Ketiganya tetap jalan dua arah.
            s1.output.write("satu".toByteArray())
            s2.output.write("dua".toByteArray())
            s3.output.write("tiga".toByteArray())
            assertArrayEquals("satu".toByteArray(), readFully(s1.input, 4))
            assertArrayEquals("dua".toByteArray(), readFully(s2.input, 3))
            assertArrayEquals("tiga".toByteArray(), readFully(s3.input, 4))
            // Menutup satu session membebaskan slot di koneksinya.
            s1.close()
            val (c1c, _) = pool.openSession("d.example.com", 80)
            assertEquals(c1, c1c, "slot yang bebas harus dipakai lagi")
            assertEquals(2, pool.connectionCount())
        } finally {
            pool.close()
            stubs.forEach { it.thread.join(5_000) }
        }
        stubs.forEach { it.error?.let { e -> throw AssertionError("Stub gagal", e) } }
    }
}
