package com.taptap.ng.core.proto

import com.taptap.ng.core.slowdns.TlsEngine
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * TLS ClientHello fragmentation tests (v1.0.5, Fragment settings).
 *
 * The stream tests use fake TLS records (no TLS stack); the
 * end-to-end tests drive a REAL JDK SSLEngine client
 * (TlsEngine) against a REAL JDK SSLEngine server
 * (test-tls.p12) over an in-memory QueueChannel — no sockets
 * (JVM loopback is intercepted in the dev VM and on CI).
 *
 * What they prove: (1) the config parser is lenient and
 * clamped; (2) the first handshake record splits into small
 * records whose payloads reassemble losslessly, maxSplit is
 * honoured, and later records pass through byte-identical;
 * (3) a peer SSLEngine accepts the split ClientHello — the
 * handshake completes and app data round-trips intact — on
 * the standard path AND the Onering (BC) path; (4) OFF leaves
 * the byte stream untouched (a single ClientHello record).
 */
class TlsFragmentTest {

    // ---------- FragmentConfig parsing ----------

    @Test
    fun `parse defaults from settings values`() {
        assertEquals(
            FragmentConfig(50, 100, 10, 20, 10),
            FragmentConfig.fromSettings("tlshello", "50-100", "10-20", "10"),
        )
    }

    @Test
    fun `parse rejects non-tlshello packets`() {
        assertNull(FragmentConfig.fromSettings("1-3", "50-100", "10-20", "10"))
        assertNull(FragmentConfig.fromSettings("all", "50-100", "10-20", "10"))
    }

    @Test
    fun `parse accepts blank packets as tlshello and is case-insensitive`() {
        assertEquals(
            FragmentConfig.DEFAULT,
            FragmentConfig.fromSettings("", "50-100", "10-20", "10"),
        )
        assertEquals(
            FragmentConfig.DEFAULT,
            FragmentConfig.fromSettings("TLSHELLO", "50-100", "10-20", "10"),
        )
    }

    @Test
    fun `parse clamps and repairs ranges instead of failing`() {
        // Reversed range is swapped.
        assertEquals(50 to 100, FragmentConfig.parseRange("100-50", 50, 100, 4, 18432))
        // Garbage falls back to defaults.
        assertEquals(50 to 100, FragmentConfig.parseRange("abc", 50, 100, 4, 18432))
        assertEquals(10 to 20, FragmentConfig.parseRange("x-y", 10, 20, 0, 1000))
        assertEquals(50 to 100, FragmentConfig.parseRange("1-2-3", 50, 100, 4, 18432))
        // Single number = fixed value.
        assertEquals(80 to 80, FragmentConfig.parseRange("80", 50, 100, 4, 18432))
        // Out-of-range ends are clamped (length min is 4: the handshake header).
        assertEquals(4 to 5, FragmentConfig.parseRange("0-5", 50, 100, 4, 18432))
        assertEquals(4 to 18432, FragmentConfig.parseRange("1-99999", 50, 100, 4, 18432))
        // maxSplit clamps to 1..64, garbage -> default 10.
        assertEquals(1, FragmentConfig.fromSettings("tlshello", "50-100", "10-20", "0")!!.maxSplit)
        assertEquals(64, FragmentConfig.fromSettings("tlshello", "50-100", "10-20", "999")!!.maxSplit)
        assertEquals(10, FragmentConfig.fromSettings("tlshello", "50-100", "10-20", "xx")!!.maxSplit)
    }

    // ---------- FragmentingOutputStream, fake records ----------

    private fun tlsRecord(type: Int, payload: ByteArray): ByteArray {
        val rec = ByteArray(5 + payload.size)
        rec[0] = type.toByte()
        rec[1] = 0x03
        rec[2] = 0x01
        rec[3] = (payload.size shr 8).toByte()
        rec[4] = payload.size.toByte()
        payload.copyInto(rec, 5)
        return rec
    }

    private fun helloPayload(size: Int): ByteArray {
        require(size >= 4)
        val payload = ByteArray(size) { (it % 251).toByte() }
        payload[0] = 0x01 // handshake type ClientHello
        val bodyLen = size - 4
        payload[1] = (bodyLen shr 16).toByte()
        payload[2] = (bodyLen shr 8).toByte()
        payload[3] = bodyLen.toByte()
        return payload
    }

    private fun parseRecords(bytes: ByteArray): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        var pos = 0
        while (pos + 5 <= bytes.size) {
            val type = bytes[pos].toInt() and 0xFF
            assertTrue(type in 20..23, "tipe record aneh: $type")
            val len = ((bytes[pos + 3].toInt() and 0xFF) shl 8) or (bytes[pos + 4].toInt() and 0xFF)
            assertTrue(pos + 5 + len <= bytes.size, "record terpotong di $pos")
            out += bytes.copyOfRange(pos, pos + 5 + len)
            pos += 5 + len
        }
        assertEquals(bytes.size, pos, "sisa byte ${bytes.size - pos} bukan record utuh")
        return out
    }

    private fun fragmentBytes(
        input: ByteArray,
        config: FragmentConfig,
        sleeps: MutableList<Int>? = null,
    ): ByteArray {
        val sink = ByteArrayOutputStream()
        val frag = FragmentingOutputStream(
            sink, config,
            sleeper = { ms -> sleeps?.add(ms) },
        )
        frag.write(input)
        frag.close()
        return sink.toByteArray()
    }

    @Test
    fun `first handshake record splits losslessly into small records`() {
        val payload = helloPayload(422)
        val record = tlsRecord(0x16, payload)
        val out = fragmentBytes(record, FragmentConfig(50, 50, 0, 0, 10))
        val records = parseRecords(out)
        assertEquals(9, records.size, "422 byte / 50 = 9 fragmen (8x50 + 22)")
        assertTrue(records.all { (it[0].toInt() and 0xFF) == 0x16 })
        assertTrue(records.all { it.size - 5 <= 50 })
        assertTrue(records[0].size - 5 >= 4, "fragmen pertama harus bawa header handshake")
        val reassembled = records.fold(ByteArrayOutputStream()) { acc, r ->
            acc.write(r, 5, r.size - 5); acc
        }.toByteArray()
        assertArrayEquals(payload, reassembled)
    }

    @Test
    fun `maxSplit caps the fragment count and the last fragment takes the rest`() {
        val payload = helloPayload(422)
        val record = tlsRecord(0x16, payload)
        val out = fragmentBytes(record, FragmentConfig(50, 50, 0, 0, 3))
        val records = parseRecords(out)
        assertEquals(3, records.size)
        assertEquals(50, records[0].size - 5)
        assertEquals(50, records[1].size - 5)
        assertEquals(422 - 100, records[2].size - 5, "fragmen terakhir menampung sisa")
        val reassembled = records.fold(ByteArrayOutputStream()) { acc, r ->
            acc.write(r, 5, r.size - 5); acc
        }.toByteArray()
        assertArrayEquals(payload, reassembled)
    }

    @Test
    fun `maxSplit one leaves the bytes unchanged`() {
        val payload = helloPayload(422)
        val record = tlsRecord(0x16, payload)
        val out = fragmentBytes(record, FragmentConfig(50, 50, 0, 0, 1))
        assertArrayEquals(record, out)
    }

    @Test
    fun `only the first record is fragmented`() {
        val hello = tlsRecord(0x16, helloPayload(200))
        val appData = tlsRecord(0x17, ByteArray(100) { 0x41 })
        val input = hello + appData
        val out = fragmentBytes(input, FragmentConfig(50, 50, 0, 0, 10))
        val records = parseRecords(out)
        assertEquals(4 + 1, records.size, "hello 200/50 = 4 fragmen + 1 record appdata utuh")
        assertArrayEquals(appData, records.last())
        val reassembled = records.subList(0, 4).fold(ByteArrayOutputStream()) { acc, r ->
            acc.write(r, 5, r.size - 5); acc
        }.toByteArray()
        assertArrayEquals(helloPayload(200), reassembled)
    }

    @Test
    fun `split writes reassemble the same way as one-shot writes`() {
        val payload = helloPayload(422)
        val record = tlsRecord(0x16, payload)
        val config = FragmentConfig(50, 50, 0, 0, 10)
        val oneShot = fragmentBytes(record, config)
        // Feed the same record byte-by-byte, then in odd chunks.
        val sink = ByteArrayOutputStream()
        val frag = FragmentingOutputStream(sink, config, sleeper = {})
        record.forEach { frag.write(it.toInt()) }
        frag.close()
        assertArrayEquals(oneShot, sink.toByteArray())
        val sink2 = ByteArrayOutputStream()
        val frag2 = FragmentingOutputStream(sink2, config, sleeper = {})
        frag2.write(record, 0, 3) // partial header
        frag2.write(record, 3, 2) // rest of header
        frag2.write(record, 5, 100)
        frag2.write(record, 105, record.size - 105)
        frag2.close()
        assertArrayEquals(oneShot, sink2.toByteArray())
    }

    @Test
    fun `non-handshake first record passes through and latches passthrough`() {
        val appData = tlsRecord(0x17, ByteArray(100) { 0x42 })
        val hello = tlsRecord(0x16, helloPayload(200))
        val out = fragmentBytes(appData + hello, FragmentConfig(50, 50, 0, 0, 10))
        assertArrayEquals(appData + hello, out)
    }

    @Test
    fun `interval sleeper is called between fragments only`() {
        val payload = helloPayload(422)
        val record = tlsRecord(0x16, payload)
        val sleeps = mutableListOf<Int>()
        fragmentBytes(record, FragmentConfig(50, 50, 10, 10, 10), sleeps)
        assertEquals(8, sleeps.size, "9 fragmen = 8 jeda")
        assertTrue(sleeps.all { it == 10 })
    }

    @Test
    fun `flush keeps partial bytes and close emits them instead of dropping`() {
        val sink = ByteArrayOutputStream()
        val frag = FragmentingOutputStream(sink, FragmentConfig(50, 50, 0, 0, 10), sleeper = {})
        frag.write(byteArrayOf(0x16, 0x03, 0x01), 0, 3) // partial record header
        frag.flush()
        assertEquals(0, sink.size(), "flush tidak boleh mengeluarkan record setengah")
        frag.close()
        assertArrayEquals(byteArrayOf(0x16, 0x03, 0x01), sink.toByteArray())
    }

    // ---------- FragmentSocket delegation ----------

    private class StubSocket : Socket() {
        val inputBytes = ByteArrayInputStream("stub-in".toByteArray())
        val outputBytes = ByteArrayOutputStream()
        var closed = false
        override fun getInputStream(): InputStream = inputBytes
        override fun getOutputStream(): OutputStream = outputBytes
        override fun close() {
            closed = true
        }

        override fun isClosed(): Boolean = closed
        override fun isConnected(): Boolean = true
        override fun getInetAddress(): InetAddress = InetAddress.getByName("10.0.0.9")
        override fun getPort(): Int = 8443
    }

    @Test
    fun `FragmentSocket delegates and returns one fragmenting stream`() {
        val stub = StubSocket()
        val fs = FragmentSocket(stub, FragmentConfig(50, 50, 0, 0, 10))
        assertSame(stub.inputBytes, fs.inputStream)
        assertTrue(fs.outputStream is FragmentingOutputStream)
        assertSame(fs.outputStream, fs.outputStream, "stream harus sama tiap panggilan")
        assertEquals(stub.inetAddress, fs.inetAddress)
        assertEquals(8443, fs.port)
        assertTrue(fs.isConnected)
        // Writing a ClientHello through it fragments into the real sink.
        val record = tlsRecord(0x16, helloPayload(200))
        fs.outputStream.write(record)
        fs.outputStream.flush()
        val records = parseRecords(stub.outputBytes.toByteArray())
        assertEquals(4, records.size)
        fs.close()
        assertTrue(stub.closed)
        assertTrue(fs.isClosed)
    }

    // ---------- Transport provider ----------

    @Test
    fun `resolveFragmentConfig follows the provider`() {
        val prev = Transport.fragmentConfigProvider
        try {
            Transport.fragmentConfigProvider = null
            assertNull(Transport.resolveFragmentConfig())
            Transport.fragmentConfigProvider = { FragmentConfig.DEFAULT }
            assertEquals(FragmentConfig.DEFAULT, Transport.resolveFragmentConfig())
        } finally {
            Transport.fragmentConfigProvider = prev
        }
    }

    // ---------- end-to-end: SSLEngine over fragmented ClientHello ----------

    private fun loadKeystore(): KeyStore {
        val ks = KeyStore.getInstance("PKCS12")
        val res: InputStream = javaClass.classLoader
            .getResourceAsStream("test-tls.p12")
            ?: throw IllegalStateException("test-tls.p12 tidak ada di test resources")
        res.use { ks.load(it, "taptapx-test".toCharArray()) }
        return ks
    }

    private fun serverContext(): SSLContext {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(loadKeystore(), "taptapx-test".toCharArray())
        return SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, null, null)
        }
    }

    /** In-memory byte channel (same shape as OneringTlsTest.QueueChannel). */
    private class QueueChannel(private val readTimeoutMs: Long = 15_000) {
        private val queue = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

        val input: InputStream = object : InputStream() {
            private var current: ByteArray? = null
            private var pos = 0
            override fun read(): Int {
                val b = ByteArray(1)
                val n = read(b, 0, 1)
                return if (n == -1) -1 else b[0].toInt() and 0xFF
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                while (current == null || pos >= current!!.size) {
                    if (closed.get() && queue.isEmpty()) return -1
                    val chunk = queue.poll(readTimeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
                        ?: throw java.net.SocketTimeoutException(
                            "QueueChannel baca menggantung > ${readTimeoutMs}ms",
                        )
                    if (chunk.isEmpty()) return -1
                    current = chunk
                    pos = 0
                }
                val cur = current!!
                val take = minOf(len, cur.size - pos)
                cur.copyInto(b, off, pos, pos + take)
                pos += take
                return take
            }

            override fun close() {
                closed.set(true)
                queue.offer(ByteArray(0))
            }
        }

        val output: OutputStream = object : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()))
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (len == 0) return
                queue.offer(b.copyOfRange(off, off + len))
            }

            override fun close() {
                closed.set(true)
                queue.offer(ByteArray(0))
            }
        }
    }

    /** OutputStream that records every byte written (wire capture). */
    private class RecordingOutputStream(private val delegate: OutputStream) : OutputStream() {
        val captured = ByteArrayOutputStream()

        @Synchronized
        override fun write(b: Int) {
            captured.write(b)
            delegate.write(b)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
            captured.write(b, off, len)
            delegate.write(b, off, len)
        }

        override fun flush() = delegate.flush()
        override fun close() = delegate.close()
    }

    private fun tlsItem(sni: String, address: String = "127.0.0.1") = ProfileItem(
        remarks = "Fragment test",
        address = address,
        port = 443,
        tls = true,
        insecure = true,
        network = "tcp",
        sni = sni,
    )

    /**
     * Run a client (TlsEngine) against a server (TlsSession) over
     * in-memory channels. [clientOut] is the stream the client
     * engine writes to: a [FragmentingOutputStream] over the
     * [recording] tap to fragment, or the tap itself for the OFF
     * baseline. Returns the captured client->server wire bytes.
     */
    private fun runHandshake(
        clientToServer: QueueChannel,
        serverToClient: QueueChannel,
        clientOut: OutputStream,
        recording: RecordingOutputStream,
        item: ProfileItem,
    ): ByteArray {
        val serverEngine = serverContext().createSSLEngine()
        serverEngine.useClientMode = false
        val serverSession = TlsEngine.TlsSession(serverEngine, clientToServer.input, serverToClient.output)
        var serverReceived = ""
        var serverError: Throwable? = null
        val serverThread = Thread({
            try {
                serverSession.handshake()
                val buf = ByteArray(1024)
                val n = serverSession.inputStream.read(buf)
                serverReceived = buf.copyOf(n).toString(Charsets.UTF_8)
                serverSession.outputStream.write(
                    "balasan:$serverReceived".toByteArray(Charsets.UTF_8),
                )
                serverSession.outputStream.flush()
            } catch (e: Throwable) {
                serverError = e
            }
        }, "fragment-test-server").apply { isDaemon = true }
        serverThread.start()

        val (tlsIn, tlsOut) = TlsEngine.wrap(serverToClient.input, clientOut, item)
        tlsOut.write("halo-fragment".toByteArray(Charsets.UTF_8))
        tlsOut.flush()
        val reply = ByteArray(1024)
        val n = tlsIn.read(reply)
        assertEquals("balasan:halo-fragment", reply.copyOf(n).toString(Charsets.UTF_8))
        assertEquals("halo-fragment", serverReceived)
        if (serverError != null) throw AssertionError("Server TLS gagal: $serverError", serverError)
        tlsIn.close()
        tlsOut.close()
        serverThread.join(5_000)
        assertTrue(!serverThread.isAlive, "thread server masih hidup sesudah close")
        return recording.captured.toByteArray()
    }

    /** Split captured wire bytes into records; return the reassembled first ClientHello + record list + its fragment count. */
    private fun reassembleClientHello(captured: ByteArray): Triple<ByteArray, List<ByteArray>, Int> {
        val records = parseRecords(captured)
        assertTrue(records.isNotEmpty(), "tidak ada record terekam")
        assertEquals(0x16, records[0][0].toInt() and 0xFF, "record pertama harus handshake")
        // Accumulate leading handshake records until the ClientHello is complete.
        val hello = ByteArrayOutputStream()
        var count = 0
        var total = -1
        for (r in records) {
            if ((r[0].toInt() and 0xFF) != 0x16) break
            hello.write(r, 5, r.size - 5)
            count++
            val payload = hello.toByteArray()
            if (payload.size >= 4 && total == -1) {
                val bodyLen = ((payload[1].toInt() and 0xFF) shl 16) or
                    ((payload[2].toInt() and 0xFF) shl 8) or
                    (payload[3].toInt() and 0xFF)
                total = 4 + bodyLen
            }
            if (total != -1 && payload.size >= total) break
        }
        assertTrue(total != -1, "ClientHello tidak lengkap di rekaman")
        val helloBytes = hello.toByteArray()
        assertEquals(total, helloBytes.size, "fragmen ClientHello harus pas, tanpa byte ekstra")
        assertEquals(0x01, helloBytes[0].toInt() and 0xFF, "harus ClientHello")
        return Triple(helloBytes, records, count)
    }

    /** Parse ClientHello extensions in wire order (adapted from OneringTlsTest). */
    private fun parseClientHelloExtensions(hello: ByteArray): List<Pair<Int, ByteArray>> {
        var pos = 4 + 2 + 32 // handshake header + version + random
        val sessionLen = hello[pos].toInt() and 0xFF
        pos += 1 + sessionLen
        val suitesLen = ((hello[pos].toInt() and 0xFF) shl 8) or (hello[pos + 1].toInt() and 0xFF)
        pos += 2 + suitesLen
        val compLen = hello[pos].toInt() and 0xFF
        pos += 1 + compLen
        val extLen = ((hello[pos].toInt() and 0xFF) shl 8) or (hello[pos + 1].toInt() and 0xFF)
        pos += 2
        val extEnd = pos + extLen
        assertTrue(extEnd <= hello.size, "extensions melewati ClientHello")
        val out = mutableListOf<Pair<Int, ByteArray>>()
        while (pos < extEnd) {
            val type = ((hello[pos].toInt() and 0xFF) shl 8) or (hello[pos + 1].toInt() and 0xFF)
            val len = ((hello[pos + 2].toInt() and 0xFF) shl 8) or (hello[pos + 3].toInt() and 0xFF)
            out += type to hello.copyOfRange(pos + 4, pos + 4 + len)
            pos += 4 + len
        }
        assertEquals(extEnd, pos, "parse extensions tidak pas")
        return out
    }

    private fun parseSniHost(data: ByteArray): String {
        val hostLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        return data.copyOfRange(5, 5 + hostLen).toString(Charsets.US_ASCII)
    }

    @Test
    fun `fragmented ClientHello handshakes and no single record holds the SNI`() {
        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val recording = RecordingOutputStream(clientToServer.output)
        // SNI host (31 chars) is longer than any 20-byte fragment,
        // so no single record can carry it whole.
        val sni = "fragmentation-test-host.example"
        val config = FragmentConfig(20, 20, 0, 0, 64)
        val fragOut = FragmentingOutputStream(recording, config, sleeper = {})
        // Address 127.0.0.2: no other test caches a TLS session
        // for it in TlsEngine's shared trustAllContext, so this
        // handshake always sends a FRESH ClientHello (~460 byte)
        // instead of a resumed one with a ~1 KB PSK ticket (see
        // the resumed test below — that is what failed CI
        // 44866708458: the resumed hello hit the maxSplit cap and
        // its last fragment was 279 byte, not <= 20).
        val captured = runHandshake(
            clientToServer, serverToClient, fragOut, recording,
            tlsItem(sni, address = "127.0.0.2"),
        )
        val (hello, records, helloFragCount) = reassembleClientHello(captured)
        val extensions = parseClientHelloExtensions(hello)
        val sniExt = extensions.firstOrNull { it.first == 0x0000 }
            ?: throw AssertionError("tidak ada ekstensi SNI di ClientHello")
        assertEquals(sni, parseSniHost(sniExt.second))
        // The DPI property: no single wire record contains the SNI host.
        val sniBytes = sni.toByteArray(Charsets.US_ASCII)
        assertTrue(records.none { rec ->
            val payload = rec.copyOfRange(5, rec.size)
            payload.indices.any { i ->
                i + sniBytes.size <= payload.size &&
                    payload.copyOfRange(i, i + sniBytes.size).contentEquals(sniBytes)
            }
        }, "satu record masih memuat SNI utuh")
        // Every fragment is small, and there was real splitting.
        // (helloFragCount counts ONLY the ClientHello pieces —
        // the Finished record after them is also type 22.)
        val helloFrags = records.take(helloFragCount)
        assertTrue(helloFragCount >= 10, "ClientHello harus terpecah banyak: $helloFragCount")
        assertTrue(
            helloFrags.dropLast(1).all { it.size - 5 <= 20 },
            "semua fragmen kecuali terakhir harus <= 20: ${helloFrags.map { it.size - 5 }}",
        )
        // The last fragment may exceed the length ONLY when
        // maxSplit capped the split (a resumed ClientHello is
        // ~1,5 KB — see the resumed test below).
        if (helloFragCount < config.maxSplit) {
            assertTrue(
                helloFrags.all { it.size - 5 <= 20 },
                "tanpa cap maxSplit semua fragmen harus <= 20: ${helloFrags.map { it.size - 5 }}",
            )
        } else {
            assertEquals(config.maxSplit, helloFragCount, "cap maxSplit harus tepat")
        }
        // Only the ClientHello was split: the next record (Finished)
        // is a single handshake record, not fragments.
        val afterHello = records.drop(helloFragCount)
        assertTrue(afterHello.isNotEmpty(), "harus ada record Finished sesudah ClientHello")
        assertEquals(0x16, afterHello[0][0].toInt() and 0xFF, "record sesudah hello harus Finished")
    }

    @Test
    fun `fragmented resumed ClientHello honours maxSplit`() {
        // Warm-up: a plain handshake on the same (host, port)
        // caches a TLS session in TlsEngine's shared
        // trustAllContext, so the fragmented handshake resumes
        // it — the ClientHello grows by the ~1 KB PSK ticket and
        // the split must cap at maxSplit instead of producing
        // more fragments. Proves the cap path AND that a big
        // hello still handshakes (this is the shape that failed
        // CI 44866708458 before the assertion was fixed).
        val item = tlsItem("fragmentation-test-host.example")
        val warmClientToServer = QueueChannel()
        val warmServerToClient = QueueChannel()
        val warmRecording = RecordingOutputStream(warmClientToServer.output)
        runHandshake(warmClientToServer, warmServerToClient, warmRecording, warmRecording, item)

        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val recording = RecordingOutputStream(clientToServer.output)
        val config = FragmentConfig(20, 20, 0, 0, 64)
        val fragOut = FragmentingOutputStream(recording, config, sleeper = {})
        val captured = runHandshake(clientToServer, serverToClient, fragOut, recording, item)
        val (hello, records, helloFragCount) = reassembleClientHello(captured)
        assertTrue(hello.size > 63 * 20, "hello resume harus > 1260 byte: ${hello.size}")
        assertEquals(config.maxSplit, helloFragCount, "split harus mentok di maxSplit")
        val helloFrags = records.take(helloFragCount)
        assertTrue(
            helloFrags.dropLast(1).all { it.size - 5 == 20 },
            "63 fragmen pertama harus 20 byte: ${helloFrags.map { it.size - 5 }}",
        )
        assertTrue(
            helloFrags.last().size - 5 > 20,
            "fragmen terakhir menampung sisa ticket PSK: ${helloFrags.last().size - 5}",
        )
        // Reassembly + SNI still intact: the SNI sits near the
        // start of the hello, far from the big last fragment.
        val extensions = parseClientHelloExtensions(hello)
        assertEquals(
            "fragmentation-test-host.example",
            parseSniHost(extensions.first { it.first == 0x0000 }.second),
        )
    }

    @Test
    fun `fragmentation OFF leaves a single ClientHello record`() {
        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val recording = RecordingOutputStream(clientToServer.output)
        val captured = runHandshake(
            clientToServer, serverToClient, recording, recording,
            tlsItem("fragmentation-test-host.example"),
        )
        val (hello, records) = reassembleClientHello(captured).let { it.first to it.second }
        // OFF: the first record IS the whole ClientHello.
        assertEquals(hello.size + 5, records[0].size)
        val extensions = parseClientHelloExtensions(hello)
        assertEquals(
            "fragmentation-test-host.example",
            parseSniHost(extensions.first { it.first == 0x0000 }.second),
        )
    }

    @Test
    fun `Onering ClientHello fragments and handshakes`() {
        val clientToServer = QueueChannel()
        val serverToClient = QueueChannel()
        val recording = RecordingOutputStream(clientToServer.output)
        val config = FragmentConfig(20, 20, 0, 0, 64)
        val fragOut = FragmentingOutputStream(recording, config, sleeper = {})
        val item = tlsItem("support.zoom.us").copy(
            oneringEnabled = true,
            oneringBug = "live.iflix.com",
        )
        val serverEngine = serverContext().createSSLEngine()
        serverEngine.useClientMode = false
        val serverSession = TlsEngine.TlsSession(serverEngine, clientToServer.input, serverToClient.output)
        var serverReceived = ""
        var serverError: Throwable? = null
        val serverThread = Thread({
            try {
                serverSession.handshake()
                val buf = ByteArray(1024)
                val n = serverSession.inputStream.read(buf)
                serverReceived = buf.copyOf(n).toString(Charsets.UTF_8)
                serverSession.outputStream.write(
                    "balasan:$serverReceived".toByteArray(Charsets.UTF_8),
                )
                serverSession.outputStream.flush()
            } catch (e: Throwable) {
                serverError = e
            }
        }, "fragment-onering-server").apply { isDaemon = true }
        serverThread.start()

        val (tlsIn, tlsOut) = OneringTls.wrap(serverToClient.input, fragOut, item, fragmentConfig = config)
        tlsOut.write("halo-onering-frag".toByteArray(Charsets.UTF_8))
        tlsOut.flush()
        val reply = ByteArray(1024)
        val n = tlsIn.read(reply)
        assertEquals("balasan:halo-onering-frag", reply.copyOf(n).toString(Charsets.UTF_8))
        assertEquals("halo-onering-frag", serverReceived)
        if (serverError != null) throw AssertionError("Server TLS gagal: $serverError", serverError)
        tlsIn.close()
        tlsOut.close()
        serverThread.join(5_000)
        assertTrue(!serverThread.isAlive, "thread server masih hidup sesudah close")

        val captured = recording.captured.toByteArray()
        val (hello, records, helloFragCount) = reassembleClientHello(captured)
        val extensions = parseClientHelloExtensions(hello)
        assertTrue(extensions.isNotEmpty(), "ClientHello tanpa extensions")
        assertEquals(
            OneringHello.EXTENSION_TYPE, extensions[0].first,
            "0xff00 harus tetap pertama sesudah fragmentasi",
        )
        assertEquals("live.iflix.com", OneringHello.parseBugExtensionData(extensions[0].second))
        val sni = extensions.firstOrNull { it.first == 0x0000 }
            ?: throw AssertionError("tidak ada ekstensi SNI di ClientHello")
        assertEquals("support.zoom.us", parseSniHost(sni.second))
        assertTrue(helloFragCount >= 2, "ClientHello Onering harus terpecah")
        assertTrue(records.take(helloFragCount).all { it.size - 5 <= 20 })
    }
}
