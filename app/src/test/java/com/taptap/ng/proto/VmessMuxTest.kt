package com.taptap.ng.proto

import com.taptap.ng.core.proto.*
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * VmessClient dengan mux ON vs fake server VMess+mux in-memory
 * (v1.0.5, kelompok D). Transport pipa (BUKAN loopback socket).
 * Fake server: buka header VMess (perintah harus Mux 0x03, target
 * v1.mux.cool:666), lalu demux frame mux dari body chunk — dan
 * berperilaku seperti xray-core: response header baru dikirim
 * sesudah data pertama tiba.
 */
class VmessMuxTest {

    private val uuid = "de305d54-75b4-431b-adb2-eb6b9e546014"

    private class PipePair(pipeSize: Int = 65536) {
        val clientOut = PipedOutputStream()
        val serverIn = PipedInputStream(clientOut, pipeSize)
        val serverOut = PipedOutputStream()
        val clientIn = PipedInputStream(serverOut, pipeSize)
    }

    /** Frame mux (parse manual, independen — lihat MuxTest). */
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

    private fun encodeTestFrame(id: Int, status: Int, option: Int, data: ByteArray?): ByteArray {
        val out = ByteArrayOutputStream()
        val meta = byteArrayOf(
            ((id ushr 8) and 0xFF).toByte(), (id and 0xFF).toByte(),
            status.toByte(), option.toByte(),
        )
        out.write(byteArrayOf(((meta.size ushr 8) and 0xFF).toByte(), (meta.size and 0xFF).toByte()))
        out.write(meta)
        if (data != null) {
            out.write(byteArrayOf(((data.size ushr 8) and 0xFF).toByte(), (data.size and 0xFF).toByte()))
            out.write(data)
        }
        return out.toByteArray()
    }

    /** Server-side chunk reader (mirip VmessClientTest). */
    private fun readChunk(
        input: InputStream,
        key: ByteArray,
        nonce: VmessCrypto.ChunkNonce,
        mask: Shake128,
        security: VmessSecurity,
    ): ByteArray {
        val maskedBytes = input.readExactBytes(2)
        val maskedSize = ((maskedBytes[0].toInt() and 0xFF) shl 8) or
            (maskedBytes[1].toInt() and 0xFF)
        val paddingLen = mask.nextPaddingLen()
        val size = maskedSize xor mask.nextUint16()
        val wire = input.readExactBytes(size)
        val sealed = wire.copyOfRange(0, size - paddingLen)
        return VmessCrypto.openBodyChunk(security, key, nonce.next(), sealed)
    }

    private fun writeChunk(
        output: OutputStream,
        key: ByteArray,
        nonce: VmessCrypto.ChunkNonce,
        mask: Shake128,
        security: VmessSecurity,
        payload: ByteArray,
    ) {
        val paddingLen = mask.nextPaddingLen()
        val sealed = VmessCrypto.sealBodyChunk(security, key, nonce.next(), payload)
        val total = sealed.size + paddingLen
        val maskedSize = total xor mask.nextUint16()
        output.write(byteArrayOf(((maskedSize ushr 8) and 0xFF).toByte(), (maskedSize and 0xFF).toByte()))
        output.write(sealed)
        if (paddingLen > 0) output.write(Crypto.randomBytes(paddingLen))
        output.flush()
    }

    /** InputStream yang men-decode VMess body chunk menjadi byte stream mux. */
    private class ChunkInputStream(
        private val rawIn: InputStream,
        private val key: ByteArray,
        private val nonce: VmessCrypto.ChunkNonce,
        private val mask: Shake128,
        private val security: VmessSecurity,
        private val readChunkFn: (InputStream, ByteArray, VmessCrypto.ChunkNonce, Shake128, VmessSecurity) -> ByteArray,
    ) : InputStream() {
        private var buf: ByteArray = ByteArray(0)
        private var pos = 0
        private var eof = false

        override fun read(): Int {
            val one = ByteArray(1)
            return if (read(one, 0, 1) == -1) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (eof) return -1
            if (pos >= buf.size) {
                val chunk = readChunkFn(rawIn, key, nonce, mask, security)
                if (chunk.isEmpty()) {
                    eof = true
                    return -1
                }
                buf = chunk
                pos = 0
            }
            val take = minOf(len, buf.size - pos)
            buf.copyInto(b, off, pos, pos + take)
            pos += take
            return take
        }
    }

    private fun readFully(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var filled = 0
        while (filled < n) {
            val r = input.read(out, filled, n - filled)
            if (r == -1) throw EOFException("EOF, dapat $filled dari $n")
            filled += r
        }
        return out
    }

    /**
     * Fake server VMess+mux: buka header (assert command Mux +
     * target), echo tiap data frame, kirim response header
     * xray-like (sesudah data pertama). Berhenti sesudah
     * [expectedEnds] End.
     */
    private class FakeMuxServer(
        val pipes: PipePair,
        val uuid: String,
        val expectedEnds: Int,
        val readChunkFn: (InputStream, ByteArray, VmessCrypto.ChunkNonce, Shake128, VmessSecurity) -> ByteArray,
        val writeChunkFn: (OutputStream, ByteArray, VmessCrypto.ChunkNonce, Shake128, VmessSecurity, ByteArray) -> Unit,
        val readFrameFn: (InputStream) -> TestFrame,
        val encodeFrameFn: (Int, Int, Int, ByteArray?) -> ByteArray,
    ) {
        val headerCommands = java.util.Collections.synchronizedList(mutableListOf<Byte>())
        val headerTargets = java.util.Collections.synchronizedList(mutableListOf<AddrCodec.Target>())
        val news = java.util.Collections.synchronizedList(mutableListOf<TestFrame>())
        val ends = java.util.Collections.synchronizedList(mutableListOf<Int>())
        @Volatile var error: Throwable? = null
        val thread = Thread({
            try {
                val input = pipes.serverIn
                val output = pipes.serverOut
                val opened = VmessCrypto.openRequestHeader(VmessCrypto.cmdKey(uuid), input)
                headerCommands.add(opened.header.command.toByte())
                headerTargets.add(opened.header.target)
                val session = VmessSession(
                    requestBytes = ByteArray(0),
                    bodyKey = opened.header.bodyKey,
                    bodyIV = opened.header.bodyIV,
                    responseBodyKey = Crypto.sha256(opened.header.bodyKey).copyOfRange(0, 16),
                    responseBodyIV = Crypto.sha256(opened.header.bodyIV).copyOfRange(0, 16),
                    responseV = opened.header.responseV,
                    security = opened.header.security,
                )
                val reqNonce = VmessCrypto.ChunkNonce(session.bodyIV)
                val reqMask = Shake128(session.bodyIV)
                val respNonce = VmessCrypto.ChunkNonce(session.responseBodyIV)
                val respMask = Shake128(session.responseBodyIV)
                val muxIn = ChunkInputStream(
                    input, session.bodyKey, reqNonce, reqMask,
                    session.security, readChunkFn,
                )
                var headerSent = false
                var endsSeen = 0
                while (endsSeen < expectedEnds) {
                    val f = try {
                        readFrameFn(muxIn)
                    } catch (e: EOFException) {
                        break
                    }
                    when (f.status) {
                        Mux.STATUS_NEW -> news.add(f)
                        Mux.STATUS_END -> {
                            ends.add(f.id)
                            endsSeen++
                            continue
                        }
                    }
                    if (f.data != null) {
                        if (!headerSent) {
                            // xray-like: response header sesudah data
                            // pertama (target sudah menjawab).
                            output.write(VmessCrypto.sealResponseHeader(session, session.responseV))
                            output.flush()
                            headerSent = true
                        }
                        writeChunkFn(
                            output, session.responseBodyKey, respNonce, respMask,
                            session.security,
                            encodeFrameFn(f.id, Mux.STATUS_KEEP, Mux.OPTION_DATA, f.data),
                        )
                    }
                }
            } catch (e: java.io.IOException) {
                // Tulis sesudah tes menutup pipa (teardown): akhir
                // normal — lihat komentar yang sama di MuxTest.
                if (e.message != "Pipe closed" && e.message != "Pipe broken") error = e
            } catch (e: Throwable) {
                error = e
            } finally {
                runCatching { pipes.serverOut.close() }
                runCatching { pipes.serverIn.close() }
            }
        }, "vmess-mux-stub").apply { isDaemon = true }
    }

    private fun vmessItem() = ProfileItem(
        configType = ConfigType.VMESS,
        address = "example.com", port = 443,
        uuid = uuid, security = "aes-128-gcm",
        network = "tcp",
    )

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `dua dial relay berbagi satu koneksi fisik mux`() {
        val pipes = PipePair()
        val ladderCalls = AtomicInteger(0)
        val ladder = LadderStream(
            pipes.clientIn, pipes.clientOut,
            onClose = {
                runCatching { pipes.clientIn.close() }
                runCatching { pipes.clientOut.close() }
            },
            onHandshakeDone = {},
        )
        val server = FakeMuxServer(
            pipes, uuid, 2, ::readChunk, ::writeChunk, ::readTestFrame, ::encodeTestFrame,
        )
        server.thread.start()
        val client = VmessClient(
            vmessItem(),
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = { _, _ ->
                ladderCalls.incrementAndGet()
                ladder
            },
        )
        try {
            val s1 = client.dial("a.example.com", 80)
            val s2 = client.dial("b.example.com", 443)
            try {
                s1.output.write("hello-1".toByteArray())
                s2.output.write("hello-2".toByteArray())
                s1.output.flush()
                s2.output.flush()
                assertArrayEquals("hello-1".toByteArray(), readFully(s1.input, 7))
                assertArrayEquals("hello-2".toByteArray(), readFully(s2.input, 7))
            } finally {
                runCatching { s1.close() }
                runCatching { s2.close() }
            }
            server.thread.join(5_000)
            assertTrue(!server.thread.isAlive, "fake server harus selesai")
            server.error?.let { throw AssertionError("Fake server gagal", it) }
            // Satu header VMess saja untuk dua dial (berbagi koneksi).
            assertEquals(1, ladderCalls.get(), "ladder harus dibuka sekali")
            assertEquals(1, server.headerCommands.size)
            assertEquals(VmessCrypto.CMD_MUX, server.headerCommands.first())
            assertEquals(Mux.TARGET_HOST, server.headerTargets.first().host)
            assertEquals(Mux.TARGET_PORT, server.headerTargets.first().port)
            // Dua session logis dengan target masing-masing.
            assertEquals(2, server.news.size)
            assertEquals("a.example.com", server.news[0].targetHost)
            assertEquals(80, server.news[0].targetPort)
            assertEquals("b.example.com", server.news[1].targetHost)
            assertEquals(443, server.news[1].targetPort)
            assertEquals(2, server.news.map { it.id }.toSet().size)
            assertEquals(2, server.ends.size)
        } finally {
            client.close()
        }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `probe dial mux berhasil dan header dibaca cepat`() {
        val pipes = PipePair()
        val probeBody = "probe-bytes".toByteArray()
        val server = FakeMuxServer(
            pipes, uuid, 1, ::readChunk, ::writeChunk, ::readTestFrame, ::encodeTestFrame,
        )
        server.thread.start()
        val client = VmessClient(
            vmessItem(),
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = { _, _ ->
                LadderStream(
                    pipes.clientIn, pipes.clientOut,
                    onClose = {
                        runCatching { pipes.clientIn.close() }
                        runCatching { pipes.clientOut.close() }
                    },
                    onHandshakeDone = {},
                )
            },
        )
        try {
            val start = System.currentTimeMillis()
            val stream = client.dial("example.com", 443, probeBody)
            val dialMs = System.currentTimeMillis() - start
            assertTrue(dialMs < 5_000, "probe dial harus kembali cepat, butuh ${dialMs}ms")
            runCatching { stream.close() }
            server.thread.join(5_000)
            assertTrue(!server.thread.isAlive, "fake server harus selesai")
            server.error?.let { throw AssertionError("Fake server gagal", it) }
            assertEquals(VmessCrypto.CMD_MUX, server.headerCommands.first())
            assertEquals(1, server.news.size)
            assertArrayEquals(probeBody, server.news.first().data)
        } finally {
            client.close()
        }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `mux penuh membuka koneksi fisik kedua`() {
        val ladderCalls = AtomicInteger(0)
        val servers = java.util.Collections.synchronizedList(mutableListOf<FakeMuxServer>())
        val client = VmessClient(
            vmessItem(),
            muxConfig = MuxConfig(enabled = true, concurrency = 1),
            muxLadderOpener = { _, _ ->
                ladderCalls.incrementAndGet()
                val pipes = PipePair()
                val server = FakeMuxServer(
                    pipes, uuid, 1, ::readChunk, ::writeChunk, ::readTestFrame, ::encodeTestFrame,
                )
                servers.add(server)
                server.thread.start()
                LadderStream(
                    pipes.clientIn, pipes.clientOut,
                    onClose = {
                        runCatching { pipes.clientIn.close() }
                        runCatching { pipes.clientOut.close() }
                    },
                    onHandshakeDone = {},
                )
            },
        )
        try {
            val s1 = client.dial("a.example.com", 80)
            val s2 = client.dial("b.example.com", 443)
            try {
                s1.output.write("satu".toByteArray())
                s2.output.write("dua".toByteArray())
                assertArrayEquals("satu".toByteArray(), readFully(s1.input, 4))
                assertArrayEquals("dua".toByteArray(), readFully(s2.input, 3))
            } finally {
                runCatching { s1.close() }
                runCatching { s2.close() }
            }
            assertEquals(2, ladderCalls.get(), "concurrency 1: dial kedua harus buka koneksi baru")
            servers.forEach { it.thread.join(5_000) }
            servers.forEach { it.error?.let { e -> throw AssertionError("Fake server gagal", e) } }
        } finally {
            client.close()
        }
    }
}
