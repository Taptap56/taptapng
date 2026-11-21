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
 * VlessClient dengan mux ON vs fake server VLESS+mux in-memory
 * (v1.0.5, kelompok D). Transport pipa (BUKAN loopback socket).
 * Fake server: baca header VLESS — command harus Mux 0x03 dan
 * header HARUS berakhir di sana (tanpa port/address) — lalu demux
 * frame mux mentah, dan berperilaku seperti xray-core: response
 * header baru dikirim sesudah data pertama tiba.
 */
class VlessMuxTest {

    private val uuid = "de305d54-75b4-431b-adb2-eb6b9e546014"

    private class PipePair(pipeSize: Int = 65536) {
        val clientOut = PipedOutputStream()
        val serverIn = PipedInputStream(clientOut, pipeSize)
        val serverOut = PipedOutputStream()
        val clientIn = PipedInputStream(serverOut, pipeSize)
    }

    private data class TestFrame(
        val id: Int,
        val status: Int,
        val option: Int,
        val targetHost: String?,
        val targetPort: Int,
        val data: ByteArray?,
    )

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
     * Fake server VLESS+mux: baca header 19 byte (version + UUID +
     * addonLen + command Mux — tanpa address), echo tiap data
     * frame, kirim response header (0x00, 0x00) sesudah data
     * pertama. Berhenti sesudah [expectedEnds] End.
     */
    private class FakeMuxServer(
        val pipes: PipePair,
        val uuid: String,
        val expectedEnds: Int,
    ) {
        val headerBytes = java.util.Collections.synchronizedList(mutableListOf<Byte>())
        val news = java.util.Collections.synchronizedList(mutableListOf<TestFrame>())
        val ends = java.util.Collections.synchronizedList(mutableListOf<Int>())
        @Volatile var error: Throwable? = null
        val thread = Thread({
            try {
                val input = pipes.serverIn
                val output = pipes.serverOut
                // Header VLESS mux: 1 + 16 + 1 + 1 = 19 byte, tanpa
                // port/address. Byte ke-20 di stream harus sudah
                // metaLen frame mux pertama.
                val head = input.readExactBytes(19)
                headerBytes.addAll(head.toList())
                val parsed = VlessCrypto.parseRequestHeader(head)
                assertArrayEquals(AddrCodec.parseUuidBytes(uuid), parsed.uuidBytes)
                if (parsed.target != null) throw AssertionError("header mux tidak boleh membawa target")
                var headerSent = false
                var endsSeen = 0
                while (endsSeen < expectedEnds) {
                    val f = try {
                        readTestFrameStatic(input)
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
                            output.write(byteArrayOf(0x00, 0x00))
                            output.flush()
                            headerSent = true
                        }
                        val frame = encodeTestFrameStatic(
                            f.id, Mux.STATUS_KEEP, Mux.OPTION_DATA, f.data,
                        )
                        output.write(frame)
                        output.flush()
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
        }, "vless-mux-stub").apply { isDaemon = true }

        companion object {
            // Static supaya bisa dipakai dari thread (tanpa outer).
            fun readTestFrameStatic(input: InputStream): TestFrame {
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

            fun encodeTestFrameStatic(id: Int, status: Int, option: Int, data: ByteArray?): ByteArray {
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
        }
    }

    private fun vlessItem() = ProfileItem(
        configType = ConfigType.VLESS,
        address = "example.com", port = 443,
        uuid = uuid, method = "none",
        network = "tcp",
    )

    private fun ladderFor(pipes: PipePair): LadderStream = LadderStream(
        pipes.clientIn, pipes.clientOut,
        onClose = {
            runCatching { pipes.clientIn.close() }
            runCatching { pipes.clientOut.close() }
        },
        onHandshakeDone = {},
    )

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `header vless mux tanpa address dan dua dial berbagi satu koneksi`() {
        val pipes = PipePair()
        val ladderCalls = AtomicInteger(0)
        val server = FakeMuxServer(pipes, uuid, 2)
        server.thread.start()
        val client = VlessClient(
            vlessItem(),
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = { _, _ ->
                ladderCalls.incrementAndGet()
                ladderFor(pipes)
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
            assertEquals(1, ladderCalls.get(), "ladder harus dibuka sekali")
            // Header: version 0, UUID, addonLen 0, command Mux —
            // tepat 19 byte, tanpa port/address.
            assertEquals(19, server.headerBytes.size)
            assertEquals(0x00, server.headerBytes[0].toInt())
            assertEquals(0x00, server.headerBytes[17].toInt())
            assertEquals(VlessCrypto.CMD_MUX.toInt(), server.headerBytes[18].toInt() and 0xFF)
            // Header mux di-parse: target null.
            val parsed = VlessCrypto.parseRequestHeader(server.headerBytes.toByteArray())
            assertEquals(null, parsed.target)
            assertEquals(2, server.news.size)
            assertEquals("a.example.com", server.news[0].targetHost)
            assertEquals("b.example.com", server.news[1].targetHost)
            assertEquals(2, server.ends.size)
        } finally {
            client.close()
        }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `probe dial vless mux berhasil`() {
        val pipes = PipePair()
        val probeBody = "probe-bytes".toByteArray()
        val server = FakeMuxServer(pipes, uuid, 1)
        server.thread.start()
        val client = VlessClient(
            vlessItem(),
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = { _, _ -> ladderFor(pipes) },
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
            assertEquals(1, server.news.size)
            assertArrayEquals(probeBody, server.news.first().data)
        } finally {
            client.close()
        }
    }

    @Test
    fun `header vless mux build dan parse tanpa target`() {
        val header = VlessCrypto.buildRequestHeader(uuid, "a.example.com", 80, VlessCrypto.CMD_MUX)
        assertEquals(19, header.size, "header mux harus 19 byte (tanpa address)")
        assertEquals(VlessCrypto.CMD_MUX, header[18])
        val parsed = VlessCrypto.parseRequestHeader(header)
        assertArrayEquals(AddrCodec.parseUuidBytes(uuid), parsed.uuidBytes)
        assertEquals(null, parsed.target)
        // Header TCP tetap membawa target seperti dulu.
        val tcp = VlessCrypto.buildRequestHeader(uuid, "a.example.com", 80)
        assertTrue(tcp.size > 19)
        assertEquals("a.example.com", VlessCrypto.parseRequestHeader(tcp).target?.host)
    }
}
