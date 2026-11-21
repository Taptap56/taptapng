package com.taptap.ng.proto

import com.taptap.ng.core.proto.AddrCodec
import com.taptap.ng.core.proto.Mux
import com.taptap.ng.core.proto.MuxConfig
import com.taptap.ng.core.proto.MuxConnection
import com.taptap.ng.core.proto.MuxConnectionPool
import com.taptap.ng.core.proto.MuxUdpSession
import com.taptap.ng.core.proto.readExactBytes
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.6 (M6): XUDP — UDP di atas mux. Stub echo independen
 * (rakit/urai frame byte manual, tanpa Mux.encodeMeta): frame New
 * sesi UDP harus membawa network 0x02, tiap datagram satu frame,
 * dan balasan tiba utuh lewat pollDatagram (bukan byte stream).
 */
@Timeout(30)
class MuxXudpTest {

    private class PipePair(pipeSize: Int = 65536) {
        val clientOut = PipedOutputStream()
        val serverIn = PipedInputStream(clientOut, pipeSize)
        val serverOut = PipedOutputStream()
        val clientIn = PipedInputStream(serverOut, pipeSize)
    }

    data class TestFrame(
        val id: Int,
        val status: Int,
        val option: Int,
        val network: Int,
        val targetHost: String?,
        val targetPort: Int,
        val data: ByteArray?,
    )

    companion object {
        fun readTestFrame(input: InputStream): TestFrame {
            val lenBytes = input.readExactBytes(2)
            val metaLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
            if (metaLen < 4 || metaLen > 512) throw IOException("stub: metaLen tidak valid: $metaLen")
            val meta = input.readExactBytes(metaLen)
            val id = ((meta[0].toInt() and 0xFF) shl 8) or (meta[1].toInt() and 0xFF)
            val status = meta[2].toInt() and 0xFF
            val option = meta[3].toInt() and 0xFF
            var host: String? = null
            var port = 0
            var network = 0
            if (status == Mux.STATUS_NEW) {
                network = meta[4].toInt() and 0xFF
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
            return TestFrame(id, status, option, network, host, port, data)
        }

        fun writeTestFrame(output: OutputStream, id: Int, status: Int, option: Int, data: ByteArray?) {
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
    }

    /** Stub echo: tiap frame data dibalas ke session yang sama. */
    private class EchoStub(val pipes: PipePair) {
        val frames = java.util.Collections.synchronizedList(mutableListOf<TestFrame>())
        @Volatile var error: Throwable? = null
        val thread = Thread({
            try {
                while (true) {
                    val f = readTestFrame(pipes.serverIn)
                    frames.add(f)
                    if ((f.option and Mux.OPTION_DATA) != 0 && f.data != null) {
                        writeTestFrame(pipes.serverOut, f.id, Mux.STATUS_KEEP, Mux.OPTION_DATA, f.data)
                    }
                }
            } catch (_: EOFException) {
                // Pipa ditutup: akhir normal.
            } catch (e: IOException) {
                if (e.message != "Pipe closed" && e.message != "Pipe broken") error = e
            } catch (e: Throwable) {
                error = e
            }
        }, "mux-xudp-stub").apply { isDaemon = true }
    }

    @Test
    fun `frame New UDP membawa network 0x02`() {
        val encoded = Mux.encodeMeta(
            1, Mux.STATUS_NEW, Mux.OPTION_DATA,
            "8.8.8.8", 53, Mux.TARGET_NETWORK_UDP,
        )
        // meta[4] (byte ke-6 keseluruhan: 2 len + 2 id + status + option) = network.
        assertEquals(Mux.TARGET_NETWORK_UDP, encoded[6].toInt() and 0xFF)
        val meta = Mux.decodeMeta(encoded.inputStream())
        assertEquals(Mux.TARGET_NETWORK_UDP, meta.targetNetwork)
        assertEquals("8.8.8.8", meta.target?.host)
    }

    @Test
    fun `xudpSupported true bila mux nyala, false bila mati`() {
        assertTrue(MuxConfig(enabled = true).xudpSupported)
        assertEquals(false, MuxConfig.DISABLED.xudpSupported)
    }

    @Test
    fun `datagram UDP di-echo utuh lewat sesi mux`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes)
        stub.thread.start()
        val conn = MuxConnection(pipes.clientIn, pipes.clientOut, onClose = {}, maxConcurrency = 8)
        try {
            val session = conn.tryOpenUdpSession("8.8.8.8", 53)!!
            val udp = MuxUdpSession(session)
            val first = "quic-hello".toByteArray()
            val second = "dns-query".toByteArray()
            udp.send(first)
            udp.send(second)
            assertArrayEquals(first, udp.receive(5000))
            assertArrayEquals(second, udp.receive(5000))
            // Batas datagram terjaga: dua kiriman tidak bergabung.
            assertNull(udp.receive(200))
            // Server melihat SATU frame New UDP + SATU Keep.
            val news = stub.frames.filter { it.status == Mux.STATUS_NEW }
            assertEquals(1, news.size)
            assertEquals(Mux.TARGET_NETWORK_UDP, news[0].network)
            assertEquals("8.8.8.8", news[0].targetHost)
            assertEquals(53, news[0].targetPort)
            udp.close()
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    @Test
    fun `pool openUdpSession membuka sesi UDP`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes)
        stub.thread.start()
        val pool = MuxConnectionPool(8) {
            MuxConnection(pipes.clientIn, pipes.clientOut, onClose = {}, maxConcurrency = 8)
        }
        try {
            val (_, session) = pool.openUdpSession("1.1.1.1", 443)
            assertTrue(session.isUdp)
            val udp = MuxUdpSession(session)
            udp.send("pool-ping".toByteArray())
            assertArrayEquals("pool-ping".toByteArray(), udp.receive(5000))
            udp.close()
        } finally {
            pool.close()
            stub.thread.join(5_000)
        }
        stub.error?.let { throw AssertionError("Stub gagal", it) }
    }

    @Test
    fun `datagram di atas 8 KiB ditolak`() {
        val pipes = PipePair()
        val stub = EchoStub(pipes)
        stub.thread.start()
        val conn = MuxConnection(pipes.clientIn, pipes.clientOut, onClose = {}, maxConcurrency = 8)
        try {
            val session = conn.tryOpenUdpSession("8.8.8.8", 53)!!
            val udp = MuxUdpSession(session)
            assertThrows(IllegalArgumentException::class.java) {
                udp.send(ByteArray(Mux.MAX_FRAME_DATA + 1))
            }
            udp.close()
        } finally {
            conn.close()
            stub.thread.join(5_000)
        }
    }
}
