package com.taptap.ng.core.slowdns

import java.io.IOException
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * In-memory tests for [SmuxSession]/[SmuxStream]: two sessions connected
 * by cross-wired [PipedInputStream]/[PipedOutputStream] pairs. No sockets,
 * no network. One side is created as the client (odd stream IDs from 1),
 * the other as the server (even IDs from 2), mirroring a real smux peer.
 */
@Timeout(30)
class SmuxTest {

    private val sessions = mutableListOf<SmuxSession>()

    @AfterEach
    fun tearDown() {
        for (s in sessions) {
            try { s.close() } catch (_: Exception) { }
        }
        sessions.clear()
    }

    private data class Pair(
        val client: SmuxSession,
        val server: SmuxSession,
    )

    private fun newPair(config: SmuxConfig = SmuxConfig()): Pair {
        val c2sOut = PipedOutputStream()
        val c2sIn = PipedInputStream(c2sOut, 65536)
        val s2cOut = PipedOutputStream()
        val s2cIn = PipedInputStream(s2cOut, 65536)
        val client = SmuxSession(s2cIn, c2sOut, config, true)
        val server = SmuxSession(c2sIn, s2cOut, config, false)
        sessions.add(client)
        sessions.add(server)
        return Pair(client, server)
    }

    private fun readFully(input: java.io.InputStream, buf: ByteArray) {
        var pos = 0
        while (pos < buf.size) {
            val r = input.read(buf, pos, buf.size - pos)
            if (r < 0) throw IOException("EOF while reading ${buf.size} bytes, got $pos")
            pos += r
        }
    }

    private fun pattern(size: Int): ByteArray =
        ByteArray(size) { i -> ((i * 31 + 7) % 251).toByte() }

    @Test
    fun `SYN frame has the exact smux wire format`() {
        // Raw check without a peer session: ver=2, cmd=SYN(0), len=0, sid=1 (LE).
        val dummyOut = PipedOutputStream()
        val dummyIn = PipedInputStream(dummyOut, 1024)
        val out = PipedOutputStream()
        val rawIn = PipedInputStream(out, 1024)
        val session = SmuxSession(dummyIn, out, SmuxConfig(), true)
        sessions.add(session)
        session.openStream()
        val header = ByteArray(8)
        readFully(rawIn, header)
        assertArrayEquals(byteArrayOf(2, 0, 0, 0, 1, 0, 0, 0), header)
    }

    @Test
    fun `echo over an accepted stream`() {
        val (client, server) = newPair()
        val clientStream = client.openStream()
        val serverStream = server.acceptStream(5_000)
        clientStream.output.write("hello".toByteArray(Charsets.UTF_8))
        val buf = ByteArray(5)
        readFully(serverStream.input, buf)
        assertEquals("hello", String(buf, Charsets.UTF_8))
        serverStream.output.write(buf, 0, buf.size)
        val echo = ByteArray(5)
        readFully(clientStream.input, echo)
        assertEquals("hello", String(echo, Charsets.UTF_8))
    }

    @Test
    fun `large transfer both directions verifies content`() {
        val (client, server) = newPair()
        val data = pattern(1024 * 1024)
        val clientStream = client.openStream()
        val serverStream = server.acceptStream(5_000)

        // Client -> server (1 MB; exceeds the 256 KB initial peer window,
        // so this exercises UPD window updates + 32 KB frame splitting).
        val writerDone = CountDownLatch(1)
        var writeErr: Throwable? = null
        Thread {
            try { clientStream.output.write(data) } catch (e: Throwable) { writeErr = e } finally { writerDone.countDown() }
        }.apply { isDaemon = true }.start()
        val received = ByteArray(data.size)
        readFully(serverStream.input, received)
        assertTrue(writerDone.await(10, TimeUnit.SECONDS), "client write did not finish")
        assertEquals(null, writeErr)
        assertArrayEquals(data, received)

        // Server -> client on the same stream.
        val back = pattern(1024 * 1024)
        val writer2Done = CountDownLatch(1)
        var write2Err: Throwable? = null
        Thread {
            try { serverStream.output.write(back) } catch (e: Throwable) { write2Err = e } finally { writer2Done.countDown() }
        }.apply { isDaemon = true }.start()
        val received2 = ByteArray(back.size)
        readFully(clientStream.input, received2)
        assertTrue(writer2Done.await(10, TimeUnit.SECONDS), "server write did not finish")
        assertEquals(null, write2Err)
        assertArrayEquals(back, received2)
    }

    @Test
    fun `closing output signals EOF after buffered data is drained`() {
        val (client, server) = newPair()
        val clientStream = client.openStream()
        val serverStream = server.acceptStream(5_000)
        clientStream.output.write("abc".toByteArray(Charsets.UTF_8))
        // Data still flows back before any FIN (local half-close keeps reading).
        serverStream.output.write("y".toByteArray(Charsets.UTF_8))
        val reply = ByteArray(1)
        readFully(clientStream.input, reply)
        assertEquals("y", String(reply, Charsets.UTF_8))
        clientStream.output.close() // sends FIN
        val buf = ByteArray(3)
        readFully(serverStream.input, buf)
        assertEquals("abc", String(buf, Charsets.UTF_8))
        assertEquals(-1, serverStream.input.read())
        // As in smux writeV2, writing after the peer's FIN is refused (EOF).
        assertThrows(IOException::class.java) {
            serverStream.output.write("x".toByteArray(Charsets.UTF_8))
        }
    }

    @Test
    fun `session close unblocks a blocked read and openStream throws`() {
        val (client, server) = newPair()
        val clientStream = client.openStream()
        val serverStream = server.acceptStream(5_000)
        val readDone = CountDownLatch(1)
        var readResult = -2
        Thread {
            readResult = try { clientStream.input.read() } catch (_: Exception) { -3 }
            readDone.countDown()
        }.apply { isDaemon = true }.start()
        Thread.sleep(200)
        client.close()
        assertTrue(readDone.await(5, TimeUnit.SECONDS), "blocked read was not unblocked")
        assertEquals(-1, readResult)
        assertThrows(IOException::class.java) { client.openStream() }
        assertTrue(client.isClosed)
        // The peer's recvLoop hits EOF on the closed pipe, so it closes too
        // and its blocked stream read also unblocks with EOF.
        assertEquals(-1, serverStream.input.read(ByteArray(1)))
    }

    @Test
    fun `read deadline throws SocketTimeoutException`() {
        val (client, server) = newPair()
        client.openStream()
        val serverStream = server.acceptStream(5_000)
        serverStream.readDeadlineMs = 200
        assertThrows(SocketTimeoutException::class.java) {
            serverStream.input.read(ByteArray(16))
        }
        serverStream.readDeadlineMs = 0
    }

    @Test
    fun `accept times out when no stream arrives`() {
        val (_, server) = newPair()
        assertThrows(SocketTimeoutException::class.java) {
            server.acceptStream(200)
        }
    }

    @Test
    fun `keepalive NOP frames are sent periodically`() {
        val config = SmuxConfig(keepAliveIntervalMs = 200, keepAliveTimeoutMs = 10_000)
        val c2sOut = PipedOutputStream()
        val c2sIn = PipedInputStream(c2sOut, 65536)
        val s2cOut = PipedOutputStream()
        val s2cIn = PipedInputStream(s2cOut, 65536)
        val bytesWritten = AtomicLong(0)
        val countingOut = object : OutputStream() {
            override fun write(b: Int) { c2sOut.write(b); bytesWritten.incrementAndGet() }
            override fun write(b: ByteArray, off: Int, len: Int) {
                c2sOut.write(b, off, len); bytesWritten.addAndGet(len.toLong())
            }
            override fun flush() { c2sOut.flush() }
            override fun close() { c2sOut.close() }
        }
        val client = SmuxSession(s2cIn, countingOut, config, true)
        val server = SmuxSession(c2sIn, s2cOut, config, false)
        sessions.add(client)
        sessions.add(server)
        val before = bytesWritten.get()
        Thread.sleep(700)
        // At a 200 ms interval at least two 8-byte NOP frames must have been sent.
        assertTrue(bytesWritten.get() - before >= 16,
            "expected >= 16 NOP bytes, got ${bytesWritten.get() - before}")
        assertTrue(!client.isClosed && !server.isClosed, "sessions must stay alive while NOPs flow")
    }

    @Test
    fun `keepalive timeout closes an idle session`() {
        val config = SmuxConfig(keepAliveIntervalMs = 10_000, keepAliveTimeoutMs = 300)
        val (client, _) = newPair(config)
        val deadline = System.currentTimeMillis() + 2_000
        while (!client.isClosed && System.currentTimeMillis() < deadline) {
            Thread.sleep(50)
        }
        assertTrue(client.isClosed, "idle session was not closed by the keepalive timeout")
    }

    @Test
    fun `concurrent streams echo independently`() {
        val (client, server) = newPair()
        val done = CountDownLatch(4)
        val errors = mutableListOf<Throwable>()
        for (i in 0 until 4) {
            Thread {
                try {
                    val cs = client.openStream()
                    val msg = "stream-$i".toByteArray(Charsets.UTF_8)
                    cs.output.write(msg)
                    val buf = ByteArray(msg.size)
                    readFully(cs.input, buf)
                    assertArrayEquals(msg, buf)
                } catch (e: Throwable) {
                    synchronized(errors) { errors.add(e) }
                } finally { done.countDown() }
            }.apply { isDaemon = true }.start()
            Thread {
                try {
                    val ss = server.acceptStream(5_000)
                    val buf = ByteArray(8)
                    readFully(ss.input, buf)
                    ss.output.write(buf, 0, buf.size)
                } catch (e: Throwable) {
                    synchronized(errors) { errors.add(e) }
                }
            }.apply { isDaemon = true }.start()
        }
        assertTrue(done.await(10, TimeUnit.SECONDS), "concurrent echo did not finish: $errors")
        assertTrue(errors.isEmpty(), "echo errors: $errors")
    }
}
