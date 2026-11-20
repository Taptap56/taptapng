package com.taptap.ng.proto
import com.taptap.ng.core.proto.*

import com.taptap.ng.core.Base64Util
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.net.ServerSocket
import java.security.MessageDigest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * WebSocket client tests against a minimal fake server on loopback:
 * handshake, binary frame echo, fragmented message reassembly,
 * ping -> pong, and handshake rejection.
 * Loopback uses ::1, not 127.0.0.1: the dev VM's sandbox blackholes
 * JVM client connects to IPv4 loopback, while ::1 connects fine.
 */
class WsTransportTest {

    @Test
    fun `ws handshake plus echo round-trip`() {
        val server = ServerSocket(0)
        val port = server.localPort
        var serverError: Throwable? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val request = readHttpRequest(input)
                assertTrue(request.contains("Upgrade: websocket"))
                assertTrue(request.contains("Sec-WebSocket-Version: 13"))
                val key = request.lines()
                    .first { it.startsWith("Sec-WebSocket-Key:", ignoreCase = true) }
                    .substringAfter(":").trim()
                val accept = Base64Util.encode(
                    MessageDigest.getInstance("SHA-1").digest(
                        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.UTF_8),
                    ),
                )
                output.write(
                    ("HTTP/1.1 101 Switching Protocols\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Sec-WebSocket-Accept: $accept\r\n\r\n")
                        .toByteArray(Charsets.UTF_8),
                )
                output.flush()
                // Echo one binary frame back unmasked.
                val (_, _, payload) = readFrame(input)
                writeFrame(output, fin = true, opcode = 0x02, payload = payload, mask = false)
                // Send a ping; expect a pong with the same payload.
                writeFrame(output, fin = true, opcode = 0x09, payload = "ping?".toByteArray(), mask = false)
                val (_, pongOpcode, pongPayload) = readFrame(input)
                assertEquals(0x0A, pongOpcode)
                assertArrayEquals("ping?".toByteArray(), pongPayload)
                // Send a fragmented message: "frag" + "mented".
                writeFrame(output, fin = false, opcode = 0x02, payload = "frag".toByteArray(), mask = false)
                writeFrame(output, fin = true, opcode = 0x00, payload = "mented".toByteArray(), mask = false)
            } catch (e: Throwable) {
                serverError = e
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val socket = java.net.Socket("::1", port)
        socket.soTimeout = 5_000
        try {
            val ws = WsTransport.connect(socket.getInputStream(), socket.getOutputStream(), "[::1]:$port", "/ws")
            ws.output.write("hello-ws".toByteArray())
            ws.output.flush()
            val echo = ByteArray(8)
            var filled = 0
            while (filled < echo.size) {
                val r = ws.input.read(echo, filled, echo.size - filled)
                if (r == -1) break
                filled += r
            }
            assertEquals(8, filled)
            assertArrayEquals("hello-ws".toByteArray(), echo)
            // The ping was answered by the client automatically; now the
            // fragmented message arrives reassembled.
            val frag = ByteArray(10)
            filled = 0
            while (filled < frag.size) {
                val r = ws.input.read(frag, filled, frag.size - filled)
                if (r == -1) break
                filled += r
            }
            assertEquals(10, filled)
            assertArrayEquals("fragmented".toByteArray(), frag)
            ws.close()
        } finally {
            runCatching { socket.close() }
        }
        serverThread.join(5_000)
        serverError?.let { throw AssertionError("Fake WS server gagal", it) }
    }

    @Test
    fun `ws handshake rejection throws`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                readHttpRequest(socket.getInputStream())
                socket.getOutputStream().write(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
                        .toByteArray(Charsets.UTF_8),
                )
                socket.getOutputStream().flush()
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val socket = java.net.Socket("::1", port)
        socket.soTimeout = 5_000
        try {
            assertThrows(Exception::class.java) {
                WsTransport.connect(socket.getInputStream(), socket.getOutputStream(), "[::1]", "/")
            }
        } finally {
            runCatching { socket.close() }
        }
        serverThread.join(5_000)
    }

    private fun readHttpRequest(input: InputStream): String {
        val out = ByteArrayOutputStream()
        val tail = ArrayDeque<Int>()
        while (true) {
            val b = input.read()
            if (b == -1) throw EOFException("HTTP request terpotong")
            out.write(b)
            tail.addLast(b)
            if (tail.size > 4) tail.removeFirst()
            if (tail.size == 4 && tail[0] == '\r'.code && tail[1] == '\n'.code &&
                tail[2] == '\r'.code && tail[3] == '\n'.code
            ) {
                return out.toString(Charsets.UTF_8)
            }
        }
    }

    /** Minimal server-side frame reader (client frames are masked). */
    private fun readFrame(input: InputStream): Triple<Boolean, Int, ByteArray> {
        val b0 = input.read()
        if (b0 == -1) throw EOFException("Frame terpotong")
        val b1 = input.read()
        if (b1 == -1) throw EOFException("Frame terpotong")
        val fin = (b0 and 0x80) != 0
        val opcode = b0 and 0x0F
        var len = (b1 and 0x7F).toLong()
        if (len == 126L) {
            val ext = input.readExactBytes(2)
            len = ((ext[0].toLong() and 0xFF) shl 8) or (ext[1].toLong() and 0xFF)
        } else if (len == 127L) {
            val ext = input.readExactBytes(8)
            len = 0
            for (i in 0 until 8) len = (len shl 8) or (ext[i].toLong() and 0xFF)
        }
        val mask = if ((b1 and 0x80) != 0) input.readExactBytes(4) else null
        val payload = input.readExactBytes(len.toInt())
        if (mask != null) {
            for (i in payload.indices) {
                payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
            }
        }
        return Triple(fin, opcode, payload)
    }

    /** Minimal server-side frame writer (server frames are unmasked). */
    private fun writeFrame(
        output: java.io.OutputStream,
        fin: Boolean,
        opcode: Int,
        payload: ByteArray,
        mask: Boolean,
    ) {
        val header = ByteArrayOutputStream()
        header.write((if (fin) 0x80 else 0x00) or opcode)
        if (payload.size < 126) {
            header.write(if (mask) 0x80 or payload.size else payload.size)
        } else {
            header.write(if (mask) 0x80 or 126 else 126)
            header.write((payload.size ushr 8) and 0xFF)
            header.write(payload.size and 0xFF)
        }
        output.write(header.toByteArray())
        output.write(payload)
        output.flush()
    }
}
