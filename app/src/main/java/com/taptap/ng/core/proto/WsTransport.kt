package com.taptap.ng.core.proto

import com.taptap.ng.core.Base64Util
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

/**
 * Minimal WebSocket client (RFC 6455), written from scratch — no OkHttp,
 * to keep the APK small. Works over plain TCP or over an SSLSocket: the
 * caller passes the already-connected streams.
 *
 * - Handshake: GET + Host + Upgrade + Sec-WebSocket-Key/Version 13;
 *   the 101 response is read byte-by-byte so no frame bytes are ever
 *   swallowed by a buffered reader. Sec-WebSocket-Accept is verified.
 * - Frames: client frames are always masked; server frames are read and
 *   reassembled across continuations; ping is answered with pong, a close
 *   frame ends the stream. Single write() calls become one binary frame
 *   each (max 16 KiB payload per frame).
 * - The raw output is shared between the data writer and the pong
 *   sender (input thread), so every raw write takes [writeLock].
 */
object WsTransport {

    private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    private const val MAX_FRAME_PAYLOAD = 16 * 1024 * 1024
    private const val MAX_HEADER_BYTES = 8192
    private const val SEND_FRAME_PAYLOAD = 16 * 1024

    class WsStream internal constructor(
        rawIn: InputStream,
        rawOut: OutputStream,
        /** v1.0.16: per-connection speed stats (null = off). */
        stats: SpeedStats? = null,
    ) {
        private val writeLock = Any()
        val input: InputStream = WsInputStream(rawIn, rawOut, writeLock, stats)
        val output: OutputStream = WsOutputStream(rawOut, writeLock)

        /** Send a Close frame (best effort). Does NOT close the raw socket. */
        fun close() {
            runCatching { (output as WsOutputStream).sendClose() }
        }
    }

    fun connect(
        rawIn: InputStream,
        rawOut: OutputStream,
        host: String,
        path: String,
        stats: SpeedStats? = null,
    ): WsStream {
        val keyBytes = Crypto.randomBytes(16)
        val key = Base64Util.encode(keyBytes)
        val request = buildString {
            append("GET ").append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(host).append("\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(key).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("\r\n")
        }
        rawOut.write(request.toByteArray(Charsets.UTF_8))
        rawOut.flush()
        val headerBytes = readHttpHeader(rawIn)
        val header = String(headerBytes, Charsets.UTF_8)
        val lines = header.split("\r\n")
        val statusLine = lines.firstOrNull() ?: ""
        if (!statusLine.contains("101")) {
            throw IOException("WebSocket handshake gagal: $statusLine")
        }
        val accept = lines.firstOrNull { it.startsWith("Sec-WebSocket-Accept:", ignoreCase = true) }
            ?.substringAfter(":", "")
            ?.trim()
            ?: throw IOException("WebSocket handshake tanpa Sec-WebSocket-Accept")
        val expected = Base64Util.encode(
            MessageDigest.getInstance("SHA-1")
                .digest((key + WS_GUID).toByteArray(Charsets.UTF_8)),
        )
        if (!MessageDigest.isEqual(accept.toByteArray(Charsets.UTF_8), expected.toByteArray(Charsets.UTF_8))) {
            throw IOException("WebSocket Sec-WebSocket-Accept tidak cocok")
        }
        return WsStream(rawIn, rawOut, stats)
    }

    /** Read HTTP response headers byte-by-byte until the blank line. */
    private fun readHttpHeader(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val tail = ArrayDeque<Int>()
        while (true) {
            val b = input.read()
            if (b == -1) throw EOFException("WebSocket handshake terpotong (EOF)")
            out.write(b)
            if (out.size() > MAX_HEADER_BYTES) {
                throw IOException("WebSocket handshake header terlalu besar")
            }
            tail.addLast(b)
            if (tail.size > 4) tail.removeFirst()
            if (tail.size == 4 &&
                tail[0] == '\r'.code && tail[1] == '\n'.code &&
                tail[2] == '\r'.code && tail[3] == '\n'.code
            ) {
                return out.toByteArray()
            }
        }
    }

    /** Read exactly [n] bytes or throw EOFException. */
    internal fun readExact(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var filled = 0
        while (filled < n) {
            val r = input.read(out, filled, n - filled)
            if (r == -1) throw EOFException("WebSocket frame terpotong (EOF)")
            filled += r
        }
        return out
    }

    internal fun writeFrame(
        rawOut: OutputStream,
        writeLock: Any,
        fin: Boolean,
        opcode: Int,
        payload: ByteArray,
    ) {
        val mask = Crypto.randomBytes(4)
        val header = ByteArrayOutputStream()
        header.write((if (fin) 0x80 else 0x00) or opcode)
        val len = payload.size
        when {
            len < 126 -> header.write(0x80 or len)
            len < 65536 -> {
                header.write(0x80 or 126)
                header.write((len ushr 8) and 0xFF)
                header.write(len and 0xFF)
            }
            else -> {
                header.write(0x80 or 127)
                for (i in 7 downTo 0) header.write((len ushr (8 * i)) and 0xFF)
            }
        }
        header.write(mask)
        val masked = ByteArray(len)
        for (i in payload.indices) {
            masked[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
        }
        synchronized(writeLock) {
            rawOut.write(header.toByteArray())
            rawOut.write(masked)
            rawOut.flush()
        }
    }

    private class WsOutputStream(
        private val rawOut: OutputStream,
        private val writeLock: Any,
    ) : OutputStream() {

        override fun write(b: Int) = write(byteArrayOf(b.toByte()))

        override fun write(b: ByteArray, off: Int, len: Int) {
            var pos = off
            var remaining = len
            while (remaining > 0) {
                val take = minOf(SEND_FRAME_PAYLOAD, remaining)
                val chunk = b.copyOfRange(pos, pos + take)
                writeFrame(rawOut, writeLock, fin = true, opcode = 0x02, payload = chunk)
                pos += take
                remaining -= take
            }
        }

        fun sendClose() {
            runCatching {
                writeFrame(rawOut, writeLock, fin = true, opcode = 0x08, payload = ByteArray(0))
            }
        }

        override fun close() = sendClose()
    }

    private class WsInputStream(
        private val rawIn: InputStream,
        private val rawOut: OutputStream,
        private val writeLock: Any,
        /** v1.0.16: per-connection speed stats (null = off). */
        private val stats: SpeedStats? = null,
    ) : InputStream() {

        private var messageBuf: ByteArray = ByteArray(0)
        private var messagePos = 0
        private var peerClosed = false
        private var closed = false

        /** Read one full message (reassembling continuations). */
        private fun readMessage(): ByteArray? {
            if (peerClosed) return null
            val out = ByteArrayOutputStream()
            var first = true
            while (true) {
                val (fin, opcode, payload) = readFrame() ?: return null
                when (opcode) {
                    0x09 -> { // ping -> pong with the same payload
                        runCatching {
                            writeFrame(rawOut, writeLock, fin = true, opcode = 0x0A, payload = payload)
                        }
                        continue
                    }
                    0x0A -> continue // pong: ignore
                    0x08 -> { // close: echo it back once, then EOF
                        peerClosed = true
                        runCatching {
                            writeFrame(rawOut, writeLock, fin = true, opcode = 0x08, payload = payload)
                        }
                        return if (out.size() > 0) out.toByteArray() else null
                    }
                    0x00, 0x01, 0x02 -> {
                        if (first && opcode == 0x00) {
                            throw IOException("WebSocket continuation tanpa frame awal")
                        }
                        first = false
                        out.write(payload)
                        if (out.size() > MAX_FRAME_PAYLOAD) {
                            throw IOException("WebSocket message terlalu besar")
                        }
                        if (fin) return out.toByteArray()
                    }
                    else -> throw IOException("WebSocket opcode tidak dikenal: $opcode")
                }
            }
        }

        private fun readFrame(): Triple<Boolean, Int, ByteArray>? {
            val b0 = rawIn.read()
            if (b0 == -1) return null
            val b1 = rawIn.read()
            if (b1 == -1) throw EOFException("WebSocket frame terpotong (EOF)")
            val fin = (b0 and 0x80) != 0
            val opcode = b0 and 0x0F
            val masked = (b1 and 0x80) != 0
            var len = (b1 and 0x7F).toLong()
            if (len == 126L) {
                val ext = readExact(rawIn, 2)
                len = ((ext[0].toLong() and 0xFF) shl 8) or (ext[1].toLong() and 0xFF)
            } else if (len == 127L) {
                val ext = readExact(rawIn, 8)
                len = 0
                for (i in 0 until 8) len = (len shl 8) or (ext[i].toLong() and 0xFF)
            }
            if (len < 0 || len > MAX_FRAME_PAYLOAD) {
                throw IOException("WebSocket frame terlalu besar: $len")
            }
            val mask = if (masked) readExact(rawIn, 4) else null
            val payload = readExact(rawIn, len.toInt())
            if (mask != null) {
                for (i in payload.indices) {
                    payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
                }
            }
            // v1.0.16: count data frames (continuation/text/binary)
            // — with the bytes delivered, this shows the WS frame
            // granularity (a 16 KiB frame per read vs many small
            // ones). Control frames (ping/pong/close) are not data.
            if (opcode == 0x00 || opcode == 0x01 || opcode == 0x02) {
                stats?.wsFrames?.incrementAndGet()
            }
            return Triple(fin, opcode, payload)
        }

        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) == -1) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (closed) return -1
            // v1.0.16: parse-only time = this read's wall time minus
            // the raw transport read time already counted in tls+net
            // (TimedInputStream). A return from the buffered message
            // has no raw read, so its whole wall is parse/copy.
            val t0 = if (stats != null) System.nanoTime() else 0L
            val tlsBefore = stats?.tlsNetNs?.get() ?: 0L
            val result: Int = run {
                if (messagePos >= messageBuf.size) {
                    val msg = readMessage() ?: return@run -1
                    messageBuf = msg
                    messagePos = 0
                }
                val take = minOf(len, messageBuf.size - messagePos)
                messageBuf.copyInto(b, off, messagePos, messagePos + take)
                messagePos += take
                take
            }
            stats?.let {
                val own = (System.nanoTime() - t0) - (it.tlsNetNs.get() - tlsBefore)
                if (own > 0) it.wsNs.addAndGet(own)
            }
            return result
        }

        override fun available(): Int = messageBuf.size - messagePos

        override fun close() {
            closed = true
        }
    }
}
