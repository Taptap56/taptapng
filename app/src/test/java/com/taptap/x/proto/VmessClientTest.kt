package com.taptap.x.proto
import com.taptap.x.core.DialLog
import com.taptap.x.core.proto.*

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * End-to-end VMess over a loopback fake server. The fake server
 * re-implements the server side from the spec (header open, chunk
 * read/write with the response keys) — it shares only the crypto
 * primitives, not the client's framing code.
 * Loopback uses ::1, not 127.0.0.1: the dev VM's sandbox blackholes
 * JVM client connects to IPv4 loopback, while ::1 connects fine.
 */
class VmessClientTest {

    private val uuid = "de305d54-75b4-431b-adb2-eb6b9e546014"

    @Test
    fun `vmess dial relays bytes both ways aes-128-gcm`() {
        vmessRelay("aes-128-gcm", VmessSecurity.AES_128_GCM)
    }

    @Test
    fun `vmess dial relays bytes both ways chacha20-poly1305`() {
        vmessRelay("chacha20-poly1305", VmessSecurity.CHACHA20_POLY1305)
    }

    private fun vmessRelay(securityName: String, security: VmessSecurity) {
        val server = ServerSocket(0)
        val port = server.localPort
        var serverError: Throwable? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val opened = VmessCrypto.openRequestHeader(VmessCrypto.cmdKey(uuid), input)
                assertEquals("example.com", opened.header.target.host)
                assertEquals(443, opened.header.target.port)
                assertEquals(security, opened.header.security)
                val session = VmessSession(
                    requestBytes = ByteArray(0),
                    bodyKey = opened.header.bodyKey,
                    bodyIV = opened.header.bodyIV,
                    responseBodyKey = Crypto.sha256(opened.header.bodyKey).copyOfRange(0, 16),
                    responseBodyIV = Crypto.sha256(opened.header.bodyIV).copyOfRange(0, 16),
                    responseV = opened.header.responseV,
                    security = security,
                )
                // Response header goes out immediately (no body wait).
                output.write(VmessCrypto.sealResponseHeader(session, session.responseV))
                output.flush()
                // Request direction state (client -> server).
                val reqNonce = VmessCrypto.ChunkNonce(session.bodyIV)
                val reqMask = Shake128(session.bodyIV)
                val clientPayload = readChunk(
                    input, session.bodyKey, reqNonce, reqMask, security,
                )
                assertArrayEquals("hello-from-client".toByteArray(), clientPayload)
                // Response direction state (server -> client).
                val respNonce = VmessCrypto.ChunkNonce(session.responseBodyIV)
                val respMask = Shake128(session.responseBodyIV)
                writeChunk(
                    output, session.responseBodyKey, respNonce, respMask, security,
                    "hello-from-server".toByteArray(),
                )
                // The client's empty termination chunk.
                val term = readChunk(input, session.bodyKey, reqNonce, reqMask, security)
                assertEquals(0, term.size)
            } catch (e: Throwable) {
                serverError = e
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            uuid = uuid, security = securityName,
            network = "tcp",
        )
        val client = VmessClient(item)
        val stream = client.dial("example.com", 443)
        try {
            stream.output.write("hello-from-client".toByteArray())
            stream.output.flush()
            val buf = ByteArray("hello-from-server".length)
            var filled = 0
            while (filled < buf.size) {
                val r = stream.input.read(buf, filled, buf.size - filled)
                if (r == -1) break
                filled += r
            }
            assertEquals(buf.size, filled)
            assertArrayEquals("hello-from-server".toByteArray(), buf)
        } finally {
            client.close()
        }
        serverThread.join(5_000)
        serverError?.let { throw AssertionError("Fake server gagal", it) }
    }

    @Test
    fun `second dial does not close the first stream`() {
        // v1.0.6: every client's dial() used to start with close(),
        // killing the previous stream — two apps connecting at once
        // killed the first session. Streams must stay open
        // independently. On v1.0.5 the write to the first stream
        // throws (socket closed by the second dial).
        val server = ServerSocket(0, 50, java.net.InetAddress.getByName("::1"))
        val port = server.localPort
        val received = java.util.Collections.synchronizedList(mutableListOf<String>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())
        val serverThreads = mutableListOf<Thread>()
        repeat(2) {
            val t = Thread {
                try {
                    val socket = server.accept()
                    socket.soTimeout = 5_000
                    val input = socket.getInputStream()
                    val output = socket.getOutputStream()
                    val opened = VmessCrypto.openRequestHeader(VmessCrypto.cmdKey(uuid), input)
                    val session = VmessSession(
                        requestBytes = ByteArray(0),
                        bodyKey = opened.header.bodyKey,
                        bodyIV = opened.header.bodyIV,
                        responseBodyKey = Crypto.sha256(opened.header.bodyKey).copyOfRange(0, 16),
                        responseBodyIV = Crypto.sha256(opened.header.bodyIV).copyOfRange(0, 16),
                        responseV = opened.header.responseV,
                        security = VmessSecurity.AES_128_GCM,
                    )
                    output.write(VmessCrypto.sealResponseHeader(session, session.responseV))
                    output.flush()
                    val reqNonce = VmessCrypto.ChunkNonce(session.bodyIV)
                    val reqMask = Shake128(session.bodyIV)
                    while (true) {
                        val payload = try {
                            readChunk(
                                input, session.bodyKey, reqNonce, reqMask,
                                VmessSecurity.AES_128_GCM,
                            )
                        } catch (e: Exception) {
                            break
                        }
                        if (payload.isEmpty()) break // termination chunk
                        received.add(String(payload, Charsets.UTF_8))
                    }
                } catch (e: Throwable) {
                    errors.add(e)
                }
            }
            t.isDaemon = true
            t.start()
            serverThreads.add(t)
        }
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            uuid = uuid, security = "aes-128-gcm",
            network = "tcp",
        )
        val client = VmessClient(item)
        val s1 = client.dial("example.com", 443)
        val s2 = client.dial("example.com", 443)
        try {
            s1.output.write("first".toByteArray())
            s1.output.flush()
            s2.output.write("second".toByteArray())
            s2.output.flush()
        } finally {
            runCatching { s1.close() }
            runCatching { s2.close() }
            client.close()
        }
        serverThreads.forEach { it.join(5_000) }
        runCatching { server.close() }
        errors.firstOrNull()?.let { throw AssertionError("Fake server gagal", it) }
        assertTrue(received.contains("first"), "server never got the first stream's bytes: $received")
        assertTrue(received.contains("second"), "server never got the second stream's bytes: $received")
    }

    @Test
    fun `vmess dial with wrong uuid fails on first read`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                // The header will not open with our key: close at once.
                runCatching {
                    VmessCrypto.openRequestHeader(VmessCrypto.cmdKey(uuid), socket.getInputStream())
                }
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            uuid = "11111111-2222-3333-4444-555555555555",
            security = "auto",
            network = "tcp",
        )
        // v1.0.12: the response header is read lazily — dial()
        // returns, and the bad UUID surfaces on the first read (EOF:
        // the server closed the connection instead of answering).
        val client = VmessClient(item)
        val stream = client.dial("example.com", 443)
        assertThrows(IOException::class.java) {
            stream.input.read()
        }
        runCatching { stream.close() }
        client.close()
        serverThread.join(5_000)
    }

    // v1.0.8, fix B: the real xray-core server does NOT send its
    // response header right after the request header — it buffers
    // the header and only flushes it once data flows from the
    // dispatch target (transferResponse reads link.Reader first).
    // The probe targets the entry itself (a TLS server that speaks
    // only when spoken to), so a probe with no body deadlocks into
    // a 10 s read timeout — the phone symptom in taptapx-5.txt.
    // These tests use an xray-like fake server: it waits for the
    // first body chunk BEFORE answering.

    @Test
    fun `probe dial succeeds against xray-like server that waits for the first body chunk`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val probeBody = ProbeBody.clientHello("example.com")
        var serverError: Throwable? = null
        var firstChunk: ByteArray? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val opened = VmessCrypto.openRequestHeader(VmessCrypto.cmdKey(uuid), input)
                val session = VmessSession(
                    requestBytes = ByteArray(0),
                    bodyKey = opened.header.bodyKey,
                    bodyIV = opened.header.bodyIV,
                    responseBodyKey = Crypto.sha256(opened.header.bodyKey).copyOfRange(0, 16),
                    responseBodyIV = Crypto.sha256(opened.header.bodyIV).copyOfRange(0, 16),
                    responseV = opened.header.responseV,
                    security = VmessSecurity.AES_128_GCM,
                )
                val reqNonce = VmessCrypto.ChunkNonce(session.bodyIV)
                val reqMask = Shake128(session.bodyIV)
                // xray-like: no response header until the first body
                // chunk arrives (the target's answer unblocks it).
                firstChunk = readChunk(
                    input, session.bodyKey, reqNonce, reqMask, VmessSecurity.AES_128_GCM,
                )
                output.write(VmessCrypto.sealResponseHeader(session, session.responseV))
                output.flush()
                // The probe closes the stream: empty termination chunk.
                val term = readChunk(
                    input, session.bodyKey, reqNonce, reqMask, VmessSecurity.AES_128_GCM,
                )
                assertEquals(0, term.size)
            } catch (e: Throwable) {
                serverError = e
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            uuid = uuid, security = "aes-128-gcm",
            network = "tcp",
        )
        val client = VmessClient(item)
        // On v1.0.7 dial() takes no probe body at all, so this call
        // does not even compile there; here it must complete.
        val stream = client.dial("example.com", 443, probeBody)
        runCatching { stream.close() }
        client.close()
        serverThread.join(5_000)
        assertTrue(!serverThread.isAlive, "fake server thread must finish")
        serverError?.let { throw AssertionError("Fake server gagal", it) }
        assertArrayEquals(probeBody, firstChunk)
    }

    // v1.0.12: the relay dial no longer reads the response header
    // in dial() — the xray-like server waits for the first body
    // chunk before flushing it, and the body can only be sent after
    // dial() returns (the forwarder sends the SYN-ACK first). So a
    // relay dial returns at once, and the 10 s timeout (if the app
    // never sends data) surfaces on the FIRST READ instead — the
    // phone symptom in taptapx-7.txt was dial() itself timing out
    // on every forwarder connection.

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `relay dial returns at once but first read times out against xray-like server with no body`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 15_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val opened = VmessCrypto.openRequestHeader(VmessCrypto.cmdKey(uuid), input)
                val session = VmessSession(
                    requestBytes = ByteArray(0),
                    bodyKey = opened.header.bodyKey,
                    bodyIV = opened.header.bodyIV,
                    responseBodyKey = Crypto.sha256(opened.header.bodyKey).copyOfRange(0, 16),
                    responseBodyIV = Crypto.sha256(opened.header.bodyIV).copyOfRange(0, 16),
                    responseV = opened.header.responseV,
                    security = VmessSecurity.AES_128_GCM,
                )
                val reqNonce = VmessCrypto.ChunkNonce(session.bodyIV)
                val reqMask = Shake128(session.bodyIV)
                // Waits for the first body chunk — a relay that never
                // sends a body never gets a response header.
                readChunk(
                    input, session.bodyKey, reqNonce, reqMask, VmessSecurity.AES_128_GCM,
                )
                output.write(VmessCrypto.sealResponseHeader(session, session.responseV))
                output.flush()
            } catch (_: Throwable) {
                // Expected: the client times out on its first read
                // (~10 s) and closes the transport (EOF), or the
                // server's own 15 s read timeout fires.
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            uuid = uuid, security = "aes-128-gcm",
            network = "tcp",
        )
        // No probe body: dial() must return at once (on v1.0.11 it
        // threw SocketTimeoutException here, ~10 s in).
        val client = VmessClient(item)
        val dialStart = System.currentTimeMillis()
        val stream = client.dial("example.com", 443)
        val dialMs = System.currentTimeMillis() - dialStart
        assertTrue(dialMs < 5_000, "dial() harus kembali seketika, butuh ${dialMs}ms")
        try {
            assertThrows(SocketTimeoutException::class.java) {
                stream.input.read()
            }
        } finally {
            runCatching { stream.close() }
            client.close()
        }
        serverThread.join(5_000)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `relay dial succeeds against xray-like server when app data is sent first`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val appData = "hello-from-app".toByteArray() // 14 byte
        var serverError: Throwable? = null
        var firstChunk: ByteArray? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val opened = VmessCrypto.openRequestHeader(VmessCrypto.cmdKey(uuid), input)
                val session = VmessSession(
                    requestBytes = ByteArray(0),
                    bodyKey = opened.header.bodyKey,
                    bodyIV = opened.header.bodyIV,
                    responseBodyKey = Crypto.sha256(opened.header.bodyKey).copyOfRange(0, 16),
                    responseBodyIV = Crypto.sha256(opened.header.bodyIV).copyOfRange(0, 16),
                    responseV = opened.header.responseV,
                    security = VmessSecurity.AES_128_GCM,
                )
                val reqNonce = VmessCrypto.ChunkNonce(session.bodyIV)
                val reqMask = Shake128(session.bodyIV)
                // xray-like: no response header until the first body
                // chunk arrives — and it must be the app's real
                // bytes, not a dummy (taptapx-7.txt: the forwarder
                // sent no body at all, so every dial deadlocked).
                firstChunk = readChunk(
                    input, session.bodyKey, reqNonce, reqMask, VmessSecurity.AES_128_GCM,
                )
                output.write(VmessCrypto.sealResponseHeader(session, session.responseV))
                output.flush()
                val respNonce = VmessCrypto.ChunkNonce(session.responseBodyIV)
                val respMask = Shake128(session.responseBodyIV)
                writeChunk(
                    output, session.responseBodyKey, respNonce, respMask,
                    VmessSecurity.AES_128_GCM, "hello-from-server".toByteArray(),
                )
                // The client's empty termination chunk.
                val term = readChunk(
                    input, session.bodyKey, reqNonce, reqMask, VmessSecurity.AES_128_GCM,
                )
                assertEquals(0, term.size)
            } catch (e: Throwable) {
                serverError = e
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            uuid = uuid, security = "aes-128-gcm",
            network = "tcp",
        )
        val logBefore = DialLog.lines().size
        val client = VmessClient(item)
        // On v1.0.11 dial() itself throws SocketTimeoutException
        // here (~10 s): it reads the response header before any
        // body exists to unblock the server.
        val stream = client.dial("example.com", 443)
        try {
            stream.output.write(appData)
            stream.output.flush()
            val buf = ByteArray("hello-from-server".length)
            var filled = 0
            while (filled < buf.size) {
                val r = stream.input.read(buf, filled, buf.size - filled)
                if (r == -1) break
                filled += r
            }
            assertEquals(buf.size, filled)
            assertArrayEquals("hello-from-server".toByteArray(), buf)
        } finally {
            runCatching { stream.close() }
            client.close()
        }
        serverThread.join(5_000)
        assertTrue(!serverThread.isAlive, "fake server thread must finish")
        serverError?.let { throw AssertionError("Fake server gagal", it) }
        // The server must have received exactly the app's bytes.
        assertArrayEquals(appData, firstChunk)
        // The log must prove the body went out and the header arrived.
        val logLines = DialLog.lines().drop(logBefore)
        assertTrue(
            logLines.any { it.contains("VMess body 14B untuk example.com:443") },
            "log harus ada 'VMess body 14B ...': $logLines",
        )
        assertTrue(
            logLines.any { it.contains("VMess handshake ok") },
            "log harus ada 'VMess handshake ok': $logLines",
        )
    }

    /** Server-side chunk reader (shared framing, caller keeps state). */
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

    /** Server-side chunk writer (shared framing, caller keeps state). */
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
}
