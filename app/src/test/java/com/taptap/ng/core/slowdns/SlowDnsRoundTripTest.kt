package com.taptap.ng.core.slowdns

import com.taptap.ng.core.proto.Crypto
import com.taptap.ng.core.proto.ProbeBody
import com.taptap.ng.core.proto.VmessClient
import com.taptap.ng.core.proto.VmessCrypto
import com.taptap.ng.core.proto.VmessSession
import com.taptap.ng.core.proto.readExactBytes
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Full-stack M3 test: a VMess client dials over a DNSTT tunnel to a
 * mock DNSTT server (in-memory fake DNS transport) that runs the
 * server side of every layer — DNS response encoding, KCP, Noise_NK
 * responder, smux server, VMess echo server — and the bytes come
 * back. FAILS on v1.0.13 code (no SlowDNS at all) and PASSES when
 * the whole M3 chain interoperates.
 *
 * No real sockets: loopback UDP is blocked in the VM, so the client
 * session is built with a transport factory returning the fake
 * transport, and the server KCP runs over queues.
 */
class SlowDnsRoundTripTest {

    // ---- fake DNS transport (client <-> mock server queues) ----

    private class FakeDnsTransport : DnsTransport {
        /** Queries sent by the client, read by the mock server. */
        val toServer = LinkedBlockingQueue<ByteArray>()
        /** Responses built by the mock server, read by the client. */
        val toClient = LinkedBlockingQueue<ByteArray>()
        @Volatile var closed = false

        override fun send(data: ByteArray, addr: InetSocketAddress) {
            toServer.offer(data.copyOf())
        }

        override fun receive(buf: ByteArray): Int {
            while (!closed) {
                val d = toClient.poll(100, TimeUnit.MILLISECONDS)
                if (d != null) {
                    d.copyInto(buf, 0, 0, minOf(d.size, buf.size))
                    return minOf(d.size, buf.size)
                }
            }
            throw IOException("transport ditutup")
        }

        override fun close() {
            closed = true
        }
    }

    // ---- Noise_NK responder (server side, test-only) ----

    /**
     * Minimal Noise_NK_25519_ChaChaPoly_BLAKE2s responder, built from
     * the same primitives as the client (Blake2s / X25519 /
     * ChaCha20Poly1305 / HMAC-BLAKE2s HKDF) and the flynn/noise
     * state machine. Only used to prove the client interoperates.
     */
    private class NoiseResponder(
        private val staticPrivate: ByteArray,
        private val staticPublic: ByteArray,
    ) {
        private var h: ByteArray
        private var ck: ByteArray
        private var hasK = false
        private lateinit var k: ByteArray
        private var n: Long = 0

        init {
            val name = "Noise_NK_25519_ChaChaPoly_BLAKE2s".toByteArray(Charsets.US_ASCII)
            // The name is 33 bytes (> BLAKE2s 32), so per
            // InitializeSymmetric h = BLAKE2s(name) — NOT the raw
            // name bytes (same branch the client takes).
            h = blake2s256(name)
            ck = h.copyOf()
            mixHash("dnstt 2020-04-13".toByteArray(Charsets.US_ASCII))
            mixHash(staticPublic) // responder pre-message: its own static
        }

        private fun mixHash(data: ByteArray) {
            h = blake2s256(h + data)
        }

        private fun mixKey(ikm: ByteArray) {
            n = 0
            hasK = true
            val (newCk, newKey) = hkdf(ck, ikm)
            ck = newCk
            k = newKey
        }

        private fun hkdf(ck: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
            val tempKey = Crypto.hmacWithHash(::blake2s256, ck, ikm)
            val out1 = Crypto.hmacWithHash(::blake2s256, tempKey, byteArrayOf(0x01))
            val out2 = Crypto.hmacWithHash(::blake2s256, tempKey, out1 + byteArrayOf(0x02))
            return out1 to out2
        }

        private fun chachaNonce(nonce: Long): ByteArray {
            val out = ByteArray(12)
            for (i in 0 until 8) out[4 + i] = ((nonce ushr (8 * i)) and 0xFF).toByte()
            return out
        }

        private fun encryptAndHash(plaintext: ByteArray): ByteArray {
            val ciphertext = com.taptap.ng.core.proto.ChaCha20Poly1305(k)
                .seal(chachaNonce(n), plaintext, h)
            n++
            mixHash(ciphertext)
            return ciphertext
        }

        private fun decryptAndHash(data: ByteArray): ByteArray {
            val plaintext = com.taptap.ng.core.proto.ChaCha20Poly1305(k)
                .open(chachaNonce(n), data, h)
            n++
            mixHash(data)
            return plaintext
        }

        /** Process the client's msg1, return msg2. */
        fun readMessage1(msg: ByteArray): ByteArray {
            require(msg.size == 48) { "Noise msg1 harus 48 byte, dapat ${msg.size}" }
            val re = msg.copyOfRange(0, 32)
            mixHash(re)
            val dh = X25519.scalarmult(staticPrivate, re)
            mixKey(dh)
            decryptAndHash(msg.copyOfRange(32, 48)) // empty payload, tag verified
            // Write msg2: e, ee.
            val ePriv = Crypto.randomBytes(32)
            val ePub = X25519.publicKey(ePriv)
            mixHash(ePub)
            val dh2 = X25519.scalarmult(ePriv, re)
            mixKey(dh2)
            return ePub + encryptAndHash(ByteArray(0))
        }

        /** (sendKey, recvKey) for the RESPONDER: send=k2, recv=k1. */
        fun transportKeys(): Pair<ByteArray, ByteArray> {
            val (k1, k2) = hkdf(ck, ByteArray(0))
            return k2 to k1
        }
    }

    // ---- server-side KCP stream (shares the mock server's KCP + lock) ----

    private class TestKcpStream(
        private val kcp: Kcp,
        private val kcpLock: Object,
    ) {
        private val closed = AtomicBoolean(false)

        init {
            thread(name = "test-kcp-update", isDaemon = true) {
                while (!closed.get()) {
                    try {
                        val now = System.currentTimeMillis() and 0xFFFFFFFFL
                        val delay = synchronized(kcpLock) {
                            kcp.update(now)
                            kcp.check(now)
                        }.coerceIn(1, 100)
                        Thread.sleep(delay)
                    } catch (_: InterruptedException) {
                        return@thread
                    } catch (_: Exception) {
                        if (closed.get()) return@thread
                        Thread.sleep(10)
                    }
                }
            }
        }

        val input: InputStream = object : InputStream() {
            private val buf = ArrayDeque<Byte>()
            override fun read(): Int {
                val b = ByteArray(1)
                return if (read(b, 0, 1) == -1) -1 else b[0].toInt() and 0xFF
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                val start = System.currentTimeMillis()
                while (System.currentTimeMillis() - start < 30_000) {
                    synchronized(buf) {
                        if (buf.isNotEmpty()) {
                            val n = minOf(len, buf.size)
                            repeat(n) { i -> b[off + i] = buf.removeFirst() }
                            return n
                        }
                    }
                    val chunk = ByteArray(8192)
                    val n = synchronized(kcpLock) {
                        try {
                            kcp.recv(chunk)
                        } catch (_: Exception) {
                            -1
                        }
                    }
                    if (n > 0) {
                        synchronized(buf) {
                            for (i in 0 until n) buf.addLast(chunk[i])
                        }
                        continue
                    }
                    if (closed.get()) return -1
                    Thread.sleep(2)
                }
                throw java.net.SocketTimeoutException("TestKcpStream read timeout")
            }
        }

        val output: OutputStream = object : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()))
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (len == 0) return
                val now = System.currentTimeMillis() and 0xFFFFFFFFL
                synchronized(kcpLock) {
                    val rc = kcp.send(b.copyOfRange(off, off + len))
                    if (rc < 0) throw IOException("TestKcp send gagal: $rc")
                    kcp.update(now)
                }
            }

            override fun flush() {
                val now = System.currentTimeMillis() and 0xFFFFFFFFL
                synchronized(kcpLock) { kcp.update(now) }
            }
        }

        fun close() {
            closed.set(true)
        }
    }

    // ---- mock DNSTT server ----

    private class MockDnsttServer(
        private val transport: FakeDnsTransport,
        private val domain: String,
        private val recordType: Int,
        private val staticPrivate: ByteArray,
        private val staticPublic: ByteArray,
    ) {
        private val closed = AtomicBoolean(false)
        private val domainLabels = DnsWire.parseDomain(domain)
        private val pendingOutput = mutableListOf<ByteArray>()
        private val pendingLock = Object()
        private val kcpLock = Object()
        @Volatile private var serverKcp: Kcp? = null
        @Volatile var streamsAccepted = 0
        @Volatile var vmessEchoed = 0

        fun start(rawEcho: Boolean = false) {
            thread(name = "mock-dnstt", isDaemon = true) { serveLoop() }
            thread(name = "mock-vmess", isDaemon = true) {
                if (rawEcho) vmessLoop(::rawEcho) else vmessLoop()
            }
        }

        fun stop() {
            closed.set(true)
        }

        private fun u16(v: Int): ByteArray =
            byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

        private fun buildResponse(query: ByteArray, payload: ByteArray): ByteArray {
            val (qname, afterName) = DnsWire.readName(query, 12)!!
            val qtype = ((query[afterName].toInt() and 0xFF) shl 8) or (query[afterName + 1].toInt() and 0xFF)
            val out = mutableListOf<Byte>()
            out.addAll(u16(((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)).toList())
            out.addAll(u16(0x8100).toList())
            out.addAll(u16(1).toList())
            out.addAll(u16(1).toList())
            out.addAll(u16(0).toList())
            out.addAll(u16(0).toList())
            // Question echo.
            for (label in qname) {
                out.add(label.size.toByte())
                out.addAll(label.toList())
            }
            out.add(0)
            out.addAll(u16(qtype).toList())
            out.addAll(u16(1).toList())
            // Answer: name = question name, TXT/NULL, RDATA = payload.
            for (label in qname) {
                out.add(label.size.toByte())
                out.addAll(label.toList())
            }
            out.add(0)
            out.addAll(u16(recordType).toList())
            out.addAll(u16(1).toList())
            out.addAll(byteArrayOf(0, 0, 0, 60).toList())
            val rdata = if (recordType == DnsWire.TYPE_NULL) payload else DnsWire.encodeRDataTxt(payload)
            out.addAll(u16(rdata.size).toList())
            out.addAll(rdata.toList())
            return out.toByteArray()
        }

        private fun serveLoop() {
            while (!closed.get()) {
                val query = try {
                    transport.toServer.poll(100, TimeUnit.MILLISECONDS) ?: continue
                } catch (_: Exception) {
                    continue
                }
                try {
                    // Decode the upstream packet from the QNAME.
                    val (qname, _) = DnsWire.readName(query, 12) ?: continue
                    val labels = qname.map { it.toString(Charsets.US_ASCII) }
                    val b32 = labels.dropLast(domainLabels.size).joinToString("")
                    val decoded = Base32.decode(b32)
                    if (decoded.size < 8) continue
                    val packet = DnsWire.decodeUpstreamPacket(decoded.copyOfRange(8, decoded.size))
                    if (packet != null && packet.isNotEmpty()) {
                        val conv = ((packet[0].toInt() and 0xFF)) or
                            ((packet[1].toInt() and 0xFF) shl 8) or
                            ((packet[2].toInt() and 0xFF) shl 16) or
                            ((packet[3].toInt() and 0xFF) shl 24)
                        val cmd = packet[4].toInt() and 0xFF
                        val frg = packet[5].toInt() and 0xFF
                        val sn = ((packet[12].toInt() and 0xFF)) or
                            ((packet[13].toInt() and 0xFF) shl 8) or
                            ((packet[14].toInt() and 0xFF) shl 16) or
                            ((packet[15].toInt() and 0xFF) shl 24)
                        val len = ((packet[20].toInt() and 0xFF)) or
                            ((packet[21].toInt() and 0xFF) shl 8) or
                            ((packet[22].toInt() and 0xFF) shl 16) or
                            ((packet[23].toInt() and 0xFF) shl 24)
                        // Feed the segment to the server KCP
                        // SYNCHRONOUSLY (under kcpLock) so the
                        // response below carries whatever the KCP
                        // produced (ACK / Noise reply) at once.
                        synchronized(kcpLock) {
                            if (serverKcp == null) {
                                // First segment: learn the conv.
                                val conv = ((packet[0].toInt() and 0xFF)) or
                                    ((packet[1].toInt() and 0xFF) shl 8) or
                                    ((packet[2].toInt() and 0xFF) shl 16) or
                                    ((packet[3].toInt() and 0xFF) shl 24)
                                val mtu = SlowDnsSession.mtuForDomain(domain)
                                val kcp = Kcp(conv) { seg ->
                                    synchronized(pendingLock) { pendingOutput.add(seg) }
                                }
                                kcp.setStreamMode(true)
                                kcp.setNoDelay(0, 0, 0, 1)
                                kcp.setWindowSize(512, 512)
                                kcp.setMtu(mtu)
                                serverKcp = kcp
                            }
                            serverKcp!!.input(packet)
                            serverKcp!!.update(System.currentTimeMillis() and 0xFFFFFFFFL)
                        }
                    }
                    // Drain whatever the server KCP has produced into
                    // this response (possibly empty — a poll answer).
                    val toSend: List<ByteArray> = synchronized(pendingLock) {
                        val copy = pendingOutput.toList()
                        pendingOutput.clear()
                        copy
                    }
                    val payload = mutableListOf<Byte>()
                    for (seg in toSend) {
                        payload.addAll(u16(seg.size).toList())
                        payload.addAll(seg.toList())
                    }
                    transport.toClient.offer(buildResponse(query, payload.toByteArray()))
                } catch (_: Exception) {
                    // A malformed query must not kill the server.
                    continue
                }
            }
        }

        /** Noise responder + smux server, then [handleStream] on the accepted stream. */
        private fun vmessLoop(handleStream: (SmuxStream) -> Unit = ::vmessEcho) {
            // Wait for the server KCP to exist (first client segment).
            var kcp: Kcp? = null
            while (!closed.get() && kcp == null) {
                kcp = serverKcp
                if (kcp == null) Thread.sleep(10)
            }
            if (kcp == null) return
            val stream = TestKcpStream(kcp, kcpLock)
            try {
                // Noise handshake (length-prefixed messages).
                val msg1 = readLengthPrefixed(stream.input)
                val responder = NoiseResponder(staticPrivate, staticPublic)
                val msg2 = responder.readMessage1(msg1)
                writeLengthPrefixed(stream.output, msg2)
                val (sendKey, recvKey) = responder.transportKeys()
                val noiseTransport = NoiseTransport(sendKey, recvKey)
                val noiseSocket = NoiseSocket(noiseTransport, stream.input, stream.output)
                val smux = SmuxSession(
                    noiseSocket.input, noiseSocket.output,
                    SmuxConfig(version = 2, keepAliveTimeoutMs = 120_000, maxStreamBuffer = 1024 * 1024),
                    isClient = false,
                )
                val accepted = smux.acceptStream(30_000)
                streamsAccepted++
                handleStream(accepted)
            } catch (e: Exception) {
                // The test asserts on the client side; a server-side
                // failure surfaces there as a dial/read failure.
                System.err.println("MockDnsttServer vmessLoop gagal: $e")
            }
        }

        /** Raw echo (no VMess): read bytes, write them back. */
        private fun rawEcho(stream: SmuxStream) {
            val buf = ByteArray(8192)
            while (!closed.get()) {
                val n = try {
                    stream.input.read(buf)
                } catch (_: Exception) {
                    -1
                }
                if (n == -1) break
                if (n == 0) continue
                stream.output.write(buf, 0, n)
                stream.output.flush()
                vmessEchoed++
            }
        }

        private fun vmessEcho(stream: SmuxStream) {
            val input = stream.input
            val output = stream.output
            // The test UUID (must match the client's item).
            val uuid = TEST_UUID
            val cmdKey = VmessCrypto.cmdKey(uuid)
            val opened = VmessCrypto.openRequestHeader(cmdKey, input)
            val header = opened.header
            val session = VmessSession(
                requestBytes = ByteArray(0),
                bodyKey = header.bodyKey,
                bodyIV = header.bodyIV,
                responseBodyKey = Crypto.sha256(header.bodyKey).copyOfRange(0, 16),
                responseBodyIV = Crypto.sha256(header.bodyIV).copyOfRange(0, 16),
                responseV = header.responseV,
                security = header.security,
            )
            output.write(VmessCrypto.sealResponseHeader(session, header.responseV))
            output.flush()
            // M3: the request body arrives sealed with the REQUEST
            // keys (bodyKey/bodyIV); the response body must be sealed
            // with the RESPONSE keys — the two body-stream classes
            // default to the client direction, so pass them here.
            val bodyIn = com.taptap.ng.core.proto.VmessBodyInputStream(
                input, session, key = header.bodyKey, iv = header.bodyIV,
            )
            val bodyOut = com.taptap.ng.core.proto.VmessBodyOutputStream(
                output, session,
                key = session.responseBodyKey, iv = session.responseBodyIV,
            )
            // Echo loop: read a body chunk, write it back.
            val buf = ByteArray(8192)
            while (!closed.get()) {
                val n = try {
                    bodyIn.read(buf)
                } catch (_: Exception) {
                    -1
                }
                if (n == -1) break
                if (n == 0) continue
                bodyOut.write(buf, 0, n)
                bodyOut.flush()
                vmessEchoed++
            }
        }

        private fun writeLengthPrefixed(out: OutputStream, msg: ByteArray) {
            out.write(byteArrayOf(((msg.size ushr 8) and 0xFF).toByte(), (msg.size and 0xFF).toByte()))
            out.write(msg)
            out.flush()
        }

        private fun readLengthPrefixed(input: InputStream): ByteArray {
            val head = input.readExactBytes(2)
            val n = ((head[0].toInt() and 0xFF) shl 8) or (head[1].toInt() and 0xFF)
            return input.readExactBytes(n)
        }
    }

    companion object {
        // Test-only UUID (not a real account).
        const val TEST_UUID = "11111111-2222-3333-4444-555555555555"
    }

    @Test
    fun `raw bytes flow over a SlowDNS smux stream (no VMess)`() {
        val serverPriv = Crypto.randomBytes(32)
        val serverPub = X25519.publicKey(serverPriv)
        val pubHex = serverPub.joinToString("") { "%02x".format(it) }
        val transport = FakeDnsTransport()
        val server = MockDnsttServer(transport, "example.com", DnsWire.TYPE_TXT, serverPriv, serverPub)
        server.start(rawEcho = true)
        try {
            val item = ProfileItem(
                remarks = "SlowDNS raw test",
                configType = ConfigType.VMESS,
                address = "example.com",
                port = 443,
                uuid = TEST_UUID,
                network = "tcp",
                tls = false,
                security = "auto",
                dnsttEnabled = true,
                dnsttNS = "example.com",
                dnsttPubkey = pubHex,
                dnsttResolver = "8.8.8.8:53",
                dnsttRecordType = "txt",
            )
            val pool = SlowDnsSessionPool(item) { transport }
            var stream: SmuxStream? = null
            var openError: Throwable? = null
            val openThread = thread(name = "test-open", isDaemon = true) {
                try {
                    stream = pool.stream()
                } catch (e: Throwable) {
                    openError = e
                }
            }
            openThread.join(30_000)
            assertTrue(!openThread.isAlive, "Buka stream SlowDNS menggantung > 30 dtk")
            if (openError != null) throw AssertionError("Buka stream SlowDNS gagal: $openError", openError)
            val s = requireNotNull(stream) { "Buka stream SlowDNS tidak menghasilkan stream" }
            // openStream() returns once the SYN is SENT; the server
            // accepts asynchronously — wait for it (up to 5 s).
            val acceptDeadline = System.currentTimeMillis() + 5_000
            while (server.streamsAccepted < 1 && System.currentTimeMillis() < acceptDeadline) {
                Thread.sleep(50)
            }
            assertTrue(server.streamsAccepted >= 1, "Mock server tidak menerima stream smux")
            s.readDeadlineMs = 10_000
            val payload = "hello-tunnel".toByteArray(Charsets.UTF_8)
            s.output.write(payload)
            s.output.flush()
            val echo = s.input.readExactBytes(payload.size)
            assertTrue(echo.contentEquals(payload), "Echo mentah tidak sama dengan yang dikirim")
            assertTrue(server.vmessEchoed >= 1, "Mock server tidak meng-echo mentah")
            s.close()
            pool.close()
        } finally {
            server.stop()
            transport.close()
        }
    }

    @Test
    fun `VMess over SlowDNS round trip through the mock server`() {
        val serverPriv = Crypto.randomBytes(32)
        val serverPub = X25519.publicKey(serverPriv)
        val pubHex = serverPub.joinToString("") { "%02x".format(it) }
        val transport = FakeDnsTransport()
        val server = MockDnsttServer(transport, "example.com", DnsWire.TYPE_TXT, serverPriv, serverPub)
        server.start()
        try {
            val item = ProfileItem(
                remarks = "SlowDNS test",
                configType = ConfigType.VMESS,
                address = "example.com",
                port = 443,
                uuid = TEST_UUID,
                network = "tcp",
                tls = false,
                security = "auto",
                dnsttEnabled = true,
                dnsttNS = "example.com",
                dnsttPubkey = pubHex,
                dnsttResolver = "8.8.8.8:53",
                dnsttRecordType = "txt",
            )
            val pool = SlowDnsSessionPool(item) { transport }
            val client = VmessClient(item, pool)
            // Probe dial (HTTP GET body) — the mock VMess server
            // answers with a valid response header.
            val probe = ProbeBody.forEntry(item)
            var stream: com.taptap.ng.core.proto.ProxyStream? = null
            var dialError: Throwable? = null
            val dialThread = thread(name = "test-dial", isDaemon = true) {
                try {
                    stream = client.dial("example.com", 443, ProbeBody.forEntry(item))
                } catch (e: Throwable) {
                    dialError = e
                }
            }
            dialThread.join(30_000)
            assertTrue(!dialThread.isAlive, "Dial SlowDNS menggantung > 30 dtk")
            if (dialError != null) throw AssertionError("Dial SlowDNS gagal: $dialError", dialError)
            val s = requireNotNull(stream) { "Dial SlowDNS tidak menghasilkan stream" }
            assertTrue(server.streamsAccepted >= 1, "Mock server tidak menerima stream smux")

            // Round trip: write through the tunnel, read the echo back.
            // The probe body is part of the body stream, so the server
            // echoes it first — drain the probe echo before the ping.
            val probeEcho = s.input.readExactBytes(probe.size)
            assertTrue(
                probeEcho.contentEquals(probe),
                "Echo probe body tidak sama dengan yang dikirim",
            )
            val payload = "ping-slowdns".toByteArray(Charsets.UTF_8)
            s.output.write(payload)
            s.output.flush()
            val echo = s.input.readExactBytes(payload.size)
            assertTrue(echo.contentEquals(payload), "Echo tidak sama dengan yang dikirim")
            assertTrue(server.vmessEchoed >= 1, "Mock VMess server tidak meng-echo")
            s.close()
            client.close()
        } finally {
            server.stop()
            transport.close()
        }
    }
}
