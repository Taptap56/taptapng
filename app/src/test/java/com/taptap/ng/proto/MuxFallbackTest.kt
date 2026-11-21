package com.taptap.ng.proto

import com.taptap.ng.core.proto.*
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/** Polling kecil (top-level supaya dipakai server palsu di bawah juga). */
private fun waitFor(
    timeoutMs: Long = 5_000,
    what: String,
    condition: () -> Boolean,
): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        if (condition()) return true
        Thread.sleep(25)
    }
    return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
}

/**
 * v1.0.16 (koreksi review Claude): fallback mux otomatis.
 * Server tanpa dukungan mux.cool membuat probe via mux gagal;
 * bila probe via mux gagal tetapi jalur direct jalan, mux
 * dimatikan untuk sisa sesi VPN ini. Tes-tes ini GAGAL pada kode
 * tanpa fallback (v1.0.15: probe via mux yang gagal langsung
 * dilempar, semua koneksi sesudahnya ikut rusak) dan lolos pada
 * kode dengan fallback. Satu instance client dipakai untuk probe
 * + relay, seperti lifecycle asli (TaptapVpnService membuat satu
 * VmessClient/VlessClient per sesi VPN dan meneruskannya ke
 * TunForwarder sebagai `proxy`).
 */
class MuxFallbackTest {

    private val uuid = "de305d54-75b4-431b-adb2-eb6b9e546014"

    private fun vmessItem(port: Int) = ProfileItem(
        configType = ConfigType.VMESS,
        address = "::1", port = port,
        uuid = uuid, security = "aes-128-gcm", network = "tcp",
    )

    private fun vlessItem(port: Int) = ProfileItem(
        configType = ConfigType.VLESS,
        address = "::1", port = port,
        uuid = uuid, method = "none", network = "tcp",
    )

    /** Port yang pasti tidak ada yang mendengarkan (ambil lalu tutup). */
    private fun freeClosedPort(): Int {
        val s = ServerSocket(0)
        val p = s.localPort
        s.close()
        return p
    }

    /**
     * Fake server VMess langsung (::1): terima koneksi berulang;
     * per koneksi buka header, kirim response header langsung,
     * lalu TCP = echo tiap chunk, UDP = echo satu datagram.
     */
    private class VmessDirectServer(private val uuid: String) {
        val server = ServerSocket(0)
        val port: Int get() = server.localPort
        val errors = Collections.synchronizedList(mutableListOf<Throwable>())
        val active = AtomicInteger(0)
        private val acceptor = Thread({
            try {
                while (!server.isClosed) {
                    val socket = server.accept()
                    Thread({ handle(socket) }, "vmess-direct-conn").apply { isDaemon = true }.start()
                }
            } catch (_: IOException) {
                // Ditutup stop().
            }
        }, "vmess-direct-acceptor").apply { isDaemon = true }

        fun start() = acceptor.start()
        fun stop() = runCatching { server.close() }

        fun waitIdle(timeoutMs: Long = 5_000): Boolean =
            waitFor(timeoutMs, "handler VMess selesai") { active.get() == 0 }

        /** Server-side chunk reader (disalin dari VmessClientTest — framing yang sama). */
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

        /** Server-side chunk writer (disalin dari VmessClientTest). */
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

        private fun handle(socket: Socket) {
            socket.soTimeout = 5_000
            active.incrementAndGet()
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
                    security = opened.header.security,
                )
                output.write(VmessCrypto.sealResponseHeader(session, session.responseV))
                output.flush()
                if (opened.header.command == VmessCrypto.CMD_TCP.toInt()) {
                    val reqNonce = VmessCrypto.ChunkNonce(session.bodyIV)
                    val reqMask = Shake128(session.bodyIV)
                    val respNonce = VmessCrypto.ChunkNonce(session.responseBodyIV)
                    val respMask = Shake128(session.responseBodyIV)
                    while (true) {
                        val chunk = readChunk(input, session.bodyKey, reqNonce, reqMask, session.security)
                        if (chunk.isEmpty()) break
                        writeChunk(output, session.responseBodyKey, respNonce, respMask, session.security, chunk)
                    }
                } else {
                    val bodyIn = VmessBodyInputStream(input, session, key = session.bodyKey, iv = session.bodyIV)
                    val bodyOut = VmessBodyOutputStream(output, session, key = session.responseBodyKey, iv = session.responseBodyIV)
                    val datagram = UdpFraming.readDatagram(bodyIn) ?: return
                    bodyOut.write(byteArrayOf(0, datagram.size.toByte()) + datagram)
                    bodyOut.flush()
                }
            } catch (e: Throwable) {
                errors.add(e)
            } finally {
                active.decrementAndGet()
                runCatching { socket.close() }
            }
        }
    }

    /**
     * Fake server VLESS langsung (::1): baca header byte-per-byte,
     * kirim (0,0), lalu TCP = echo mentah, UDP = echo satu datagram.
     */
    private class VlessDirectServer {
        val server = ServerSocket(0)
        val port: Int get() = server.localPort
        val errors = Collections.synchronizedList(mutableListOf<Throwable>())
        val active = AtomicInteger(0)
        private val acceptor = Thread({
            try {
                while (!server.isClosed) {
                    val socket = server.accept()
                    Thread({ handle(socket) }, "vless-direct-conn").apply { isDaemon = true }.start()
                }
            } catch (_: IOException) {
                // Ditutup stop().
            }
        }, "vless-direct-acceptor").apply { isDaemon = true }

        fun start() = acceptor.start()
        fun stop() = runCatching { server.close() }

        fun waitIdle(timeoutMs: Long = 5_000): Boolean =
            waitFor(timeoutMs, "handler VLESS selesai") { active.get() == 0 }

        private fun handle(socket: Socket) {
            socket.soTimeout = 5_000
            active.incrementAndGet()
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val head = input.readExactBytes(19)
                val command = head[18]
                val addonLen = head[17].toInt() and 0xFF
                input.readExactBytes(2) // port tujuan
                val atyp = input.read()
                val addrLen = when (atyp) {
                    0x01 -> 4
                    0x03 -> input.read()
                    0x04 -> 16
                    else -> throw IOException("atyp VLESS tidak dikenal: $atyp")
                }
                input.readExactBytes(addrLen)
                if (addonLen > 0) input.readExactBytes(addonLen)
                output.write(byteArrayOf(0x00, 0x00)) // version + addon length
                output.flush()
                if (command == VlessCrypto.CMD_TCP) {
                    val buf = ByteArray(8192)
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        output.write(buf, 0, n)
                        output.flush()
                    }
                } else {
                    val datagram = UdpFraming.readDatagram(input) ?: return
                    UdpFraming.writeDatagram(output, datagram)
                }
            } catch (e: Throwable) {
                errors.add(e)
            } finally {
                active.decrementAndGet()
                runCatching { socket.close() }
            }
        }
    }

    private fun failingOpener(openerCalls: AtomicInteger): (ProfileItem, SpeedStats?) -> LadderStream =
        { _, _ ->
            openerCalls.incrementAndGet()
            throw IOException("mux down")
        }

    // ---- VMess ----

    @Test
    @Timeout(20, TimeUnit.SECONDS)
    fun `vmess probe via mux gagal lalu direct jalan — mux dimatikan untuk sesi ini`() {
        val server = VmessDirectServer(uuid).apply { start() }
        val openerCalls = AtomicInteger(0)
        val item = vmessItem(server.port)
        val client = VmessClient(
            item,
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = failingOpener(openerCalls),
        )
        try {
            // Probe: mux gagal (opener melempar), direct jalan.
            val probeBody = ProbeBody.forEntry(item)
            val probe = client.dial("example.com", 443, probeBody)
            try {
                // Server meng-echo probe body sebagai chunk pertama.
                assertArrayEquals(probeBody, probe.input.readExactBytes(probeBody.size))
                probe.output.write("hello".toByteArray())
                probe.output.flush()
                assertArrayEquals("hello".toByteArray(), probe.input.readExactBytes(5))
            } finally {
                probe.close()
            }
            assertEquals(1, openerCalls.get(), "probe via mux hanya dicoba sekali")
            // Relay sesudah fallback: langsung direct, tanpa panggil opener lagi.
            val relay = client.dial("example.com", 443)
            try {
                relay.output.write("hello".toByteArray())
                relay.output.flush()
                assertArrayEquals("hello".toByteArray(), relay.input.readExactBytes(5))
            } finally {
                relay.close()
            }
            assertEquals(1, openerCalls.get(), "relay sesudah fallback tidak boleh memanggil opener mux lagi")
        } finally {
            client.close()
            server.stop()
        }
        assertTrue(server.waitIdle(), "handler server VMess tidak selesai")
        assertTrue(server.errors.isEmpty(), "fake server VMess error: ${server.errors}")
    }

    @Test
    @Timeout(20, TimeUnit.SECONDS)
    fun `vmess probe via mux gagal dan direct juga gagal — exception mux yang dilempar`() {
        val openerCalls = AtomicInteger(0)
        val item = vmessItem(freeClosedPort())
        val client = VmessClient(
            item,
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = failingOpener(openerCalls),
        )
        try {
            val probeBody = ProbeBody.forEntry(item)
            val e = assertThrows<IOException> {
                client.dial("example.com", 443, probeBody)
            }
            assertTrue(e.message?.contains("mux down") == true, "exception asli mux harus dilempar, dapat: ${e.message}")
            assertEquals(1, openerCalls.get())
            // Direct TIDAK terbukti jalan, jadi mux tetap nyala:
            // relay berikutnya masih mencoba mux (opener dipanggil lagi).
            val e2 = assertThrows<IOException> {
                client.dial("example.com", 443)
            }
            assertTrue(e2.message?.contains("mux down") == true, "relay masih lewat mux, dapat: ${e2.message}")
            assertEquals(2, openerCalls.get())
        } finally {
            client.close()
        }
    }

    @Test
    @Timeout(20, TimeUnit.SECONDS)
    fun `vmess relay via mux gagal — tidak ada fallback, mux tetap nyala`() {
        val openerCalls = AtomicInteger(0)
        val item = vmessItem(freeClosedPort())
        val client = VmessClient(
            item,
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = failingOpener(openerCalls),
        )
        try {
            // Relay tidak bisa diverifikasi per-dial (header respons
            // baru keluar sesudah data mengalir), jadi tidak ada
            // fallback: exception mux langsung dilempar.
            val e = assertThrows<IOException> { client.dial("example.com", 443) }
            assertTrue(e.message?.contains("mux down") == true, "exception mux harus dilempar, dapat: ${e.message}")
            assertEquals(1, openerCalls.get())
            // Relay kedua: mux masih nyala — opener dipanggil lagi.
            val e2 = assertThrows<IOException> { client.dial("example.com", 443) }
            assertTrue(e2.message?.contains("mux down") == true, "relay kedua masih lewat mux, dapat: ${e2.message}")
            assertEquals(2, openerCalls.get())
        } finally {
            client.close()
        }
    }

    @Test
    @Timeout(20, TimeUnit.SECONDS)
    fun `vmess udp ikut muxDisabled sesudah fallback probe`() {
        val server = VmessDirectServer(uuid).apply { start() }
        val openerCalls = AtomicInteger(0)
        val item = vmessItem(server.port)
        val client = VmessClient(
            item,
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = failingOpener(openerCalls),
        )
        try {
            // Probe dulu supaya fallback terjadi (mux dimatikan).
            val probeBody = ProbeBody.forEntry(item)
            val probe = client.dial("example.com", 443, probeBody)
            try {
                assertArrayEquals(probeBody, probe.input.readExactBytes(probeBody.size))
            } finally {
                probe.close()
            }
            assertEquals(1, openerCalls.get())
            // UDP: harus langsung direct (opener tidak dipanggil lagi).
            val udp = client.dialUdp("8.8.8.8", 53)
            try {
                udp.send("udp-ping".toByteArray())
                assertArrayEquals("udp-ping".toByteArray(), udp.receive(5_000))
            } finally {
                udp.close()
            }
            assertEquals(1, openerCalls.get(), "UDP sesudah fallback tidak boleh memanggil opener mux lagi")
        } finally {
            client.close()
            server.stop()
        }
        assertTrue(server.waitIdle(), "handler server VMess tidak selesai")
        assertTrue(server.errors.isEmpty(), "fake server VMess error: ${server.errors}")
    }

    // ---- VLESS ----

    @Test
    @Timeout(20, TimeUnit.SECONDS)
    fun `vless probe via mux gagal lalu direct jalan — mux dimatikan untuk sesi ini`() {
        val server = VlessDirectServer().apply { start() }
        val openerCalls = AtomicInteger(0)
        val item = vlessItem(server.port)
        val client = VlessClient(
            item,
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = failingOpener(openerCalls),
        )
        try {
            val probeBody = ProbeBody.forEntry(item)
            val probe = client.dial("example.com", 443, probeBody)
            try {
                assertArrayEquals(probeBody, probe.input.readExactBytes(probeBody.size))
                probe.output.write("hello".toByteArray())
                probe.output.flush()
                assertArrayEquals("hello".toByteArray(), probe.input.readExactBytes(5))
            } finally {
                probe.close()
            }
            assertEquals(1, openerCalls.get(), "probe via mux hanya dicoba sekali")
            val relay = client.dial("example.com", 443)
            try {
                relay.output.write("hello".toByteArray())
                relay.output.flush()
                assertArrayEquals("hello".toByteArray(), relay.input.readExactBytes(5))
            } finally {
                relay.close()
            }
            assertEquals(1, openerCalls.get(), "relay sesudah fallback tidak boleh memanggil opener mux lagi")
        } finally {
            client.close()
            server.stop()
        }
        assertTrue(server.waitIdle(), "handler server VLESS tidak selesai")
        assertTrue(server.errors.isEmpty(), "fake server VLESS error: ${server.errors}")
    }

    @Test
    @Timeout(20, TimeUnit.SECONDS)
    fun `vless probe via mux gagal dan direct juga gagal — exception mux yang dilempar`() {
        val openerCalls = AtomicInteger(0)
        val item = vlessItem(freeClosedPort())
        val client = VlessClient(
            item,
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = failingOpener(openerCalls),
        )
        try {
            val probeBody = ProbeBody.forEntry(item)
            val e = assertThrows<IOException> {
                client.dial("example.com", 443, probeBody)
            }
            assertTrue(e.message?.contains("mux down") == true, "exception asli mux harus dilempar, dapat: ${e.message}")
            assertEquals(1, openerCalls.get())
            val e2 = assertThrows<IOException> {
                client.dial("example.com", 443)
            }
            assertTrue(e2.message?.contains("mux down") == true, "relay masih lewat mux, dapat: ${e2.message}")
            assertEquals(2, openerCalls.get())
        } finally {
            client.close()
        }
    }

    @Test
    @Timeout(20, TimeUnit.SECONDS)
    fun `vless relay via mux gagal — tidak ada fallback, mux tetap nyala`() {
        val openerCalls = AtomicInteger(0)
        val item = vlessItem(freeClosedPort())
        val client = VlessClient(
            item,
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = failingOpener(openerCalls),
        )
        try {
            val e = assertThrows<IOException> { client.dial("example.com", 443) }
            assertTrue(e.message?.contains("mux down") == true, "exception mux harus dilempar, dapat: ${e.message}")
            assertEquals(1, openerCalls.get())
            val e2 = assertThrows<IOException> { client.dial("example.com", 443) }
            assertTrue(e2.message?.contains("mux down") == true, "relay kedua masih lewat mux, dapat: ${e2.message}")
            assertEquals(2, openerCalls.get())
        } finally {
            client.close()
        }
    }

    @Test
    @Timeout(20, TimeUnit.SECONDS)
    fun `vless udp ikut muxDisabled sesudah fallback probe`() {
        val server = VlessDirectServer().apply { start() }
        val openerCalls = AtomicInteger(0)
        val item = vlessItem(server.port)
        val client = VlessClient(
            item,
            muxConfig = MuxConfig(enabled = true, concurrency = 8),
            muxLadderOpener = failingOpener(openerCalls),
        )
        try {
            val probeBody = ProbeBody.forEntry(item)
            val probe = client.dial("example.com", 443, probeBody)
            try {
                assertArrayEquals(probeBody, probe.input.readExactBytes(probeBody.size))
            } finally {
                probe.close()
            }
            assertEquals(1, openerCalls.get())
            val udp = client.dialUdp("8.8.8.8", 53)
            try {
                udp.send("udp-ping".toByteArray())
                assertArrayEquals("udp-ping".toByteArray(), udp.receive(5_000))
            } finally {
                udp.close()
            }
            assertEquals(1, openerCalls.get(), "UDP sesudah fallback tidak boleh memanggil opener mux lagi")
        } finally {
            client.close()
            server.stop()
        }
        assertTrue(server.waitIdle(), "handler server VLESS tidak selesai")
        assertTrue(server.errors.isEmpty(), "fake server VLESS error: ${server.errors}")
    }
}
