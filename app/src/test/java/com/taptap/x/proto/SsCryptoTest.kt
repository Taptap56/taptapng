package com.taptap.x.proto
import com.taptap.x.core.proto.*

import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Shadowsocks AEAD: key derivation, chunk framing, and a loopback
 * relay against a fake server that decrypts with the same session
 * subkey (independent counter state per direction).
 * Loopback uses ::1, not 127.0.0.1: the dev VM's sandbox blackholes
 * JVM client connects to IPv4 loopback, while ::1 connects fine.
 */
class SsCryptoTest {

    @Test
    fun `evpBytesToKey starts with MD5 of password`() {
        val key16 = Crypto.evpBytesToKey("password".toByteArray(Charsets.UTF_8), 16)
        // MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
        assertEquals(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            key16.joinToString("") { "%02x".format(it) },
        )
        val key32 = Crypto.evpBytesToKey("password".toByteArray(Charsets.UTF_8), 32)
        assertEquals(32, key32.size)
        assertArrayEquals(key16, key32.copyOfRange(0, 16))
        assertNotEquals(key16.toList(), key32.copyOfRange(16, 32).toList())
    }

    @Test
    fun `hkdf subkey is deterministic and salt-sensitive`() {
        val master = Crypto.evpBytesToKey("secret".toByteArray(Charsets.UTF_8), 32)
        val salt = ByteArray(32) { it.toByte() }
        val a = SsCrypto.deriveSubkey(master, salt, 32)
        val b = SsCrypto.deriveSubkey(master, salt, 32)
        assertArrayEquals(a, b)
        assertEquals(32, a.size)
        val other = SsCrypto.deriveSubkey(master, ByteArray(32) { (it + 1).toByte() }, 32)
        assertNotEquals(a.toList(), other.toList())
    }

    @Test
    fun `ss chunk round-trip all ciphers`() {
        for (cipher in SsCipher.values()) {
            val subkey = Crypto.randomBytes(cipher.keyLen)
            val payload = Crypto.randomBytes(1000)
            val (bytes, next) = SsCrypto.encryptChunk(subkey, cipher, 0, payload)
            assertEquals(2, next)
            // encLen(18) + encPayload(payload + 16)
            assertEquals(18 + payload.size + 16, bytes.size)
            val (opened, next2) = SsCrypto.decryptChunk(
                ByteArrayInputStream(bytes), subkey, cipher, 0,
            )
            assertEquals(2, next2)
            assertArrayEquals(payload, opened)
        }
    }

    @Test
    fun `ss chunk rejects a tampered tag`() {
        val subkey = Crypto.randomBytes(32)
        val (bytes, _) = SsCrypto.encryptChunk(
            subkey, SsCipher.AES_256_GCM, 0, "hello".toByteArray(),
        )
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0x01).toByte()
        assertThrows(Exception::class.java) {
            SsCrypto.decryptChunk(ByteArrayInputStream(bytes), subkey, SsCipher.AES_256_GCM, 0)
        }
    }

    @Test
    fun `ss nonce is a little-endian counter`() {
        assertArrayEquals(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            SsCrypto.nonce(0),
        )
        assertArrayEquals(
            byteArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            SsCrypto.nonce(1),
        )
        assertArrayEquals(
            byteArrayOf(0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            SsCrypto.nonce(256),
        )
    }

    @Test
    fun `ss session salt and subkey lengths match cipher`() {
        val session = SsCrypto.newSession("password", SsCipher.AES_256_GCM)
        assertEquals(32, session.salt.size)
        assertEquals(32, session.subkey.size)
        val session128 = SsCrypto.newSession("password", SsCipher.AES_128_GCM)
        assertEquals(16, session128.salt.size)
        assertEquals(16, session128.subkey.size)
    }

    @Test
    fun `resolveCipher rejects unknown and 2022 methods`() {
        assertEquals(SsCipher.AES_128_GCM, SsCrypto.resolveCipher("aes-128-gcm"))
        assertEquals(SsCipher.CHACHA20_POLY1305, SsCrypto.resolveCipher("chacha20-ietf-poly1305"))
        assertThrows(IllegalArgumentException::class.java) {
            SsCrypto.resolveCipher("aes-256-cfb")
        }
        assertThrows(IllegalArgumentException::class.java) {
            SsCrypto.resolveCipher("2022-blake3-aes-128-gcm")
        }
    }

    @Test
    fun `ss dial relays bytes aes-256-gcm`() {
        ssRelay(SsCipher.AES_256_GCM, "aes-256-gcm")
    }

    @Test
    fun `ss dial relays bytes chacha20-ietf-poly1305`() {
        ssRelay(SsCipher.CHACHA20_POLY1305, "chacha20-ietf-poly1305")
    }

    private fun ssRelay(cipher: SsCipher, method: String) {
        val server = ServerSocket(0)
        val port = server.localPort
        var serverError: Throwable? = null
        val serverThread = Thread {
            val socket = server.accept()
            socket.soTimeout = 5_000
            try {
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                val salt = input.readExactBytes(cipher.keyLen)
                val master = Crypto.evpBytesToKey("secret".toByteArray(Charsets.UTF_8), cipher.keyLen)
                val subkey = SsCrypto.deriveSubkey(master, salt, cipher.keyLen)
                // First chunk: target address + payload.
                val (first, nextIn) = SsCrypto.decryptChunk(input, subkey, cipher, 0)
                val (target, afterTarget) = AddrCodec.parseSocksTarget(first, 0)
                assertEquals("example.com", target.host)
                assertEquals(443, target.port)
                val clientPayload = first.copyOfRange(afterTarget, first.size)
                assertArrayEquals("hello-ss".toByteArray(), clientPayload)
                // Reply with one chunk (server counter starts at 0).
                val (reply, _) = SsCrypto.encryptChunk(subkey, cipher, 0, "hello-back".toByteArray())
                output.write(reply)
                output.flush()
                // Drain the client's remaining chunks until close.
                runCatching {
                    while (true) {
                        SsCrypto.decryptChunk(input, subkey, cipher, nextIn)
                    }
                }
            } catch (e: Throwable) {
                // EOF after the client closes is expected; anything
                // else is a real failure.
                if (e !is java.io.EOFException) serverError = e
            } finally {
                runCatching { socket.close() }
                runCatching { server.close() }
            }
        }
        serverThread.start()
        val item = ProfileItem(
            configType = ConfigType.SHADOWSOCKS,
            address = "::1", port = port,
            password = "secret", method = method, network = "tcp",
        )
        val client = SsClient(item)
        val stream = client.dial("example.com", 443)
        try {
            stream.output.write("hello-ss".toByteArray())
            stream.output.flush()
            val buf = ByteArray(10)
            var filled = 0
            while (filled < buf.size) {
                val r = stream.input.read(buf, filled, buf.size - filled)
                if (r == -1) break
                filled += r
            }
            assertEquals(10, filled)
            assertArrayEquals("hello-back".toByteArray(), buf)
        } finally {
            client.close()
        }
        serverThread.join(5_000)
        serverError?.let { throw AssertionError("Fake SS server gagal", it) }
    }

    @Test
    fun `ss body streams round-trip large payload`() {
        val session = SsCrypto.newSession("password", SsCipher.AES_128_GCM)
        val payload = ByteArray(40_000) { (it % 251).toByte() }
        val sink = ByteArrayOutputStream()
        val writer = SsBodyOutputStream(sink, session, "example.com", 443)
        writer.write(payload)
        writer.close()
        // Server side: salt is separate; here we read the chunks back
        // with the same session (counter from 0, first chunk has addr).
        val input = ByteArrayInputStream(sink.toByteArray())
        val (first, next) = SsCrypto.decryptChunk(input, session.subkey, session.cipher, 0)
        val (target, afterTarget) = AddrCodec.parseSocksTarget(first, 0)
        assertEquals("example.com", target.host)
        val got = ByteArrayOutputStream()
        got.write(first, afterTarget, first.size - afterTarget)
        var counter = next
        while (input.available() > 0) {
            val (chunk, n) = SsCrypto.decryptChunk(input, session.subkey, session.cipher, counter)
            counter = n
            got.write(chunk)
        }
        assertArrayEquals(payload, got.toByteArray())
    }
}
