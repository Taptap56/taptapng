package com.taptap.ng.proto
import com.taptap.ng.core.proto.*

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * VMess AEAD crypto unit tests — no network, no Android API.
 * Vectors:
 * - SHAKE128: Python hashlib oracle (hashlib.shake_128).
 * - ChaCha20-Poly1305: RFC 8439 §2.8.2 vector + JDK Cipher cross-check.
 * - Header/chunk framing: encode with the production code, decode with
 *   the production parser (round-trip), plus a manual frame check.
 */
class VmessCryptoTest {

    private val uuid = "de305d54-75b4-431b-adb2-eb6b9e546014"

    @Test
    fun `kdf is deterministic and path-sensitive`() {
        val key = ByteArray(16) { it.toByte() }
        val a = Crypto.kdf(key, "VMess Header AEAD Key".toByteArray())
        val b = Crypto.kdf(key, "VMess Header AEAD Key".toByteArray())
        assertArrayEquals(a, b)
        assertEquals(32, a.size)
        val c = Crypto.kdf(key, "VMess Header AEAD Nonce".toByteArray())
        assertNotEquals(a.toList(), c.toList())
        assertEquals(16, Crypto.kdf16(key, "x".toByteArray()).size)
        assertEquals(12, Crypto.kdf12(key, "x".toByteArray()).size)
    }

    @Test
    fun `cmdKey matches MD5 of uuid plus magic`() {
        val expected = Crypto.md5(
            AddrCodec.parseUuidBytes(uuid) +
                "c48619fe-8f02-49e0-b9e9-edf763e17e21".toByteArray(Charsets.UTF_8),
        )
        assertArrayEquals(expected, VmessCrypto.cmdKey(uuid))
    }

    @Test
    fun `authId decrypts to timestamp plus valid crc`() {
        val cmdKey = VmessCrypto.cmdKey(uuid)
        val now = 1_700_000_000L
        val authId = VmessCrypto.createAuthId(cmdKey, now, byteArrayOf(1, 2, 3, 4))
        val key = Crypto.kdf16(cmdKey, "AES Auth ID Encryption".toByteArray(Charsets.UTF_8))
        val plain = Crypto.aesEcbDecrypt(key, authId)
        var ts = 0L
        for (i in 0 until 8) ts = (ts shl 8) or (plain[i].toLong() and 0xFF)
        assertEquals(now, ts)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), plain.copyOfRange(8, 12))
        val crcRead = ((plain[12].toInt() and 0xFF) shl 24) or
            ((plain[13].toInt() and 0xFF) shl 16) or
            ((plain[14].toInt() and 0xFF) shl 8) or
            (plain[15].toInt() and 0xFF)
        assertEquals(Crypto.crc32Ieee(plain.copyOfRange(0, 12)), crcRead)
    }

    @Test
    fun `shake128 matches python hashlib vectors`() {
        // hashlib.shake_128(b'').hexdigest(64)
        assertEquals(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
            Shake128.digest(ByteArray(0), 64).joinToString("") { "%02x".format(it) },
        )
        // hashlib.shake_128(b'abc').hexdigest(32)
        assertEquals(
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
            Shake128.digest("abc".toByteArray(Charsets.UTF_8), 32).joinToString("") { "%02x".format(it) },
        )
        // hashlib.shake_128(bytes(range(16))).hexdigest(16)
        assertEquals(
            "98481946de85c670a7a84432ab4091a8",
            Shake128.digest(ByteArray(16) { it.toByte() }, 16).joinToString("") { "%02x".format(it) },
        )
    }

    @Test
    fun `shake128 stream is continuous across pulls`() {
        val shake = Shake128("abc".toByteArray(Charsets.UTF_8))
        val a = shake.nextBytes(10)
        val b = shake.nextBytes(22)
        val whole = Shake128.digest("abc".toByteArray(Charsets.UTF_8), 32)
        assertArrayEquals(whole.copyOfRange(0, 10), a)
        assertArrayEquals(whole.copyOfRange(10, 32), b)
        // nextUint16 reads big-endian pairs from the same stream.
        val shake2 = Shake128(ByteArray(0))
        val first = shake2.nextUint16()
        val bytes = Shake128.digest(ByteArray(0), 2)
        assertEquals(((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF), first)
    }

    @Test
    fun `chacha20-poly1305 matches RFC 8439 vector`() {
        // RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 test vector.
        val key = ByteArray(32) { (0x80 + it).toByte() }
        val nonce = byteArrayOf(
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        )
        val plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you " +
            "only one tip for the future, sunscreen would be it.").toByteArray(Charsets.UTF_8)
        val aad = byteArrayOf(
            0x50, 0x51, 0x52, 0x53, 0xc0.toByte(), 0xc1.toByte(), 0xc2.toByte(), 0xc3.toByte(),
            0xc4.toByte(), 0xc5.toByte(), 0xc6.toByte(), 0xc7.toByte(),
        )
        val expectedHex = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        // The final 16 bytes are the Poly1305 tag (RFC 8439 §2.8.2);
        // the 114-byte ciphertext alone is not the AEAD output.
        val sealed = ChaCha20Poly1305(key).seal(nonce, plaintext, aad)
        assertEquals(expectedHex, sealed.joinToString("") { "%02x".format(it) })
        val opened = ChaCha20Poly1305(key).open(nonce, sealed, aad)
        assertArrayEquals(plaintext, opened)
    }

    @Test
    fun `chacha20-poly1305 matches JDK cipher on random inputs`() {
        val key = Crypto.randomBytes(32)
        val nonce = Crypto.randomBytes(12)
        val plaintext = Crypto.randomBytes(1000)
        val aad = Crypto.randomBytes(13)
        val mine = ChaCha20Poly1305(key).seal(nonce, plaintext, aad)
        val jce = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        jce.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "ChaCha20"),
            javax.crypto.spec.IvParameterSpec(nonce),
        )
        jce.updateAAD(aad)
        val theirs = jce.doFinal(plaintext)
        assertArrayEquals(theirs, mine)
        // And my open() accepts the JDK output.
        assertArrayEquals(plaintext, ChaCha20Poly1305(key).open(nonce, theirs, aad))
    }

    @Test
    fun `chacha20-poly1305 rejects a tampered tag`() {
        val key = Crypto.randomBytes(32)
        val nonce = Crypto.randomBytes(12)
        val sealed = ChaCha20Poly1305(key).seal(nonce, "hello".toByteArray(), null)
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 0x01).toByte()
        assertThrows(javax.crypto.AEADBadTagException::class.java) {
            ChaCha20Poly1305(key).open(nonce, sealed, null)
        }
    }

    @Test
    fun `vmess chunk round-trip aes-128-gcm`() {
        chunkRoundTrip(VmessSecurity.AES_128_GCM)
    }

    @Test
    fun `vmess chunk round-trip chacha20-poly1305`() {
        chunkRoundTrip(VmessSecurity.CHACHA20_POLY1305)
    }

    private fun chunkRoundTrip(security: VmessSecurity) {
        val bodyKey = Crypto.randomBytes(16)
        val bodyIV = Crypto.randomBytes(16)
        val nonceOut = VmessCrypto.ChunkNonce(bodyIV)
        val nonceIn = VmessCrypto.ChunkNonce(bodyIV)
        val payload = Crypto.randomBytes(5000)
        val sealed = VmessCrypto.sealBodyChunk(security, bodyKey, nonceOut.next(), payload)
        assertEquals(payload.size + 16, sealed.size)
        val opened = VmessCrypto.openBodyChunk(security, bodyKey, nonceIn.next(), sealed)
        assertArrayEquals(payload, opened)
        // Nonce counter advances: a second chunk uses a different nonce.
        val sealed2 = VmessCrypto.sealBodyChunk(security, bodyKey, nonceOut.next(), payload)
        assertNotEquals(sealed.toList(), sealed2.toList())
        assertArrayEquals(payload, VmessCrypto.openBodyChunk(security, bodyKey, nonceIn.next(), sealed2))
    }

    @Test
    fun `vmess logical header parses back`() {
        val bodyKey = Crypto.randomBytes(16)
        val bodyIV = Crypto.randomBytes(16)
        val responseV: Byte = 0x42
        val header = VmessCrypto.buildLogicalHeader(
            bodyKey, bodyIV, responseV, VmessSecurity.AES_128_GCM, "example.com", 8443,
        )
        val parsed = VmessCrypto.parseLogicalHeader(header)
        assertArrayEquals(bodyKey, parsed.bodyKey)
        assertArrayEquals(bodyIV, parsed.bodyIV)
        assertEquals(responseV, parsed.responseV)
        assertEquals(VmessSecurity.AES_128_GCM, parsed.security)
        assertEquals(0x01, parsed.command)
        assertEquals("example.com", parsed.target.host)
        assertEquals(8443, parsed.target.port)
        assertEquals(VmessCrypto.OPTION_AEAD, parsed.option)
    }

    @Test
    fun `vmess logical header rejects a bad checksum`() {
        val header = VmessCrypto.buildLogicalHeader(
            Crypto.randomBytes(16), Crypto.randomBytes(16), 0x01,
            VmessSecurity.CHACHA20_POLY1305, "example.com", 443,
        )
        header[header.size - 1] = (header[header.size - 1].toInt() xor 0xFF).toByte()
        assertThrows(IllegalArgumentException::class.java) {
            VmessCrypto.parseLogicalHeader(header)
        }
    }

    @Test
    fun `vmess sealed request header opens back`() {
        val item = com.taptap.ng.data.ProfileItem(
            configType = com.taptap.ng.data.ConfigType.VMESS,
            address = "127.0.0.1", port = 1,
            uuid = uuid, security = "chacha20-poly1305",
        )
        val session = VmessCrypto.newSession(item, "example.com", 8443)
        val opened = VmessCrypto.openRequestHeader(
            VmessCrypto.cmdKey(uuid),
            ByteArrayInputStream(session.requestBytes),
        )
        assertEquals("example.com", opened.header.target.host)
        assertEquals(8443, opened.header.target.port)
        assertEquals(VmessSecurity.CHACHA20_POLY1305, opened.header.security)
        assertArrayEquals(session.bodyKey, opened.header.bodyKey)
        assertArrayEquals(session.bodyIV, opened.header.bodyIV)
        assertEquals(session.responseV, opened.header.responseV)
    }

    @Test
    fun `vmess response header seals and opens`() {
        val item = com.taptap.ng.data.ProfileItem(
            configType = com.taptap.ng.data.ConfigType.VMESS,
            uuid = uuid, security = "auto",
        )
        val session = VmessCrypto.newSession(item, "example.com", 443)
        val sealed = VmessCrypto.sealResponseHeader(session, session.responseV)
        val opened = VmessCrypto.readResponseHeader(ByteArrayInputStream(sealed), session)
        assertEquals(session.responseV, opened[0])
        assertEquals(0, opened[2]) // command 0
    }

    @Test
    fun `vmess body streams round-trip with termination`() {
        bodyStreamRoundTrip(VmessSecurity.AES_128_GCM)
        bodyStreamRoundTrip(VmessSecurity.CHACHA20_POLY1305)
    }

    private fun bodyStreamRoundTrip(security: VmessSecurity) {
        val item = com.taptap.ng.data.ProfileItem(
            configType = com.taptap.ng.data.ConfigType.VMESS,
            uuid = uuid,
            security = when (security) {
                VmessSecurity.AES_128_GCM -> "aes-128-gcm"
                VmessSecurity.CHACHA20_POLY1305 -> "chacha20-poly1305"
                VmessSecurity.NONE -> "none"
            },
        )
        val sessionOut = VmessCrypto.newSession(item, "example.com", 443)
        // The reader side uses the writer's keys as its *response* keys.
        val sessionIn = sessionOut.copy(
            responseBodyKey = sessionOut.bodyKey,
            responseBodyIV = sessionOut.bodyIV,
        )
        val payload = ByteArray(20_000) { (it % 251).toByte() }
        val sink = ByteArrayOutputStream()
        val writer = VmessBodyOutputStream(sink, sessionOut)
        writer.write(payload)
        writer.close() // sends the empty termination chunk
        val reader = VmessBodyInputStream(ByteArrayInputStream(sink.toByteArray()), sessionIn)
        val got = reader.readBytes()
        assertArrayEquals(payload, got)
        assertEquals(-1, reader.read())
    }

    @Test
    fun `body streams honour request vs response key direction (M3)`() {
        val item = com.taptap.ng.data.ProfileItem(
            configType = com.taptap.ng.data.ConfigType.VMESS,
            uuid = uuid,
            security = "aes-128-gcm",
        )
        val session = VmessCrypto.newSession(item, "example.com", 443)
        val payload = "ping-slowdns".toByteArray(Charsets.UTF_8)

        // Server reading the REQUEST body: writer uses the request
        // keys (default), reader must be given the request keys too.
        val reqSink = ByteArrayOutputStream()
        VmessBodyOutputStream(reqSink, session).apply { write(payload); close() }
        val reqReader = VmessBodyInputStream(
            ByteArrayInputStream(reqSink.toByteArray()), session,
            key = session.bodyKey, iv = session.bodyIV,
        )
        assertArrayEquals(payload, reqReader.readBytes())

        // Server writing the RESPONSE body: writer must be given the
        // response keys; the client reader uses them by default.
        val respSink = ByteArrayOutputStream()
        VmessBodyOutputStream(
            respSink, session,
            key = session.responseBodyKey, iv = session.responseBodyIV,
        ).apply { write(payload); close() }
        val respReader = VmessBodyInputStream(
            ByteArrayInputStream(respSink.toByteArray()), session,
        )
        assertArrayEquals(payload, respReader.readBytes())

        // The old mock-server pairing (request-key writer, default
        // response-key reader) must NOT round-trip: the unmasked
        // chunk size is garbage and the read fails.
        val badSink = ByteArrayOutputStream()
        VmessBodyOutputStream(badSink, session).apply { write(payload); close() }
        val badReader = VmessBodyInputStream(
            ByteArrayInputStream(badSink.toByteArray()), session,
        )
        assertThrows(java.io.IOException::class.java) { badReader.readBytes() }
    }

    @Test
    fun `resolveSecurity maps auto and rejects unknown`() {
        assertEquals(VmessSecurity.AES_128_GCM, VmessCrypto.resolveSecurity("auto"))
        assertEquals(VmessSecurity.AES_128_GCM, VmessCrypto.resolveSecurity("aes-128-gcm"))
        assertEquals(VmessSecurity.CHACHA20_POLY1305, VmessCrypto.resolveSecurity("chacha20-poly1305"))
        assertEquals(VmessSecurity.NONE, VmessCrypto.resolveSecurity("none"))
        assertThrows(IllegalArgumentException::class.java) {
            VmessCrypto.resolveSecurity("aes-128-cfb")
        }
    }

    @Test
    fun `uuid parsing handles dashes and falls back for short ids`() {
        val bytes = AddrCodec.parseUuidBytes(uuid)
        assertEquals(16, bytes.size)
        assertEquals(0xDE.toByte(), bytes[0])
        assertEquals(0x14.toByte(), bytes[15])
        // Short custom id: deterministic MD5 fallback, still 16 bytes.
        val short = AddrCodec.parseUuidBytes("my-server")
        assertEquals(16, short.size)
        assertArrayEquals(Crypto.md5("my-server".toByteArray(Charsets.UTF_8)), short)
    }
}
