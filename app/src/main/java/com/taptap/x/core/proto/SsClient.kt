package com.taptap.x.core.proto

import com.taptap.x.core.DialLog
import com.taptap.x.data.ProfileItem
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.AEADBadTagException

/**
 * Shadowsocks client — AEAD ciphers only (SIP004):
 * aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305.
 *
 * TCP stream: random salt (key-length bytes) | AEAD chunks.
 * - Master key = EVP_BytesToKey(password) (MD5 chain, no salt).
 * - Session subkey = HKDF-SHA1(master key, salt, info "ss-subkey").
 * - Each chunk: AEAD(2-byte big-endian plaintext length) ||
 *   AEAD(payload). Max payload 0x3FFF (16383) bytes.
 * - Nonce: 12-byte little-endian counter, starts at 0, +1 per AEAD
 *   operation (so +2 per chunk). Each direction has its own counter
 *   starting at 0; both directions share the subkey.
 * - The first chunk's plaintext starts with the SOCKS target address
 *   (ATYP + address + PORT), then payload bytes.
 *
 * No WS, no TLS — raw TCP only. The 2022-blake3 ciphers need Blake3
 * and are NOT supported; unknown methods throw IllegalArgumentException.
 */
class SsClient(private val item: ProfileItem) : ProxyClient {

    // v1.0.6: see VmessClient — streams stay open independently.
    private val openStreams = ConcurrentHashMap.newKeySet<ProxyStream>()

    override fun dial(targetHost: String, targetPort: Int, probeBody: ByteArray?): ProxyStream {
        // probeBody is ignored: Shadowsocks has no response
        // handshake to unblock — the stream is raw right after the
        // salt + target header.
        val cipher = SsCrypto.resolveCipher(item.method)
        val transport = Transport.open(item.copy(network = "tcp", tls = false))
        try {
            Transport.noteStage("SS")
            val session = SsCrypto.newSession(item.password, cipher)
            transport.output.write(session.salt)
            val bodyOut = SsBodyOutputStream(transport.output, session, targetHost, targetPort)
            val bodyIn = SsBodyInputStream(transport.input, session)
            transport.socket.soTimeout = 0
            Transport.clearWatchdogSocket()
            DialLog.log("SS", "dial ok")
            return TrackedProxyStream(
                SocketProxyStream(transport.socket, bodyIn, bodyOut),
                openStreams,
            )
        } catch (e: Exception) {
            transport.close()
            val failure = Transport.preferWatchdogFailure(e)
            DialLog.failure("SS", failure)
            throw failure
        }
    }

    override fun close() {
        openStreams.toList().forEach { runCatching { it.close() } }
    }
}

enum class SsCipher(val methodName: String, val keyLen: Int) {
    AES_128_GCM("aes-128-gcm", 16),
    AES_256_GCM("aes-256-gcm", 32),
    CHACHA20_POLY1305("chacha20-ietf-poly1305", 32),
}

data class SsSession(
    val salt: ByteArray,
    val subkey: ByteArray,
    val cipher: SsCipher,
)

object SsCrypto {

    const val MAX_CHUNK_PLAINTEXT = 0x3FFF
    const val TAG_LEN = 16

    fun resolveCipher(method: String): SsCipher {
        return when (method.trim().lowercase()) {
            "aes-128-gcm" -> SsCipher.AES_128_GCM
            "aes-256-gcm" -> SsCipher.AES_256_GCM
            "chacha20-ietf-poly1305", "chacha20-poly1305" -> SsCipher.CHACHA20_POLY1305
            else -> throw IllegalArgumentException(
                "Method Shadowsocks tidak didukung: $method " +
                    "(hanya aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305)",
            )
        }
    }

    fun deriveSubkey(masterKey: ByteArray, salt: ByteArray, keyLen: Int): ByteArray =
        Crypto.hkdfSha1(masterKey, salt, "ss-subkey".toByteArray(Charsets.UTF_8), keyLen)

    fun newSession(password: String, cipher: SsCipher): SsSession {
        require(password.isNotEmpty()) { "Password Shadowsocks kosong" }
        val masterKey = Crypto.evpBytesToKey(password.toByteArray(Charsets.UTF_8), cipher.keyLen)
        val salt = Crypto.randomBytes(cipher.keyLen)
        val subkey = deriveSubkey(masterKey, salt, cipher.keyLen)
        return SsSession(salt, subkey, cipher)
    }

    /** 12-byte nonce: little-endian counter value. */
    fun nonce(counter: Long): ByteArray {
        val out = ByteArray(12)
        for (i in 0 until 8) {
            out[i] = ((counter ushr (8 * i)) and 0xFF).toByte()
        }
        return out
    }

    fun sealChunk(subkey: ByteArray, cipher: SsCipher, counter: Long, plaintext: ByteArray): ByteArray {
        return when (cipher) {
            SsCipher.AES_128_GCM, SsCipher.AES_256_GCM ->
                Crypto.aesGcmSeal(subkey, nonce(counter), plaintext, null)
            SsCipher.CHACHA20_POLY1305 ->
                ChaCha20Poly1305(subkey).seal(nonce(counter), plaintext, null)
        }
    }

    fun openChunk(subkey: ByteArray, cipher: SsCipher, counter: Long, sealed: ByteArray): ByteArray {
        return when (cipher) {
            SsCipher.AES_128_GCM, SsCipher.AES_256_GCM ->
                Crypto.aesGcmOpen(subkey, nonce(counter), sealed, null)
            SsCipher.CHACHA20_POLY1305 ->
                ChaCha20Poly1305(subkey).open(nonce(counter), sealed, null)
        }
    }

    /** One SS AEAD chunk: AEAD(len 2B) || AEAD(payload). Returns bytes + next counter. */
    fun encryptChunk(
        subkey: ByteArray,
        cipher: SsCipher,
        counter: Long,
        payload: ByteArray,
    ): Pair<ByteArray, Long> {
        require(payload.size <= MAX_CHUNK_PLAINTEXT) { "Chunk SS melebihi 0x3FFF" }
        val lenBytes = byteArrayOf(((payload.size ushr 8) and 0xFF).toByte(), (payload.size and 0xFF).toByte())
        val encLen = sealChunk(subkey, cipher, counter, lenBytes)
        val encPayload = sealChunk(subkey, cipher, counter + 1, payload)
        return (encLen + encPayload) to (counter + 2)
    }

    /** Read + decrypt one SS AEAD chunk from [input]. Returns payload + next counter. */
    fun decryptChunk(
        input: InputStream,
        subkey: ByteArray,
        cipher: SsCipher,
        counter: Long,
    ): Pair<ByteArray, Long> {
        val encLen = input.readExactBytes(2 + TAG_LEN)
        val lenPlain = try {
            openChunk(subkey, cipher, counter, encLen)
        } catch (e: AEADBadTagException) {
            throw IOException("Chunk SS gagal diverifikasi (panjang)", e)
        }
        val len = ((lenPlain[0].toInt() and 0xFF) shl 8) or (lenPlain[1].toInt() and 0xFF)
        require(len <= MAX_CHUNK_PLAINTEXT) { "Panjang chunk SS tidak wajar: $len" }
        val encPayload = input.readExactBytes(len + TAG_LEN)
        val payload = try {
            openChunk(subkey, cipher, counter + 1, encPayload)
        } catch (e: AEADBadTagException) {
            throw IOException("Chunk SS gagal diverifikasi (payload)", e)
        }
        return payload to (counter + 2)
    }
}

/** SS request body writer: first chunk carries the target address. */
class SsBodyOutputStream(
    private val rawOut: OutputStream,
    private val session: SsSession,
    private val targetHost: String,
    private val targetPort: Int,
) : OutputStream() {

    /**
     * v1.0.15: same fix as VmessBodyOutputStream — the pending bytes
     * live in a reusable ByteArray, not a MutableList<Byte> that
     * boxed every byte. Same chunking semantics, zero boxing.
     */
    private val pendingBuf = ByteArray(SsCrypto.MAX_CHUNK_PLAINTEXT)
    private var pendingLen = 0
    private var counter: Long = 0
    private var firstChunk = true
    private var closed = false

    override fun write(b: Int) = write(byteArrayOf(b.toByte()))

    override fun write(b: ByteArray, off: Int, len: Int) {
        check(!closed) { "SS body stream sudah ditutup" }
        var pos = off
        var remaining = len
        while (remaining > 0) {
            val take = minOf(SsCrypto.MAX_CHUNK_PLAINTEXT - pendingLen, remaining)
            b.copyInto(pendingBuf, pendingLen, pos, pos + take)
            pendingLen += take
            pos += take
            remaining -= take
            if (pendingLen >= SsCrypto.MAX_CHUNK_PLAINTEXT) flushChunk()
        }
    }

    override fun flush() {
        if (pendingLen > 0) flushChunk()
        rawOut.flush()
    }

    private fun flushChunk() {
        if (pendingLen == 0 && !firstChunk) return
        var payload = pendingBuf.copyOf(pendingLen)
        pendingLen = 0
        if (firstChunk) {
            firstChunk = false
            payload = AddrCodec.encodeSocksTarget(targetHost, targetPort) + payload
            // The address header can push the first chunk over the limit;
            // split it so no chunk exceeds 0x3FFF.
            if (payload.size > SsCrypto.MAX_CHUNK_PLAINTEXT) {
                val head = payload.copyOfRange(0, SsCrypto.MAX_CHUNK_PLAINTEXT)
                val rest = payload.copyOfRange(SsCrypto.MAX_CHUNK_PLAINTEXT, payload.size)
                emitChunk(head)
                emitChunk(rest)
                return
            }
        }
        emitChunk(payload)
    }

    private fun emitChunk(payload: ByteArray) {
        val (bytes, next) = SsCrypto.encryptChunk(session.subkey, session.cipher, counter, payload)
        counter = next
        rawOut.write(bytes)
    }

    /** Close: flush pending data. SS has no termination record. */
    override fun close() {
        if (closed) return
        closed = true
        runCatching {
            flush()
        }
    }
}

/** SS response body reader (server direction, counter starts at 0). */
class SsBodyInputStream(
    private val rawIn: InputStream,
    private val session: SsSession,
) : InputStream() {

    private var counter: Long = 0
    private var chunkBuf: ByteArray = ByteArray(0)
    private var chunkPos = 0
    private var eof = false
    private var closed = false

    override fun read(): Int {
        val b = ByteArray(1)
        return if (read(b, 0, 1) == -1) -1 else b[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (closed || eof) return -1
        if (chunkPos >= chunkBuf.size) {
            val (payload, next) = try {
                SsCrypto.decryptChunk(rawIn, session.subkey, session.cipher, counter)
            } catch (e: java.io.EOFException) {
                eof = true
                return -1
            }
            counter = next
            chunkBuf = payload
            chunkPos = 0
            if (payload.isEmpty()) {
                eof = true
                return -1
            }
        }
        val take = minOf(len, chunkBuf.size - chunkPos)
        chunkBuf.copyInto(b, off, chunkPos, chunkPos + take)
        chunkPos += take
        return take
    }

    override fun available(): Int = chunkBuf.size - chunkPos

    override fun close() {
        closed = true
    }
}
