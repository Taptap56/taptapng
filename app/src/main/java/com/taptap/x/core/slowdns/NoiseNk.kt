package com.taptap.x.core.slowdns

import com.taptap.x.core.proto.ChaCha20Poly1305
import com.taptap.x.core.proto.Crypto
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.AEADBadTagException
import kotlin.concurrent.thread

/**
 * Noise_NK_25519_ChaChaPoly_BLAKE2s, initiator (client) side, matching
 * github.com/flynn/noise v1.0.0 exactly.
 *
 * Pattern NK = pre-message (responder static), messages [[E, DHES],
 * [E, DHEE]]. HKDF is HMAC-BLAKE2s (BLAKE2s has a 64-byte block, so
 * [Crypto.hmacWithHash] is the correct HMAC construction for it).
 * ChaCha20-Poly1305 nonces are 12 bytes: 4 zero bytes + 8-byte
 * little-endian counter, as in flynn/noise cipher_suite.go.
 *
 * Note on the protocol name: "Noise_NK_25519_ChaChaPoly_BLAKE2s" is
 * 33 bytes, i.e. longer than the 32-byte BLAKE2s output, so per
 * InitializeSymmetric h = BLAKE2s(name) — it is NOT the raw name
 * bytes. The flynn/noise vectors.txt golden test pins this down.
 *
 * Never log keys, nonces, or handshake material.
 */

/** HKDF-BLAKE2s (flynn/noise hkdf.go): returns (out1, out2). */
private fun hkdfBlake2s(ck: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
    val hashFn: (ByteArray) -> ByteArray = ::blake2s256
    val tempKey = Crypto.hmacWithHash(hashFn, ck, ikm)
    val out1 = Crypto.hmacWithHash(hashFn, tempKey, byteArrayOf(0x01))
    val out2 = Crypto.hmacWithHash(hashFn, tempKey, out1 + byteArrayOf(0x02))
    return out1 to out2
}

private fun chachaNonce(counter: Long): ByteArray {
    val nonce = ByteArray(12)
    for (i in 0 until 8) nonce[4 + i] = ((counter ushr (8 * i)) and 0xFF).toByte()
    return nonce
}

/**
 * Noise SymmetricState (flynn/noise state.go) specialised to
 * ChaChaPoly + BLAKE2s.
 */
private class SymmetricState(protocolName: ByteArray) {
    var h: ByteArray
    var ck: ByteArray
    private var key: ByteArray = ByteArray(32)
    private var nonce: Long = 0
    private var hasKey = false

    init {
        h = if (protocolName.size <= 32) {
            // Short name: zero-padded to the hash size.
            protocolName.copyOf(32)
        } else {
            blake2s256(protocolName)
        }
        ck = h.copyOf()
    }

    fun mixHash(data: ByteArray) {
        h = blake2s256(h + data)
    }

    fun mixKey(ikm: ByteArray) {
        nonce = 0
        hasKey = true
        val (newCk, newKey) = hkdfBlake2s(ck, ikm)
        ck = newCk
        key = newKey
    }

    /** Encrypts with ad = h, then MixHash(ciphertext). */
    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        if (!hasKey) {
            mixHash(plaintext)
            return plaintext.copyOf()
        }
        val ciphertext = ChaCha20Poly1305(key).seal(chachaNonce(nonce), plaintext, h)
        nonce++
        mixHash(ciphertext)
        return ciphertext
    }

    /** Decrypts with ad = h (throws on a bad tag), then MixHash(data). */
    fun decryptAndHash(data: ByteArray): ByteArray {
        if (!hasKey) {
            mixHash(data)
            return data.copyOf()
        }
        val plaintext = ChaCha20Poly1305(key).open(chachaNonce(nonce), data, h)
        nonce++
        mixHash(data)
        return plaintext
    }

    /** Split() via HKDF(ck, empty, 2): (k1, k2). */
    fun split(): Pair<ByteArray, ByteArray> = hkdfBlake2s(ck, ByteArray(0))
}

/**
 * Noise_NK client (initiator).
 *
 * @param serverPublicKey the responder's static public key (rs), 32 bytes.
 * @param prologue mixed into h before the handshake; defaults to the
 *   dnstt prologue "dnstt 2020-04-13". Pass an empty array for the
 *   flynn/noise test vectors.
 * @param ephemeralPrivate test injection: used as the ephemeral private
 *   key instead of a random one. Null (the default) generates one.
 */
class NoiseNkClient(
    serverPublicKey: ByteArray,
    prologue: ByteArray = "dnstt 2020-04-13".toByteArray(Charsets.US_ASCII),
    private val ephemeralPrivate: ByteArray? = null,
) {
    companion object {
        val PROTOCOL_NAME: ByteArray =
            "Noise_NK_25519_ChaChaPoly_BLAKE2s".toByteArray(Charsets.US_ASCII)
    }

    private val rs: ByteArray = serverPublicKey.copyOf()
    private val ss = SymmetricState(PROTOCOL_NAME)
    private var ePrivate: ByteArray? = null
    private var wroteMessage1 = false
    private var transport: NoiseTransport? = null

    init {
        require(serverPublicKey.size == 32) { "server public key must be 32 bytes" }
        if (ephemeralPrivate != null) {
            require(ephemeralPrivate.size == 32) { "ephemeral private key must be 32 bytes" }
        }
        ss.mixHash(prologue)
        ss.mixHash(rs)
    }

    /**
     * Handshake message 1: e.public (32 bytes) + AEAD tag (16 bytes)
     * over the empty payload. 48 bytes total.
     */
    fun writeMessage1(): ByteArray {
        check(!wroteMessage1) { "writeMessage1() already called" }
        val ePriv = ephemeralPrivate?.copyOf() ?: Crypto.randomBytes(32)
        val ePub = X25519.publicKey(ePriv)
        ePrivate = ePriv
        ss.mixHash(ePub)
        ss.mixKey(X25519.scalarmult(ePriv, rs))
        val out = ePub + ss.encryptAndHash(ByteArray(0))
        wroteMessage1 = true
        return out
    }

    /**
     * Handshake message 2 (48 bytes from the server). Verifies the AEAD
     * tag — throws [AEADBadTagException] on failure — then Split()s
     * into the transport keys. The initiator sends with k1 and receives
     * with k2.
     */
    fun readMessage2(message: ByteArray): NoiseTransport {
        check(wroteMessage1) { "writeMessage1() must be called first" }
        check(transport == null) { "readMessage2() already called" }
        require(message.size == 48) { "Noise handshake message 2 must be 48 bytes" }
        val re = message.copyOfRange(0, 32)
        ss.mixHash(re)
        ss.mixKey(X25519.scalarmult(ePrivate!!, re))
        ss.decryptAndHash(message.copyOfRange(32, 48))
        val (k1, k2) = ss.split()
        return NoiseTransport(k1, k2).also { transport = it }
    }
}

/**
 * Post-handshake transport cipher state. ChaCha20-Poly1305 with a
 * per-direction nonce starting at 0 and incrementing per message, and
 * no associated data. [decrypt] throws on a bad tag (and does not
 * advance the receive nonce in that case).
 */
class NoiseTransport internal constructor(
    sendKey: ByteArray,
    recvKey: ByteArray,
) {
    private val sendCipher = ChaCha20Poly1305(sendKey.copyOf())
    private val recvCipher = ChaCha20Poly1305(recvKey.copyOf())
    private var sendNonce = 0L
    private var recvNonce = 0L

    @Synchronized
    fun encrypt(plaintext: ByteArray): ByteArray {
        val out = sendCipher.seal(chachaNonce(sendNonce), plaintext, null)
        sendNonce++
        return out
    }

    @Synchronized
    fun decrypt(ciphertext: ByteArray): ByteArray {
        val out = recvCipher.open(chachaNonce(recvNonce), ciphertext, null)
        recvNonce++
        return out
    }
}

/**
 * The dnstt socket: a stream of plaintext bytes over a [NoiseTransport],
 * framed as 2-byte big-endian length + encrypted message on the wire.
 *
 * [input] is fed by a daemon background thread that reads
 * length-prefixed messages from [rawIn], decrypts them, and enqueues
 * the plaintext; close() (or end-of-stream, or a bad tag) unblocks
 * readers with EOF (-1). [output] buffers writes and splits them into
 * chunks of at most 4096 plaintext bytes, each encrypted separately;
 * [OutputStream.flush] forces pending bytes out. close() flushes
 * pending output, then closes the raw streams.
 */
class NoiseSocket(
    private val transport: NoiseTransport,
    private val rawIn: InputStream,
    private val rawOut: OutputStream,
) {
    companion object {
        /** Max plaintext bytes per encrypted transport message. */
        const val MAX_CHUNK = 4096
    }

    private class Chunk(val data: ByteArray, val eof: Boolean)

    private val queue = LinkedBlockingQueue<Chunk>()
    private val closedState = AtomicBoolean(false)
    private val readerThread: Thread

    init {
        readerThread = thread(
            start = true,
            isDaemon = true,
            name = "NoiseSocket-reader",
        ) { readLoop() }
    }

    val input: InputStream = object : InputStream() {
        private var current: ByteArray? = null
        private var pos = 0
        private var eof = false

        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) <= 0) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            while (current == null || pos >= current!!.size) {
                if (eof) return -1
                val chunk = takeChunk() ?: run { eof = true; return -1 }
                if (chunk.eof) {
                    eof = true
                    return -1
                }
                current = chunk.data
                pos = 0
                // An empty plaintext message carries no bytes; wait for
                // the next chunk instead of returning 0 mid-stream.
            }
            val cur = current!!
            val take = minOf(len, cur.size - pos)
            cur.copyInto(b, off, pos, pos + take)
            pos += take
            return take
        }

        override fun available(): Int {
            val cur = current
            return if (cur != null) cur.size - pos else 0
        }

        override fun close() {
            this@NoiseSocket.close()
        }

        private fun takeChunk(): Chunk? {
            while (true) {
                try {
                    return queue.take()
                } catch (_: InterruptedException) {
                    if (closedState.get()) return null
                    // Otherwise retry: the read was not cancelled.
                }
            }
        }
    }

    val output: OutputStream = object : OutputStream() {
        private val pending = ByteArrayOutputStream()

        @Synchronized
        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
            var o = off
            var remaining = len
            while (remaining > 0) {
                if (pending.size() >= MAX_CHUNK) flushPendingLocked()
                val take = minOf(MAX_CHUNK - pending.size(), remaining)
                pending.write(b, o, take)
                o += take
                remaining -= take
                if (pending.size() == MAX_CHUNK) flushPendingLocked()
            }
        }

        @Synchronized
        override fun flush() {
            flushPendingLocked()
            rawOut.flush()
        }

        @Synchronized
        override fun close() {
            this@NoiseSocket.close()
        }

        /** Caller must hold this stream's monitor. */
        private fun flushPendingLocked() {
            if (pending.size() == 0) return
            val plain = pending.toByteArray()
            pending.reset()
            val cipher = transport.encrypt(plain)
            synchronized(rawOut) {
                rawOut.write((cipher.size ushr 8) and 0xFF)
                rawOut.write(cipher.size and 0xFF)
                rawOut.write(cipher)
            }
        }
    }

    private fun readLoop() {
        try {
            while (!closedState.get()) {
                val lenBytes = ByteArray(2)
                if (!readFully(rawIn, lenBytes)) break
                val len = ((lenBytes[0].toInt() and 0xFF) shl 8) or
                    (lenBytes[1].toInt() and 0xFF)
                val cipher = ByteArray(len)
                if (!readFully(rawIn, cipher)) break
                val plain = try {
                    transport.decrypt(cipher)
                } catch (_: Exception) {
                    break // Bad tag (or other failure): kill the stream.
                }
                queue.put(Chunk(plain, false))
            }
        } catch (_: Exception) {
            // Raw read failure: fall through to EOF.
        } finally {
            queue.offer(Chunk(ByteArray(0), true))
        }
    }

    private fun readFully(input: InputStream, buf: ByteArray): Boolean {
        var filled = 0
        while (filled < buf.size) {
            val n = input.read(buf, filled, buf.size - filled)
            if (n < 0) return false
            filled += n
        }
        return true
    }

    /** Idempotent. Flushes pending output, then closes the raw streams. */
    fun close() {
        if (!closedState.compareAndSet(false, true)) return
        try {
            output.flush()
        } catch (_: Exception) {
        }
        try {
            rawIn.close()
        } catch (_: Exception) {
        }
        queue.offer(Chunk(ByteArray(0), true))
        try {
            rawOut.close()
        } catch (_: Exception) {
        }
    }
}
