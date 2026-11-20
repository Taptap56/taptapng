package com.taptap.ng.core.proto

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.CRC32
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto primitives for the in-app protocols (M2). Pure JDK + hand-rolled
 * constructions only — no new dependencies.
 *
 * Two primitives are hand-rolled on purpose, because the JDK provider is
 * not guaranteed to offer them on every Android API level (minSdk 24):
 * - SHAKE128 (Keccak-f[1600]) — VMess chunk-length masking.
 * - ChaCha20-Poly1305 (RFC 8439 AEAD) — VMess + Shadowsocks body cipher.
 * Both are validated in unit tests against known vectors (SHAKE128 via
 * Python hashlib oracle, ChaCha20-Poly1305 via the JDK Cipher + RFC 8439).
 *
 * AES-GCM / AES-ECB / MD5 / SHA-1 / SHA-256 / HMAC come from the JDK
 * (available on all API levels we target).
 */
object Crypto {

    private val secureRandom = SecureRandom()

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { secureRandom.nextBytes(it) }

    fun md5(data: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(data)

    fun sha1(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun sha224(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-224").digest(data)

    fun crc32Ieee(data: ByteArray): Int {
        val crc = CRC32()
        crc.update(data)
        return crc.value.toInt()
    }

    /** FNV-1a 32-bit, as used by the VMess instruction-section checksum. */
    fun fnv1a32(data: ByteArray): Int {
        var h = 0x811C9DC5.toInt()
        for (b in data) {
            h = h xor (b.toInt() and 0xFF)
            h *= 0x01000193
        }
        return h
    }

    fun hmacSha256(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    fun hmacSha1(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        return mac.doFinal(msg)
    }

    /**
     * HMAC with an arbitrary 32-byte-output hash function (SHA-256 block
     * size 64). This is the building block of the nested VMess KDF, where
     * each level's "hash function" is the previous level's HMAC.
     */
    fun hmacWithHash(hashFn: (ByteArray) -> ByteArray, key: ByteArray, msg: ByteArray): ByteArray {
        var k = key
        if (k.size > 64) k = hashFn(k)
        val kb = ByteArray(64)
        k.copyInto(kb)
        val ipad = ByteArray(64) { (kb[it].toInt() xor 0x36).toByte() }
        val opad = ByteArray(64) { (kb[it].toInt() xor 0x5C).toByte() }
        return hashFn(opad + hashFn(ipad + msg))
    }

    /**
     * VMess KDF (v2fly spec): nested HMAC-SHA256.
     *   L0 = HMAC-SHA256(key="VMess AEAD KDF")
     *   Li = HMAC(hash=Li-1, key=path[i])
     *   KDF(key, path...) = Ln(key)
     * Returns 32 bytes; use [kdf16]/[kdf12] for the truncated forms.
     */
    fun kdf(key: ByteArray, vararg path: ByteArray): ByteArray {
        var hashFn: (ByteArray) -> ByteArray =
            { msg -> hmacSha256("VMess AEAD KDF".toByteArray(Charsets.UTF_8), msg) }
        for (p in path) {
            val prev = hashFn
            val salt = p
            hashFn = { msg -> hmacWithHash(prev, salt, msg) }
        }
        return hashFn(key)
    }

    fun kdf16(key: ByteArray, vararg path: ByteArray): ByteArray =
        kdf(key, *path).copyOfRange(0, 16)

    fun kdf12(key: ByteArray, vararg path: ByteArray): ByteArray =
        kdf(key, *path).copyOfRange(0, 12)

    /** AES-128/256-GCM seal. Returns ciphertext || 16-byte tag. */
    fun aesGcmSeal(key: ByteArray, nonce12: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, nonce12),
        )
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    /** AES-GCM open. Throws [AEADBadTagException] when the tag is invalid. */
    fun aesGcmOpen(key: ByteArray, nonce12: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, nonce12),
        )
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertextAndTag)
    }

    /** Single-block AES-128-ECB encrypt (VMess AuthID). [block] must be 16 bytes. */
    fun aesEcbEncrypt(key16: ByteArray, block: ByteArray): ByteArray {
        require(block.size == 16) { "AES-ECB block must be 16 bytes" }
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key16, "AES"))
        return cipher.doFinal(block)
    }

    /** Single-block AES-128-ECB decrypt. [block] must be 16 bytes. */
    fun aesEcbDecrypt(key16: ByteArray, block: ByteArray): ByteArray {
        require(block.size == 16) { "AES-ECB block must be 16 bytes" }
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key16, "AES"))
        return cipher.doFinal(block)
    }

    /**
     * HKDF-SHA1 (RFC 5869), used by Shadowsocks AEAD to derive the session
     * subkey from the master key and the per-connection salt.
     */
    fun hkdfSha1(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha1(salt, ikm)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var produced = 0
        var counter = 1
        while (produced < length) {
            val mac = Mac.getInstance("HmacSHA1")
            mac.init(SecretKeySpec(prk, "HmacSHA1"))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val take = minOf(t.size, length - produced)
            t.copyInto(out, produced, 0, take)
            produced += take
            counter++
        }
        return out
    }

    /**
     * Shadowsocks EVP_BytesToKey: MD5 chain, no salt, 1 iteration.
     * key = MD5(pw) || MD5(MD5(pw) || pw) || ...
     */
    fun evpBytesToKey(password: ByteArray, keyLen: Int): ByteArray {
        val out = ByteArray(keyLen)
        var produced = 0
        var prev = ByteArray(0)
        while (produced < keyLen) {
            val md = MessageDigest.getInstance("MD5")
            md.update(prev)
            md.update(password)
            prev = md.digest()
            val take = minOf(prev.size, keyLen - produced)
            prev.copyInto(out, produced, 0, take)
            produced += take
        }
        return out
    }
}

/**
 * SHAKE128 (FIPS 202) built on a hand-rolled Keccak-f[1600]. The JDK
 * MessageDigest does not reliably offer SHAKE128 on Android, so the
 * permutation is implemented here and the stream is squeezed on demand.
 *
 * Usage: create once per mask stream (seed = body IV), then pull bytes
 * with [nextBytes]/[nextUint16]. The stream is continuous — never
 * re-seed mid-connection or the peer's masks desync.
 */
class Shake128(seed: ByteArray) {

    companion object {
        private const val RATE = 168 // 1344 bits for SHAKE128
        private const val SUFFIX = 0x1F // SHAKE domain separation

        // Keccak-f[1600] round constants (hex kept verbatim from FIPS 202;
        // values with the top bit set are written as ULong then reinterpreted).
        private val RC = longArrayOf(
            0x0000000000000001UL.toLong(), 0x0000000000008082UL.toLong(),
            0x800000000000808aUL.toLong(), 0x8000000080008000UL.toLong(),
            0x000000000000808bUL.toLong(), 0x0000000080000001UL.toLong(),
            0x8000000080008081UL.toLong(), 0x8000000000008009UL.toLong(),
            0x000000000000008aUL.toLong(), 0x0000000000000088UL.toLong(),
            0x0000000080008009UL.toLong(), 0x000000008000000aUL.toLong(),
            0x000000008000808bUL.toLong(), 0x800000000000008bUL.toLong(),
            0x8000000000008089UL.toLong(), 0x8000000000008003UL.toLong(),
            0x8000000000008002UL.toLong(), 0x8000000000000080UL.toLong(),
            0x000000000000800aUL.toLong(), 0x800000008000000aUL.toLong(),
            0x8000000080008081UL.toLong(), 0x8000000000008080UL.toLong(),
            0x0000000080000001UL.toLong(), 0x8000000080008008UL.toLong(),
        )

        // Rho rotation offsets, indexed [x][y].
        private val ROT = arrayOf(
            intArrayOf(0, 36, 3, 41, 18),
            intArrayOf(1, 44, 10, 45, 2),
            intArrayOf(62, 6, 43, 15, 61),
            intArrayOf(28, 55, 25, 21, 56),
            intArrayOf(27, 20, 39, 8, 14),
        )

        private fun rotl(x: Long, n: Int): Long =
            if (n == 0) x else (x shl n) or (x ushr (64 - n))

        /** The Keccak-f[1600] permutation, in place on 25 lanes. */
        fun permute(a: LongArray) {
            for (round in 0 until 24) {
                // Theta
                val c = LongArray(5)
                for (x in 0..4) {
                    c[x] = a[x] xor a[x + 5] xor a[x + 10] xor a[x + 15] xor a[x + 20]
                }
                val d = LongArray(5)
                for (x in 0..4) {
                    d[x] = c[(x + 4) % 5] xor rotl(c[(x + 1) % 5], 1)
                }
                for (x in 0..4) {
                    for (y in 0..4) a[x + 5 * y] = a[x + 5 * y] xor d[x]
                }
                // Rho + Pi
                val b = LongArray(25)
                for (x in 0..4) {
                    for (y in 0..4) {
                        val newX = y
                        val newY = (2 * x + 3 * y) % 5
                        b[newX + 5 * newY] = rotl(a[x + 5 * y], ROT[x][y])
                    }
                }
                // Chi
                for (x in 0..4) {
                    for (y in 0..4) {
                        a[x + 5 * y] = b[x + 5 * y] xor
                            (b[(x + 1) % 5 + 5 * y].inv() and b[(x + 2) % 5 + 5 * y])
                    }
                }
                // Iota
                a[0] = a[0] xor RC[round]
            }
        }

        /** One-shot SHAKE128: squeeze exactly [outLen] bytes from [seed]. */
        fun digest(seed: ByteArray, outLen: Int): ByteArray {
            val shake = Shake128(seed)
            return shake.nextBytes(outLen)
        }
    }

    private val state = LongArray(25)
    private val squeezeBuf = ByteArray(RATE)
    private var squeezePos = RATE // absorb() fills the first block and resets this to 0

    init {
        absorb(seed)
    }

    private fun absorb(seed: ByteArray) {
        // Absorb the seed, then pad10*1 with the SHAKE suffix.
        val block = ByteArray(RATE)
        var offset = 0
        var done = false
        while (!done) {
            if (offset < seed.size) {
                val chunk = minOf(RATE, seed.size - offset)
                seed.copyInto(block, 0, offset, offset + chunk)
                if (chunk == RATE) {
                    xorBlockIntoState(block)
                    permute(state)
                    block.fill(0)
                    offset += chunk
                    continue
                }
                // Last partial block: suffix + final bit, then permute once.
                block[chunk] = (block[chunk].toInt() or SUFFIX).toByte()
                block[RATE - 1] = (block[RATE - 1].toInt() or 0x80).toByte()
                xorBlockIntoState(block)
                permute(state)
                done = true
            } else {
                // Seed was empty or an exact multiple of RATE: one more padded block.
                block[0] = (block[0].toInt() or SUFFIX).toByte()
                block[RATE - 1] = (block[RATE - 1].toInt() or 0x80).toByte()
                xorBlockIntoState(block)
                permute(state)
                done = true
            }
        }
        // The state is already permuted: the first squeeze block comes
        // straight from it (no extra permutation).
        extractSqueezeBuffer()
    }

    private fun xorBlockIntoState(block: ByteArray) {
        for (i in 0 until RATE) {
            val lane = i / 8
            val shift = (i % 8) * 8
            state[lane] = state[lane] xor ((block[i].toLong() and 0xFF) shl shift)
        }
    }

    private fun extractSqueezeBuffer() {
        for (i in 0 until RATE) {
            val lane = i / 8
            val shift = (i % 8) * 8
            squeezeBuf[i] = ((state[lane] ushr shift) and 0xFF).toByte()
        }
        squeezePos = 0
    }

    private fun refillSqueezeBuffer() {
        permute(state)
        extractSqueezeBuffer()
    }

    /** Pull the next [n] bytes from the XOF stream. */
    fun nextBytes(n: Int): ByteArray {
        val out = ByteArray(n)
        var filled = 0
        while (filled < n) {
            if (squeezePos >= RATE) refillSqueezeBuffer()
            val take = minOf(RATE - squeezePos, n - filled)
            squeezeBuf.copyInto(out, filled, squeezePos, squeezePos + take)
            squeezePos += take
            filled += take
        }
        return out
    }

    /** Next 2 bytes of the mask stream, big-endian (VMess chunk masks). */
    fun nextUint16(): Int {
        val b = nextBytes(2)
        return ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
    }

    /** Next global-padding length (0..63) for a VMess chunk. */
    fun nextPaddingLen(): Int = nextUint16() % 64
}

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439 §2.8), hand-rolled: 32-byte key,
 * 12-byte nonce, 16-byte tag appended to the ciphertext. The JDK
 * Cipher offers this only on newer Android versions, so the app ships
 * its own — validated against the JDK Cipher and the RFC 8439 vector.
 *
 * Poly1305 here uses BigInteger (simple, obviously correct); it is not
 * the fastest possible implementation, but chunk sizes are small.
 */
class ChaCha20Poly1305(private val key: ByteArray) {

    init {
        require(key.size == 32) { "ChaCha20-Poly1305 key must be 32 bytes" }
    }

    fun seal(nonce12: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray {
        require(nonce12.size == 12) { "ChaCha20 nonce must be 12 bytes" }
        val otk = chachaBlock(counter = 0, nonce12).copyOfRange(0, 32)
        val ciphertext = chachaXor(counter = 1, nonce12, plaintext)
        val tag = poly1305(otk, macData(aad ?: ByteArray(0), ciphertext))
        return ciphertext + tag
    }

    fun open(nonce12: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray?): ByteArray {
        require(nonce12.size == 12) { "ChaCha20 nonce must be 12 bytes" }
        require(ciphertextAndTag.size >= 16) { "ChaCha20-Poly1305 input too short" }
        val ciphertext = ciphertextAndTag.copyOfRange(0, ciphertextAndTag.size - 16)
        val tag = ciphertextAndTag.copyOfRange(ciphertextAndTag.size - 16, ciphertextAndTag.size)
        val otk = chachaBlock(counter = 0, nonce12).copyOfRange(0, 32)
        val expected = poly1305(otk, macData(aad ?: ByteArray(0), ciphertext))
        if (!MessageDigest.isEqual(tag, expected)) {
            throw AEADBadTagException("ChaCha20-Poly1305 tag mismatch")
        }
        return chachaXor(counter = 1, nonce12, ciphertext)
    }

    private fun macData(aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val out = mutableListOf<Byte>()
        fun appendPadded(data: ByteArray) {
            out.addAll(data.toList())
            val rem = data.size % 16
            if (rem != 0) repeat(16 - rem) { out.add(0) }
        }
        appendPadded(aad)
        appendPadded(ciphertext)
        fun appendLe64(v: Long) {
            for (i in 0 until 8) out.add(((v ushr (8 * i)) and 0xFF).toByte())
        }
        appendLe64(aad.size.toLong())
        appendLe64(ciphertext.size.toLong())
        return out.toByteArray()
    }

    private fun chachaBlock(counter: Int, nonce12: ByteArray): ByteArray {
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for (i in 0 until 8) {
            state[4 + i] = le32(key, i * 4)
        }
        state[12] = counter
        for (i in 0 until 3) {
            state[13 + i] = le32(nonce12, i * 4)
        }
        val working = state.copyOf()
        repeat(10) {
            quarterRound(working, 0, 4, 8, 12)
            quarterRound(working, 1, 5, 9, 13)
            quarterRound(working, 2, 6, 10, 14)
            quarterRound(working, 3, 7, 11, 15)
            quarterRound(working, 0, 5, 10, 15)
            quarterRound(working, 1, 6, 11, 12)
            quarterRound(working, 2, 7, 8, 13)
            quarterRound(working, 3, 4, 9, 14)
        }
        val out = ByteArray(64)
        for (i in 0 until 16) {
            val v = working[i] + state[i]
            out[i * 4] = (v and 0xFF).toByte()
            out[i * 4 + 1] = ((v ushr 8) and 0xFF).toByte()
            out[i * 4 + 2] = ((v ushr 16) and 0xFF).toByte()
            out[i * 4 + 3] = ((v ushr 24) and 0xFF).toByte()
        }
        return out
    }

    private fun quarterRound(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
        s[a] += s[b]; s[d] = rotl32(s[d] xor s[a], 16)
        s[c] += s[d]; s[b] = rotl32(s[b] xor s[c], 12)
        s[a] += s[b]; s[d] = rotl32(s[d] xor s[a], 8)
        s[c] += s[d]; s[b] = rotl32(s[b] xor s[c], 7)
    }

    private fun rotl32(x: Int, n: Int): Int = (x shl n) or (x ushr (32 - n))

    private fun le32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
            ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or
            ((b[off + 3].toInt() and 0xFF) shl 24)

    private fun chachaXor(counter: Int, nonce12: ByteArray, data: ByteArray): ByteArray {
        val out = ByteArray(data.size)
        var pos = 0
        var ctr = counter
        while (pos < data.size) {
            val block = chachaBlock(ctr, nonce12)
            ctr++
            val take = minOf(64, data.size - pos)
            for (i in 0 until take) {
                out[pos + i] = (data[pos + i].toInt() xor block[i].toInt()).toByte()
            }
            pos += take
        }
        return out
    }

    private fun poly1305(key32: ByteArray, msg: ByteArray): ByteArray {
        // r = LE(key[0:16]) clamped; s = LE(key[16:32]); p = 2^130 - 5.
        val rMask = BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)
        val r = BigInteger(1, key32.copyOfRange(0, 16).reversedArray()).and(rMask)
        val s = BigInteger(1, key32.copyOfRange(16, 32).reversedArray())
        val p = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5))
        var acc = BigInteger.ZERO
        var off = 0
        while (off < msg.size) {
            val blockLen = minOf(16, msg.size - off)
            val block = msg.copyOfRange(off, off + blockLen)
            val n = BigInteger(1, block.reversedArray())
                .add(BigInteger.ONE.shiftLeft(8 * blockLen))
            acc = acc.add(n).multiply(r).mod(p)
            off += blockLen
        }
        acc = acc.add(s)
        // Output 16 bytes little-endian.
        val be = acc.toByteArray()
        val out = ByteArray(16)
        // BigInteger is big-endian; reverse into the low 16 bytes.
        val src = if (be.size > 16) be.copyOfRange(be.size - 16, be.size) else be
        for (i in src.indices) {
            out[i] = src[src.size - 1 - i]
        }
        return out
    }
}
