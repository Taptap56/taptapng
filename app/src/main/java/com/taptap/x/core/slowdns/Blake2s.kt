package com.taptap.x.core.slowdns

/**
 * BLAKE2s-256 (RFC 7693), pure Kotlin. 32-byte digest, 64-byte block,
 * unkeyed, sequential mode (fanout 1, depth 1).
 *
 * Used as the Noise HASH function (BLAKE2s) for the DNSTT handshake:
 * MixHash / MixKey HKDF both run over this. No Android imports, no
 * logging of inputs.
 */

/** One-shot BLAKE2s-256. */
fun blake2s256(data: ByteArray): ByteArray {
    val h = Blake2s()
    h.update(data)
    return h.digest()
}

class Blake2s {

    companion object {
        // BLAKE2s IV (first 32 bits of the fractional parts of the square
        // roots of the first 8 primes). Written via Long so the values
        // with the top bit set compile; .toInt() reinterprets the bits.
        private val IV = intArrayOf(
            0x6A09E667L.toInt(), 0xBB67AE85L.toInt(),
            0x3C6EF372L.toInt(), 0xA54FF53AL.toInt(),
            0x510E527FL.toInt(), 0x9B05688CL.toInt(),
            0x1F83D9ABL.toInt(), 0x5BE0CD19L.toInt(),
        )

        // Message-word schedule permutations, one row per round (RFC 7693 §2.7).
        private val SIGMA = arrayOf(
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        )

        private fun rotr(x: Int, n: Int): Int = (x ushr n) or (x shl (32 - n))

        private fun le32(b: ByteArray, off: Int): Int =
            (b[off].toInt() and 0xFF) or
                ((b[off + 1].toInt() and 0xFF) shl 8) or
                ((b[off + 2].toInt() and 0xFF) shl 16) or
                ((b[off + 3].toInt() and 0xFF) shl 24)
    }

    private val h = IntArray(8)
    private val buf = ByteArray(64)
    private var bufLen = 0
    /** Bytes already absorbed into full (non-final) blocks. */
    private var total = 0L

    init {
        reset()
    }

    private fun reset() {
        // Parameter block for BLAKE2s-256, unkeyed: digest_length 32,
        // key_length 0, fanout 1, depth 1, everything else 0. Only h[0]
        // differs from the IV: h[0] = IV[0] ^ 0x01010000 ^ 32.
        IV.copyInto(h)
        h[0] = h[0] xor 0x01010000 xor 32
        buf.fill(0)
        bufLen = 0
        total = 0L
    }

    /**
     * Feed [len] bytes starting at [off]. Full 64-byte blocks are
     * compressed immediately, except a trailing full block is held back:
     * only digest() knows whether it is the last block, and the last
     * block is compressed with the finalization flag.
     */
    fun update(data: ByteArray, off: Int = 0, len: Int = data.size - off) {
        require(off >= 0 && len >= 0 && off + len <= data.size) {
            "Blake2s.update out of bounds"
        }
        var o = off
        var remaining = len
        if (bufLen > 0) {
            val take = minOf(64 - bufLen, remaining)
            data.copyInto(buf, bufLen, o, o + take)
            bufLen += take
            o += take
            remaining -= take
            if (bufLen == 64 && remaining > 0) {
                compress(buf, 0, total + 64, last = false)
                total += 64
                bufLen = 0
            }
        }
        while (remaining >= 64) {
            if (remaining == 64) {
                // Might be the final block; hold it for digest().
                data.copyInto(buf, 0, o, o + 64)
                bufLen = 64
                remaining = 0
                break
            }
            compress(data, o, total + 64, last = false)
            total += 64
            o += 64
            remaining -= 64
        }
        if (remaining > 0) {
            data.copyInto(buf, bufLen, o, o + remaining)
            bufLen += remaining
        }
    }

    /** Returns the 32-byte digest and resets this instance for reuse. */
    fun digest(): ByteArray {
        val block = ByteArray(64)
        buf.copyInto(block, 0, 0, bufLen)
        compress(block, 0, total + bufLen, last = true)
        val out = ByteArray(32)
        for (i in 0 until 8) {
            val v = h[i]
            out[i * 4] = (v and 0xFF).toByte()
            out[i * 4 + 1] = ((v ushr 8) and 0xFF).toByte()
            out[i * 4 + 2] = ((v ushr 16) and 0xFF).toByte()
            out[i * 4 + 3] = ((v ushr 24) and 0xFF).toByte()
        }
        reset()
        return out
    }

    /**
     * Compression function. [counter] is the number of bytes compressed
     * so far including this block; [last] sets the final-block flag.
     */
    private fun compress(block: ByteArray, blockOff: Int, counter: Long, last: Boolean) {
        val m = IntArray(16) { le32(block, blockOff + it * 4) }
        val v = IntArray(16)
        h.copyInto(v, 0, 0, 8)
        IV.copyInto(v, 8, 0, 8)
        v[12] = v[12] xor (counter and 0xFFFFFFFFL).toInt()
        v[13] = v[13] xor (counter ushr 32).toInt()
        if (last) v[14] = v[14].inv()
        for (round in 0 until 10) {
            val s = SIGMA[round]
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
    }

    private fun g(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a] = v[a] + v[b] + x
        v[d] = rotr(v[d] xor v[a], 16)
        v[c] = v[c] + v[d]
        v[b] = rotr(v[b] xor v[c], 12)
        v[a] = v[a] + v[b] + y
        v[d] = rotr(v[d] xor v[a], 8)
        v[c] = v[c] + v[d]
        v[b] = rotr(v[b] xor v[c], 7)
    }
}
