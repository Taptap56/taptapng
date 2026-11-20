package com.taptap.x.core.slowdns

import java.math.BigInteger

/**
 * X25519 (RFC 7748 §5) — Montgomery ladder over Curve25519, pure Kotlin
 * on [BigInteger]. minSdk 24 has no JCA XDH, so this is hand-rolled.
 *
 * Correctness-first: the ladder follows the RFC pseudocode exactly
 * (including the conditional swaps and the top-bit mask on decode).
 * It is not constant-time — BigInteger operations are not — so it must
 * not be used where a timing side channel matters; for the DNSTT
 * handshake (a handful of DH operations per connection) that is
 * acceptable. Never log keys.
 */
object X25519 {

    /** u-coordinate of the base point: 9 followed by 31 zero bytes. */
    val BASEPOINT: ByteArray = ByteArray(32).also { it[0] = 9 }

    private val P: BigInteger =
        BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

    /** (A - 2) / 4 with A = 486662. */
    private val A24: BigInteger = BigInteger.valueOf(121665)

    /**
     * X25519(scalar, point). The scalar is clamped per RFC 7748 §5:
     * clear bits 0, 1, 2 of byte 0, clear bit 255, set bit 254.
     * Both inputs must be 32 bytes; the output is 32 bytes.
     */
    fun scalarmult(scalar: ByteArray, point: ByteArray): ByteArray {
        require(scalar.size == 32) { "X25519 scalar must be 32 bytes" }
        require(point.size == 32) { "X25519 point must be 32 bytes" }
        val e = scalar.copyOf()
        e[0] = (e[0].toInt() and 248).toByte()
        e[31] = (e[31].toInt() and 127).toByte()
        e[31] = (e[31].toInt() or 64).toByte()
        val k = BigInteger(1, e.reversedArray())

        // decodeU: little-endian, top bit of the last byte masked off.
        val uBytes = point.copyOf()
        uBytes[31] = (uBytes[31].toInt() and 0x7F).toByte()
        val x1 = BigInteger(1, uBytes.reversedArray()).mod(P)

        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val kt = if (k.testBit(t)) 1 else 0
            swap = swap xor kt
            if (swap == 1) {
                val tmpX = x2; x2 = x3; x3 = tmpX
                val tmpZ = z2; z2 = z3; z3 = tmpZ
            }
            swap = kt

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e2 = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            x3 = da.add(cb).mod(P).let { it.multiply(it).mod(P) }
            z3 = x1.multiply(da.subtract(cb).mod(P).let { it.multiply(it).mod(P) }).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e2.multiply(aa.add(A24.multiply(e2)).mod(P)).mod(P)
        }
        if (swap == 1) {
            val tmpX = x2; x2 = x3; x3 = tmpX
            val tmpZ = z2; z2 = z3; z3 = tmpZ
        }

        if (z2.mod(P) == BigInteger.ZERO) return ByteArray(32)
        return toLittleEndian32(x2.multiply(z2.modInverse(P)).mod(P))
    }

    /** Public key for [privateKey]: X25519(privateKey, base point). */
    fun publicKey(privateKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "X25519 private key must be 32 bytes" }
        return scalarmult(privateKey, BASEPOINT)
    }

    private fun toLittleEndian32(v: BigInteger): ByteArray {
        val be = v.toByteArray()
        // BigInteger is big-endian two's complement; drop a leading sign
        // byte, then reverse into 32 little-endian bytes, zero-padded.
        val out = ByteArray(32)
        val src = if (be.size > 32) be.copyOfRange(be.size - 32, be.size) else be
        for (i in src.indices) out[i] = src[src.size - 1 - i]
        return out
    }
}
