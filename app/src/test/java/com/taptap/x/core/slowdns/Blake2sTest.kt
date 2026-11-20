package com.taptap.x.core.slowdns

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * BLAKE2s-256 vectors (RFC 7693). The "abc" vector is
 * 508c5e8c… — ba80a53f… is the BLAKE2b-512("abc") digest, not BLAKE2s
 * (verified against Python hashlib.blake2s/blake2b). Multi-block
 * vectors are Python hashlib.blake2s oracles.
 */
class Blake2sTest {

    private fun digestHex(data: ByteArray): String =
        blake2s256(data).joinToString("") { "%02x".format(it) }

    @Test
    fun `empty input`() {
        assertEquals(
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
            digestHex(ByteArray(0)),
        )
    }

    @Test
    fun `abc`() {
        assertEquals(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            digestHex("abc".toByteArray(Charsets.US_ASCII)),
        )
    }

    @Test
    fun `one full block`() {
        assertEquals(
            "651d2f5f20952eacaea2fba2f2af2bcd633e511ea2d2e4c9ae2ac0d9ffb7b252",
            digestHex(ByteArray(64) { 'a'.code.toByte() }),
        )
    }

    @Test
    fun `multi-block input`() {
        assertEquals(
            "3ac477e27353f9019b81694afe60c8049403784f91a58288428ea318bfa82809",
            digestHex(ByteArray(128) { 'a'.code.toByte() }),
        )
        assertEquals(
            "a4691c2bf852334ece63c024234338fc6c150bdf04fa3f6e0e4c5209b326438d",
            digestHex(ByteArray(1000) { 'a'.code.toByte() }),
        )
    }

    @Test
    fun `streaming split matches one-shot`() {
        val data = "The quick brown fox jumps over the lazy dog"
            .toByteArray(Charsets.US_ASCII)
        assertEquals(
            "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812",
            digestHex(data),
        )
        val h = Blake2s()
        h.update(data, 0, 10)
        h.update(data, 10, 10)
        h.update(data, 20, data.size - 20)
        assertArrayEquals(blake2s256(data), h.digest())
        // digest() resets: a second digest of the same stream repeats.
        h.update(data)
        assertArrayEquals(blake2s256(data), h.digest())
    }

    @Test
    fun `byte-at-a-time streaming matches one-shot`() {
        val data = ByteArray(1000) { 'a'.code.toByte() }
        val h = Blake2s()
        for (b in data) h.update(byteArrayOf(b))
        assertArrayEquals(blake2s256(data), h.digest())
    }
}
