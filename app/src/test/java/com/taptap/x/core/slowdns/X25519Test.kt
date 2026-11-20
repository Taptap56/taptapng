package com.taptap.x.core.slowdns

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * X25519 vectors, RFC 7748 §5.2/§6.1. The §5.2 iteration vector
 * (scalar = u = 09 00…00, i.e. the base point) is
 * 422c8e7a… after one iteration — verified against the RFC text at
 * rfc-editor.org; the 2fe57da3… value is not the RFC vector.
 */
class X25519Test {

    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun hexOf(b: ByteArray): String =
        b.joinToString("") { "%02x".format(it) }

    @Test
    fun `RFC 7748 section 6-1 Alice and Bob`() {
        val alicePriv =
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val alicePub =
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val bobPriv =
            hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bobPub =
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val shared =
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        assertArrayEquals(alicePub, X25519.publicKey(alicePriv))
        assertArrayEquals(bobPub, X25519.publicKey(bobPriv))
        assertArrayEquals(shared, X25519.scalarmult(alicePriv, bobPub))
        assertArrayEquals(shared, X25519.scalarmult(bobPriv, alicePub))
    }

    @Test
    fun `RFC 7748 section 5-2 iteration vector, one iteration`() {
        val nine = hex("0900000000000000000000000000000000000000000000000000000000000000")
        assertArrayEquals(X25519.BASEPOINT, nine)
        assertEquals(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            hexOf(X25519.scalarmult(nine, X25519.BASEPOINT)),
        )
    }

    @Test
    fun `Diffie-Hellman is commutative on random keys`() {
        val a = ByteArray(32) { (it * 37 + 11).toByte() }
        val b = ByteArray(32) { (it * 53 + 7).toByte() }
        assertArrayEquals(
            X25519.scalarmult(a, X25519.publicKey(b)),
            X25519.scalarmult(b, X25519.publicKey(a)),
        )
    }

    @Test
    fun `clamping makes low bits of the scalar irrelevant`() {
        // Scalars differing only in bits 0-2 / 254 / 255 give the same result.
        val base = ByteArray(32) { 0x55 }
        val tweaked = base.copyOf().also {
            it[0] = 0x56 // flips bit 1, cleared by clamping
            it[31] = 0xD5.toByte() // flips bits 254/255, forced by clamping
        }
        assertArrayEquals(
            X25519.publicKey(base),
            X25519.publicKey(tweaked),
        )
    }
}
