package com.taptap.x.core.slowdns

import java.io.PipedInputStream
import java.io.PipedOutputStream
import javax.crypto.AEADBadTagException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Noise_NK_25519_ChaChaPoly_BLAKE2s golden vector: the first
 * Noise_NK_25519_ChaChaPoly_BLAKE2s entry of flynn/noise v1.0.0
 * vectors.txt. The prologue for the vector is EMPTY (ByteArray(0));
 * resp_static is the responder's private key, so the server public
 * key is derived with [X25519.publicKey].
 */
class NoiseNkTest {

    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun hexOf(b: ByteArray): String =
        b.joinToString("") { "%02x".format(it) }

    private fun goldenClient(): NoiseNkClient {
        val respStaticPriv =
            hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        val serverPub = X25519.publicKey(respStaticPriv)
        val ephemeral =
            hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        return NoiseNkClient(serverPub, ByteArray(0), ephemeralPrivate = ephemeral)
    }

    @Test
    fun `golden vector handshake and transport`() {
        val client = goldenClient()
        val msg0 = client.writeMessage1()
        assertEquals(
            "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254" +
                "c796bf92e018434c9b2146fab78f30d0",
            hexOf(msg0),
        )
        val msg1 = hex(
            "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466" +
                "cb3abc71944afc6463300a32ba99b33d",
        )
        val transport = client.readMessage2(msg1)
        // msg_2_payload 79656c6c6f777375626d6172696e65 is "yellowsubmarine"
        // (15 bytes), not "hellosubmarine".
        assertEquals(
            "56a475d3db0d0d5931542a93e3cd57c7dc51b29fc6d0a7cea41aea05d99fe5",
            hexOf(transport.encrypt(hex("79656c6c6f777375626d6172696e65"))),
        )
        assertArrayEquals(
            "submarineyellow".toByteArray(Charsets.US_ASCII),
            transport.decrypt(
                hex(
                    "5c239eb65b5f0d0641f6c6c20aec65646626249f9194e4211a2f8e761c2d72",
                ),
            ),
        )
    }

    @Test
    fun `handshake message 2 with a flipped byte fails the tag check`() {
        val client = goldenClient()
        client.writeMessage1()
        val msg1 = hex(
            "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466" +
                "cb3abc71944afc6463300a32ba99b33d",
        )
        msg1[40] = (msg1[40].toInt() xor 0x01).toByte()
        assertThrows(AEADBadTagException::class.java) { client.readMessage2(msg1) }
    }

    @Test
    fun `transport decrypt with a flipped byte fails the tag check`() {
        val client = goldenClient()
        client.writeMessage1()
        val transport = client.readMessage2(
            hex(
                "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466" +
                    "cb3abc71944afc6463300a32ba99b33d",
            ),
        )
        val bad = hex("5c239eb65b5f0d0641f6c6c20aec65646626249f9194e4211a2f8e761c2d72")
        bad[0] = (bad[0].toInt() xor 0x01).toByte()
        assertThrows(AEADBadTagException::class.java) { transport.decrypt(bad) }
    }

    @Test
    fun `socket round-trips bytes and chunks at 4096`() {
        val keyA = ByteArray(32) { (it + 1).toByte() }
        val keyB = ByteArray(32) { (it + 101).toByte() }
        val pipeAtoB = PipedOutputStream()
        val pipeAIn = PipedInputStream(pipeAtoB)
        val pipeBtoA = PipedOutputStream()
        val pipeBIn = PipedInputStream(pipeBtoA)
        val socketA = NoiseSocket(NoiseTransport(keyA, keyB), pipeBIn, pipeAtoB)
        val socketB = NoiseSocket(NoiseTransport(keyB, keyA), pipeAIn, pipeBtoA)
        try {
            // Small write: stays buffered until flush().
            socketA.output.write("hi".toByteArray(Charsets.US_ASCII))
            assertEquals(0, socketB.input.available())
            socketA.output.flush()

            // 9000 bytes: split into 4096 + 4096 + 808 on the wire.
            val payload = ByteArray(9000) { (it % 251).toByte() }
            socketA.output.write(payload)
            socketA.output.flush()

            val expected = "hi".toByteArray(Charsets.US_ASCII) + payload
            val got = ByteArray(expected.size)
            var filled = 0
            while (filled < got.size) {
                val n = socketB.input.read(got, filled, got.size - filled)
                if (n < 0) break
                filled += n
            }
            assertEquals(expected.size, filled)
            assertArrayEquals(expected, got)

            // Reply direction works too.
            socketB.output.write("ack".toByteArray(Charsets.US_ASCII))
            socketB.output.flush()
            val reply = ByteArray(3)
            var rfilled = 0
            while (rfilled < 3) {
                val n = socketA.input.read(reply, rfilled, 3 - rfilled)
                if (n < 0) break
                rfilled += n
            }
            assertArrayEquals("ack".toByteArray(Charsets.US_ASCII), reply)
        } finally {
            socketA.close()
            socketB.close()
        }
        // Close unblocks readers with EOF.
        assertEquals(-1, socketB.input.read())
    }
}
