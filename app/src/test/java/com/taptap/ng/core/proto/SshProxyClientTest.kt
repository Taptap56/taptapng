package com.taptap.ng.core.proto

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * SshProxyClient tests (v1.0.30) — the SSH entry rides the tunnel
 * through direct-tcpip channels on a shared session. All tests run
 * against the fake [SshChannelOpener] seam (in-memory streams):
 * JSch cannot run on the intercepted JVM loopback in this VM, and
 * the client logic (probeBody ignored, per-dial channel, close)
 * needs no real session at all.
 */
class SshProxyClientTest {

    private class FakeChannel(
        override val input: InputStream,
        override val output: OutputStream,
    ) : SshChannel {
        var closed = false
        override fun close() {
            closed = true
            runCatching { input.close() }
            runCatching { output.close() }
        }
    }

    private class FakeOpener(
        private val makeChannel: () -> SshChannel = {
            FakeChannel(ByteArrayInputStream("halo".toByteArray(Charsets.UTF_8)), ByteArrayOutputStream())
        },
        private val failWith: Exception? = null,
    ) : SshChannelOpener {
        val opened = mutableListOf<Pair<String, Int>>()
        val channels = mutableListOf<SshChannel>()
        var closed = false
        override fun openChannel(targetHost: String, targetPort: Int): SshChannel {
            failWith?.let { throw it }
            opened += targetHost to targetPort
            return makeChannel().also { channels += it }
        }
        override fun close() { closed = true }
    }

    private fun sshItem() = ProfileItem(
        remarks = "tes edukasi",
        configType = ConfigType.SSH,
        address = "vip.sshvpn.web.id",
        port = 80,
        username = "user",
    )

    @Test
    fun `dial opens a channel and carries traffic both ways`() {
        val opener = FakeOpener()
        val client = SshProxyClient(sshItem(), opener)
        val stream = client.dial("example.com", 443, probeBody = null)
        stream.output.write("ping".toByteArray(Charsets.UTF_8))
        stream.output.flush()
        val got = stream.input.readBytes()
        assertEquals("halo", String(got, Charsets.UTF_8))
        assertEquals(listOf("example.com" to 443), opener.opened)
    }

    @Test
    fun `dial ignores probeBody`() {
        // v1.0.6 probe-first start passes the app's first data as
        // probeBody; for SSH the session connect + channel open IS
        // the probe, and writing the body into the channel would
        // corrupt the SSH banner wait. The body must never reach
        // the channel.
        val out = ByteArrayOutputStream()
        val opener = FakeOpener(makeChannel = {
            FakeChannel(ByteArrayInputStream(ByteArray(0)), out)
        })
        val client = SshProxyClient(sshItem(), opener)
        val stream = client.dial("example.com", 443, probeBody = byteArrayOf(1, 2, 3))
        stream.output.write("data".toByteArray(Charsets.UTF_8))
        assertEquals("data", out.toString(Charsets.UTF_8.name()))
    }

    @Test
    fun `dial opens one channel per target`() {
        val opener = FakeOpener()
        val client = SshProxyClient(sshItem(), opener)
        val a = client.dial("a.example.com", 80, null)
        val b = client.dial("b.example.com", 443, null)
        assertEquals(
            listOf("a.example.com" to 80, "b.example.com" to 443),
            opener.opened,
        )
        assertEquals(2, opener.channels.size)
        // Closing one stream must not close the other.
        a.close()
        assertTrue((opener.channels[0] as FakeChannel).closed)
        assertTrue(!(opener.channels[1] as FakeChannel).closed)
        b.close()
    }

    @Test
    fun `dial wraps a non-IO failure with the SSH gagal tag`() {
        val opener = FakeOpener(failWith = IllegalStateException("no session"))
        val client = SshProxyClient(sshItem(), opener)
        val e = assertThrows(IOException::class.java) {
            client.dial("example.com", 443, null)
        }
        assertTrue(e.message!!.contains("SSH gagal"), "msg: ${e.message}")
    }

    @Test
    fun `dial rethrows an IO failure unchanged`() {
        val opener = FakeOpener(failWith = IOException("boom"))
        val client = SshProxyClient(sshItem(), opener)
        val e = assertThrows(IOException::class.java) {
            client.dial("example.com", 443, null)
        }
        assertEquals("boom", e.message)
    }

    @Test
    fun `close closes every open stream and the opener`() {
        val opener = FakeOpener()
        val client = SshProxyClient(sshItem(), opener)
        val stream = client.dial("example.com", 443, null)
        client.close()
        assertTrue((opener.channels[0] as FakeChannel).closed, "stream must be closed")
        assertTrue(opener.closed, "opener must be closed")
        // The stream is already closed — closing again is a no-op.
        stream.close()
    }

    @Test
    fun `factory builds an SshProxyClient for SSH entries`() {
        val client = ProxyClientFactory.create(sshItem())
        assertTrue(client is SshProxyClient, "got: ${client::class.simpleName}")
    }
}
