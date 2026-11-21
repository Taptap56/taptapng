package com.taptap.ng.service

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.SpeedStats
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.15: forwarder kedua Root mode — listener lokal + alamat
 * tujuan asli (SO_ORIGINAL_DST) + dial lewat ProxyClient yang sama.
 * Resolver di-fake (SO_ORIGINAL_DST asli butuh iptables + root di HP);
 * yang diuji di sini: pemetaan listener→port tujuan, dial, relay
 * dua arah, dan gate route-only.
 */
@Timeout(30)
class RootForwarderTest {

    private class EchoStream(
        val feedOut: PipedOutputStream,
        val feedIn: PipedInputStream,
        val sink: ByteArrayOutputStream,
    ) : ProxyStream {
        override val input: InputStream = feedIn
        override val output: OutputStream = sink
        override fun close() {
            runCatching { feedOut.close() }
            runCatching { feedIn.close() }
        }
    }

    private class FakeProxy : ProxyClient {
        val dialed = mutableListOf<Pair<String, Int>>()
        var lastStream: EchoStream? = null

        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream {
            dialed += targetHost to targetPort
            val feedOut = PipedOutputStream()
            val feedIn = PipedInputStream(feedOut, 16384)
            return EchoStream(feedOut, feedIn, ByteArrayOutputStream()).also { lastStream = it }
        }

        override fun close() = Unit
    }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun waitFor(what: String, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(25)
        }
        return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
    }

    @Test
    fun `http listener dials port 80 and https listener dials port 443 with the original address`() {
        val proxy = FakeProxy()
        val dst = InetAddress.getByName("93.184.216.34")
        val httpPort = freePort()
        val httpsPort = freePort()
        val fwd = RootForwarder(
            proxy = proxy,
            httpPort = httpPort,
            httpsPort = httpsPort,
            resolveOriginalDst = RootForwarder.OriginalDstResolver { dst },
        )
        fwd.start()
        try {
            Socket("127.0.0.1", httpPort).use { s ->
                s.getOutputStream().write("hello-http".toByteArray())
                s.getOutputStream().flush()
                assertTrue(
                    waitFor("dial 80") { proxy.dialed.contains("93.184.216.34" to 80) },
                    "dialed: ${proxy.dialed}",
                )
                assertTrue(
                    waitFor("data sampai proxy") {
                        proxy.lastStream?.sink?.size() == "hello-http".length
                    },
                    "data tidak sampai ke proxy",
                )
            }
            Socket("127.0.0.1", httpsPort).use { s ->
                assertTrue(
                    waitFor("dial 443") { proxy.dialed.contains("93.184.216.34" to 443) },
                    "dialed: ${proxy.dialed}",
                )
                // Balasan server mengalir balik ke klien.
                val stream = proxy.lastStream!!
                stream.feedOut.write("world-tls".toByteArray())
                stream.feedOut.flush()
                val buf = ByteArray(64)
                s.soTimeout = 5000
                val n = s.getInputStream().read(buf)
                assertArrayEquals("world-tls".toByteArray(), buf.copyOfRange(0, n))
            }
        } finally {
            fwd.stop()
        }
    }

    @Test
    fun `unresolvable original destination closes without dialling`() {
        val proxy = FakeProxy()
        val httpPort = freePort()
        val httpsPort = freePort()
        val fwd = RootForwarder(
            proxy = proxy,
            httpPort = httpPort,
            httpsPort = httpsPort,
            resolveOriginalDst = RootForwarder.OriginalDstResolver { null },
        )
        fwd.start()
        try {
            Socket("127.0.0.1", httpPort).use { s ->
                s.soTimeout = 5000
                assertEquals(-1, s.getInputStream().read(), "koneksi harus ditutup tanpa dial")
            }
            assertTrue(proxy.dialed.isEmpty(), "tidak boleh ada dial: ${proxy.dialed}")
            assertTrue(
                DialLog.lines().any { it.contains("tujuan asli tidak terbaca") },
                "expected an unreadable-destination log line",
            )
        } finally {
            fwd.stop()
        }
    }

    @Test
    fun `route only refuses an unknown destination and dials a known one`() {
        val proxy = FakeProxy()
        val dst = InetAddress.getByName("93.184.216.34")
        val httpPort = freePort()
        val httpsPort = freePort()
        val knownV4 = mapOf(
            ((93 shl 24) or (184 shl 16) or (216 shl 8) or 34) to "example.com",
        )
        val fwd = RootForwarder(
            proxy = proxy,
            httpPort = httpPort,
            httpsPort = httpsPort,
            resolveOriginalDst = RootForwarder.OriginalDstResolver { dst },
            routeOnlyEnabled = true,
            knownHosts4 = knownV4,
        )
        fwd.start()
        try {
            Socket("127.0.0.1", httpPort).use { s ->
                assertTrue(
                    waitFor("dial dikenal") { proxy.dialed.isNotEmpty() },
                    "tujuan dikenal harus di-dial",
                )
                s.getOutputStream().write(0)
            }
        } finally {
            fwd.stop()
        }
        // Tujuan tidak dikenal: forwarder kedua, map kosong.
        val proxy2 = FakeProxy()
        val http2 = freePort()
        val https2 = freePort()
        val fwd2 = RootForwarder(
            proxy = proxy2,
            httpPort = http2,
            httpsPort = https2,
            resolveOriginalDst = RootForwarder.OriginalDstResolver { dst },
            routeOnlyEnabled = true,
            knownHosts4 = emptyMap(),
        )
        fwd2.start()
        try {
            Socket("127.0.0.1", http2).use { s ->
                s.soTimeout = 5000
                assertEquals(-1, s.getInputStream().read(), "tujuan tidak dikenal harus ditutup")
            }
            Thread.sleep(300)
            assertTrue(proxy2.dialed.isEmpty(), "tidak boleh ada dial: ${proxy2.dialed}")
        } finally {
            fwd2.stop()
        }
    }
}
