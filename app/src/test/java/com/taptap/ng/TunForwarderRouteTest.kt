package com.taptap.ng

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.RouteDecision
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.SpeedStats
import com.taptap.ng.service.TcpPacket
import com.taptap.ng.service.TunForwarder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.InetAddress
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Forwarder routing tests (M7, W2): a REJECT decision RSTs without
 * dialling, a Proxy decision dials the client for that guid (not
 * the tunnel's single client), and a Direct decision uses the
 * injected direct dial. The legacy path (no resolver) is locked
 * too — it must keep dialling the single proxy client.
 */
class TunForwarderRouteTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 0, 0, 2)
    private val serverIp = TcpPacket.ipFromBytes(1, 2, 3, 4)

    /** Proxy that records whether it was dialled; input blocks forever. */
    private class RecordingProxy : ProxyClient {
        val dialed = AtomicBoolean(false)
        var lastHost: String? = null

        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream {
            dialed.set(true)
            lastHost = targetHost
            val input = PipedInputStream()
            return object : ProxyStream {
                override val input: InputStream = input
                override val output: OutputStream = ByteArrayOutputStream()
                override fun close() {
                    runCatching { input.close() }
                }
            }
        }

        override fun close() = Unit
    }

    private inner class Harness(
        routeResolver: ((String?, InetAddress, Int) -> RouteDecision)? = null,
        clientProvider: ((String) -> ProxyClient?)? = null,
        directDial: ((String, Int, SpeedStats?) -> ProxyStream)? = null,
        val proxy: RecordingProxy = RecordingProxy(),
    ) {
        val statuses = Collections.synchronizedList(mutableListOf<String>())
        private val tunInRead = PipedInputStream()
        private val tunInWrite = PipedOutputStream(tunInRead)
        private val tunOutRead = PipedInputStream()
        private val tunOutWrite = PipedOutputStream(tunOutRead)
        private val drained = ByteArrayOutputStream()
        private val drainer = thread(name = "tun-test-drain", isDaemon = true) {
            runCatching { tunOutRead.copyTo(drained) }
        }
        val fwd = TunForwarder(
            tunIn = tunInRead,
            tunOut = tunOutWrite,
            proxy = proxy,
            dnsServer = "8.8.8.8",
            protectUdp = { true },
            onStatus = { statuses.add(it) },
            routeResolver = routeResolver,
            clientProvider = clientProvider,
            directDial = directDial,
        )

        fun sendSyn() {
            val syn = TcpPacket.buildTcp(
                clientIp, serverIp, 12345, 443,
                1000L, 0L, TcpPacket.FLAG_SYN, ByteArray(0),
                mss = TcpPacket.TCP_MSS,
            )
            tunInWrite.write(syn)
            tunInWrite.flush()
        }

        fun waitFor(timeoutMs: Long = 5000L, condition: () -> Boolean): Boolean {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                if (condition()) return true
                Thread.sleep(50)
            }
            return condition()
        }

        fun stop() {
            runCatching { fwd.stop() }
            runCatching { tunInWrite.close() }
            runCatching { tunOutWrite.close() }
            drainer.join(1000)
        }
    }

    @Test
    fun rejectDecisionRstsWithoutDialling() {
        val h = Harness(routeResolver = { _, _, _ -> RouteDecision.Reject })
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { DialLog.lines().any { it.contains("tolak 1.2.3.4:443") } },
                "expected a ROUTE tolak line, got: ${DialLog.lines().takeLast(10)}",
            )
            Thread.sleep(200)
            assertEquals(0, h.fwd.sessionCount())
            assertFalse(h.proxy.dialed.get(), "reject must not dial the proxy")
            assertFalse(h.statuses.contains("Connected"))
        } finally {
            h.stop()
        }
    }

    @Test
    fun proxyDecisionDialsClientForGuid() {
        val clientB = RecordingProxy()
        val h = Harness(
            routeResolver = { _, _, _ -> RouteDecision.Proxy("guid-b") },
            clientProvider = { guid -> if (guid == "guid-b") clientB else null },
        )
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            assertTrue(clientB.dialed.get(), "expected the guid-b client to be dialled")
            assertFalse(h.proxy.dialed.get(), "the tunnel client must not be dialled")
            assertEquals("1.2.3.4", clientB.lastHost)
        } finally {
            h.stop()
        }
    }

    @Test
    fun proxyDecisionFallsBackToTunnelClientForUnknownGuid() {
        val h = Harness(
            routeResolver = { _, _, _ -> RouteDecision.Proxy("gone") },
            clientProvider = { null },
        )
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected via fallback, got ${h.statuses}",
            )
            assertTrue(h.proxy.dialed.get(), "unknown guid must fall back to the tunnel client")
        } finally {
            h.stop()
        }
    }

    @Test
    fun directDecisionUsesInjectedDirectDial() {
        val directDialed = AtomicBoolean(false)
        val direct = RecordingProxy()
        val h = Harness(
            routeResolver = { _, _, _ -> RouteDecision.Direct },
            directDial = { host, port, stats ->
                directDialed.set(true)
                direct.dial(host, port, null, stats)
            },
        )
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            assertTrue(directDialed.get(), "expected the direct dial to be used")
            assertFalse(h.proxy.dialed.get(), "direct must not dial the proxy")
        } finally {
            h.stop()
        }
    }

    @Test
    fun noResolverKeepsLegacySingleProxyDial() {
        val h = Harness()
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            assertTrue(h.proxy.dialed.get(), "legacy path must dial the single proxy client")
        } finally {
            h.stop()
        }
    }
}
