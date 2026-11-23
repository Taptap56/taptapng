package com.taptap.ng

import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.ProxyGroupType
import com.taptap.ng.core.ResolvedRoute
import com.taptap.ng.core.RouteDecision
import com.taptap.ng.core.RouteEngine
import com.taptap.ng.core.RouteRecord
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.RouteRuleType
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.ProxyUdpSession
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
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * Forwarder route-record tests (v1.0.29): every live session —
 * TCP and UDP — carries the rule that matched plus its proxy
 * chain ([TunForwarder.connectionRoutes]), so GET /connections
 * can report them. The record resolver here is the real
 * [RouteEngine.resolveDetailed]; the chain names come from the
 * same displayNames the Clash API uses.
 */
@Timeout(30)
class TunForwarderRouteRecordTest {

    private val clientIp = TcpPacket.ipFromBytes(10, 0, 0, 2)
    private val serverIp = TcpPacket.ipFromBytes(1, 2, 3, 4)
    private val udpServerIp = TcpPacket.ipFromBytes(8, 8, 8, 8)

    /** Proxy that records dials; TCP input blocks forever, UDP echoes. */
    private class RecordingProxy : ProxyClient {
        val dialed = AtomicBoolean(false)

        override fun dial(
            targetHost: String,
            targetPort: Int,
            probeBody: ByteArray?,
            stats: SpeedStats?,
        ): ProxyStream {
            dialed.set(true)
            val input = PipedInputStream()
            return object : ProxyStream {
                override val input: InputStream = input
                override val output: OutputStream = ByteArrayOutputStream()
                override fun close() {
                    runCatching { input.close() }
                }
            }
        }

        override fun dialUdp(targetHost: String, targetPort: Int, stats: SpeedStats?): ProxyUdpSession {
            return EchoUdpSession()
        }

        override fun close() = Unit
    }

    private class EchoUdpSession : ProxyUdpSession {
        val sent = LinkedBlockingQueue<ByteArray>()
        private val closed = AtomicBoolean(false)

        override fun send(datagram: ByteArray) {
            sent.add(datagram)
        }

        override fun receive(timeoutMs: Long): ByteArray? {
            while (!closed.get()) {
                sent.poll(100, TimeUnit.MILLISECONDS)?.let { return it }
            }
            return null
        }

        override fun close() {
            closed.set(true)
        }
    }

    private fun group(
        id: String,
        name: String,
        type: ProxyGroupType = ProxyGroupType.SELECT,
        members: List<String> = listOf("guid-81"),
        selected: String? = null,
        nested: List<String>? = null,
    ) = ProxyGroup(
        id = id, name = name, type = type, members = members,
        selectedMemberGuid = selected, groupMembers = nested,
    )

    private fun rule(type: RouteRuleType, pattern: String = "", target: String) =
        RouteRule(type = type, pattern = pattern, target = target)

    private val names = mapOf("guid-81" to "81")

    /** Record resolver wired to the real engine (FINAL -> taptap). */
    private fun finalResolver(
        groups: List<ProxyGroup>,
        rules: List<RouteRule>,
        delays: Map<String, Long?> = emptyMap(),
    ): (String?, InetAddress, Int) -> ResolvedRoute = { host, ip, port ->
        RouteEngine.resolveDetailed(
            host, ip, port, groups, rules, delays, serverNames = names,
        )
    }

    private inner class Harness(
        routeResolver: ((String?, InetAddress, Int) -> RouteDecision)? = null,
        routeRecordResolver: ((String?, InetAddress, Int) -> ResolvedRoute)? = null,
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
            routeRecordResolver = routeRecordResolver,
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

        fun sendUdp(payload: ByteArray = "quic-ping".toByteArray()) {
            val pkt = TcpPacket.buildUdp(clientIp, udpServerIp, 5000, 443, payload)
            tunInWrite.write(pkt)
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
    fun tcpFinalToProxyRecordsServerChain() {
        val groups = listOf(group("g1", "taptap", selected = "guid-81"))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val h = Harness(routeRecordResolver = finalResolver(groups, rules))
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            val id = h.fwd.activeConnections().first { it.network == "tcp" }.id
            assertEquals(RouteRecord("FINAL", "", listOf("81")), h.fwd.connectionRoutes()[id])
        } finally {
            h.stop()
        }
    }

    @Test
    fun tcpNestedSelectionRecordsFullGroupChain() {
        val main = group("main", "taptap", members = emptyList(), selected = "tes", nested = listOf("tes"))
        val nested = group("tes", "tes", type = ProxyGroupType.URL_TEST)
        val groups = listOf(main, nested)
        val rules = listOf(rule(RouteRuleType.FINAL, target = "main"))
        val delays = mapOf<String, Long?>("guid-81" to 312L)
        val h = Harness(routeRecordResolver = finalResolver(groups, rules, delays))
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            val id = h.fwd.activeConnections().first { it.network == "tcp" }.id
            assertEquals(
                RouteRecord("FINAL", "", listOf("taptap", "tes", "81")),
                h.fwd.connectionRoutes()[id],
            )
        } finally {
            h.stop()
        }
    }

    @Test
    fun tcpDirectRuleRecordsDirectChain() {
        val groups = listOf(group("g1", "taptap", selected = "guid-81"))
        val rules = listOf(
            rule(RouteRuleType.IP_CIDR, pattern = "1.2.3.0/24", target = RouteRule.TARGET_DIRECT),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        val direct = RecordingProxy()
        val h = Harness(
            routeRecordResolver = finalResolver(groups, rules),
            directDial = { host, port, stats -> direct.dial(host, port, null, stats) },
        )
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            assertTrue(direct.dialed.get(), "direct dial must be used")
            val id = h.fwd.activeConnections().first { it.network == "tcp" }.id
            assertEquals(
                RouteRecord("IP-CIDR", "1.2.3.0/24", listOf("DIRECT")),
                h.fwd.connectionRoutes()[id],
            )
        } finally {
            h.stop()
        }
    }

    @Test
    fun tcpRejectCreatesNoSessionAndNoRecord() {
        val groups = listOf(group("g1", "taptap", selected = "guid-81"))
        val rules = listOf(
            rule(RouteRuleType.IP_CIDR, pattern = "1.2.3.0/24", target = RouteRule.TARGET_REJECT),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        val h = Harness(routeRecordResolver = finalResolver(groups, rules))
        try {
            h.fwd.start()
            h.sendSyn()
            Thread.sleep(500)
            assertEquals(0, h.fwd.sessionCount())
            assertTrue(h.fwd.connectionRoutes().isEmpty())
            assertTrue(!h.proxy.dialed.get(), "reject must not dial the proxy")
        } finally {
            h.stop()
        }
    }

    @Test
    fun tcpPlainResolverSynthesisesGuidChain() {
        val h = Harness(routeResolver = { _, _, _ -> RouteDecision.Proxy("guid-81") })
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            val id = h.fwd.activeConnections().first { it.network == "tcp" }.id
            assertEquals(
                RouteRecord("FINAL", "", listOf("guid-81")),
                h.fwd.connectionRoutes()[id],
            )
        } finally {
            h.stop()
        }
    }

    @Test
    fun tcpNoResolverKeepsSafeDefaults() {
        val h = Harness()
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            val id = h.fwd.activeConnections().first { it.network == "tcp" }.id
            assertEquals(RouteRecord("FINAL", "", emptyList()), h.fwd.connectionRoutes()[id])
        } finally {
            h.stop()
        }
    }

    @Test
    fun udpFinalToProxyRecordsServerChainWithZeroBytes() {
        val groups = listOf(group("g1", "taptap", selected = "guid-81"))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val h = Harness(routeRecordResolver = finalResolver(groups, rules))
        try {
            h.fwd.start()
            h.sendUdp()
            assertTrue(
                h.waitFor { h.fwd.udpSessionCount() == 1 },
                "expected one UDP session",
            )
            val conn = h.fwd.activeConnections().first { it.network == "udp" }
            assertEquals(0L, conn.upload)
            assertEquals(0L, conn.download)
            assertEquals(RouteRecord("FINAL", "", listOf("81")), h.fwd.connectionRoutes()[conn.id])
        } finally {
            h.stop()
        }
    }

    @Test
    fun udpRejectCreatesNoSessionAndNoRecord() {
        val groups = listOf(group("g1", "taptap", selected = "guid-81"))
        val rules = listOf(
            rule(RouteRuleType.IP_CIDR, pattern = "8.8.8.0/24", target = RouteRule.TARGET_REJECT),
            rule(RouteRuleType.FINAL, target = "g1"),
        )
        val h = Harness(routeRecordResolver = finalResolver(groups, rules))
        try {
            h.fwd.start()
            h.sendUdp()
            Thread.sleep(500)
            assertEquals(0, h.fwd.udpSessionCount())
            assertTrue(h.fwd.connectionRoutes().isEmpty())
        } finally {
            h.stop()
        }
    }

    /**
     * v1.0.29 (merge): the wiring [activeConnections] does —
     * the session record must also ride the [ConnectionInfo]
     * that GET /connections serialises, not only
     * [TunForwarder.connectionRoutes]. Fails on the pre-merge
     * code (fields default to "" / "" / []).
     */
    @Test
    fun tcpFinalToProxyActiveConnectionCarriesRuleAndChain() {
        val groups = listOf(group("g1", "taptap", selected = "guid-81"))
        val rules = listOf(rule(RouteRuleType.FINAL, target = "g1"))
        val h = Harness(routeRecordResolver = finalResolver(groups, rules))
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            val conn = h.fwd.activeConnections().first { it.network == "tcp" }
            assertEquals("FINAL", conn.rule)
            assertEquals("", conn.rulePayload)
            assertEquals(listOf("81"), conn.chains)
        } finally {
            h.stop()
        }
    }

    @Test
    fun tcpNestedSelectionActiveConnectionCarriesFullChain() {
        val main = group("main", "taptap", members = emptyList(), selected = "tes", nested = listOf("tes"))
        val nested = group("tes", "tes", type = ProxyGroupType.URL_TEST)
        val groups = listOf(main, nested)
        val rules = listOf(rule(RouteRuleType.FINAL, target = "main"))
        val delays = mapOf<String, Long?>("guid-81" to 312L)
        val h = Harness(routeRecordResolver = finalResolver(groups, rules, delays))
        try {
            h.fwd.start()
            h.sendSyn()
            assertTrue(
                h.waitFor { h.statuses.contains("Connected") },
                "expected Connected, got ${h.statuses}",
            )
            val conn = h.fwd.activeConnections().first { it.network == "tcp" }
            assertEquals("FINAL", conn.rule)
            assertEquals("", conn.rulePayload)
            assertEquals(listOf("taptap", "tes", "81"), conn.chains)
        } finally {
            h.stop()
        }
    }
}
