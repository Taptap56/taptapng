package com.taptap.ng.core

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import com.taptap.ng.core.proto.ProxyClient
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.core.proto.SpeedStats
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ObservatoryTest {

    private fun item(guid: String, remarks: String = guid) = ProfileItem(
        guid = guid,
        remarks = remarks,
        configType = ConfigType.VMESS,
        address = "1.2.3.4",
        port = 443,
        uuid = "00000000-0000-0000-0000-000000000000",
    )

    private fun config(
        ping: String = "3m",
        load: String = "5m",
        method: String = "HEAD",
        sampling: String = "2",
        timeout: String = "30s",
    ) = Observatory.Config.fromSettings(ping, load, method, sampling, timeout, "")

    @Test
    fun `parse duration handles v2rayng units and falls back on garbage`() {
        assertEquals(180_000L, Observatory.parseDurationMs("3m", 60_000))
        assertEquals(300_000L, Observatory.parseDurationMs("5m", 60_000))
        assertEquals(30_000L, Observatory.parseDurationMs("30s", 60_000))
        assertEquals(500L, Observatory.parseDurationMs("500ms", 60_000))
        assertEquals(7_200_000L, Observatory.parseDurationMs("2h", 60_000))
        assertEquals(60_000L, Observatory.parseDurationMs("", 60_000))
        assertEquals(60_000L, Observatory.parseDurationMs("abc", 60_000))
        assertEquals(60_000L, Observatory.parseDurationMs("0s", 60_000))
        assertEquals(60_000L, Observatory.parseDurationMs("-5m", 60_000))
    }

    @Test
    fun `config from settings normalises method sampling and timeout`() {
        val c = config(method = "get", sampling = "99", timeout = "5m")
        assertEquals("GET", c.leastLoadMethod)
        assertEquals(10, c.sampling) // clamped 1..10
        assertEquals(120_000, c.timeoutMs) // clamped 1s..120s
        assertEquals(180_000L, c.leastPingIntervalMs)
        val bad = config(method = "DELETE", sampling = "x", timeout = "x")
        assertEquals("HEAD", bad.leastLoadMethod)
        assertEquals(2, bad.sampling)
        assertEquals(30_000, bad.timeoutMs)
    }

    @Test
    fun `best least ping picks the lowest successful probe`() {
        Observatory.clear()
        try {
            val a = item("a")
            val b = item("b")
            val c = item("c")
            Observatory.record(Observatory.ProbeResult("a", 300, 1, "GET", 1, null))
            Observatory.record(Observatory.ProbeResult("b", 120, 1, "GET", 1, null))
            Observatory.record(Observatory.ProbeResult("c", -1, 1, "GET", 1, "TCP gagal"))
            assertEquals("b", Observatory.bestLeastPing(listOf(a, b, c))?.guid)
            // A failure must never beat a slow success.
            Observatory.record(Observatory.ProbeResult("b", -1, 2, "GET", 1, "TCP gagal"))
            assertEquals("a", Observatory.bestLeastPing(listOf(a, b, c))?.guid)
        } finally {
            Observatory.clear()
        }
    }

    @Test
    fun `best returns null when nothing succeeded`() {
        Observatory.clear()
        try {
            val a = item("a")
            Observatory.record(Observatory.ProbeResult("a", -1, 1, "GET", 1, "TCP gagal"))
            assertNull(Observatory.bestLeastPing(listOf(a)))
            assertNull(Observatory.bestLeastLoad(listOf(a)))
            assertNull(Observatory.bestGuidForNextStart(listOf(a)))
        } finally {
            Observatory.clear()
        }
    }

    @Test
    fun `prober load round averages samples and uses the configured method`() {
        Observatory.clear()
        try {
            val seenMethods = mutableListOf<String>()
            val seenTimeouts = mutableListOf<Int>()
            val latencies = ArrayDeque(listOf(100L, 200L, 300L))
            val prober = ObservatoryProber(
                config(method = "HEAD", sampling = "3", timeout = "10s"),
                tester = { _, method, timeoutMs ->
                    seenMethods += method
                    seenTimeouts += timeoutMs
                    ServerTester.TestResult(latencies.removeFirst(), null)
                },
            )
            val a = item("a")
            val out = prober.probeOnce(listOf(a), ObservatoryProber.Mode.LOAD)
            assertEquals(200L, out["a"]?.ms) // mean of 100/200/300
            assertEquals(3, out["a"]?.samples)
            assertEquals(listOf("HEAD", "HEAD", "HEAD"), seenMethods)
            assertEquals(listOf(10_000, 10_000, 10_000), seenTimeouts)
            // The stored result follows the probe: best picks it up.
            assertEquals("a", Observatory.bestLeastLoad(listOf(a))?.guid)
        } finally {
            Observatory.clear()
        }
    }

    @Test
    fun `prober ping round takes one get sample and a failure stores minus one`() {
        Observatory.clear()
        try {
            var calls = 0
            val prober = ObservatoryProber(
                config(),
                tester = { _, method, _ ->
                    calls++
                    assertEquals("GET", method)
                    ServerTester.TestResult(-1, "TCP gagal")
                },
            )
            val a = item("a")
            val out = prober.probeOnce(listOf(a), ObservatoryProber.Mode.PING)
            assertEquals(1, calls)
            assertEquals(-1, out["a"]?.ms)
            assertEquals("TCP gagal", out["a"]?.failureStage)
            assertNull(Observatory.bestLeastPing(listOf(a)))
        } finally {
            Observatory.clear()
        }
    }

    @Test
    fun `prober best changes when a slower entry becomes faster`() {
        Observatory.clear()
        try {
            val lat = mutableMapOf("a" to 100L, "b" to 200L)
            val prober = ObservatoryProber(
                config(),
                tester = { item, _, _ -> ServerTester.TestResult(lat[item.guid] ?: -1, null) },
            )
            val a = item("a")
            val b = item("b")
            prober.probeOnce(listOf(a, b), ObservatoryProber.Mode.PING)
            assertEquals("a", Observatory.bestLeastPing(listOf(a, b))?.guid)
            lat["a"] = 500L
            lat["b"] = 150L
            prober.probeOnce(listOf(a, b), ObservatoryProber.Mode.PING)
            assertEquals("b", Observatory.bestLeastPing(listOf(a, b))?.guid)
            assertEquals("b", Observatory.bestGuidForNextStart(listOf(a, b)))
        } finally {
            Observatory.clear()
        }
    }

    @Test
    fun `real ping through proxy sends head when method is head`() {
        val written = ByteArrayOutputStream()
        val proxy = object : ProxyClient {
            override fun dial(
                targetHost: String,
                targetPort: Int,
                probeBody: ByteArray?,
                stats: SpeedStats?,
            ): ProxyStream {
                val input: InputStream = ByteArrayInputStream(
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.UTF_8),
                )
                return object : ProxyStream {
                    override val input: InputStream = input
                    override val output: OutputStream = written
                    override fun close() = Unit
                }
            }

            override fun close() = Unit
        }
        val r = ServerTester.testRealPingThroughProxy(
            item("a"), "http://www.gstatic.com/generate_204",
            clientFactory = { proxy }, method = "HEAD",
        )
        assertTrue(r.ms >= 0, "expected >= 0 ms, got ${r.ms} stage=${r.failureStage}")
        val sent = written.toString(Charsets.UTF_8.name())
        assertTrue(sent.startsWith("HEAD /generate_204 HTTP/1.1"), "expected HEAD, got: $sent")
        // An unknown method falls back to GET.
        written.reset()
        val r2 = ServerTester.testRealPingThroughProxy(
            item("a"), "http://www.gstatic.com/generate_204",
            clientFactory = { proxy }, method = "DELETE",
        )
        assertTrue(r2.ms >= 0)
        assertTrue(
            written.toString(Charsets.UTF_8.name()).startsWith("GET /generate_204 HTTP/1.1"),
            "expected GET fallback, got: ${written.toString(Charsets.UTF_8.name())}",
        )
    }
}
