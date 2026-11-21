package com.taptap.ng.core

import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for the v1.0.5 DNS additions in [DnsResolver] (kelompok C):
 * pemetaan statis (dnsHosts), metode resolve outbound
 * ([OutboundResolveMethod]), dan helper wire [DnsResolver.parseQuery]
 * / [DnsResolver.buildResponse] yang dipakai relay.
 *
 * Tanpa socket loopback untuk jalur metode: hook operator + hook
 * sistem di-inject in-memory; jalur UDP langsung hanya diarahkan ke
 * port mati (timeout pendek) untuk membuktikan ia dicoba / dilewati.
 */
class DnsResolverMethodTest {

    private fun resetGlobals(
        oldHook: ((String, Int) -> List<InetAddress>)?,
        oldSystemHook: ((String, Int) -> List<InetAddress>)?,
        oldServer: String,
        oldPort: Int,
        oldMethod: OutboundResolveMethod,
        oldHosts: Map<String, InetAddress>,
    ) {
        DnsResolver.operatorResolve = oldHook
        DnsResolver.systemResolveHook = oldSystemHook
        DnsResolver.dnsServer = oldServer
        DnsResolver.dnsPort = oldPort
        DnsResolver.resolveMethod = oldMethod
        DnsResolver.staticHosts = oldHosts
        DnsResolver.clearAddrCache()
    }

    @Test
    fun `static host menang atas hook operator dan UDP langsung`() {
        val oldHook = DnsResolver.operatorResolve
        val oldSystemHook = DnsResolver.systemResolveHook
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        val oldMethod = DnsResolver.resolveMethod
        val oldHosts = DnsResolver.staticHosts
        DnsResolver.clearAddrCache()
        try {
            var operatorCalls = 0
            DnsResolver.operatorResolve = { _, _ ->
                operatorCalls++
                listOf(InetAddress.getByName("10.0.0.1"))
            }
            // UDP langsung diarahkan ke port mati — bila pemetaan
            // statis tidak dipakai duluan, lookup ini timeout.
            DnsResolver.dnsServer = "127.0.0.1"
            DnsResolver.dnsPort = 1
            DnsResolver.staticHosts = mapOf(
                "example.com" to InetAddress.getByName("10.9.9.9"),
            )
            val all = DnsResolver.resolveAll("example.com", 443, timeoutMs = 1000)
            assertEquals(listOf("10.9.9.9"), all.map { it.hostAddress })
            assertEquals(0, operatorCalls)
            // Subdomain ikut terpetakan; resolve() tunggal juga.
            assertEquals(
                listOf("10.9.9.9"),
                DnsResolver.resolveAll("sub.example.com", 443, timeoutMs = 1000)
                    .map { it.hostAddress },
            )
            assertEquals("10.9.9.9", DnsResolver.resolve("example.com").hostAddress)
            assertEquals(0, operatorCalls)
        } finally {
            resetGlobals(oldHook, oldSystemHook, oldServer, oldPort, oldMethod, oldHosts)
        }
    }

    @Test
    fun `metode 1 operator dulu lalu sistem`() {
        val oldHook = DnsResolver.operatorResolve
        val oldSystemHook = DnsResolver.systemResolveHook
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        val oldMethod = DnsResolver.resolveMethod
        val oldHosts = DnsResolver.staticHosts
        DnsResolver.clearAddrCache()
        try {
            DnsResolver.resolveMethod = OutboundResolveMethod.OPERATOR_FIRST
            var operatorCalls = 0
            var systemCalls = 0
            DnsResolver.operatorResolve = { _, _ ->
                operatorCalls++
                listOf(InetAddress.getByName("10.0.0.1"))
            }
            DnsResolver.systemResolveHook = { _, _ ->
                systemCalls++
                listOf(InetAddress.getByName("10.0.0.9"))
            }
            DnsResolver.dnsServer = "127.0.0.1"
            DnsResolver.dnsPort = 1
            val all = DnsResolver.resolveAll("example.com", 443, timeoutMs = 1000)
            assertEquals(listOf("10.0.0.1"), all.map { it.hostAddress })
            assertEquals(1, operatorCalls)
            assertEquals(0, systemCalls)
        } finally {
            resetGlobals(oldHook, oldSystemHook, oldServer, oldPort, oldMethod, oldHosts)
        }
    }

    @Test
    fun `metode 0 hanya sistem tanpa operator tanpa UDP langsung`() {
        // Ganti metode -> jalur resolve berubah (bukti item 7):
        // hook operator TIDAK boleh dipanggil; jawaban datang dari
        // hook sistem. UDP langsung tidak tersentuh (server mati
        // tidak akan terasa — tidak ada timeout yang ditunggu).
        val oldHook = DnsResolver.operatorResolve
        val oldSystemHook = DnsResolver.systemResolveHook
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        val oldMethod = DnsResolver.resolveMethod
        val oldHosts = DnsResolver.staticHosts
        DnsResolver.clearAddrCache()
        try {
            DnsResolver.resolveMethod = OutboundResolveMethod.SYSTEM_ONLY
            var operatorCalls = 0
            DnsResolver.operatorResolve = { _, _ ->
                operatorCalls++
                listOf(InetAddress.getByName("10.0.0.1"))
            }
            DnsResolver.systemResolveHook = { _, _ ->
                listOf(InetAddress.getByName("10.0.0.9"))
            }
            DnsResolver.dnsServer = "127.0.0.1"
            DnsResolver.dnsPort = 1
            val start = System.nanoTime()
            val all = DnsResolver.resolveAll("example.com", 443, timeoutMs = 1000)
            val elapsedMs = (System.nanoTime() - start) / 1_000_000
            assertEquals(listOf("10.0.0.9"), all.map { it.hostAddress })
            assertEquals(0, operatorCalls)
            // Tanpa timeout UDP (server mati tidak dicoba).
            assertTrue(elapsedMs < 500, "metode 0 menunggu $elapsedMs ms")
        } finally {
            resetGlobals(oldHook, oldSystemHook, oldServer, oldPort, oldMethod, oldHosts)
        }
    }

    @Test
    fun `metode 2 lewati operator coba UDP langsung lalu sistem`() {
        val oldHook = DnsResolver.operatorResolve
        val oldSystemHook = DnsResolver.systemResolveHook
        val oldServer = DnsResolver.dnsServer
        val oldPort = DnsResolver.dnsPort
        val oldMethod = DnsResolver.resolveMethod
        val oldHosts = DnsResolver.staticHosts
        DnsResolver.clearAddrCache()
        try {
            DnsResolver.resolveMethod = OutboundResolveMethod.DIRECT_ONLY
            var operatorCalls = 0
            DnsResolver.operatorResolve = { _, _ ->
                operatorCalls++
                listOf(InetAddress.getByName("10.0.0.1"))
            }
            DnsResolver.systemResolveHook = { _, _ ->
                listOf(InetAddress.getByName("10.0.0.9"))
            }
            // UDP langsung ke port mati: timeout 200 ms, lalu
            // fallback sistem menjawab.
            DnsResolver.dnsServer = "127.0.0.1"
            DnsResolver.dnsPort = 1
            val all = DnsResolver.resolveAll("example.com", 443, timeoutMs = 200)
            assertEquals(listOf("10.0.0.9"), all.map { it.hostAddress })
            assertEquals(0, operatorCalls)
        } finally {
            resetGlobals(oldHook, oldSystemHook, oldServer, oldPort, oldMethod, oldHosts)
        }
    }

    @Test
    fun `metode default tetap operator first`() {
        assertEquals(OutboundResolveMethod.OPERATOR_FIRST, DnsResolver.resolveMethod)
    }

    @Test
    fun `parseQuery membaca nama dan qtype`() {
        val q = DnsResolver.buildQuery("Example.COM.", 0x1234, DnsResolver.TYPE_A)
        val parsed = DnsResolver.parseQuery(q)
        assertEquals(0x1234, parsed?.id)
        assertEquals("example.com", parsed?.name)
        assertEquals(DnsResolver.TYPE_A, parsed?.qtype)
        assertNull(DnsResolver.parseQuery(ByteArray(0)))
        assertNull(DnsResolver.parseQuery(ByteArray(11)))
        // QDCOUNT 0 -> null.
        val noQd = q.copyOf().also { it[5] = 0 }
        assertNull(DnsResolver.parseQuery(noQd))
    }

    @Test
    fun `buildResponse menjawab A dan AAAA lalu parseAnswers membacanya`() {
        val q = DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_A)
        val resp = DnsResolver.buildResponse(
            q,
            listOf(
                InetAddress.getByName("93.184.216.34"),
                InetAddress.getByName("2001:db8::1"),
            ),
        )!!
        // Query A hanya membawa jawaban A (AAAA disaring).
        assertEquals(
            listOf("93.184.216.34"),
            DnsResolver.parseAnswers(resp, 0x1234).map { it.hostAddress },
        )
        val q6 = DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_AAAA)
        val resp6 = DnsResolver.buildResponse(
            q6,
            listOf(
                InetAddress.getByName("93.184.216.34"),
                InetAddress.getByName("2001:db8::1"),
            ),
        )!!
        assertEquals(
            listOf("2001:db8:0:0:0:0:0:1"),
            DnsResolver.parseAnswers(resp6, 0x1234).map { it.hostAddress },
        )
    }

    @Test
    fun `buildResponse null bila tak ada jawaban sekeluarga atau query rusak`() {
        val q = DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_A)
        // Hanya jawaban AAAA untuk query A -> null (pemanggil
        // meneruskan ke upstream, bukan menjawab kosong).
        assertNull(
            DnsResolver.buildResponse(q, listOf(InetAddress.getByName("2001:db8::1"))),
        )
        assertNull(DnsResolver.buildResponse(q, emptyList()))
        assertNull(DnsResolver.buildResponse(ByteArray(0), listOf(InetAddress.getByName("10.0.0.1"))))
    }

    @Test
    fun `buildResponse memakai TTL yang diminta`() {
        val q = DnsResolver.buildQuery("example.com", 0x1234, DnsResolver.TYPE_A)
        val resp = DnsResolver.buildResponse(
            q,
            listOf(InetAddress.getByName("10.0.0.1")),
            ttlSeconds = 60,
        )!!
        // Header 12 + pertanyaan (17 byte: 7+1 + 3+1 + 1 + 4) = 29;
        // jawaban: pointer 2 + type 2 + class 2 + TTL 4 + rdlen 2.
        val ttlPos = 29 + 2 + 2 + 2
        val ttl = ((resp[ttlPos].toInt() and 0xFF) shl 24) or
            ((resp[ttlPos + 1].toInt() and 0xFF) shl 16) or
            ((resp[ttlPos + 2].toInt() and 0xFF) shl 8) or
            (resp[ttlPos + 3].toInt() and 0xFF)
        assertEquals(60, ttl)
    }
}
