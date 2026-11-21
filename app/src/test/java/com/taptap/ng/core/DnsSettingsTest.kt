package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for [DnsSettings] (v1.0.5, kelompok C): pure rules over the
 * seven stored DNS settings. No Android, no network.
 */
class DnsSettingsTest {

    @Test
    fun `vpnDns kosong memakai 1111`() {
        assertEquals("1.1.1.1", DnsSettings().effectiveTunnelDns())
        assertEquals("1.1.1.1", DnsSettings(vpnDns = "   ").effectiveTunnelDns())
    }

    @Test
    fun `vpnDns literal dipakai sebagai DNS utama tunnel`() {
        // Ganti setting -> upstream berubah (bukti item 1).
        assertEquals("8.8.4.4", DnsSettings(vpnDns = "8.8.4.4").effectiveTunnelDns())
        assertEquals("9.9.9.9", DnsSettings(vpnDns = "  9.9.9.9  ").effectiveTunnelDns())
    }

    @Test
    fun `vpnDns bukan IP kembali ke 1111`() {
        // Hostname butuh resolve dulu (chicken-and-egg) — diabaikan.
        assertEquals("1.1.1.1", DnsSettings(vpnDns = "dns.example.com").effectiveTunnelDns())
        assertEquals("1.1.1.1", DnsSettings(vpnDns = "999.1.1.1").effectiveTunnelDns())
    }

    @Test
    fun `domesticDns kosong memakai 223555`() {
        assertEquals("223.5.5.5", DnsSettings().effectiveDomesticDns())
        assertEquals("114.114.114.114", DnsSettings(domesticDns = "114.114.114.114").effectiveDomesticDns())
        assertEquals("223.5.5.5", DnsSettings(domesticDns = "bukan-ip").effectiveDomesticDns())
    }

    @Test
    fun `remoteDns kosong berarti DoH mati`() {
        // DoH aktif hanya bila URL https valid — perilaku default
        // (relay UDP) tidak berubah bila user tidak mengisinya.
        assertNull(DnsSettings().remoteDohUrl())
        assertNull(DnsSettings(remoteDns = "   ").remoteDohUrl())
        assertNull(DnsSettings(remoteDns = "http://cloudflare-dns.com/dns-query").remoteDohUrl())
        assertNull(DnsSettings(remoteDns = "https://").remoteDohUrl())
        assertNull(DnsSettings(remoteDns = "cloudflare-dns.com/dns-query").remoteDohUrl())
    }

    @Test
    fun `remoteDns URL https valid dipakai sebagai DoH`() {
        assertEquals(
            "https://cloudflare-dns.com/dns-query",
            DnsSettings(remoteDns = "https://cloudflare-dns.com/dns-query").remoteDohUrl(),
        )
        assertEquals(
            "https://dns.example.org/dns-query?x=1",
            DnsSettings(remoteDns = "  https://dns.example.org/dns-query?x=1 ").remoteDohUrl(),
        )
    }

    @Test
    fun `parseDnsHosts membaca domain ip per baris`() {
        val hosts = DnsSettings.parseDnsHosts(
            """
            example.com:10.9.9.9
            sub.example.org : 192.0.2.1

            # komentar dilewati
            baris-tanpa-titik-dua
            :10.0.0.1
            rusak.com:bukan-ip
            ipv6.example:2001:db8::1
            """.trimIndent(),
        )
        assertEquals("10.9.9.9", hosts["example.com"]?.hostAddress)
        assertEquals("192.0.2.1", hosts["sub.example.org"]?.hostAddress)
        assertEquals("2001:db8::1", hosts["ipv6.example"]?.hostAddress)
        assertEquals(3, hosts.size)
    }

    @Test
    fun `parseDnsHosts entri terakhir menang dan domain dilowercase`() {
        val hosts = DnsSettings.parseDnsHosts(
            "Example.COM:10.0.0.1\nEXAMPLE.com:10.0.0.2\n",
        )
        assertEquals(1, hosts.size)
        assertEquals("10.0.0.2", hosts["example.com"]?.hostAddress)
    }

    @Test
    fun `lookupStaticHost cocok persis lalu subdomain`() {
        val hosts = DnsSettings.parseDnsHosts("example.com:10.9.9.9\n")
        assertEquals("10.9.9.9", DnsSettings.lookupStaticHost(hosts, "example.com")?.hostAddress)
        assertEquals("10.9.9.9", DnsSettings.lookupStaticHost(hosts, "sub.example.com")?.hostAddress)
        assertEquals("10.9.9.9", DnsSettings.lookupStaticHost(hosts, "EXAMPLE.COM.")?.hostAddress)
        assertNull(DnsSettings.lookupStaticHost(hosts, "badexample.com"))
        assertNull(DnsSettings.lookupStaticHost(hosts, "other.org"))
        assertNull(DnsSettings.lookupStaticHost(hosts, ""))
    }

    @Test
    fun `isDomestic hanya akhiran id secara default`() {
        // Tanpa database geo, satu-satunya sinyal domestik yang bisa
        // diverifikasi dari nama saja adalah akhiran ccTLD .id.
        val s = DnsSettings()
        assertTrue(s.isDomestic("example.id"))
        assertTrue(s.isDomestic("sub.example.id"))
        assertTrue(s.isDomestic("id"))
        assertFalse(s.isDomestic("example.com"))
        assertFalse(s.isDomestic("example.co.id.example.com"))
        assertFalse(s.isDomestic("192.0.2.1"))
        assertFalse(s.isDomestic(""))
    }

    @Test
    fun `isDomestic memakai daftar akhiran yang diberikan`() {
        val s = DnsSettings(domesticSuffixes = setOf("id", "example.local"))
        assertTrue(s.isDomestic("a.example.local"))
        assertTrue(s.isDomestic("example.id"))
        assertFalse(s.isDomestic("example.org"))
    }

    @Test
    fun `resolveMethod memetakan 0 1 2 dan default 1`() {
        assertEquals(OutboundResolveMethod.SYSTEM_ONLY, DnsSettings(outboundResolveMethod = "0").resolveMethod())
        assertEquals(OutboundResolveMethod.OPERATOR_FIRST, DnsSettings(outboundResolveMethod = "1").resolveMethod())
        assertEquals(OutboundResolveMethod.DIRECT_ONLY, DnsSettings(outboundResolveMethod = "2").resolveMethod())
        // Nilai tak dikenal / kosong = default v1.0.4 (operator-first).
        assertEquals(OutboundResolveMethod.OPERATOR_FIRST, DnsSettings(outboundResolveMethod = "").resolveMethod())
        assertEquals(OutboundResolveMethod.OPERATOR_FIRST, DnsSettings(outboundResolveMethod = "9").resolveMethod())
        assertEquals(OutboundResolveMethod.OPERATOR_FIRST, DnsSettings().resolveMethod())
    }

    @Test
    fun `fakeDns aktif hanya bila local juga on`() {
        assertFalse(DnsSettings(localDnsEnabled = false, fakeDnsEnabled = true).fakeDnsActive)
        assertFalse(DnsSettings(localDnsEnabled = false, fakeDnsEnabled = false).fakeDnsActive)
        assertFalse(DnsSettings(localDnsEnabled = true, fakeDnsEnabled = false).fakeDnsActive)
        assertTrue(DnsSettings(localDnsEnabled = true, fakeDnsEnabled = true).fakeDnsActive)
    }
}
