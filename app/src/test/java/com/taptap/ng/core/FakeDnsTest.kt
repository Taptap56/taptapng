package com.taptap.ng.core

import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for [FakeDns] (v1.0.5, kelompok C): pool IP fake +
 * pemetaan dua arah + TTL. Tanpa jaringan; jam di-inject.
 */
class FakeDnsTest {

    @Test
    fun `alokasi pertama 1981801 dan stabil untuk host yang sama`() {
        val fake = FakeDns()
        val first = fake.allocate("example.com")
        assertEquals("198.18.0.1", first.hostAddress)
        assertEquals(first, fake.allocate("example.com"))
        assertEquals(first, fake.lookupIp("example.com"))
        assertEquals("example.com", fake.lookupHost(first))
        assertEquals(1, fake.size())
    }

    @Test
    fun `host berbeda dapat IP berbeda secara urut`() {
        val fake = FakeDns()
        assertEquals("198.18.0.1", fake.allocate("a.example").hostAddress)
        assertEquals("198.18.0.2", fake.allocate("b.example").hostAddress)
        assertEquals("198.18.0.3", fake.allocate("c.example").hostAddress)
        assertEquals("b.example", fake.lookupHost(InetAddress.getByName("198.18.0.2")))
        assertEquals(3, fake.size())
    }

    @Test
    fun `lookupHost null untuk IP bukan fake dan IP fake yang tak dikenal`() {
        val fake = FakeDns()
        fake.allocate("example.com")
        assertNull(fake.lookupHost(InetAddress.getByName("8.8.8.8")))
        assertNull(fake.lookupHost(InetAddress.getByName("198.18.0.99")))
        assertNull(fake.lookupIp("tidak-ada.example"))
        assertNull(fake.lookupHost(0x08080808))
    }

    @Test
    fun `isFakeIp hanya untuk range 1981800 per 15`() {
        assertTrue(FakeDns.isFakeIp(InetAddress.getByName("198.18.0.1")))
        assertTrue(FakeDns.isFakeIp(InetAddress.getByName("198.19.255.255")))
        assertTrue(FakeDns.isFakeIp(InetAddress.getByName("198.18.0.0")))
        assertTrue(FakeDns.isFakeIp(0xC6120001.toInt()))
        assertTrue(FakeDns.isFakeIp(0xC613FFFF.toInt()))
        assertTrue(!FakeDns.isFakeIp(InetAddress.getByName("198.20.0.1")))
        assertTrue(!FakeDns.isFakeIp(InetAddress.getByName("198.17.255.255")))
        assertTrue(!FakeDns.isFakeIp(InetAddress.getByName("10.0.0.1")))
    }

    @Test
    fun `mapping kedaluwarsa sesudah TTL dan IP dipakai ulang`() {
        var now = 1_000_000L
        val fake = FakeDns(ttlSeconds = 60, clock = { now })
        val ip = fake.allocate("example.com")
        assertEquals("198.18.0.1", ip.hostAddress)
        // Masih hidup di 59 detik.
        now += 59_000
        assertEquals(ip, fake.lookupIp("example.com"))
        assertEquals("example.com", fake.lookupHost(ip))
        // Mati di 60 detik: lookup null, alokasi baru dapat IP
        // berikutnya (slot kedaluwarsa dipakai ulang saat probe
        // membungkus — bukan di sini), IP lama bebas.
        now += 1_000
        assertNull(fake.lookupIp("example.com"))
        assertNull(fake.lookupHost(ip))
        assertEquals(0, fake.size())
        val other = fake.allocate("other.example")
        assertEquals("198.18.0.2", other.hostAddress)
        assertEquals("other.example", fake.lookupHost(other))
        assertNull(fake.lookupHost(ip))
    }

    @Test
    fun `allocate ulang host kedaluwarsa dapat IP baru dan IP lama bebas`() {
        var now = 1_000_000L
        val fake = FakeDns(ttlSeconds = 60, clock = { now })
        val first = fake.allocate("a.example")
        assertEquals("198.18.0.1", first.hostAddress)
        now += 61_000
        // Entri lama kedaluwarsa: host yang sama alokasi ulang dapat
        // IP baru, IP lama tidak lagi memetakan ke siapa pun.
        val again = fake.allocate("a.example")
        assertEquals("198.18.0.2", again.hostAddress)
        assertEquals("a.example", fake.lookupHost(again))
        assertNull(fake.lookupHost(first))
        assertEquals(1, fake.size())
    }

    @Test
    fun `host dinormalisasi lowercase dan tanpa trailing dot`() {
        val fake = FakeDns()
        val ip = fake.allocate("Example.COM.")
        assertEquals(ip, fake.lookupIp("example.com"))
        assertEquals("example.com", fake.lookupHost(ip))
    }

    @Test
    fun `allocate menolak host kosong`() {
        val fake = FakeDns()
        assertThrows(IllegalArgumentException::class.java) { fake.allocate("  ") }
    }

    @Test
    fun `clear mengosongkan mapping dan mengulang alokasi`() {
        val fake = FakeDns()
        fake.allocate("a.example")
        fake.allocate("b.example")
        assertEquals(2, fake.size())
        fake.clear()
        assertEquals(0, fake.size())
        assertNull(fake.lookupIp("a.example"))
        assertEquals("198.18.0.1", fake.allocate("c.example").hostAddress)
    }
}
