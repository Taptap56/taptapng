package com.taptap.ng.core

import java.net.Inet4Address
import java.net.InetAddress

/**
 * IPv6 support (v1.0.5, kelompok F) — scope yang JUJUR di M2.
 *
 * Yang SUDAH jalan tanpa perubahan (v1.0.4, diverifikasi dari kode):
 * - Rute ::/0 ditambahkan ke TUN bila [SettingsStore.ipv6Enabled]
 *   (TaptapVpnService.establishTunnel) — v2rayNG meng-gate hal yang
 *   sama pada PREF_IPV6_ENABLED.
 * - Query DNS AAAA lewat relay DNS forwarder apa adanya (UDP/53
 *   diteruskan byte-per-byte ke upstream; query dan jawaban tidak
 *   dipilah berdasarkan tipe) — jadi aplikasi bisa resolve AAAA.
 * - Dial ke IPv6 LITERAL: Transport/DnsResolver mengembalikan literal
 *   tanpa lookup (getByName), dan Socket.connect ke Inet6Address
 *   adalah jalur standar — tidak ada yang memblokirnya di M2.
 *
 * Yang BELUM (dan kenapa — bukan diam-diam dilewati):
 * - Paket IPv6 di TUN tetap DI-DROP forwarder (M6): relay TCP M2
 *   memakai kunci sesi IPv4 32-bit + state machine TCP IPv4; IPv6
 *   butuh kunci 128-bit, parser header IPv6, TCP/UDP/ICMPv6 di atas
 *   IPv6, dan penanganan MTU/extension header — itu skala M6 (full
 *   tunnel), bukan v1.0.5.
 * - [preferIpv6] TERSAMBUNG di v1.0.5 (integrasi): [DnsResolver]
 *   mengurutkan hasil [DnsResolver.resolveAll] lewat
 *   [orderAddresses] — false = IPv4 dulu (default v1.0.4),
 *   true = IPv6 dulu. Berlaku untuk dial utama, prime, dan
 *   delay test (semuanya lewat resolveAll). Paket IPv6 di TUN
 *   tetap di-drop (di bawah), jadi preferensi ini hanya soal
 *   alamat dial proxy, bukan lalu lintas aplikasi.
 */
object Ipv6Support {

    /**
     * Urutkan daftar alamat hasil resolve: IPv6 dulu bila
     * [preferIpv6], IPv4 dulu bila tidak (default DnsResolver /
     * v2rayNG). Stabil — urutan relatif di dalam tiap keluarga
     * dipertahankan. Pure — unit-testable.
     */
    fun orderAddresses(
        addresses: List<InetAddress>,
        preferIpv6: Boolean,
    ): List<InetAddress> =
        if (preferIpv6) {
            addresses.sortedBy { if (it is Inet4Address) 1 else 0 }
        } else {
            addresses.sortedBy { if (it is Inet4Address) 0 else 1 }
        }

    /**
     * Resolve [host] ke SEMUA alamat (A + AAAA, via
     * [DnsResolver.resolveAll]) lalu urutkan sesuai [preferIpv6].
     * Literal (v4/v6) kembali tanpa lookup. Melempar IOException
     * yang sama seperti resolveAll bila kedua jalur gagal.
     */
    fun resolveOrdered(
        host: String,
        preferIpv6: Boolean,
        timeoutMs: Int = DnsResolver.DEFAULT_TIMEOUT_MS,
    ): List<InetAddress> {
        // resolveAll butuh port untuk fallback sistem; port tidak
        // dipakai untuk pemilihan alamat di sini.
        val all = DnsResolver.resolveAll(host, 443, timeoutMs)
        return orderAddresses(all, preferIpv6)
    }
}
