package com.taptap.ng.core

import java.io.IOException
import java.net.InetAddress
import java.net.Inet4Address

/**
 * Satu pertukaran DNS lewat UDP: kirim [query] ke [server]:[port],
 * kembalikan byte jawaban. @throws IOException bila timeout / gagal.
 * Implementasi produksi = socket UDP ter-protect (lihat
 * [com.taptap.ng.service.TunForwarder]); tes meng-inject stub
 * in-memory — tanpa socket loopback.
 */
fun interface DnsExchange {
    @Throws(IOException::class)
    fun exchange(query: ByteArray, server: String, port: Int, timeoutMs: Int): ByteArray
}

/** Ke mana satu query DNS in-tunnel dirutekan ([DnsRelayPolicy.route]). */
sealed class DnsRoute {
    /** Jawab lokal dari pemetaan statis (dnsHosts). */
    data class Static(val address: InetAddress) : DnsRoute()
    /** Jawab lokal dari pool FakeDNS (hanya query A). */
    object Fake : DnsRoute()
    /** Resolve lewat jaringan lokal (operator) — localDnsEnabled ON. */
    object Local : DnsRoute()
    /** UDP ke upstream domestik. */
    object Domestic : DnsRoute()
    /** DoH ke remoteDns (bila DoH aktif). */
    object RemoteDoh : DnsRoute()
    /** UDP ke DNS utama tunnel (vpnDns / 1.1.1.1). */
    object RemoteUdp : DnsRoute()
}

/**
 * Kebijakan relay DNS in-tunnel (v1.0.5, kelompok C) — dipegang
 * [com.taptap.ng.service.TunForwarder], dibangun service dari
 * [DnsSettings] tiap tunnel naik. [route] murni (tanpa I/O) dan
 * JVM-testable; transport ([dnsExchange], [dohClient],
 * [localResolve]) di-inject — produksi memakai yang asli, tes
 * memakai stub in-memory.
 *
 * Urutan rute (pertama yang cocok menang):
 * 1. dnsHosts (statis) — menang atas semua upstream, untuk qtype
 *    yang cocok keluarganya (A↔IPv4, AAAA↔IPv6; bila tidak cocok,
 *    query diteruskan — bukan dijawab kosong).
 * 2. FakeDNS — hanya query A, hanya bila [fakeDns] dipasang
 *    (service memasangnya hanya bila local + fake sama-sama ON).
 * 3. Local — bila [localDnsEnabled]: resolver jaringan lokal.
 * 4. Domestik — akhiran di [domesticSuffixes] (default: `.id` —
 *    lihat [DnsSettings.isDomestic]).
 * 5. Remote — DoH bila [remoteDohUrl] diset (dan qtype A/AAAA),
 *    bila tidak UDP ke DNS utama tunnel.
 *
 * Pengecualian loop DoH: query untuk host DoH itu sendiri TIDAK
 * pernah dirutekan ke DoH (host itu harus bisa di-resolve lewat
 * UDP, kalau tidak DoH memanggil dirinya sendiri tanpa henti).
 */
data class DnsRelayPolicy(
    val staticHosts: Map<String, InetAddress> = emptyMap(),
    val domesticSuffixes: Set<String> = DnsSettings.DEFAULT_DOMESTIC_SUFFIXES,
    val domesticDnsServer: String = DnsSettings.DEFAULT_DOMESTIC_DNS,
    val remoteDohUrl: String? = null,
    val localDnsEnabled: Boolean = false,
    val fakeDns: FakeDns? = null,
    /** Resolver lokal (host, qtype) -> alamat; null = hook operator [DnsResolver.operatorResolve]. */
    val localResolve: ((String, Int) -> List<InetAddress>)? = null,
    /** Klien DoH; null = DoH tidak dipakai (pakai UDP). */
    val dohClient: DohClient? = null,
    /** Transport UDP upstream; null = socket UDP ter-protect asli. */
    val dnsExchange: DnsExchange? = null,
) {
    fun route(host: String, qtype: Int): DnsRoute {
        DnsSettings.lookupStaticHost(staticHosts, host)?.let { addr ->
            val isV4 = addr is Inet4Address
            val familyOk = (qtype == DnsResolver.TYPE_A && isV4) ||
                (qtype == DnsResolver.TYPE_AAAA && !isV4)
            if (familyOk) return DnsRoute.Static(addr)
        }
        if (fakeDns != null && qtype == DnsResolver.TYPE_A) return DnsRoute.Fake
        if (localDnsEnabled) return DnsRoute.Local
        if (DnsSettings.isDomestic(host, domesticSuffixes)) return DnsRoute.Domestic
        if (remoteDohUrl != null &&
            (qtype == DnsResolver.TYPE_A || qtype == DnsResolver.TYPE_AAAA)
        ) {
            val dohHost = DohClient.hostOf(remoteDohUrl)
            val clean = host.trim().trimEnd('.').lowercase()
            if (dohHost == null || clean != dohHost) return DnsRoute.RemoteDoh
            // Query untuk host DoH sendiri -> UDP (pengecualian loop).
        }
        return DnsRoute.RemoteUdp
    }

    companion object {
        /** Kebijakan default = perilaku relay v1.0.4 (UDP primer → fallback). */
        val DEFAULT = DnsRelayPolicy()
    }
}
