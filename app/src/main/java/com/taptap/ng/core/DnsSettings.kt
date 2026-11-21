package com.taptap.ng.core

import com.taptap.ng.core.proto.AddrCodec
import java.net.InetAddress

/**
 * DNS settings, v1.0.5 (kelompok C) — pure model over the raw stored
 * values ([com.taptap.ng.data.SettingsStore] holds the same seven
 * fields; the service builds this from the store at tunnel start).
 * No Android APIs here, so every rule below is JVM-testable.
 *
 * The seven settings, and what the engine does with each:
 * - vpnDns: DNS utama tunnel (menggantikan 1.1.1.1 yang paten di
 *   v1.0.4); hanya literal IP yang dipakai — kosong / bukan IP =
 *   1.1.1.1. Fallback tetap 1.0.0.1. Bila [localDnsEnabled] ON,
 *   vpnDns tidak dipakai relay (lihat SettingsActivity: "only when
 *   local DNS is off"), tapi tetap dipasang di addDnsServer.
 * - remoteDns: URL DoH (format v2rayNG:
 *   https://cloudflare-dns.com/dns-query). DoH AKTIF hanya bila
 *   nilainya URL https yang valid; kosong / bukan https = DoH MATI
 *   dan relay tetap UDP seperti v1.0.4 (perilaku default TIDAK
 *   berubah — nilai display di Settings bukan nilai engine).
 * - domesticDns: upstream domestik ("Direct DNS" / "DNS used for
 *   direct domains" di v2rayNG). Kosong / bukan IP = 223.5.5.5
 *   (default v2rayNG). Dipakai hanya untuk query yang dirutekan
 *   domestik (lihat [isDomestic]).
 * - dnsHosts: "domain:ip" per baris — menang atas semua upstream,
 *   di resolver DAN di relay.
 * - localDnsEnabled: ON = query in-tunnel dijawab resolver
 *   jaringan lokal (fisik operator), bukan upstream di atas.
 * - fakeDnsEnabled: ON (dan localDnsEnabled ON — UI menguncinya
 *   begitu) = jawab query A dengan IP fake dari [FakeDns].
 * - outboundResolveMethod: "0"/"1"/"2" (lihat
 *   [OutboundResolveMethod]); default "1" = perilaku v1.0.4.
 */
data class DnsSettings(
    val vpnDns: String = "",
    val remoteDns: String = "",
    val domesticDns: String = "",
    val dnsHosts: String = "",
    val localDnsEnabled: Boolean = false,
    val fakeDnsEnabled: Boolean = false,
    val outboundResolveMethod: String = "1",
    /** Daftar akhiran domestik (lihat [isDomestic]). */
    val domesticSuffixes: Set<String> = DEFAULT_DOMESTIC_SUFFIXES,
) {

    /** DNS utama tunnel: vpnDns bila literal IP, bila bukan = 1.1.1.1. */
    fun effectiveTunnelDns(): String {
        val v = vpnDns.trim()
        return if (AddrCodec.isIpLiteral(v)) v else DEFAULT_PRIMARY_DNS
    }

    /** Upstream domestik: domesticDns bila literal IP, bila bukan = 223.5.5.5. */
    fun effectiveDomesticDns(): String {
        val v = domesticDns.trim()
        return if (AddrCodec.isIpLiteral(v)) v else DEFAULT_DOMESTIC_DNS
    }

    /**
     * URL DoH yang dipakai, atau null bila DoH mati (kosong / bukan
     * https:// / tanpa host). Query DoH TIDAK pernah mencatat nama
     * host yang ditanya ([DohClient] tidak log).
     */
    fun remoteDohUrl(): String? {
        val u = remoteDns.trim()
        if (u.isEmpty() || !u.startsWith("https://")) return null
        val afterScheme = u.removePrefix("https://")
        val host = afterScheme.substringBefore('/').substringBefore(':')
        if (host.isEmpty() || host.contains(' ')) return null
        return u
    }

    /** Pemetaan statis dari [dnsHosts] ("domain:ip" per baris). */
    fun staticHosts(): Map<String, InetAddress> = parseDnsHosts(dnsHosts)

    /** Cari [host] di [hosts] (exact, lalu subdomain) — lihat [lookupStaticHost]. */
    fun lookupStaticHost(host: String): InetAddress? =
        lookupStaticHost(staticHosts(), host)

    /**
     * Apakah [host] dirutekan ke upstream domestik.
     *
     * BATAS (jujur): aplikasi TIDAK membawa database geo (geosite /
     * geoip tidak dibundel — APK harus tetap kecil), jadi tidak ada
     * cara mengetahui dari nama saja apakah sebuah domain "domestik"
     * menurut operator. Satu-satunya sinyal yang bisa diverifikasi
     * dari nama saja adalah akhiran ccTLD: `.id` = domain Indonesia.
     * Default: hanya akhiran [DEFAULT_DOMESTIC_SUFFIXES] yang
     * domestik; SEMUA yang lain ke remote. Daftar ini eksplisit dan
     * bisa ditambah (bukan klaim geo). Di v2rayNG, "direct domains"
     * ditentukan routing (domain yang bypass proxy); di TaptapNG M2
     * tidak ada routing direct — split ini penggantinya.
     */
    fun isDomestic(host: String): Boolean = isDomestic(host, domesticSuffixes)

    /** Metode resolve outbound (lihat [OutboundResolveMethod]). */
    fun resolveMethod(): OutboundResolveMethod =
        parseOutboundResolveMethod(outboundResolveMethod)

    /**
     * FakeDNS aktif hanya bila local DNS juga ON — sama seperti kunci
     * UI (`SettingsStore.isFakeDnsAvailable`); nilai tersimpan
     * fakeDnsEnabled yang ON sendirian (mis. local dimatikan
     * belakangan) TIDAK mengaktifkan FakeDNS.
     */
    val fakeDnsActive: Boolean get() = localDnsEnabled && fakeDnsEnabled

    companion object {
        /** Harus sama dengan TaptapVpnService.PRIMARY_DNS. */
        const val DEFAULT_PRIMARY_DNS = "1.1.1.1"
        /** Harus sama dengan TaptapVpnService.SECONDARY_DNS. */
        const val DEFAULT_SECONDARY_DNS = "1.0.0.1"
        /** Default v2rayNG untuk Direct/Domestic DNS. */
        const val DEFAULT_DOMESTIC_DNS = "223.5.5.5"
        /** Nilai display v2rayNG untuk Remote DNS (bukan nilai engine). */
        const val DISPLAY_REMOTE_DOH_URL = "https://cloudflare-dns.com/dns-query"

        /**
         * Akhiran domestik default: hanya "id" (lihat [DnsSettings.isDomestic]).
         * Bukan database geo — satu-satunya sinyal yang bisa
         * diverifikasi dari nama domain saja.
         */
        val DEFAULT_DOMESTIC_SUFFIXES: Set<String> = setOf("id")

        /**
         * Parse "domain:ip" per baris (format v2rayNG). Baris kosong,
         * komentar (#...), baris tanpa ':', domain kosong, dan IP
         * bukan literal dilewati diam-diam. Domain dilowercase-kan;
         * entri terakhir menang bila domain dobel.
         */
        fun parseDnsHosts(raw: String): Map<String, InetAddress> {
            val out = LinkedHashMap<String, InetAddress>()
            for (line in raw.lines()) {
                val t = line.trim()
                if (t.isEmpty() || t.startsWith("#")) continue
                val idx = t.indexOf(':')
                if (idx <= 0) continue
                val domain = t.substring(0, idx).trim().lowercase()
                val ip = t.substring(idx + 1).trim()
                if (domain.isEmpty() || !AddrCodec.isIpLiteral(ip)) continue
                out[domain] = InetAddress.getByName(ip)
            }
            return out
        }

        /**
         * Cari [host] di [hosts]: cocok persis dulu, lalu tiap
         * induknya ("sub.example.com" cocok entri "example.com") —
         * perilaku `hosts` xray. "badexample.com" TIDAK cocok entri
         * "example.com" (potong hanya di titik). Case-insensitive,
         * trailing dot diabaikan.
         */
        fun lookupStaticHost(hosts: Map<String, InetAddress>, host: String): InetAddress? {
            val clean = host.trim().trimEnd('.').lowercase()
            if (clean.isEmpty()) return null
            hosts[clean]?.let { return it }
            var rest = clean
            while (true) {
                val dot = rest.indexOf('.')
                if (dot < 0) return null
                rest = rest.substring(dot + 1)
                hosts[rest]?.let { return it }
            }
        }

        /** Split domestik murni atas nama + daftar akhiran (lihat [DnsSettings.isDomestic]). */
        fun isDomestic(host: String, suffixes: Set<String>): Boolean {
            val clean = host.trim().trimEnd('.').lowercase()
            if (clean.isEmpty() || AddrCodec.isIpLiteral(clean)) return false
            return suffixes.any { suffix ->
                val s = suffix.trim().trimStart('.').lowercase()
                s.isNotEmpty() && (clean == s || clean.endsWith(".$s"))
            }
        }

        /**
         * Parse nilai mentah [OutboundResolveMethod]. Nilai tak
         * dikenal (termasuk kosong) = default "1" — perilaku v1.0.4
         * dipertahankan, bukan gagal.
         */
        fun parseOutboundResolveMethod(raw: String): OutboundResolveMethod =
            when (raw.trim()) {
                "0" -> OutboundResolveMethod.SYSTEM_ONLY
                "2" -> OutboundResolveMethod.DIRECT_ONLY
                else -> OutboundResolveMethod.OPERATOR_FIRST
            }
    }
}

/**
 * Cara [DnsResolver] me-resolve domain outbound (dial / delay test /
 * prime). Nilai mentahnya adalah string Settings
 * "outbound_resolve_method" (UI: "0 = IP if available, 1 = resolve,
 * 2 = resolve if IP not available"; default "1").
 *
 * Pemetaan ke jalur [DnsResolver] (v1.0.5, kelompok C) — dicek dari
 * nilai UI + perilaku v2rayNG yang sebenarnya (CoreConfigManager /
 * CoreOutboundBuilder: "1" = resolve outbound domains,
 * "2" = resolve-and-replace alamat outbound dengan IP hasil resolve,
 * "0" = keduanya tidak — domain diteruskan apa adanya):
 * - "1" RESOLVE / OPERATOR_FIRST: rantai penuh v1.0.4 — operator
 *   dulu, lalu UDP langsung, lalu sistem. Ini DEFAULT dan TIDAK
 *   berubah.
 * - "0" IP_IF_AVAILABLE / SYSTEM_ONLY: tanpa pre-resolve oleh
 *   aplikasi — domain diteruskan ke resolver sistem (bounded)
 *   saja, tanpa hook operator dan tanpa UDP langsung. Setara
 *   "AsIs"-nya v2rayNG: yang me-resolve adalah platform, bukan
 *   rantai [DnsResolver].
 * - "2" RESOLVE_IF_IP_UNAVAILABLE / DIRECT_ONLY: resolve hanya
 *   bila alamat bukan IP literal (literal selalu dipakai langsung
 *   tanpa DNS — itu berlaku di semua metode), dan resolve-nya
 *   lewat UDP langsung (server [DnsResolver.dnsServer], default
 *   8.8.8.8) lalu sistem — hook operator DILEWATI. Setara
 *   "resolve-and-replace"-nya v2rayNG: hasil resolve menggantikan
 *   domain sebagai target dial (itulah yang memang dilakukan
 *   [com.taptap.ng.core.proto.Transport] — dial selalu ke IP hasil
 *   resolve).
 *
 * BATAS (jujur): ketiga metode tetap me-resolve domain — dial TCP
 * butuh IP, jadi "0" pun akhirnya resolve (lewat sistem). Yang
 * dibedakan metode ini adalah JALUR resolvernya, bukan apakah
 * resolve terjadi.
 */
enum class OutboundResolveMethod {
    /** "0": resolver sistem saja (bounded), tanpa operator / UDP langsung. */
    SYSTEM_ONLY,
    /** "1" (default): operator → UDP langsung → sistem (perilaku v1.0.4). */
    OPERATOR_FIRST,
    /** "2": UDP langsung (8.8.8.8) → sistem, tanpa hook operator. */
    DIRECT_ONLY,
}
