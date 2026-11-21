package com.taptap.ng.core

/**
 * Route-only gate (v1.0.5, kelompok F) — SEMANTIK EKSPLISIT.
 *
 * v2rayNG: "route only" = hanya lalu lintas yang cocok dengan routing
 * yang lewat VPN; sisanya BYPASS VPN (langsung, direct). TaptapNG M2
 * tidak punya rule engine DAN tidak punya jalur direct: TunForwarder
 * hanya bisa dial via proxy atau menolak (RST) — tidak ada relay TCP
 * direct lewat socket ter-protect (itu kerja M6, full tunnel).
 *
 * Jadi versi minimal yang JUJUR di M2 ini:
 * - Tujuan DIKENAL = IP tujuan pernah dijawab oleh relay DNS in-tunnel
 *   (query A/AAAA dari aplikasi → jawaban dicatat) ATAU pernah
 *   ter-sniff (SNI/Host) pada koneksi sebelumnya ke IP yang sama.
 *   Peta itu diisi forwarder sendiri ([knownHosts]); sniffing pada
 *   koneksi BERJALAN tidak bisa menentukan dial-nya sendiri, karena
 *   dial terjadi saat SYN — SNI/Host baru tiba sesudah SYN-ACK.
 * - Bila route-only MATI: semua dial lewat proxy (perilaku v1.0.4).
 * - Bila route-only NYALA dan tujuan DIKENAL: dial lewat proxy.
 * - Bila route-only NYALA dan tujuan TIDAK DIKENAL: koneksi DITOLAK
 *   (RST + log "ROUTE-ONLY"), BUKAN dial direct dan BUKAN dial proxy.
 *   Fail-closed: tanpa rule engine, "tidak dikenal" tidak boleh
 *   diasumsikan boleh lewat proxy — dan tanpa relay direct, "bypass"
 *   tidak bisa diwujudkan selain menolak.
 *
 * Konsekuensi yang harus diketahui user: dengan route-only nyala,
 * aplikasi yang konek ke IP literal / IP hardcode tanpa DNS dulu
 * (mis. IP Cloudflare literal) akan DITOLAK sampai IP itu pernah
 * dijawab DNS in-tunnel. Itulah harga versi minimal ini; routing
 * penuh ala v2rayNG (rule engine + bypass direct) tetap butuh M6.
 */
object RouteOnlyGate {

    enum class Decision { PROXY, REFUSE }

    /**
     * Keputusan dial untuk satu tujuan. [knownHosts] memetakan IP
     * tujuan (int big-endian, kunci yang sama dengan TunForwarder)
     * ke hostname yang dikenal. Pure — unit-testable.
     */
    fun decide(
        routeOnlyEnabled: Boolean,
        dstIp: Int,
        knownHosts: Map<Int, String>,
    ): Decision {
        if (!routeOnlyEnabled) return Decision.PROXY
        return if (knownHosts.containsKey(dstIp)) Decision.PROXY else Decision.REFUSE
    }
}
