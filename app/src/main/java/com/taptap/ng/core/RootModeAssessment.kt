package com.taptap.ng.core

/**
 * Root mode assessment (v1.0.5, kelompok F) — ASESMEN SAJA, tidak
 * diimplementasikan.
 *
 * v1.0.15: DIIMPLEMENTASIKAN (eksperimental) — lihat
 * [RootIptables], [RootTunnelController],
 * [com.taptap.ng.service.RootForwarder],
 * [com.taptap.ng.service.RootDnsRelay]. Verdict v1.0.5 di bawah tetap
 * dibiarkan sebagai catatan sejarah; status per poin:
 * - Eksekutor root + fallback: ADA (SuExecutor + NoRoot → VpnService).
 * - Aturan iptables lengkap: ADA (generator murni RootIptables) —
 *   dengan satu penyimpangan sadar: REDIRECT, bukan TPROXY, jadi
 *   fwmark + ip rule TIDAK dipakai (tidak dibutuhkan REDIRECT).
 * - Forwarder kedua: ADA (RootForwarder, listener lokal +
 *   SO_ORIGINAL_DST; port tujuan dari listener 18080=80 / 18081=443).
 * - DNS hijack: ADA (RootDnsRelay, UDP 53 → dialUdp lewat proxy).
 * - Lifecycle/cleanup: ADA (stop + start + boot); risiko aturan
 *   nyangkut tetap ada bila HP mati mendadak sebelum cleanup —
 *   itu batasan yang didokumentasikan, bukan dijamin hilang.
 * - SELinux/Android 12+: TETAP BATASAN (lihat README v1.0.15).
 *
 * Root mode (v2rayNG: "Root mode" / mode root) = tunnel via iptables
 * sebagai pengganti VpnService: traffic dialihkan dengan aturan
 * iptables (REDIRECT/TPROXY + mark) ke proxy lokal, tanpa perlu izin
 * VPN dari user dan tanpa TUN interface.
 *
 * VERDIK: TIDAK FEASIBLE di v1.0.5 — alasannya persis di bawah.
 * Setting [SettingsStore.enableRootMode] tetap tersimpan; di
 * v1.0.5 tidak jalan (service selalu memakai VpnService) — di
 * v1.0.15 jalan sebagai Root mode (lihat catatan di atas).
 */
object RootModeAssessment {

    /** Root mode bisa dipakai di versi ini? Tidak. */
    const val FEASIBLE_IN_V105: Boolean = false

    /**
     * Perubahan arsitektur yang dibutuhkan — masing-masing adalah
     * pekerjaan besar sendiri, bukan toggle:
     */
    val requiredChanges: List<String> = listOf(
        "Eksekutor root (su) + deteksi root + fallback bila su tidak ada: " +
            "seluruh start/stop tunnel harus bercabang VpnService vs root.",
        "Aturan iptables lengkap (nat/mangle): REDIRECT/TPROXY port 80/443 " +
            "ke proxy lokal + mark + ip rule + pengecualian UID aplikasi " +
            "sendiri (anti-loop) + bypass LAN — hari ini tidak ada satu " +
            "baris pun kode iptables di repo.",
        "Proxy lokal SOCKS/HTTP yang bisa menerima traffic REDIRECT " +
            "(bukan TUN): forwarder M2 membaca paket dari fd TUN; " +
            "mode root butuh listener TCP lokal + transparansi alamat " +
            "tujuan (SO_ORIGINAL_DST) — forwarder harus ditulis ulang.",
        "DNS hijack via iptables (port 53 → resolver lokal) sebagai " +
            "pengganti relay DNS TUN; tanpa ini DNS aplikasi bocor direct.",
        "Lifecycle tanpa VpnService: tidak ada onRevoke / stopForeground " +
            "VPN; cleanup aturan iptables saat crash/kill harus dijamin " +
            "sendiri (aturan nyangkut = internet mati total).",
        "SELinux + Android 12+: iptables dari app butuh konteks root " +
            "yang benar; di banyak ROM, aturan tproxy dari userspace " +
            "ditolak meski uid=0.",
    )

    /** Alasan pemblokir ringkas (satu baris per alasan). */
    val blockingReasons: List<String> = listOf(
        "Tidak ada kode iptables / eksekutor root di repo — mulai dari nol.",
        "Forwarder M2 terikat fd TUN; mode root butuh forwarder kedua (listener lokal + SO_ORIGINAL_DST).",
        "Cleanup aturan saat crash tidak terjamin — risiko internet mati total lebih besar dari manfaatnya.",
        "Tanpa VpnService, Android tidak memberi sinyal revoke/stop yang andal untuk teardown.",
    )
}
