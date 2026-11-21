package com.taptap.ng.core

/**
 * Root mode assessment (v1.0.5, kelompok F) — ASESMEN SAJA, tidak
 * diimplementasikan.
 *
 * Root mode (v2rayNG: "Root mode" / mode root) = tunnel via iptables
 * sebagai pengganti VpnService: traffic dialihkan dengan aturan
 * iptables (REDIRECT/TPROXY + mark) ke proxy lokal, tanpa perlu izin
 * VPN dari user dan tanpa TUN interface.
 *
 * VERDIK: TIDAK FEASIBLE di v1.0.5 — alasannya persis di bawah.
 * Setting [SettingsStore.enableRootMode] tetap tersimpan tapi tidak
 * jalan (service selalu memakai VpnService).
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
