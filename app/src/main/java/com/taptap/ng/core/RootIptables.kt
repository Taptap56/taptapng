package com.taptap.ng.core

/**
 * Root mode — generator aturan iptables (v1.0.15).
 *
 * Pure Kotlin, tanpa API Android — SEMUA aturan yang dipasang
 * Root mode dihasilkan di sini sebagai string, supaya urutan,
 * pengecualian, dan rollback bisa diuji di JVM. Tidak ada satu
 * pun aturan yang ditempel mentah di shell / service.
 *
 * Desain (REDIRECT, bukan TPROXY — keputusan sadar, lihat bawah):
 * - Trafik lokal (OUTPUT): TCP 80/443 + UDP 53 di-REDIRECT ke
 *   listener lokal ([RootForwarder] / [RootDnsRelay]). REDIRECT
 *   menulis ulang tujuan menjadi 127.0.0.1:port-lokal, jadi TIDAK
 *   butuh fwmark + ip rule + tabel routing (itu kebutuhan TPROXY,
 *   yang menyimpan alamat tujuan asli di socket dan butuh tabel
 *   khusus). Assessment v1.0.5 menulis "mark + ip rule" sebagai
 *   bagian dari sketsa TPROXY; dengan REDIRECT keduanya tidak
 *   diperlukan — menambahkannya hanya menambah permukaan gagal
 *   (aturan mark yang salah = internet mati). TPROXY tetap
 *   didokumentasikan sebagai pekerjaan lanjutan, bukan disembunyikan.
 * - Anti-loop: socket aplikasi sendiri (UID aplikasi) di-RETURN
 *   duluan di OUTPUT — dial proxy + DNS relay + prime TIDAK
 *   pernah masuk REDIRECT, jadi tidak berputar.
 * - Bypass LAN: tujuan RFC 1918 + link-local di-RETURN (bila
 *   [Config.bypassLan] nyala, default ON — sama seperti TUN).
 * - TETHER: trafik perangkat tethering tiba sebagai FORWARDED
 *   (bukan OUTPUT), jadi aturannya di PREROUTING, dicocokkan
 *   dari SOURCE range tethering AOSP (bukan nama interface —
 *   nama interface hotspot berbeda-beda per ROM: wlan1, ap0,
 *   rndis0, bt-pan; range DHCP-nya yang stabil). Range dari
 *   AOSP `TetheringConfiguration.DHCP_DEFAULT_RANGE`: USB
 *   192.168.42.0/24, WiFi 192.168.43.0/24, BT 192.168.44–48.0/24,
 *   P2P 192.168.49.0/24. Peringatan: ROM yang mengubah range
 *   DHCP tethering (overlay `config_tether_dhcp_range`) TIDAK
 *   tercakup — perangkat tether-nya tetap direct, bukan lewat
 *   VPN, dan itu terlihat di tes HP (cek IP perangkat kedua).
 * - Dua port listener: REDIRECT tidak menyimpan port tujuan
 *   asli di socket (hanya alamat, via SO_ORIGINAL_DST), jadi
 *   port 80 dan 443 di-REDIRECT ke port lokal BERBEDA
 *   ([Config.proxyPortHttp] / [Config.proxyPortHttps]) — listener
 *   mana yang menerima koneksi itulah port tujuannya. Tanpa ini
 *   forwarder tidak bisa membedakan HTTP vs HTTPS.
 * - Hanya TCP 80/443 yang dialihkan di v1 (plus UDP 53 → relay
 *   DNS lokal). TCP port lain (mis. 22, 5222, game) TIDAK lewat
 *   VPN di Root mode v1 — jalan direct. Itu batasan jujur, bukan
 *   bug tersembunyi (lihat README v1.0.15).
 * - IPv6: TIDAK ada aturan ip6tables di v1 — trafik IPv6 di
 *   Root mode jalan direct. Alasan: REDIRECT IPv6 butuh ip6tables
 *   + listener v6 + SO_ORIGINAL_DST v6, belum dibangun.
 *
 * Identifikasi milik TaptapNG: rantai bernama [CHAIN] /
 * [TETHER_CHAIN] + jump rule yang persis mengarah ke rantai itu.
 * Cleanup ([cleanupCommands]) HANYA menyentuh rantai itu dan
 * jump rule itu — tidak pernah `-F` / `-X` rantai lain, tidak
 * pernah flush tabel nat.
 */
object RootIptables {

    /** Rantai nat untuk trafik lokal (OUTPUT). */
    const val CHAIN = "TAPTAPNG"

    /** Rantai nat untuk trafik tether (PREROUTING). */
    const val TETHER_CHAIN = "TAPTAPNG_TETH"

    /** Port lokal tujuan REDIRECT TCP 80 (HTTP). */
    const val DEFAULT_PROXY_PORT_HTTP = 18080

    /** Port lokal tujuan REDIRECT TCP 443 (HTTPS). */
    const val DEFAULT_PROXY_PORT_HTTPS = 18081

    /** Port lokal relay DNS (UDP 53 di-REDIRECT ke sini). */
    const val DEFAULT_DNS_PORT = 18053

    /**
     * Range DHCP tethering AOSP (TetheringConfiguration).
     * USB .42, WiFi .43, BT .44–.48, P2P .49 — masing-masing /24.
     */
    val TETHER_RANGES: List<String> = listOf(
        "192.168.42.0/24",
        "192.168.43.0/24",
        "192.168.44.0/24",
        "192.168.45.0/24",
        "192.168.46.0/24",
        "192.168.47.0/24",
        "192.168.48.0/24",
        "192.168.49.0/24",
    )

    /** Range LAN/link-local yang di-bypass (sama seperti [LanBypass]). */
    val LAN_RANGES: List<String> = listOf(
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    )

    data class Config(
        /** UID aplikasi sendiri (anti-loop). Wajib — tanpa ini dial proxy berputar. */
        val appUid: Int,
        val proxyPortHttp: Int = DEFAULT_PROXY_PORT_HTTP,
        val proxyPortHttps: Int = DEFAULT_PROXY_PORT_HTTPS,
        val dnsPort: Int = DEFAULT_DNS_PORT,
        val tetherRanges: List<String> = TETHER_RANGES,
        /** Bila true, tujuan LAN di-RETURN (direct), seperti TUN. */
        val bypassLan: Boolean = true,
    )

    /**
     * Perintah install, DALAM URUTAN pasang: rantai dibuat dulu,
     * jump rule OUTPUT sesudahnya, isi rantai sesudah jump rule
     * ada (aturan `-A` ke rantai yang belum ada akan gagal).
     * Urutan di dalam rantai: RETURN (UID/LAN) dulu, REDIRECT
     * sesudahnya, RETURN penutup terakhir (trafik lain direct).
     */
    fun installCommands(cfg: Config): List<String> {
        val cmds = ArrayList<String>()
        // --- Rantai lokal (OUTPUT) ---
        cmds += "iptables -t nat -N $CHAIN"
        cmds += "iptables -t nat -A OUTPUT -m owner --uid-owner ${cfg.appUid} -j RETURN"
        cmds += "iptables -t nat -A OUTPUT -j $CHAIN"
        if (cfg.bypassLan) {
            for (range in LAN_RANGES) {
                cmds += "iptables -t nat -A $CHAIN -d $range -j RETURN"
            }
        }
        cmds += "iptables -t nat -A $CHAIN -p tcp --dport 80 -j REDIRECT --to-ports ${cfg.proxyPortHttp}"
        cmds += "iptables -t nat -A $CHAIN -p tcp --dport 443 -j REDIRECT --to-ports ${cfg.proxyPortHttps}"
        cmds += "iptables -t nat -A $CHAIN -p udp --dport 53 -j REDIRECT --to-ports ${cfg.dnsPort}"
        cmds += "iptables -t nat -A $CHAIN -j RETURN"
        // --- Rantai tether (PREROUTING, source = range tether) ---
        cmds += "iptables -t nat -N $TETHER_CHAIN"
        for (range in cfg.tetherRanges) {
            cmds += "iptables -t nat -A PREROUTING -s $range -j $TETHER_CHAIN"
        }
        // Perangkat tether menuju gateway hotspot sendiri / LAN:
        // jangan dialihkan — itu trafik lokal ke HP ini.
        for (range in cfg.tetherRanges + LAN_RANGES) {
            cmds += "iptables -t nat -A $TETHER_CHAIN -d $range -j RETURN"
        }
        cmds += "iptables -t nat -A $TETHER_CHAIN -p tcp --dport 80 -j REDIRECT --to-ports ${cfg.proxyPortHttp}"
        cmds += "iptables -t nat -A $TETHER_CHAIN -p tcp --dport 443 -j REDIRECT --to-ports ${cfg.proxyPortHttps}"
        cmds += "iptables -t nat -A $TETHER_CHAIN -p udp --dport 53 -j REDIRECT --to-ports ${cfg.dnsPort}"
        cmds += "iptables -t nat -A $TETHER_CHAIN -j RETURN"
        return cmds
    }

    /**
     * Perintah cleanup, URUTAN TERBALIK dari install: jump rule
     * dihapus dulu, rantai di-flush + dihapus sesudahnya (rantai
     * yang masih dirujuk tidak bisa di-`-X`). Setiap perintah
     * bersifat idempotent-tolerant: bila aturan sudah tidak ada,
     * iptables mengembalikan error — [RootTunnelController] yang
     * mengabaikan kegagalan cleanup (aturan basi dibersihkan
     * best-effort, bukan gagal start).
     */
    fun cleanupCommands(cfg: Config): List<String> {
        val cmds = ArrayList<String>()
        for (range in cfg.tetherRanges) {
            cmds += "iptables -t nat -D PREROUTING -s $range -j $TETHER_CHAIN"
        }
        cmds += "iptables -t nat -D OUTPUT -j $CHAIN"
        cmds += "iptables -t nat -D OUTPUT -m owner --uid-owner ${cfg.appUid} -j RETURN"
        cmds += "iptables -t nat -F $CHAIN"
        cmds += "iptables -t nat -X $CHAIN"
        cmds += "iptables -t nat -F $TETHER_CHAIN"
        cmds += "iptables -t nat -X $TETHER_CHAIN"
        return cmds
    }

    /** Perintah verifikasi install: rantai harus ada sesudah install. */
    fun chainCheckCommand(cfg: Config): String =
        "iptables -t nat -S $CHAIN"

    /** Benar bila perintah ini adalah salah satu aturan milik TaptapNG (untuk audit log). */
    fun isOwnedCommand(cmd: String): Boolean =
        cmd.contains(" $CHAIN") || cmd.contains(" $TETHER_CHAIN") ||
            cmd.contains("-j $CHAIN") || cmd.contains("-j $TETHER_CHAIN")
}
