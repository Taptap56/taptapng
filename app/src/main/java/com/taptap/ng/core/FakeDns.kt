package com.taptap.ng.core

import java.net.InetAddress

/**
 * FakeDNS (v1.0.5, kelompok C) — pool IP fake + pemetaan dua arah
 * IP fake <-> hostname, seperti `fakedns` xray.
 *
 * Cara pakai (lihat [com.taptap.ng.service.TunForwarder]):
 * - Relay DNS: query A untuk host yang belum punya mapping dijawab
 *   [allocate] (IP fake baru); query ulang host yang sama dijawab IP
 *   yang sama selama mapping masih hidup.
 * - Dial TCP: tujuan IP fake dipetakan balik ke hostname lewat
 *   [lookupHost] sebelum `ProxyClient.dial` — server proxy yang
 *   me-resolve hostname aslinya, bukan IP fake.
 *
 * Pool: 198.18.0.0/15 (RFC 2544, range benchmarking — default
 * `fakedns` xray; bukan alamat yang bisa dirutekan di internet,
 * jadi tabrakan dengan IP asli praktis tidak ada). Alokasi urut
 * dari 198.18.0.1; entri kedaluwarsa dipakai ulang. Mapping hidup
 * [ttlSeconds] (sama dengan TTL jawaban DNS yang dikirim relay).
 *
 * Semua metode synchronized — relay DNS + dial TCP memanggilnya
 * dari thread yang berbeda. Jam bisa di-inject ([clock]) untuk tes.
 */
class FakeDns(
    /** Umur mapping (detik) — juga TTL jawaban DNS. */
    val ttlSeconds: Int = DEFAULT_TTL_SECONDS,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Entry(val host: String, val ipInt: Int, val expiresAtMs: Long)

    private val ipToEntry = HashMap<Int, Entry>()
    private val hostToIp = HashMap<String, Int>()
    private var nextOffset = 1

    /**
     * Alokasi (atau pakai ulang) IP fake untuk [host]. Host yang sama
     * selama mapping hidup selalu dapat IP yang sama.
     * @throws IllegalStateException bila pool habis (semua 131071
     * alamat sedang hidup — pemanggil fallback ke upstream).
     */
    @Synchronized
    fun allocate(host: String): InetAddress {
        val clean = host.trim().trimEnd('.').lowercase()
        require(clean.isNotEmpty()) { "Host FakeDNS kosong" }
        val now = clock()
        hostToIp[clean]?.let { ip ->
            val entry = ipToEntry[ip]
            if (entry != null && entry.expiresAtMs > now) return intToAddress(ip)
            // Kedaluwarsa: bersihkan dua arah sebelum alokasi baru.
            hostToIp.remove(clean)
            if (entry != null) ipToEntry.remove(ip)
        }
        var probe = nextOffset
        repeat(POOL_SIZE) {
            val ip = POOL_BASE_INT + probe
            val entry = ipToEntry[ip]
            if (entry == null || entry.expiresAtMs <= now) {
                if (entry != null) hostToIp.remove(entry.host)
                val fresh = Entry(clean, ip, now + ttlSeconds * 1000L)
                ipToEntry[ip] = fresh
                hostToIp[clean] = ip
                nextOffset = if (probe + 1 > POOL_SIZE) 1 else probe + 1
                return intToAddress(ip)
            }
            probe = if (probe + 1 > POOL_SIZE) 1 else probe + 1
        }
        throw IllegalStateException("Pool FakeDNS habis ($POOL_SIZE alamat hidup)")
    }

    /** IP fake untuk [host] bila mapping-nya masih hidup, bila tidak null. */
    @Synchronized
    fun lookupIp(host: String): InetAddress? {
        val clean = host.trim().trimEnd('.').lowercase()
        val ip = hostToIp[clean] ?: return null
        val entry = ipToEntry[ip] ?: run {
            hostToIp.remove(clean)
            return null
        }
        if (entry.expiresAtMs <= clock()) {
            ipToEntry.remove(ip)
            hostToIp.remove(clean)
            return null
        }
        return intToAddress(ip)
    }

    /** Hostname untuk IP fake [address], atau null (bukan fake / kedaluwarsa). */
    @Synchronized
    fun lookupHost(address: InetAddress): String? = lookupHost(addressToInt(address))

    /** Seperti [lookupHost], untuk IP sebagai int (format [com.taptap.ng.service.TcpPacket]). */
    @Synchronized
    fun lookupHost(ipInt: Int): String? {
        if (!isFakeIp(ipInt)) return null
        val entry = ipToEntry[ipInt] ?: return null
        if (entry.expiresAtMs <= clock()) {
            ipToEntry.remove(ipInt)
            hostToIp.remove(entry.host)
            return null
        }
        return entry.host
    }

    /** Jumlah mapping yang sedang hidup (tes). */
    @Synchronized
    fun size(): Int {
        val now = clock()
        return ipToEntry.values.count { it.expiresAtMs > now }
    }

    @Synchronized
    fun clear() {
        ipToEntry.clear()
        hostToIp.clear()
        nextOffset = 1
    }

    companion object {
        /** TTL default mapping + jawaban DNS (detik). */
        const val DEFAULT_TTL_SECONDS = 60

        /** 198.18.0.0/15 = 131072 alamat (198.18.0.0–198.19.255.255). */
        const val POOL_SIZE = 131072

        /** Offset 0 (198.18.0.0) tidak pernah dialokasikan. */
        private const val POOL_BASE_INT = (198 shl 24) or (18 shl 16)

        /** Apakah [address] IP fake dari pool ini. */
        fun isFakeIp(address: InetAddress): Boolean =
            address.address.size == 4 && isFakeIp(addressToInt(address))

        /** Apakah [ipInt] (host order) masuk 198.18.0.0/15. */
        fun isFakeIp(ipInt: Int): Boolean =
            (ipInt ushr 17) == (POOL_BASE_INT ushr 17)

        private fun addressToInt(address: InetAddress): Int {
            val b = address.address
            require(b.size == 4) { "FakeDNS hanya IPv4" }
            return ((b[0].toInt() and 0xFF) shl 24) or
                ((b[1].toInt() and 0xFF) shl 16) or
                ((b[2].toInt() and 0xFF) shl 8) or
                (b[3].toInt() and 0xFF)
        }

        private fun intToAddress(ipInt: Int): InetAddress =
            InetAddress.getByAddress(
                byteArrayOf(
                    ((ipInt ushr 24) and 0xFF).toByte(),
                    ((ipInt ushr 16) and 0xFF).toByte(),
                    ((ipInt ushr 8) and 0xFF).toByte(),
                    (ipInt and 0xFF).toByte(),
                ),
            )
    }
}
