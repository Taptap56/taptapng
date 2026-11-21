package com.taptap.ng.core

import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * SO_ORIGINAL_DST (v1.0.15) — alamat tujuan asli koneksi yang
 * di-REDIRECT iptables.
 *
 * `getsockopt(fd, SOL_IP, SO_ORIGINAL_DST)` mengembalikan struct
 * sockaddr — [parseSockaddr] menguraikannya secara murni (tanpa
 * API Android, unit-testable). Dipakai [RootForwarder] lewat
 * `OsOriginalDstResolver` (android.system.Os hanya mengembalikan
 * InetAddress, bukan port — portnya justru diketahui dari listener
 * mana yang menerima: 18080 = 80, 18081 = 443, lihat
 * [RootIptables]).
 */
object OriginalDst {

    /** Linux SO_ORIGINAL_DST (SOL_IP / SOL_IPV6, nilai 80). */
    const val SO_ORIGINAL_DST = 80

    /**
     * Uraikan struct sockaddr (sockaddr_in 16 byte atau
     * sockaddr_in6 28 byte) menjadi alamat + port. Keluarga
     * dibaca little-endian (sa_family_t di kernel), port
     * big-endian (network order). Null bila byte tidak cukup
     * atau keluarga bukan AF_INET (2) / AF_INET6 (10).
     */
    fun parseSockaddr(bytes: ByteArray): InetSocketAddress? {
        if (bytes.size < 16) return null
        val family = (bytes[0].toInt() and 0xFF) or ((bytes[1].toInt() and 0xFF) shl 8)
        val port = ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)
        return when (family) {
            2 -> { // AF_INET
                val addr = InetAddress.getByAddress(bytes.copyOfRange(4, 8))
                InetSocketAddress(addr, port)
            }
            10 -> { // AF_INET6
                if (bytes.size < 28) return null
                val addr = InetAddress.getByAddress(bytes.copyOfRange(8, 24))
                InetSocketAddress(addr, port)
            }
            else -> null
        }
    }
}
