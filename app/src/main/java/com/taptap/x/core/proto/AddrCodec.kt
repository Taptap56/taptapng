package com.taptap.x.core.proto

import java.net.InetAddress
import java.util.UUID

/**
 * Target address encoding shared by the M2 protocols.
 *
 * Two orders exist — do not mix them up:
 * - VMess / VLESS: PORT (2B big-endian) first, then ATYP + address.
 * - SOCKS-style (Trojan / Shadowsocks): ATYP + address first, then PORT.
 *
 * ATYP values also differ: VMess/VLESS use 1=IPv4, 2=domain, 3=IPv6;
 * SOCKS uses 1=IPv4, 3=domain, 4=IPv6.
 */
object AddrCodec {

    data class Target(val host: String, val port: Int)

    private val IPV4_REGEX = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val IPV6_CHARS_REGEX = Regex("^[0-9a-fA-F:]+$")

    fun isIpv4(host: String): Boolean {
        if (!IPV4_REGEX.matches(host)) return false
        return host.split(".").all { (it.toIntOrNull() ?: 256) in 0..255 }
    }

    /** True only for an IPv6 *literal* (never triggers a DNS lookup). */
    fun isIpv6Literal(host: String): Boolean =
        host.contains(':') && IPV6_CHARS_REGEX.matches(host)

    fun isIpLiteral(host: String): Boolean = isIpv4(host) || isIpv6Literal(host)

    private fun ipv4Bytes(host: String): ByteArray {
        val parts = host.split(".")
        require(parts.size == 4) { "IPv4 tidak valid: $host" }
        return ByteArray(4) { parts[it].toInt().toByte() }
    }

    private fun ipv6Bytes(host: String): ByteArray {
        // Literal only (checked by the caller) — no DNS lookup happens.
        val addr = InetAddress.getByName(host)
        val bytes = addr.address
        require(bytes.size == 16) { "IPv6 tidak valid: $host" }
        return bytes
    }

    private fun domainBytes(host: String): ByteArray {
        val bytes = host.toByteArray(Charsets.UTF_8)
        require(bytes.isNotEmpty() && bytes.size <= 255) {
            "Domain terlalu panjang/kosong: $host"
        }
        return bytes
    }

    /** VMess/VLESS address body (without the port): ATYP + address. */
    fun encodeVmessAddress(host: String): ByteArray = when {
        isIpv4(host) -> byteArrayOf(0x01) + ipv4Bytes(host)
        isIpv6Literal(host) -> byteArrayOf(0x03) + ipv6Bytes(host)
        else -> byteArrayOf(0x02, domainBytes(host).size.toByte()) + domainBytes(host)
    }

    /** VMess/VLESS target: PORT (2B BE) + ATYP + address. */
    fun encodeVmessTarget(host: String, port: Int): ByteArray {
        require(port in 1..65535) { "Port target di luar 1..65535: $port" }
        return byteArrayOf(((port ushr 8) and 0xFF).toByte(), (port and 0xFF).toByte()) +
            encodeVmessAddress(host)
    }

    /** SOCKS-style target: ATYP + address + PORT (2B BE). */
    fun encodeSocksTarget(host: String, port: Int): ByteArray {
        require(port in 1..65535) { "Port target di luar 1..65535: $port" }
        val addr = when {
            isIpv4(host) -> byteArrayOf(0x01) + ipv4Bytes(host)
            isIpv6Literal(host) -> byteArrayOf(0x04) + ipv6Bytes(host)
            else -> byteArrayOf(0x03, domainBytes(host).size.toByte()) + domainBytes(host)
        }
        return addr + byteArrayOf(((port ushr 8) and 0xFF).toByte(), (port and 0xFF).toByte())
    }

    /** Parse a VMess/VLESS target starting at [offset]. Returns target + next offset. */
    fun parseVmessTarget(bytes: ByteArray, offset: Int): Pair<Target, Int> {
        require(offset + 3 <= bytes.size) { "Header VMess terpotong (port+atyp)" }
        val port = ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
        val (host, next) = parseVmessAddress(bytes, offset + 2)
        return Target(host, port) to next
    }

    /** Parse a VMess/VLESS address body (ATYP + address) at [offset]. */
    fun parseVmessAddress(bytes: ByteArray, offset: Int): Pair<String, Int> {
        require(offset < bytes.size) { "Header VMess terpotong (atyp)" }
        return when (val atyp = bytes[offset].toInt() and 0xFF) {
            0x01 -> {
                require(offset + 5 <= bytes.size) { "Alamat IPv4 terpotong" }
                val host = (1..4).joinToString(".") { (bytes[offset + it].toInt() and 0xFF).toString() }
                host to offset + 5
            }
            0x02 -> {
                require(offset + 2 <= bytes.size) { "Panjang domain terpotong" }
                val len = bytes[offset + 1].toInt() and 0xFF
                require(offset + 2 + len <= bytes.size) { "Domain terpotong" }
                String(bytes, offset + 2, len, Charsets.UTF_8) to offset + 2 + len
            }
            0x03 -> {
                require(offset + 17 <= bytes.size) { "Alamat IPv6 terpotong" }
                val raw = bytes.copyOfRange(offset + 1, offset + 17)
                InetAddress.getByAddress(raw).hostAddress to offset + 17
            }
            else -> throw IllegalArgumentException("ATYP VMess tidak dikenal: $atyp")
        }
    }

    /** Parse a SOCKS-style target (ATYP + address + PORT) at [offset]. */
    fun parseSocksTarget(bytes: ByteArray, offset: Int): Pair<Target, Int> {
        require(offset < bytes.size) { "Header SOCKS terpotong (atyp)" }
        val (host, afterAddr) = when (val atyp = bytes[offset].toInt() and 0xFF) {
            0x01 -> {
                require(offset + 5 <= bytes.size) { "Alamat IPv4 terpotong" }
                val host = (1..4).joinToString(".") { (bytes[offset + it].toInt() and 0xFF).toString() }
                host to offset + 5
            }
            0x03 -> {
                require(offset + 2 <= bytes.size) { "Panjang domain terpotong" }
                val len = bytes[offset + 1].toInt() and 0xFF
                require(offset + 2 + len <= bytes.size) { "Domain terpotong" }
                String(bytes, offset + 2, len, Charsets.UTF_8) to offset + 2 + len
            }
            0x04 -> {
                require(offset + 17 <= bytes.size) { "Alamat IPv6 terpotong" }
                val raw = bytes.copyOfRange(offset + 1, offset + 17)
                InetAddress.getByAddress(raw).hostAddress to offset + 17
            }
            else -> throw IllegalArgumentException("ATYP SOCKS tidak dikenal: $atyp")
        }
        require(afterAddr + 2 <= bytes.size) { "Port SOCKS terpotong" }
        val port = ((bytes[afterAddr].toInt() and 0xFF) shl 8) or
            (bytes[afterAddr + 1].toInt() and 0xFF)
        return Target(host, port) to afterAddr + 2
    }

    /**
     * UUID string (with dashes) to its 16 raw bytes. A non-UUID string is
     * mapped deterministically via MD5 (Xray accepts short custom IDs the
     * same way); an empty string is rejected.
     */
    fun parseUuidBytes(uuid: String): ByteArray {
        require(uuid.isNotBlank()) { "UUID kosong" }
        return try {
            val u = UUID.fromString(uuid.trim())
            val out = ByteArray(16)
            for (i in 0 until 8) {
                out[i] = ((u.mostSignificantBits ushr (56 - 8 * i)) and 0xFF).toByte()
                out[8 + i] = ((u.leastSignificantBits ushr (56 - 8 * i)) and 0xFF).toByte()
            }
            out
        } catch (e: IllegalArgumentException) {
            Crypto.md5(uuid.trim().toByteArray(Charsets.UTF_8))
        }
    }

    fun hexLower(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append(String.format("%02x", b.toInt() and 0xFF))
        return sb.toString()
    }
}
