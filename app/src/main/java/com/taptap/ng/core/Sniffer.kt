package com.taptap.ng.core

/**
 * Traffic sniffing (v1.0.5, kelompok F): pure parsers over the first
 * bytes of a TCP stream — no sockets, no Android APIs, fully JVM
 * testable.
 *
 * - TLS ClientHello → SNI (extension server_name, type host_name).
 * - Plaintext HTTP request → Host header.
 *
 * Anything else (other TLS records, ServerHello, binary protocols,
 * truncated data) returns null — a missed sniff is never an error,
 * the destination just stays "unknown" (see [RouteOnlyGate]).
 *
 * Limits (documented, not hidden):
 * - Only the first few data chunks of a session are inspected (see
 *   TunForwarder); a ClientHello split across many TCP segments may
 *   be missed if its first chunks do not yet contain the full SNI
 *   extension.
 * - The SNI / Host is what the APP sent; it is used for routing
 *   decisions and logging of the destination name only — never for
 *   authentication, and never logged together with credentials.
 */
object Sniffer {

    /** Where a sniffed hostname came from. */
    enum class Kind { TLS_SNI, HTTP_HOST }

    data class SniffedHost(val host: String, val kind: Kind)

    /**
     * Extract the hostname from the first bytes of a stream: SNI
     * first, HTTP Host second. Null when the bytes are neither a
     * (complete-enough) ClientHello with SNI nor an HTTP request
     * with a Host header.
     */
    fun extract(data: ByteArray): SniffedHost? {
        extractSni(data)?.let { return SniffedHost(it, Kind.TLS_SNI) }
        extractHttpHost(data)?.let { return SniffedHost(it, Kind.HTTP_HOST) }
        return null
    }

    /**
     * SNI from a TLS ClientHello. Layout (all bounds-checked):
     * TLS record (0x16, version, u16 length) → handshake (0x01,
     * u24 length) → version(2) + random(32) + session-id(u8 len) +
     * cipher-suites(u16 len) + compression(u8 len) → extensions
     * (u16 len) → extension 0x0000 server_name → list(u16) →
     * entries (u8 type, u16 len, bytes); type 0 = host_name.
     * Returns the lower-cased hostname, or null.
     */
    fun extractSni(data: ByteArray): String? {
        // TLS record header: type 0x16 (handshake), TLS 1.x.
        if (data.size < 5) return null
        if (data[0].toInt() and 0xFF != 0x16) return null
        if (data[1].toInt() and 0xFF != 0x03) return null
        val recordLen = u16(data, 3)
        if (recordLen < 4 || 5 + recordLen > data.size) return null
        // Handshake header inside the record.
        var pos = 5
        if (data[pos].toInt() and 0xFF != 0x01) return null // not ClientHello
        val hsLen = u24(data, pos + 1)
        if (hsLen < 34 || pos + 4 + hsLen > data.size) return null
        pos += 4
        pos += 2 + 32 // version + random
        if (pos >= data.size) return null
        val sessionLen = data[pos].toInt() and 0xFF
        pos += 1 + sessionLen
        if (pos + 2 > data.size) return null
        val cipherLen = u16(data, pos)
        pos += 2 + cipherLen
        if (pos >= data.size) return null
        val compLen = data[pos].toInt() and 0xFF
        pos += 1 + compLen
        if (pos + 2 > data.size) return null
        val extTotal = u16(data, pos)
        pos += 2
        val extEnd = minOf(pos + extTotal, data.size)
        while (pos + 4 <= extEnd) {
            val extType = u16(data, pos)
            val extLen = u16(data, pos + 2)
            pos += 4
            if (pos + extLen > extEnd) return null
            if (extType == 0x0000) {
                // server_name: u16 list len, then entries.
                if (extLen < 3) return null
                val listLen = u16(data, pos)
                var p = pos + 2
                val listEnd = minOf(pos + 2 + listLen, pos + extLen)
                while (p + 3 <= listEnd) {
                    val nameType = data[p].toInt() and 0xFF
                    val nameLen = u16(data, p + 1)
                    p += 3
                    if (p + nameLen > listEnd) return null
                    if (nameType == 0) {
                        val host = data.copyOfRange(p, p + nameLen)
                            .toString(Charsets.US_ASCII).trim().lowercase()
                        if (host.isNotEmpty()) return host
                        return null
                    }
                    p += nameLen
                }
                return null
            }
            pos += extLen
        }
        return null
    }

    /**
     * Host header from a plaintext HTTP request. The first line must
     * start with a known method + space (so random binary / TLS bytes
     * never parse as HTTP); headers are scanned line by line for
     * "Host:" (case-insensitive). Returns the host lower-cased,
     * without any :port suffix, or null.
     */
    fun extractHttpHost(data: ByteArray): String? {
        val text = data.toString(Charsets.US_ASCII)
        val firstSpace = text.indexOf(' ')
        if (firstSpace <= 0) return null
        val method = text.substring(0, firstSpace)
        if (method !in HTTP_METHODS) return null
        val headerEnd = text.indexOf("\r\n\r\n")
        val head = if (headerEnd >= 0) text.substring(0, headerEnd) else text
        for (line in head.split("\r\n").drop(1)) {
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            if (!line.substring(0, colon).trim().equals("host", ignoreCase = true)) continue
            val value = line.substring(colon + 1).trim()
            if (value.isEmpty()) return null
            return value.substringBefore(':').trim().lowercase()
                .ifEmpty { null }
        }
        return null
    }

    private val HTTP_METHODS = setOf(
        "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    )

    /**
     * QNAME (dotted hostname) from a DNS query message: labels from
     * offset 12 until the root label. Null on truncated / malformed
     * input. Used by the forwarder's DNS relay to map an answer IP
     * back to the hostname the app asked for (see [RouteOnlyGate]).
     */
    fun parseDnsQueryName(query: ByteArray): String? {
        if (query.size < 13) return null
        val labels = ArrayList<String>()
        var pos = 12
        while (true) {
            if (pos >= query.size) return null
            val len = query[pos].toInt() and 0xFF
            if (len == 0) break
            if (len and 0xC0 != 0) return null // pointer — not a query QNAME
            if (len > 63 || pos + 1 + len > query.size) return null
            labels += query.copyOfRange(pos + 1, pos + 1 + len)
                .toString(Charsets.US_ASCII)
            pos += 1 + len
        }
        if (labels.isEmpty()) return null
        return labels.joinToString(".").lowercase()
    }

    /** IPv4 [InetAddress] bytes → big-endian int (TunForwarder key). */
    fun ipv4ToInt(address: java.net.InetAddress): Int? {
        val b = address.address
        if (b.size != 4) return null
        return ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
    }

    private fun u16(buf: ByteArray, pos: Int): Int =
        ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)

    private fun u24(buf: ByteArray, pos: Int): Int =
        ((buf[pos].toInt() and 0xFF) shl 16) or
            ((buf[pos + 1].toInt() and 0xFF) shl 8) or
            (buf[pos + 2].toInt() and 0xFF)
}
