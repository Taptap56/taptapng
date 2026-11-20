package com.taptap.x.core.slowdns

import java.io.EOFException

/**
 * DNS wire format for DNSTT (M3), ported from TB's Go implementation
 * (singbox-fork/protocol/slowdns/dnstt/dnsttdns.go + packetconn.go —
 * itself adapted from the public DNSTT library, bamsoftware.com).
 *
 * Only what the DNSTT client needs:
 * - build a query: one Question (name = base32 labels + tunnel domain,
 *   type TXT=16 or NULL=10, class IN) + one EDNS(0) OPT additional
 *   record (root name, type 41, class 4096 = requester's UDP payload
 *   size, TTL 0, empty data). Flags 0x0100 (RD=1). Random 16-bit ID.
 * - parse a response: QR=1, RCODE=0, exactly 1 answer whose name is a
 *   subdomain of the tunnel domain; TXT → concatenated
 *   character-strings, NULL → raw RDATA bytes. Payload = sequence of
 *   [uint16 BE length][packet]*.
 * - base32 (RFC 4648 alphabet A-Z2-7, no padding, lowercase) for the
 *   query-name encoding.
 *
 * Names in responses may use compression pointers (0xC0, max 10
 * followed) — the parser handles them. The query builder writes names
 * without compression (one question + one root-named OPT, nothing
 * repeats, so compression buys nothing).
 *
 * No credentials are ever logged here (DNS names carry encoded tunnel
 * data, not credentials, but they are still not logged).
 */
object DnsWire {

    const val TYPE_TXT = 16
    const val TYPE_NULL = 10
    const val TYPE_OPT = 41
    const val CLASS_IN = 1

    const val FLAG_QR = 0x8000
    const val FLAG_RD = 0x0100

    private const val COMPRESSION_LIMIT = 10

    /** Build a DNSTT query for [encodedName] (already base32 labels + domain). */
    fun buildQuery(id: Int, nameLabels: List<ByteArray>, qtype: Int): ByteArray {
        require(qtype == TYPE_TXT || qtype == TYPE_NULL) { "Tipe record DNSTT tidak didukung: $qtype" }
        val out = mutableListOf<Byte>()
        fun u16(v: Int) {
            out.add(((v ushr 8) and 0xFF).toByte())
            out.add((v and 0xFF).toByte())
        }
        fun u32(v: Long) {
            out.add(((v ushr 24) and 0xFF).toByte())
            out.add(((v ushr 16) and 0xFF).toByte())
            out.add(((v ushr 8) and 0xFF).toByte())
            out.add((v and 0xFF).toByte())
        }
        fun writeName(labels: List<ByteArray>) {
            for (label in labels) {
                require(label.isNotEmpty() && label.size <= 63) { "Label DNS tidak valid" }
                out.add(label.size.toByte())
                out.addAll(label.toList())
            }
            out.add(0) // root
        }
        u16(id and 0xFFFF)
        u16(FLAG_RD)
        u16(1) // QDCOUNT
        u16(0) // ANCOUNT
        u16(0) // NSCOUNT
        u16(1) // ARCOUNT (EDNS OPT)
        writeName(nameLabels)
        u16(qtype)
        u16(CLASS_IN)
        // EDNS(0) OPT: root name, type 41, class 4096, TTL 0, empty RDATA.
        out.add(0)
        u16(TYPE_OPT)
        u16(4096)
        u32(0)
        u16(0)
        return out.toByteArray()
    }

    /** Result of parsing a DNSTT response: the downstream payload bytes, or null when invalid. */
    data class ParsedResponse(val payload: ByteArray, val questionName: List<ByteArray>)

    /**
     * Parse a DNS response and extract the DNSTT payload. Returns null
     * when the message fails any check (not a response, RCODE != 0,
     * answer count != 1, answer name not a subdomain of [domainLabels],
     * answer type != [qtype], TXT decode failure).
     */
    fun parseResponse(msg: ByteArray, domainLabels: List<String>, qtype: Int): ParsedResponse? {
        if (msg.size < 12) return null
        val flags = u16(msg, 2)
        if (flags and FLAG_QR == 0) return null
        if (flags and 0x000F != 0) return null // RCODE != NOERROR
        val qdCount = u16(msg, 4)
        val anCount = u16(msg, 6)
        if (anCount != 1) return null
        var pos = 12
        var questionName: List<ByteArray>? = null
        repeat(qdCount) {
            val (labels, next) = readName(msg, pos) ?: return null
            if (questionName == null) questionName = labels
            pos = next
            if (pos + 4 > msg.size) return null
            pos += 4 // QTYPE + QCLASS
        }
        // Exactly one answer.
        val (answerName, afterName) = readName(msg, pos) ?: return null
        pos = afterName
        if (pos + 10 > msg.size) return null
        val type = u16(msg, pos)
        val rdLen = u16(msg, pos + 8)
        pos += 10 // TYPE + CLASS + TTL + RDLENGTH
        if (pos + rdLen > msg.size) return null
        if (type != qtype) return null
        if (!isSubdomainOf(answerName, domainLabels)) return null
        val rdata = msg.copyOfRange(pos, pos + rdLen)
        val payload = when (qtype) {
            TYPE_TXT -> decodeRDataTxt(rdata) ?: return null
            TYPE_NULL -> rdata
            else -> return null
        }
        return ParsedResponse(payload, questionName ?: emptyList())
    }

    /** Split a downstream payload into its length-prefixed packets. */
    fun splitPackets(payload: ByteArray): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        var pos = 0
        while (pos + 2 <= payload.size) {
            val n = u16(payload, pos)
            pos += 2
            if (pos + n > payload.size) break // truncated tail: drop it
            out.add(payload.copyOfRange(pos, pos + n))
            pos += n
        }
        return out
    }

    /** Encode one upstream packet the way the DNSTT client does (clientID + padding + length + data). */
    fun encodeUpstreamPacket(packet: ByteArray, clientId: ByteArray, randomPadding: ByteArray): ByteArray {
        require(clientId.size == 8) { "ClientID harus 8 byte" }
        require(packet.size < 224) { "Paket DNSTT terlalu panjang: ${packet.size}" }
        val out = mutableListOf<Byte>()
        out.addAll(clientId.toList())
        out.add((0xE0 + randomPadding.size).toByte())
        out.addAll(randomPadding.toList())
        if (packet.isNotEmpty()) {
            out.add(packet.size.toByte())
            out.addAll(packet.toList())
        }
        return out.toByteArray()
    }

    /** Decode an upstream packet body (after base32 + clientID strip): returns the packet, or null. */
    fun decodeUpstreamPacket(body: ByteArray): ByteArray? {
        // body = [padding-prefix][padding][len][packet] (len+packet absent for polls).
        if (body.isEmpty()) return null
        val first = body[0].toInt() and 0xFF
        if (first < 0xE0) return null // must be a padding prefix
        val padLen = first - 0xE0
        var pos = 1 + padLen
        if (pos >= body.size) return ByteArray(0) // poll packet (empty)
        val len = body[pos].toInt() and 0xFF
        pos += 1
        if (pos + len > body.size) return null
        return body.copyOfRange(pos, pos + len)
    }

    /** Decode TXT RDATA (concatenated character-strings). Null on malformed input. */
    fun decodeRDataTxt(p: ByteArray): ByteArray? {
        if (p.isEmpty()) return null
        val out = mutableListOf<Byte>()
        var pos = 0
        while (pos < p.size) {
            val n = p[pos].toInt() and 0xFF
            pos += 1
            if (pos + n > p.size) return null
            out.addAll(p.copyOfRange(pos, pos + n).toList())
            pos += n
        }
        return out.toByteArray()
    }

    /** Encode bytes as TXT RDATA (character-strings of <= 255 bytes). */
    fun encodeRDataTxt(p: ByteArray): ByteArray {
        val out = mutableListOf<Byte>()
        var pos = 0
        while (pos < p.size) {
            val n = minOf(255, p.size - pos)
            out.add(n.toByte())
            out.addAll(p.copyOfRange(pos, pos + n).toList())
            pos += n
        }
        if (p.isEmpty()) out.add(0)
        return out.toByteArray()
    }

    /** A name is a subdomain of [domainLabels] when its trailing labels equal the domain (case-insensitive). */
    fun isSubdomainOf(nameLabels: List<ByteArray>, domainLabels: List<String>): Boolean {
        if (nameLabels.size < domainLabels.size) return false
        val tail = nameLabels.takeLast(domainLabels.size)
        return tail.indices.all { i ->
            tail[i].toString(Charsets.US_ASCII).equals(domainLabels[i], ignoreCase = true)
        }
    }

    /** Parse a dotted domain into labels (lowercased, no trailing dot). */
    fun parseDomain(domain: String): List<String> {
        val clean = domain.trim().trimEnd('.')
        require(clean.isNotBlank()) { "Domain tunnel kosong" }
        val labels = clean.split(".")
        for (label in labels) {
            require(label.isNotEmpty() && label.length <= 63) { "Label domain tidak valid: $label" }
            require(label.all { it.isLetterOrDigit() || it == '-' }) {
                "Label domain hanya boleh huruf/angka/-: $label"
            }
        }
        return labels
    }

    /** Read a DNS name at [pos] (handles compression pointers, max 10). Returns (labels, position-after-name) or null. */
    fun readName(msg: ByteArray, pos: Int): Pair<List<ByteArray>, Int>? {
        val labels = mutableListOf<ByteArray>()
        var p = pos
        var pointers = 0
        var afterPointer: Int? = null
        while (true) {
            if (p >= msg.size) return null
            val len = msg[p].toInt() and 0xFF
            when {
                len == 0 -> {
                    val end = afterPointer ?: (p + 1)
                    return labels to end
                }
                len and 0xC0 == 0xC0 -> {
                    if (p + 1 >= msg.size) return null
                    if (afterPointer == null) afterPointer = p + 2
                    pointers++
                    if (pointers > COMPRESSION_LIMIT) return null
                    val offset = ((len and 0x3F) shl 8) or (msg[p + 1].toInt() and 0xFF)
                    if (offset >= msg.size) return null
                    p = offset
                }
                len and 0xC0 != 0 -> return null
                else -> {
                    if (p + 1 + len > msg.size) return null
                    labels.add(msg.copyOfRange(p + 1, p + 1 + len))
                    p += 1 + len
                }
            }
        }
    }

    private fun u16(buf: ByteArray, pos: Int): Int =
        ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
}

/** Base32 (RFC 4648, alphabet A-Z2-7), no padding, lowercase output — the DNSTT query-name encoding. */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val DECODE = IntArray(128) { -1 }.apply {
        for (i in ALPHABET.indices) {
            this[ALPHABET[i].code] = i
            this[ALPHABET[i].lowercaseChar().code] = i
        }
    }

    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val out = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                bitsLeft -= 5
                out.append(ALPHABET[(buffer ushr bitsLeft) and 0x1F])
            }
        }
        if (bitsLeft > 0) {
            out.append(ALPHABET[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        return out.toString().lowercase()
    }

    fun decode(s: String): ByteArray {
        val clean = s.trim()
        if (clean.isEmpty()) return ByteArray(0)
        val out = mutableListOf<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (ch in clean) {
            val v = if (ch.code < 128) DECODE[ch.code] else -1
            require(v >= 0) { "Karakter base32 tidak valid: $ch" }
            buffer = (buffer shl 5) or v
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                out.add(((buffer ushr bitsLeft) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }
}

/** Split bytes into chunks of at most [n] (greedy; only the last chunk is short). */
fun ByteArray.chunkedMax(n: Int): List<ByteArray> {
    require(n > 0) { "chunk size harus > 0" }
    val out = mutableListOf<ByteArray>()
    var pos = 0
    while (pos < size) {
        val end = minOf(size, pos + n)
        out.add(copyOfRange(pos, end))
        pos = end
    }
    return out
}

internal fun ByteArray.readExactOrThrow(n: Int): ByteArray {
    if (size < n) throw EOFException("Butuh $n byte, hanya ada $size")
    return copyOfRange(0, n)
}
