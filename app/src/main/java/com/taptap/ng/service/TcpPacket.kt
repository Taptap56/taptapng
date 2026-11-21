package com.taptap.ng.service

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure IPv4/TCP/UDP/ICMP packet codec (no Android APIs) — covered by
 * JVM unit tests ([TcpPacketTest]). Used by [TunForwarder] to speak
 * TCP to the apps on the TUN interface while the payload travels
 * through an in-app [com.taptap.ng.core.proto.ProxyClient].
 *
 * v1.0.6 (M6): IPv6 too — [IpAddr] (4 or 16 bytes), IPv6 header
 * parse ([parseIpv6Header]), TCP/UDP/ICMPv6 build over IPv6
 * ([buildTcp6]/[buildUdp6]/[buildIcmpv6EchoReply]) with IPv6
 * pseudo-header checksums. Extension headers are NOT parsed: a
 * packet whose Next Header is an extension (0/43/44/60) is dropped
 * (app traffic from Android virtually never carries them; the
 * forwarder logs nothing — dropping is the safe default).
 *
 * The forwarder only implements the subset of TCP it needs: SYN /
 * SYN-ACK / ACK / data / FIN / RST, no retransmission (the TUN is a
 * local reliable link), no window scaling, MSS 1460 by default
 * ([TCP_MSS]; the forwarder derives up to 8960 from a 9000 MTU
 * since v1.0.21, see TunForwarder.maxMssForMtu).
 */
object TcpPacket {

    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17
    const val PROTO_ICMPV6 = 58

    /** Next Header values that are extension headers (dropped, see KDoc). */
    private val IPV6_EXTENSION_HEADERS = setOf(0, 43, 44, 60)

    /**
     * An IP address, IPv4 (4 bytes) or IPv6 (16 bytes). Content
     * equality — usable as a map key (v1.0.6: TCP/UDP session keys
     * are [IpAddr], so IPv6 sessions are 128-bit).
     */
    class IpAddr(val bytes: ByteArray) {
        val isV6: Boolean get() = bytes.size == 16
        val isV4: Boolean get() = bytes.size == 4

        /** IPv4 as Int (big-endian), or 0 for IPv6. */
        fun toInt(): Int {
            if (!isV4) return 0
            return ((bytes[0].toInt() and 0xFF) shl 24) or
                ((bytes[1].toInt() and 0xFF) shl 16) or
                ((bytes[2].toInt() and 0xFF) shl 8) or
                (bytes[3].toInt() and 0xFF)
        }

        override fun toString(): String =
            java.net.InetAddress.getByAddress(bytes).hostAddress

        override fun equals(other: Any?): Boolean =
            other is IpAddr && bytes.contentEquals(other.bytes)

        override fun hashCode(): Int = bytes.contentHashCode()

        companion object {
            fun v4(ip: Int): IpAddr = IpAddr(
                byteArrayOf(
                    (ip ushr 24).toByte(), (ip ushr 16).toByte(),
                    (ip ushr 8).toByte(), ip.toByte(),
                ),
            )

            fun v6(bytes: ByteArray): IpAddr {
                require(bytes.size == 16) { "IPv6 harus 16 byte: ${bytes.size}" }
                return IpAddr(bytes.copyOf())
            }

            fun parse(text: String): IpAddr {
                val addr = java.net.InetAddress.getByName(text)
                return IpAddr(addr.address)
            }
        }
    }

    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10

    const val TCP_MSS = 1460
    const val TCP_WINDOW = 65535

    /**
     * Max wire bytes of one relay TCP segment: IP + TCP headers +
     * MSS, no options (v1.0.15 — the relay's reusable packet
     * buffer size).
     */
    const val MAX_TCP_SEGMENT_BYTES = 20 + 20 + TCP_MSS

    /**
     * Window-scale shift the forwarder echoes when the app's SYN
     * offers window scaling, and the window field it advertises
     * with that shift — the same numbers xray-core's tun stack
     * uses (tcpWindowShift = 5, tcpWindow = 256 KiB, so the
     * advertised field is 256 KiB >> 5 = 8192). v1.0.9 sent MSS
     * only with a 65535 window and no scale: legal, but a visible
     * difference from v2rayNG, and the small unscaled window
     * throttles bulk transfer.
     */
    const val TCP_WINDOW_SHIFT = 5
    const val TCP_WINDOW_SCALED = 8192

    data class IpPacket(val src: Int, val dst: Int, val protocol: Int, val payload: ByteArray)

    data class TcpSegment(
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val flags: Int,
        val window: Int,
        val payload: ByteArray,
        /** Raw TCP options (bytes 20..dataOffset); empty when none. */
        val options: ByteArray = byteArrayOf(),
    )

    data class UdpDatagram(val srcPort: Int, val dstPort: Int, val payload: ByteArray)

    /** What a SYN offers, parsed from its options (RFC 7323 / 2018). */
    data class TcpOptions(
        /** Peer's MSS (kind 2), null when absent. */
        val mss: Int? = null,
        /** Peer's window-scale shift (kind 3), null when absent. */
        val windowScale: Int? = null,
        /** Peer's SACK-permitted (kind 4). */
        val sackPermitted: Boolean = false,
    )

    /**
     * Parse TCP options. NOP (1) is skipped, EOL (0) stops the
     * scan, unknown kinds are skipped by their length byte.
     * Malformed options (length < 2, or running past the end)
     * stop the scan instead of throwing — a bad option must not
     * kill the reader thread.
     */
    fun parseTcpOptions(options: ByteArray): TcpOptions {
        var mss: Int? = null
        var windowScale: Int? = null
        var sackPermitted = false
        var i = 0
        while (i < options.size) {
            val kind = options[i].toInt() and 0xFF
            when (kind) {
                0 -> break // EOL
                1 -> i += 1 // NOP
                2 -> {
                    if (i + 3 >= options.size || options[i + 1].toInt() != 4) break
                    mss = ((options[i + 2].toInt() and 0xFF) shl 8) or
                        (options[i + 3].toInt() and 0xFF)
                    i += 4
                }
                3 -> {
                    if (i + 2 >= options.size || options[i + 1].toInt() != 3) break
                    windowScale = options[i + 2].toInt() and 0xFF
                    i += 3
                }
                4 -> {
                    if (i + 1 >= options.size || options[i + 1].toInt() != 2) break
                    sackPermitted = true
                    i += 2
                }
                else -> {
                    if (i + 1 >= options.size) break
                    val len = options[i + 1].toInt() and 0xFF
                    if (len < 2 || i + len > options.size) break
                    i += len
                }
            }
        }
        return TcpOptions(mss, windowScale, sackPermitted)
    }

    /** Parse an IPv4 packet. Returns null for non-IPv4 / truncated input. */
    fun parseIp(packet: ByteArray, len: Int): IpPacket? {
        if (len < 20) return null
        if (packet[0].toInt() shr 4 != 4) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (len < ihl) return null
        val total = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        val end = minOf(total, len)
        if (end < ihl) return null
        val buf = ByteBuffer.wrap(packet, 0, end).order(ByteOrder.BIG_ENDIAN)
        val protocol = buf.get(9).toInt() and 0xFF
        val src = buf.getInt(12)
        val dst = buf.getInt(16)
        val payload = packet.copyOfRange(ihl, end)
        return IpPacket(src, dst, protocol, payload)
    }

    /** Parse a TCP segment. Returns null for truncated input. */
    fun parseTcp(payload: ByteArray): TcpSegment? {
        if (payload.size < 20) return null
        val buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        val srcPort = buf.short.toInt() and 0xFFFF
        val dstPort = buf.short.toInt() and 0xFFFF
        val seq = buf.int.toLong() and 0xFFFFFFFFL
        val ack = buf.int.toLong() and 0xFFFFFFFFL
        val dataOffset = ((buf.get(12).toInt() and 0xFF) ushr 4) * 4
        if (payload.size < dataOffset) return null
        val flags = buf.get(13).toInt() and 0xFF
        // v1.0.10: the window field is at TCP offset 14 — the old
        // relative buf.short() read at position 12 (data-offset +
        // flags bytes) instead. And the data-offset byte above must
        // be masked BEFORE ushr: a signed Byte >= 0x80 (ANY header
        // with options — every real app SYN carries MSS/WS/SACK/
        // timestamps, data offset 0x80/0xA0) sign-extends to a
        // negative Int, ushr turns it into a huge number, and
        // parseTcp returned null — the forwarder silently dropped
        // every real SYN. That is the v1.0.9 "zero DIAL lines"
        // root cause, not routing: the old tests only ever fed
        // MSS-only SYNs (0x60, a positive byte).
        val window = buf.getShort(14).toInt() and 0xFFFF
        val options = payload.copyOfRange(20, dataOffset)
        val data = payload.copyOfRange(dataOffset, payload.size)
        return TcpSegment(srcPort, dstPort, seq, ack, flags, window, data, options)
    }

    /** IP header fields WITHOUT copying the payload (v1.0.15 hot
     * path): the TUN reader parses the header in place and only
     * the TCP data payload is copied out ([parseTcpSegment]). */
    data class IpHeader(
        val src: Int,
        val dst: Int,
        val protocol: Int,
        /** Offset of the IP payload inside the packet. */
        val payloadOff: Int,
        /** Length of the IP payload (clamped by total-length). */
        val payloadLen: Int,
    )

    /** Parse an IPv4 header without copying the payload. Same
     * validation as [parseIp] (version, header length,
     * total-length clamp); null for non-IPv4 / truncated input. */
    fun parseIpHeader(packet: ByteArray, len: Int): IpHeader? {
        if (len < 20) return null
        if (packet[0].toInt() shr 4 != 4) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (len < ihl) return null
        val total = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        val end = minOf(total, len)
        if (end < ihl) return null
        val buf = ByteBuffer.wrap(packet, 0, end).order(ByteOrder.BIG_ENDIAN)
        val protocol = buf.get(9).toInt() and 0xFF
        val src = buf.getInt(12)
        val dst = buf.getInt(16)
        return IpHeader(src, dst, protocol, ihl, end - ihl)
    }

    /** IPv6 header fields (v1.0.6, M6) — same shape as [IpHeader]
     * but with 16-byte addresses. */
    data class Ip6Header(
        val src: ByteArray,
        val dst: ByteArray,
        val protocol: Int,
        /** Offset of the payload inside the packet (always 40 here). */
        val payloadOff: Int,
        /** Length of the payload (from the Payload Length field). */
        val payloadLen: Int,
    )

    /**
     * Parse an IPv6 header (v1.0.6, M6). Fixed 40-byte header
     * only — null for non-IPv6 / truncated input / extension
     * headers (Next Header in [IPV6_EXTENSION_HEADERS]).
     */
    fun parseIpv6Header(packet: ByteArray, len: Int): Ip6Header? {
        if (len < 40) return null
        if (packet[0].toInt() shr 4 != 6) return null
        val payloadLen = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
        val nextHeader = packet[6].toInt() and 0xFF
        if (nextHeader in IPV6_EXTENSION_HEADERS) return null
        if (len < 40 + payloadLen) return null
        val src = packet.copyOfRange(8, 24)
        val dst = packet.copyOfRange(24, 40)
        return Ip6Header(src, dst, nextHeader, 40, payloadLen)
    }

    /**
     * Parse a TCP segment that starts at [off] in [packet]
     * (the IP payload, [len] bytes), copying ONLY the data payload
     * out — the single-copy hot path (v1.0.15). Equivalent to
     * [parseIp] + [parseTcp] on the same bytes, minus the
     * intermediate copy of the whole segment. The payload copy is
     * load-bearing: the forwarder's writer queue holds it while
     * the TUN read buffer is reused for the next packet. Same
     * validation as [parseTcp], including the v1.0.10 signed-byte
     * data-offset fix.
     */
    fun parseTcpSegment(packet: ByteArray, off: Int, len: Int): TcpSegment? {
        if (len < 20) return null
        // wrap(packet, off, len) starts the position AT off — but
        // absolute gets (get(12), getShort(14)) are ARRAY-indexed,
        // not off-indexed, so they would read the IP header. All
        // reads below are RELATIVE (position starts at off), which
        // is what lands on the TCP header at packet[off..].
        val buf = ByteBuffer.wrap(packet, off, len).order(ByteOrder.BIG_ENDIAN)
        val srcPort = buf.short.toInt() and 0xFFFF
        val dstPort = buf.short.toInt() and 0xFFFF
        val seq = buf.int.toLong() and 0xFFFFFFFFL
        val ack = buf.int.toLong() and 0xFFFFFFFFL
        val dataOffset = ((buf.get().toInt() and 0xFF) ushr 4) * 4
        if (dataOffset < 20 || len < dataOffset) return null
        val flags = buf.get().toInt() and 0xFF
        val window = buf.short.toInt() and 0xFFFF
        val options = packet.copyOfRange(off + 20, off + dataOffset)
        val data = packet.copyOfRange(off + dataOffset, off + len)
        return TcpSegment(srcPort, dstPort, seq, ack, flags, window, data, options)
    }

    /** Parse a UDP datagram. Returns null for truncated input. */
    fun parseUdp(payload: ByteArray): UdpDatagram? {
        if (payload.size < 8) return null
        val buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        val srcPort = buf.short.toInt() and 0xFFFF
        val dstPort = buf.short.toInt() and 0xFFFF
        val data = payload.copyOfRange(8, payload.size)
        return UdpDatagram(srcPort, dstPort, data)
    }

    /**
     * Build an IPv4 + TCP packet. [mss] > 0 adds an MSS option
     * (SYN-ACK only); [options] adds further options after it
     * (SACK-permitted / window scale, each 4 bytes: NOP + kind +
     * length + value) — the caller must keep the total option
     * length a multiple of 4. [window] is the advertised window
     * field (TCP_WINDOW unless the caller echoes a scale).
     *
     * v1.0.15: delegates to [buildTcpInto] — the relay's hot path
     * builds straight into a reusable buffer instead of allocating
     * a ByteBuffer + a packet array per segment.
     */
    fun buildTcp(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray,
        mss: Int = 0,
        options: ByteArray = byteArrayOf(),
        window: Int = TCP_WINDOW,
    ): ByteArray {
        val total = packetTotalLen(payload.size, mss, options)
        val out = ByteArray(total)
        buildTcpInto(out, srcIp, dstIp, srcPort, dstPort, seq, ack, flags,
            payload, 0, payload.size, mss, options, window)
        return out
    }

    /** Total wire bytes of a TCP packet for [payloadLen] + options. */
    fun packetTotalLen(payloadLen: Int, mss: Int, options: ByteArray): Int {
        val mssOptLen = if (mss > 0) 4 else 0
        return 20 + 20 + mssOptLen + options.size + payloadLen
    }

    /**
     * Build the same packet as [buildTcp], but into the caller-
     * supplied [out] (which must hold at least
     * [packetTotalLen] bytes) and return the wire length — no
     * allocation. The relay reuses one [out] per thread: the
     * packet is written to the TUN synchronously before the next
     * build, so reuse is safe. [payloadOff]/[payloadLen] let the
     * caller build straight from a larger read buffer (no
     * copyOf per segment); [payloadLen] < 0 means "to the end".
     */
    fun buildTcpInto(
        out: ByteArray,
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray,
        payloadOff: Int = 0,
        payloadLen: Int = -1,
        mss: Int = 0,
        options: ByteArray = byteArrayOf(),
        window: Int = TCP_WINDOW,
    ): Int {
        val plen = if (payloadLen < 0) payload.size - payloadOff else payloadLen
        require(payloadOff >= 0 && plen >= 0 && payloadOff + plen <= payload.size) {
            "buildTcpInto: payload range tidak valid ($payloadOff..${payloadOff + plen} of ${payload.size})"
        }
        val mssOptLen = if (mss > 0) 4 else 0
        val optLen = mssOptLen + options.size
        val tcpLen = 20 + optLen + plen
        val total = 20 + tcpLen
        require(out.size >= total) {
            "buildTcpInto: buffer terlalu kecil (${out.size} < $total)"
        }
        val buf = ByteBuffer.wrap(out, 0, total).order(ByteOrder.BIG_ENDIAN)
        // IPv4 header.
        buf.put(0x45.toByte())
        buf.put(0)
        buf.putShort(total.toShort())
        buf.putShort(ipId())
        buf.putShort(0x4000.toShort()) // DF
        buf.put(64.toByte()) // TTL
        buf.put(PROTO_TCP.toByte())
        buf.putShort(0) // checksum, filled below
        buf.putInt(srcIp)
        buf.putInt(dstIp)
        // TCP header.
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putInt(seq.toInt())
        buf.putInt(ack.toInt())
        buf.put(((5 + optLen / 4) shl 4).toByte())
        buf.put(flags.toByte())
        buf.putShort(window.toShort())
        buf.putShort(0) // checksum, filled below
        buf.putShort(0) // urgent pointer
        if (mss > 0) {
            buf.put(2.toByte()) // MSS kind
            buf.put(4.toByte()) // MSS length
            buf.putShort(mss.toShort())
        }
        if (options.isNotEmpty()) buf.put(options)
        buf.put(payload, payloadOff, plen)
        // IPv4 header checksum.
        val ipSum = checksum(out, 0, 20)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xFF).toByte()
        // TCP checksum over the pseudo-header + TCP segment. The
        // checksum field is always at TCP offset 16 (packet 36) —
        // options live after the fixed 20-byte header.
        val tcpSum = tcpChecksum(srcIp, dstIp, out, 20, tcpLen)
        out[36] = (tcpSum ushr 8).toByte()
        out[37] = (tcpSum and 0xFF).toByte()
        return total
    }

    /**
     * Build an IPv6 + TCP packet (v1.0.6, M6). Same parameters as
     * [buildTcp], with 16-byte addresses. Delegates to
     * [buildTcp6Into].
     */
    fun buildTcp6(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray,
        mss: Int = 0,
        options: ByteArray = byteArrayOf(),
        window: Int = TCP_WINDOW,
    ): ByteArray {
        val total = 40 + 20 + (if (mss > 0) 4 else 0) + options.size + payload.size
        val out = ByteArray(total)
        buildTcp6Into(out, srcIp, dstIp, srcPort, dstPort, seq, ack, flags,
            payload, 0, payload.size, mss, options, window)
        return out
    }

    /**
     * Build the same packet as [buildTcp6] into the caller-supplied
     * [out] (which must hold at least the total) and return the
     * wire length — no allocation (mirror of [buildTcpInto]).
     * The TCP checksum uses the IPv6 pseudo-header (src + dst +
     * 4-byte length + 3 zero bytes + Next Header).
     */
    fun buildTcp6Into(
        out: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray,
        payloadOff: Int = 0,
        payloadLen: Int = -1,
        mss: Int = 0,
        options: ByteArray = byteArrayOf(),
        window: Int = TCP_WINDOW,
    ): Int {
        require(srcIp.size == 16 && dstIp.size == 16) { "buildTcp6Into: alamat harus IPv6 16 byte" }
        val plen = if (payloadLen < 0) payload.size - payloadOff else payloadLen
        require(payloadOff >= 0 && plen >= 0 && payloadOff + plen <= payload.size) {
            "buildTcp6Into: payload range tidak valid ($payloadOff..${payloadOff + plen} of ${payload.size})"
        }
        val mssOptLen = if (mss > 0) 4 else 0
        val optLen = mssOptLen + options.size
        val tcpLen = 20 + optLen + plen
        val total = 40 + tcpLen
        require(out.size >= total) {
            "buildTcp6Into: buffer terlalu kecil (${out.size} < $total)"
        }
        val buf = ByteBuffer.wrap(out, 0, total).order(ByteOrder.BIG_ENDIAN)
        // IPv6 header: version 6 + traffic class/flow label 0.
        buf.put(0x60.toByte())
        buf.put(0)
        buf.put(0)
        buf.put(0)
        buf.putShort(tcpLen.toShort())
        buf.put(PROTO_TCP.toByte())
        buf.put(64.toByte()) // Hop limit
        buf.put(srcIp)
        buf.put(dstIp)
        // TCP header.
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putInt(seq.toInt())
        buf.putInt(ack.toInt())
        buf.put(((5 + optLen / 4) shl 4).toByte())
        buf.put(flags.toByte())
        buf.putShort(window.toShort())
        buf.putShort(0) // checksum, filled below
        buf.putShort(0) // urgent pointer
        if (mss > 0) {
            buf.put(2.toByte())
            buf.put(4.toByte())
            buf.putShort(mss.toShort())
        }
        if (options.isNotEmpty()) buf.put(options)
        buf.put(payload, payloadOff, plen)
        // TCP checksum over the IPv6 pseudo-header + TCP segment.
        // The checksum field is at TCP offset 16 (packet 56).
        val tcpSum = tcpChecksum6(srcIp, dstIp, out, 40, tcpLen)
        out[56] = (tcpSum ushr 8).toByte()
        out[57] = (tcpSum and 0xFF).toByte()
        return total
    }

    /** Build an IPv6 + UDP packet (v1.0.6, M6). UDP checksum is
     * mandatory in IPv6 (a computed 0 is written as 0xffff). */
    fun buildUdp6(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        require(srcIp.size == 16 && dstIp.size == 16) { "buildUdp6: alamat harus IPv6 16 byte" }
        val udpLen = 8 + payload.size
        val total = 40 + udpLen
        val buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)
        buf.put(0x60.toByte())
        buf.put(0)
        buf.put(0)
        buf.put(0)
        buf.putShort(udpLen.toShort())
        buf.put(PROTO_UDP.toByte())
        buf.put(64.toByte())
        buf.put(srcIp)
        buf.put(dstIp)
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort())
        buf.putShort(0) // checksum, filled below
        buf.put(payload)
        val out = buf.array()
        var udpSum = udpChecksum6(srcIp, dstIp, out, 40, udpLen)
        if (udpSum == 0) udpSum = 0xFFFF
        out[46] = (udpSum ushr 8).toByte()
        out[47] = (udpSum and 0xFF).toByte()
        return out
    }

    /**
     * Build an ICMPv6 echo reply for an echo request packet (the
     * full IPv6 packet, [len] bytes). Returns null when it is not
     * an echo request (type 128). Type 129 = echo reply; checksum
     * over the IPv6 pseudo-header.
     */
    fun buildIcmpv6EchoReply(request: ByteArray, len: Int): ByteArray? {
        val ip = parseIpv6Header(request, len) ?: return null
        if (ip.protocol != PROTO_ICMPV6 || ip.payloadLen < 8) return null
        if (request[40].toInt() and 0xFF != 128) return null // type 128 = echo request
        val total = 40 + ip.payloadLen
        val out = request.copyOf(total)
        // Swap source/destination.
        val src = request.copyOfRange(8, 24)
        val dst = request.copyOfRange(24, 40)
        dst.copyInto(out, 8)
        src.copyInto(out, 24)
        // ICMPv6 type 129 (echo reply), recompute checksum.
        out[40] = 129.toByte()
        out[42] = 0
        out[43] = 0
        val icmpSum = checksum6(
            out, 40, ip.payloadLen,
            out.copyOfRange(8, 24), out.copyOfRange(24, 40), PROTO_ICMPV6,
        )
        out[42] = (icmpSum ushr 8).toByte()
        out[43] = (icmpSum and 0xFF).toByte()
        return out
    }

    /** Build an IPv4 + UDP packet. */
    fun buildUdp(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)
        buf.put(0x45.toByte())
        buf.put(0)
        buf.putShort(total.toShort())
        buf.putShort(ipId())
        buf.putShort(0x4000.toShort())
        buf.put(64.toByte())
        buf.put(PROTO_UDP.toByte())
        buf.putShort(0)
        buf.putInt(srcIp)
        buf.putInt(dstIp)
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort())
        buf.putShort(0) // checksum, filled below
        buf.put(payload)
        val out = buf.array()
        val ipSum = checksum(out, 0, 20)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xFF).toByte()
        // v1.0.10: a REAL UDP checksum (pseudo-header + UDP header
        // + payload), like xray-core's tun stack (sendUDP) — v1.0.9
        // wrote 0 ("optional"). Zero is legal for IPv4, but a
        // checksum of 0 means "none", and a packet that claims none
        // is exactly the kind a strict stack drops silently — the
        // DNS reply is the first packet the app ever receives from
        // us, so it must be beyond doubt. A computed 0 is written
        // as 0xffff (0 means "no checksum").
        var udpSum = udpChecksum(srcIp, dstIp, out, 20, udpLen)
        if (udpSum == 0) udpSum = 0xFFFF
        out[26] = (udpSum ushr 8).toByte()
        out[27] = (udpSum and 0xFF).toByte()
        return out
    }

    /**
     * Build an ICMP echo reply for an echo request packet (the full
     * IPv4 packet, [len] bytes). Returns null when it is not an echo
     * request.
     */
    fun buildIcmpEchoReply(request: ByteArray, len: Int): ByteArray? {
        val ip = parseIp(request, len) ?: return null
        if (ip.protocol != PROTO_ICMP || ip.payload.size < 8) return null
        if (ip.payload[0].toInt() and 0xFF != 8) return null // type 8 = echo request
        val out = request.copyOf(len)
        // Swap source/destination.
        out[12] = request[16]
        out[13] = request[17]
        out[14] = request[18]
        out[15] = request[19]
        out[16] = request[12]
        out[17] = request[13]
        out[18] = request[14]
        out[19] = request[15]
        // ICMP type 0 (echo reply), recompute checksums.
        val ihl = (out[0].toInt() and 0x0F) * 4
        out[ihl] = 0
        out[ihl + 2] = 0
        out[ihl + 3] = 0
        val icmpSum = checksum(out, ihl, len - ihl)
        out[ihl + 2] = (icmpSum ushr 8).toByte()
        out[ihl + 3] = (icmpSum and 0xFF).toByte()
        out[10] = 0
        out[11] = 0
        val ipSum = checksum(out, 0, 20)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xFF).toByte()
        return out
    }

    /** One's-complement checksum over [len] bytes at [offset]. */
    fun checksum(data: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    /** UDP checksum: pseudo-header + UDP segment starting at [offset]. */
    fun udpChecksum(srcIp: Int, dstIp: Int, segment: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        sum += (srcIp ushr 16) and 0xFFFF
        sum += srcIp and 0xFFFF
        sum += (dstIp ushr 16) and 0xFFFF
        sum += dstIp and 0xFFFF
        sum += PROTO_UDP
        sum += len
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            sum += ((segment[i].toInt() and 0xFF) shl 8) or (segment[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (segment[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    /** TCP checksum: pseudo-header + TCP segment starting at [offset]. */
    fun tcpChecksum(srcIp: Int, dstIp: Int, segment: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        sum += (srcIp ushr 16) and 0xFFFF
        sum += srcIp and 0xFFFF
        sum += (dstIp ushr 16) and 0xFFFF
        sum += dstIp and 0xFFFF
        sum += PROTO_TCP
        sum += len
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            sum += ((segment[i].toInt() and 0xFF) shl 8) or (segment[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (segment[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    /**
     * One's-complement sum over an IPv6 pseudo-header + a segment
     * (v1.0.6, M6): src(16) + dst(16) + length(4 BE) + 3 zero bytes
     * + Next Header(1) + segment bytes at [segOff] ([segLen] bytes).
     * [src]/[dst] are the 16-byte addresses inside [packet]
     * (at [srcOff]/[dstOff]); the segment lives in the same array.
     * Returns the checksum value (already complemented).
     */
    fun checksum6(
        packet: ByteArray,
        segOff: Int,
        segLen: Int,
        src: ByteArray,
        dst: ByteArray,
        nextHeader: Int,
    ): Int {
        var sum = 0L
        fun addBytes(b: ByteArray) {
            var i = 0
            while (i + 1 < b.size) {
                sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
                i += 2
            }
            if (i < b.size) sum += (b[i].toInt() and 0xFF) shl 8
        }
        addBytes(src)
        addBytes(dst)
        sum += (segLen ushr 16) and 0xFFFF
        sum += segLen and 0xFFFF
        sum += nextHeader
        var i = segOff
        val end = segOff + segLen
        while (i + 1 < end) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (packet[i].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    /** TCP checksum over the IPv6 pseudo-header (see [checksum6]). */
    fun tcpChecksum6(srcIp: ByteArray, dstIp: ByteArray, segment: ByteArray, offset: Int, len: Int): Int =
        checksum6(segment, offset, len, srcIp, dstIp, PROTO_TCP)

    /** UDP checksum over the IPv6 pseudo-header (see [checksum6]). */
    fun udpChecksum6(srcIp: ByteArray, dstIp: ByteArray, segment: ByteArray, offset: Int, len: Int): Int =
        checksum6(segment, offset, len, srcIp, dstIp, PROTO_UDP)

    fun ipToString(ip: Int): String =
        "${ip ushr 24 and 0xFF}.${ip ushr 16 and 0xFF}.${ip ushr 8 and 0xFF}.${ip and 0xFF}"

    fun ipFromBytes(b0: Int, b1: Int, b2: Int, b3: Int): Int =
        (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3

    private var nextId = 0

    @Synchronized
    private fun ipId(): Short {
        nextId = (nextId + 1) and 0xFFFF
        return nextId.toShort()
    }
}
