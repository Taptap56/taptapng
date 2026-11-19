package com.taptap.x.service

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure IPv4/TCP/UDP/ICMP packet codec (no Android APIs) — covered by
 * JVM unit tests ([TcpPacketTest]). Used by [TunForwarder] to speak
 * TCP to the apps on the TUN interface while the payload travels
 * through an in-app [com.taptap.x.core.proto.ProxyClient].
 *
 * The forwarder only implements the subset of TCP it needs: SYN /
 * SYN-ACK / ACK / data / FIN / RST, no retransmission (the TUN is a
 * local reliable link), no window scaling, MSS 1460.
 */
object TcpPacket {

    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10

    const val TCP_MSS = 1460
    const val TCP_WINDOW = 65535

    data class IpPacket(val src: Int, val dst: Int, val protocol: Int, val payload: ByteArray)

    data class TcpSegment(
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val flags: Int,
        val window: Int,
        val payload: ByteArray,
    )

    data class UdpDatagram(val srcPort: Int, val dstPort: Int, val payload: ByteArray)

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
        val dataOffset = (buf.get(12).toInt() ushr 4) * 4
        if (payload.size < dataOffset) return null
        val flags = buf.get(13).toInt() and 0xFF
        val window = buf.short.toInt() and 0xFFFF
        val data = payload.copyOfRange(dataOffset, payload.size)
        return TcpSegment(srcPort, dstPort, seq, ack, flags, window, data)
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
     * (SYN-ACK only); otherwise the header is the plain 20 bytes.
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
    ): ByteArray {
        val optLen = if (mss > 0) 4 else 0
        val tcpLen = 20 + optLen + payload.size
        val total = 20 + tcpLen
        val buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)
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
        buf.putShort(TCP_WINDOW.toShort())
        buf.putShort(0) // checksum, filled below
        buf.putShort(0) // urgent pointer
        if (mss > 0) {
            buf.put(2.toByte()) // MSS kind
            buf.put(4.toByte()) // MSS length
            buf.putShort(mss.toShort())
        }
        buf.put(payload)
        val out = buf.array()
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
        buf.putShort(0) // UDP checksum optional (0 = none)
        buf.put(payload)
        val out = buf.array()
        val ipSum = checksum(out, 0, 20)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xFF).toByte()
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
