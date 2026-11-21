package com.taptap.ng.core.proto

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * UDP datagram framing shared by the M6 protocol clients
 * (v1.0.6). VMess / VLESS carry UDP as length-prefixed datagrams
 * over their (TCP) stream: each datagram is [2-byte big-endian
 * length][payload], max 65535 bytes — the same framing xray-core
 * uses for UDP over VMess/VLESS (and for mux XUDP frames, one
 * datagram per frame). Trojan has its own packet shape (see
 * [TrojanUdpPacket]); Shadowsocks UDP is one AEAD packet per
 * datagram (see [SsCrypto]).
 */
object UdpFraming {

    const val MAX_DATAGRAM = 65535

    /** Write one datagram: 2-byte length + payload. */
    fun writeDatagram(out: OutputStream, datagram: ByteArray) {
        require(datagram.isNotEmpty()) { "Datagram UDP kosong" }
        require(datagram.size <= MAX_DATAGRAM) {
            "Datagram UDP terlalu besar: ${datagram.size}"
        }
        out.write(byteArrayOf(((datagram.size ushr 8) and 0xFF).toByte(), (datagram.size and 0xFF).toByte()))
        out.write(datagram)
        out.flush()
    }

    /**
     * Read one datagram: 2-byte length + payload. Null on clean EOF
     * before the length (stream closed with no datagram in flight);
     * EOF mid-datagram throws.
     */
    fun readDatagram(input: InputStream): ByteArray? {
        val lenBytes = ByteArray(2)
        var filled = 0
        while (filled < 2) {
            val r = input.read(lenBytes, filled, 2 - filled)
            if (r == -1) {
                if (filled == 0) return null
                throw IOException("Datagram UDP terpotong (panjang)")
            }
            filled += r
        }
        val len = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        require(len > 0) { "Datagram UDP panjang 0" }
        return input.readExactBytes(len)
    }
}

/**
 * A [ProxyUdpSession] over a pair of byte streams (VMess/VLESS
 * UDP, mux XUDP): datagrams are length-prefixed on the wire (see
 * [UdpFraming]). [send] is serialised — two threads must never
 * interleave chunk writes. [receive] blocks until a datagram
 * arrives; [close] unblocks it by closing the streams (the read
 * then fails and returns null). [timeoutMs] is not honoured here
 * (see [ProxyUdpSession]); the caller evicts idle sessions by
 * closing them.
 */
class LengthPrefixedUdpSession(
    private val input: InputStream,
    private val output: OutputStream,
    private val onClose: () -> Unit,
) : ProxyUdpSession {
    private val sendLock = Any()
    private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

    override fun send(datagram: ByteArray) {
        check(!closed.get()) { "Sesi UDP sudah ditutup" }
        synchronized(sendLock) {
            UdpFraming.writeDatagram(output, datagram)
        }
    }

    override fun receive(timeoutMs: Long): ByteArray? {
        if (closed.get()) return null
        return try {
            UdpFraming.readDatagram(input)
        } catch (_: Exception) {
            null
        }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { input.close() }
            runCatching { output.close() }
            runCatching { onClose() }
        }
    }
}

/**
 * Trojan UDP packet (trojan-gfw): [SOCKS target][2-byte length]
 * [payload][CRLF]. The request header (CMD 0x03, UDP ASSOCIATE)
 * is sent once per session; every datagram after it has this
 * shape, in both directions.
 */
object TrojanUdpPacket {

    private val CRLF = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())

    fun encode(targetHost: String, targetPort: Int, payload: ByteArray): ByteArray {
        require(payload.isNotEmpty()) { "Datagram UDP kosong" }
        require(payload.size <= UdpFraming.MAX_DATAGRAM) {
            "Datagram UDP terlalu besar: ${payload.size}"
        }
        val target = AddrCodec.encodeSocksTarget(targetHost, targetPort)
        val out = ByteArray(target.size + 2 + payload.size + 2)
        target.copyInto(out, 0)
        out[target.size] = ((payload.size ushr 8) and 0xFF).toByte()
        out[target.size + 1] = (payload.size and 0xFF).toByte()
        payload.copyInto(out, target.size + 2)
        CRLF.copyInto(out, target.size + 2 + payload.size)
        return out
    }

    /** Decode one packet from a byte stream. Returns target + payload. */
    fun decode(input: InputStream): Pair<AddrCodec.Target, ByteArray> {
        val first = input.read()
        if (first == -1) throw IOException("Paket UDP Trojan terpotong (EOF)")
        val atyp = first
        // Rebuild the target bytes: atyp + address + port, then
        // parse with the shared SOCKS parser.
        val head = when (atyp) {
            0x01 -> byteArrayOf(atyp.toByte()) + input.readExactBytes(4)
            0x03 -> {
                val len = input.read()
                if (len == -1) throw IOException("Paket UDP Trojan terpotong (domain)")
                byteArrayOf(atyp.toByte(), len.toByte()) + input.readExactBytes(len)
            }
            0x04 -> byteArrayOf(atyp.toByte()) + input.readExactBytes(16)
            else -> throw IllegalArgumentException("ATYP SOCKS tidak dikenal: $atyp")
        } + input.readExactBytes(2)
        val (target, _) = AddrCodec.parseSocksTarget(head, 0)
        val lenBytes = input.readExactBytes(2)
        val len = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        val payload = input.readExactBytes(len)
        val crlf = input.readExactBytes(2)
        require(crlf[0] == '\r'.code.toByte() && crlf[1] == '\n'.code.toByte()) {
            "Paket UDP Trojan tanpa CRLF penutup"
        }
        return target to payload
    }
}
