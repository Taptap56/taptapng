package com.taptap.x.core.proto

import com.taptap.x.core.DialLog
import com.taptap.x.data.ProfileItem
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap

/**
 * VLESS client (version 0, XTLS). No body encryption — the stream after
 * the header is raw. The header is plaintext by design (UUID on the
 * wire), so VLESS is normally run under TLS.
 *
 * Request: version(1)=0 | UUID(16) | addon length(1)=0 | command(1)=1
 *   | PORT(2 BE) | ATYP + address.
 * Response: version(1) | addon length(1) | addon bytes (usually 0),
 *   then the raw stream.
 *
 * Only encryption "none" is supported (field item.method). Anything
 * else (e.g. mlkem768...) is rejected — the post-quantum encryption
 * layer is out of scope for M2.
 * Transport: TCP or WS, optionally under TLS (TCP → TLS → WS).
 */
class VlessClient(private val item: ProfileItem) : ProxyClient {

    // v1.0.6: see VmessClient — streams stay open independently.
    private val openStreams = ConcurrentHashMap.newKeySet<ProxyStream>()

    override fun dial(targetHost: String, targetPort: Int): ProxyStream {
        val encryption = item.method.ifBlank { "none" }.lowercase()
        require(encryption == "none") {
            "VLESS encryption tidak didukung: $encryption (hanya none)"
        }
        val transport = Transport.open(item)
        try {
            val header = VlessCrypto.buildRequestHeader(item.uuid, targetHost, targetPort)
            transport.output.write(header)
            transport.output.flush()
            Transport.noteStage("VLESS")
            VlessCrypto.readResponseHeader(transport.input)
            transport.socket.soTimeout = 0
            Transport.clearWatchdogSocket()
            DialLog.log("VLESS", "handshake ok")
            return TrackedProxyStream(
                SocketProxyStream(transport.socket, transport.input, transport.output),
                openStreams,
            )
        } catch (e: Exception) {
            transport.close()
            val failure = Transport.preferWatchdogFailure(e)
            DialLog.failure("VLESS", failure)
            throw failure
        }
    }

    override fun close() {
        openStreams.toList().forEach { runCatching { it.close() } }
    }
}

object VlessCrypto {

    const val VERSION: Byte = 0x00
    const val CMD_TCP: Byte = 0x01

    fun buildRequestHeader(uuid: String, targetHost: String, targetPort: Int): ByteArray {
        val uuidBytes = AddrCodec.parseUuidBytes(uuid)
        val out = mutableListOf<Byte>()
        out.add(VERSION)
        out.addAll(uuidBytes.toList())
        out.add(0) // addon length
        out.add(CMD_TCP)
        out.addAll(AddrCodec.encodeVmessTarget(targetHost, targetPort).toList())
        return out.toByteArray()
    }

    /** Parse a request header back (tests). Returns UUID bytes + target. */
    data class ParsedRequest(val uuidBytes: ByteArray, val target: AddrCodec.Target)

    fun parseRequestHeader(bytes: ByteArray): ParsedRequest {
        require(bytes.size >= 1 + 16 + 1 + 1 + 2 + 1) { "Header VLESS terlalu pendek" }
        require(bytes[0] == VERSION) { "Versi VLESS bukan 0: ${bytes[0]}" }
        val uuidBytes = bytes.copyOfRange(1, 17)
        val addonLen = bytes[17].toInt() and 0xFF
        require(bytes[18] == CMD_TCP) { "Command VLESS bukan TCP: ${bytes[18]}" }
        // Addon (addonLen bytes) sits AFTER the address, at the end.
        val (target, afterTarget) = AddrCodec.parseVmessTarget(bytes, 19)
        require(afterTarget + addonLen == bytes.size) {
            "Panjang header VLESS tidak konsisten"
        }
        return ParsedRequest(uuidBytes, target)
    }

    /** Read the 2-byte response header (version + addon length) + addon. */
    fun readResponseHeader(input: java.io.InputStream) {
        val head = input.readExactBytes(2)
        if (head[0] != VERSION) {
            throw IOException("VLESS response version bukan 0: ${head[0]}")
        }
        val addonLen = head[1].toInt() and 0xFF
        if (addonLen > 0) input.readExactBytes(addonLen)
    }
}
