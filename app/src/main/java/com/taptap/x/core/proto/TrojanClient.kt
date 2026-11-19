package com.taptap.x.core.proto

import com.taptap.x.data.ProfileItem

/**
 * Trojan client (trojan-gfw). After the (normally TLS) handshake the
 * client sends one plaintext request, then the stream is raw:
 *
 *   hex(SHA224(password)) (56 chars) | CRLF | CMD(1)=0x01 |
 *   ATYP + address + PORT (SOCKS order) | CRLF | payload...
 *
 * The hex encoding is deliberate: a raw SHA224 digest could contain
 * 0x0D 0x0A and break the CRLF framing.
 *
 * TLS: Trojan normally always runs over TLS. This client follows the
 * profile field — TLS only when item.tls is true; with tls=false the
 * request goes over plain TCP (works against plain test servers, but
 * is NOT how real Trojan deployments run — documented, not silently
 * "fixed", because the field is the user's explicit choice).
 * Transport: TCP or WS, optionally under TLS (TCP → TLS → WS).
 */
class TrojanClient(private val item: ProfileItem) : ProxyClient {

    private var stream: ProxyStream? = null

    override fun dial(targetHost: String, targetPort: Int): ProxyStream {
        close()
        val transport = Transport.open(item)
        try {
            val header = TrojanCrypto.buildRequestHeader(item.password, targetHost, targetPort)
            transport.output.write(header)
            transport.output.flush()
            transport.socket.soTimeout = 0
            val s = SocketProxyStream(transport.socket, transport.input, transport.output)
            stream = s
            return s
        } catch (e: Exception) {
            transport.close()
            throw e
        }
    }

    override fun close() {
        runCatching { stream?.close() }
        stream = null
    }
}

object TrojanCrypto {

    const val CMD_TCP: Byte = 0x01
    private val CRLF = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())

    fun passwordHashHex(password: String): String =
        AddrCodec.hexLower(Crypto.sha224(password.toByteArray(Charsets.UTF_8)))

    fun buildRequestHeader(password: String, targetHost: String, targetPort: Int): ByteArray {
        require(password.isNotEmpty()) { "Password Trojan kosong" }
        val hashHex = passwordHashHex(password).toByteArray(Charsets.UTF_8)
        return hashHex + CRLF +
            byteArrayOf(CMD_TCP) +
            AddrCodec.encodeSocksTarget(targetHost, targetPort) +
            CRLF
    }

    /** Parse a request header back (tests). Returns password hash + target. */
    data class ParsedRequest(val passwordHashHex: String, val target: AddrCodec.Target)

    fun parseRequestHeader(bytes: ByteArray): ParsedRequest {
        require(bytes.size >= 56 + 2 + 1 + 1 + 2) { "Header Trojan terlalu pendek" }
        val hashHex = String(bytes, 0, 56, Charsets.UTF_8)
        require(bytes[56] == '\r'.code.toByte() && bytes[57] == '\n'.code.toByte()) {
            "Header Trojan tanpa CRLF setelah hash"
        }
        require(bytes[58] == CMD_TCP) { "Command Trojan bukan TCP: ${bytes[58]}" }
        val (target, afterTarget) = AddrCodec.parseSocksTarget(bytes, 59)
        require(bytes.size >= afterTarget + 2 &&
            bytes[afterTarget] == '\r'.code.toByte() &&
            bytes[afterTarget + 1] == '\n'.code.toByte()) {
            "Header Trojan tanpa CRLF penutup"
        }
        return ParsedRequest(hashHex, target)
    }
}
