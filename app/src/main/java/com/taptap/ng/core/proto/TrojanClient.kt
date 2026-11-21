package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import com.taptap.ng.data.ProfileItem
import java.util.concurrent.ConcurrentHashMap

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

    // v1.0.6: see VmessClient — streams stay open independently.
    private val openStreams = ConcurrentHashMap.newKeySet<ProxyStream>()

    /** v1.0.6 (M6): every UDP session this client opened (same rule). */
    private val openUdpSessions = ConcurrentHashMap.newKeySet<ProxyUdpSession>()

    override fun dial(
        targetHost: String,
        targetPort: Int,
        probeBody: ByteArray?,
        stats: SpeedStats?,
    ): ProxyStream {
        // Validate eagerly, before opening the TCP connection — like
        // VlessClient/SsClient. (Otherwise an empty password only
        // fails after a useless connect, with the wrong exception.)
        // probeBody is ignored: Trojan has no response handshake to
        // unblock — the stream is raw right after the header.
        require(item.password.isNotEmpty()) { "Password Trojan kosong" }
        val transport = Transport.open(item, stats)
        try {
            Transport.noteStage("Trojan")
            val header = TrojanCrypto.buildRequestHeader(item.password, targetHost, targetPort)
            transport.output.write(header)
            transport.output.flush()
            transport.socket.soTimeout = 0
            Transport.clearWatchdogSocket()
            // v1.0.3 (XVEON parity): "Xray Trojan handshake &
            // transport ready!" (Trojan has no response handshake
            // to verify — the stream is raw right after the
            // header — so there is no "Verifying Xray Trojan ..."
            // line, same as v1.0.2's reasoning; only the ready
            // line is renamed).
            DialLog.log("Trojan", "Xray Trojan handshake & transport ready!")
            return TrackedProxyStream(
                SocketProxyStream(transport.socket, transport.input, transport.output),
                openStreams,
            )
        } catch (e: Exception) {
            transport.close()
            val failure = Transport.preferWatchdogFailure(e)
            DialLog.failure("Trojan", failure)
            throw failure
        }
    }

    /**
     * v1.0.6 (M6): UDP over Trojan. Command UDP ASSOCIATE (0x03);
     * each datagram is a [TrojanUdpPacket] (SOCKS target + length
     * + payload + CRLF) over the raw stream. No response header —
     * the stream is datagrams right after the request header.
     */
    override fun dialUdp(
        targetHost: String,
        targetPort: Int,
        stats: SpeedStats?,
    ): ProxyUdpSession {
        require(item.password.isNotEmpty()) { "Password Trojan kosong" }
        val transport = Transport.open(item, stats)
        try {
            Transport.noteStage("Trojan")
            val header = TrojanCrypto.buildRequestHeader(
                item.password, targetHost, targetPort, TrojanCrypto.CMD_UDP,
            )
            transport.output.write(header)
            transport.output.flush()
            transport.socket.soTimeout = 0
            Transport.clearWatchdogSocket()
            DialLog.log("Trojan", "Xray Trojan handshake & transport ready!")
            DialLog.log("Trojan", "UDP $targetHost:$targetPort")
            return TrackedProxyUdpSession(
                TrojanUdpSession(transport.input, transport.output, targetHost, targetPort) {
                    transport.close()
                },
                openUdpSessions,
            )
        } catch (e: Exception) {
            transport.close()
            val failure = Transport.preferWatchdogFailure(e)
            DialLog.failure("Trojan", failure)
            throw failure
        }
    }

    override fun close() {
        openUdpSessions.toList().forEach { runCatching { it.close() } }
        openStreams.toList().forEach { runCatching { it.close() } }
    }
}

/**
 * One Trojan UDP session over a raw stream (v1.0.6, M6). [send]
 * encodes one [TrojanUdpPacket]; [receive] decodes one (the
 * target in the reply is ignored — the session's target is fixed).
 * Blocking read; [close] unblocks it by closing the streams.
 */
class TrojanUdpSession(
    private val input: java.io.InputStream,
    private val output: java.io.OutputStream,
    private val targetHost: String,
    private val targetPort: Int,
    private val onClose: () -> Unit,
) : ProxyUdpSession {
    private val sendLock = Any()
    private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

    override fun send(datagram: ByteArray) {
        check(!closed.get()) { "Sesi UDP sudah ditutup" }
        synchronized(sendLock) {
            output.write(TrojanUdpPacket.encode(targetHost, targetPort, datagram))
            output.flush()
        }
    }

    override fun receive(timeoutMs: Long): ByteArray? {
        if (closed.get()) return null
        return try {
            TrojanUdpPacket.decode(input).second
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

object TrojanCrypto {

    const val CMD_TCP: Byte = 0x01
    /**
     * v1.0.6 (M6): command UDP ASSOCIATE (trojan-gfw UDP = 0x03).
     */
    const val CMD_UDP: Byte = 0x03
    private val CRLF = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())

    fun passwordHashHex(password: String): String =
        AddrCodec.hexLower(Crypto.sha224(password.toByteArray(Charsets.UTF_8)))

    fun buildRequestHeader(
        password: String,
        targetHost: String,
        targetPort: Int,
        command: Byte = CMD_TCP,
    ): ByteArray {
        require(password.isNotEmpty()) { "Password Trojan kosong" }
        val hashHex = passwordHashHex(password).toByteArray(Charsets.UTF_8)
        return hashHex + CRLF +
            byteArrayOf(command) +
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
        require(bytes[58] == CMD_TCP || bytes[58] == CMD_UDP) {
            "Command Trojan bukan TCP/UDP: ${bytes[58]}"
        }
        val (target, afterTarget) = AddrCodec.parseSocksTarget(bytes, 59)
        require(bytes.size >= afterTarget + 2 &&
            bytes[afterTarget] == '\r'.code.toByte() &&
            bytes[afterTarget + 1] == '\n'.code.toByte()) {
            "Header Trojan tanpa CRLF penutup"
        }
        return ParsedRequest(hashHex, target)
    }
}
