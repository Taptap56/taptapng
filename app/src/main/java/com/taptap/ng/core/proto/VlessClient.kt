package com.taptap.ng.core.proto

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.slowdns.SlowDnsSessionPool
import com.taptap.ng.core.slowdns.SlowDnsTransport
import com.taptap.ng.data.ProfileItem
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
class VlessClient(
    private val item: ProfileItem,
    /** Test seam: a pool with a fake DNS transport (default: a real pool). */
    slowDnsPool: SlowDnsSessionPool? = null,
) : ProxyClient {

    // v1.0.6: see VmessClient — streams stay open independently.
    private val openStreams = ConcurrentHashMap.newKeySet<ProxyStream>()

    // M3: one DNSTT session per client (see VmessClient).
    private val slowDns = slowDnsPool ?: SlowDnsSessionPool(item)

    override fun dial(
        targetHost: String,
        targetPort: Int,
        probeBody: ByteArray?,
        stats: SpeedStats?,
    ): ProxyStream {
        val encryption = item.method.ifBlank { "none" }.lowercase()
        require(encryption == "none") {
            "VLESS encryption tidak didukung: $encryption (hanya none)"
        }
        // M3: socket ladder or DNSTT ladder (see VmessClient).
        val transport = SlowDnsTransport.open(item, slowDns, stats)
        try {
            val header = VlessCrypto.buildRequestHeader(item.uuid, targetHost, targetPort)
            transport.output.write(header)
            transport.output.flush()
            // v1.0.8, fix B: same deadlock as VMess — the xray-core
            // VLESS server only flushes its response header once
            // data flows (EncodeResponseHeader + SetFlushNext, then
            // dispatch). The probe body unblocks it.
            if (probeBody != null) {
                transport.output.write(probeBody)
                transport.output.flush()
                DialLog.log("VLESS", "probe body ${probeBody.size}B")
                Transport.noteStage("VLESS")
                // v1.0.3 (XVEON parity): "Verifying Xray VLESS ..."
                // / "Xray VLESS handshake & transport ready!" —
                // the verify + ready lines bracket the
                // response-header read.
                DialLog.log("VLESS", "Verifying Xray VLESS authentication & protocol stream...")
                VlessCrypto.readResponseHeader(transport.input)
                transport.clearHandshakeTimeout()
                DialLog.log("VLESS", "Xray VLESS handshake & transport ready!")
                return TrackedProxyStream(
                    StreamProxyStream(transport.input, transport.output) { transport.close() },
                    openStreams,
                )
            }
            // v1.0.12: RELAY dial — same deadlock as VMess, same
            // fix. Reading the response header here waits ~10 s
            // while the app's first data — the body that unblocks
            // the server's flush — can only be sent after dial()
            // returns. Read it lazily on the first relay read
            // instead (xray-core's client runs both directions
            // concurrently); the 10 s handshake timeout still
            // bounds the lazy read, and the first body write is
            // logged so the phone log proves a body was sent.
            val lazyIn = LazyHeaderInputStream(transport.input) {
                try {
                    Transport.noteStage("VLESS")
                    // v1.0.3 (XVEON parity): same verify + ready
                    // lines as the probe branch, around the lazy
                    // read ("Verifying Xray VLESS ..." /
                    // "Xray VLESS handshake & transport ready!").
                    DialLog.log("VLESS", "Verifying Xray VLESS authentication & protocol stream...")
                    VlessCrypto.readResponseHeader(transport.input)
                } catch (e: java.net.SocketTimeoutException) {
                    val failure = Transport.preferWatchdogFailure(
                        java.net.SocketTimeoutException("VLESS gagal: ${e.message}"),
                    )
                    DialLog.failure("VLESS", failure)
                    throw failure
                } catch (e: Exception) {
                    val failure = Transport.preferWatchdogFailure(e)
                    DialLog.failure("VLESS", failure)
                    throw failure
                }
                transport.clearHandshakeTimeout()
                DialLog.log("VLESS", "Xray VLESS handshake & transport ready!")
            }
            val loggedOut = FirstWriteLoggingOutputStream(transport.output) { n ->
                DialLog.log("VLESS", "body ${n}B untuk $targetHost:$targetPort")
            }
            return TrackedProxyStream(
                StreamProxyStream(lazyIn, loggedOut) { transport.close() },
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
        // M3: tear the DNSTT session down too (see VmessClient).
        runCatching { slowDns.close() }
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
