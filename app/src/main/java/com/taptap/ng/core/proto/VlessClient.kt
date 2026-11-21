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
 * Mux (v1.0.5, kelompok D): bila [muxConfig] nyala, dial berbagi
 * satu koneksi fisik lewat [MuxConnection] (command Mux 0x03, header
 * TANPA port/address — lihat [Mux]); mux mati = jalur di bawah ini
 * tidak berubah sama sekali.
 */
class VlessClient(
    private val item: ProfileItem,
    /** Test seam: a pool with a fake DNS transport (default: a real pool). */
    slowDnsPool: SlowDnsSessionPool? = null,
    /** Mux config (default OFF — perilaku lama). Lihat [MuxConfig]. */
    private val muxConfig: MuxConfig = MuxConfig.DISABLED,
    /**
     * Test seam: transport ladder untuk jalur mux (pipa in-memory
     * di tes; null = [SlowDnsTransport.open] yang asli).
     */
    private val muxLadderOpener: ((ProfileItem, SpeedStats?) -> LadderStream)? = null,
) : ProxyClient {

    // v1.0.6: see VmessClient — streams stay open independently.
    private val openStreams = ConcurrentHashMap.newKeySet<ProxyStream>()

    // M3: one DNSTT session per client (see VmessClient).
    private val slowDns = slowDnsPool ?: SlowDnsSessionPool(item)

    // v1.0.5 (kelompok D): pool koneksi mux (lihat VmessClient —
    // null = mux mati atau entry SlowDNS, fail-safe OFF).
    private val muxPool: MuxConnectionPool? =
        if (muxConfig.enabled && !item.dnsttEnabled) {
            MuxConnectionPool(muxConfig.concurrency, ::openMuxConnection)
        } else {
            null
        }

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
        // v1.0.5 (kelompok D): mux ON = dial lewat pool koneksi
        // mux; mux OFF = jalur lama di bawah ini, tanpa perubahan.
        val pool = muxPool
        if (pool != null) return dialMux(pool, targetHost, targetPort, probeBody, stats)
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

    /**
     * v1.0.5 (kelompok D): dial lewat mux (lihat
     * [VmessClient.dialMux] — bentuknya sama, hanya label dan
     * header yang VLESS). Probe menunggu response header dibaca
     * thread mux; relay kembali seketika.
     */
    private fun dialMux(
        pool: MuxConnectionPool,
        targetHost: String,
        targetPort: Int,
        probeBody: ByteArray?,
        stats: SpeedStats?,
    ): ProxyStream {
        val (conn, session) = pool.openSession(targetHost, targetPort, stats)
        var headerFailed = false
        try {
            if (probeBody != null) {
                session.output.write(probeBody)
                session.output.flush()
                DialLog.log("VLESS", "probe body ${probeBody.size}B")
                val headerError = conn.awaitHeader(Transport.HANDSHAKE_TIMEOUT_MS.toLong())
                if (headerError != null) {
                    headerFailed = true
                    throw headerError
                }
                return TrackedProxyStream(
                    StreamProxyStream(session.input, session.output) { session.close() },
                    openStreams,
                )
            }
            val loggedOut = FirstWriteLoggingOutputStream(session.output) { n ->
                DialLog.log("VLESS", "body ${n}B untuk $targetHost:$targetPort")
            }
            return TrackedProxyStream(
                StreamProxyStream(session.input, loggedOut) { session.close() },
                openStreams,
            )
        } catch (e: Exception) {
            runCatching { session.close() }
            if (headerFailed) runCatching { conn.close() }
            val failure = Transport.preferWatchdogFailure(e)
            DialLog.failure("VLESS", failure)
            throw failure
        }
    }

    /**
     * v1.0.5 (kelompok D): buka satu koneksi fisik mux VLESS —
     * ladder transport + header VLESS command Mux (TANPA
     * port/address — lihat [VlessCrypto.buildRequestHeader]) +
     * [MuxConnection] di atas stream mentah. Response header dibaca
     * LAZY oleh thread pembaca mux (sama seperti VMess: server
     * baru mem-flush header sesudah data target pertama mengalir).
     */
    private fun openMuxConnection(stats: SpeedStats?): MuxConnection {
        val opener = muxLadderOpener
            ?: { it: ProfileItem, s: SpeedStats? -> SlowDnsTransport.open(it, slowDns, s) }
        val transport = opener(item, stats)
        try {
            val header = VlessCrypto.buildRequestHeader(
                item.uuid, Mux.TARGET_HOST, Mux.TARGET_PORT, VlessCrypto.CMD_MUX,
            )
            transport.output.write(header)
            transport.output.flush()
            val headerResult = MuxHeaderResult()
            val lazyIn = LazyHeaderInputStream(transport.input) {
                try {
                    Transport.noteStage("VLESS")
                    DialLog.log("VLESS", "Verifying Xray VLESS authentication & protocol stream...")
                    VlessCrypto.readResponseHeader(transport.input)
                    transport.clearHandshakeTimeout()
                    DialLog.log("VLESS", "Xray VLESS handshake & transport ready!")
                    headerResult.complete(null)
                } catch (e: java.net.SocketTimeoutException) {
                    val failure = Transport.preferWatchdogFailure(
                        java.net.SocketTimeoutException("VLESS gagal: ${e.message}"),
                    )
                    DialLog.failure("VLESS", failure)
                    headerResult.complete(failure)
                    throw failure
                } catch (e: Exception) {
                    val failure = Transport.preferWatchdogFailure(e)
                    DialLog.failure("VLESS", failure)
                    headerResult.complete(failure)
                    throw failure
                }
            }
            DialLog.log("Mux", "mux connection dibuka (max ${muxConfig.concurrency} stream)")
            return MuxConnection(
                lazyIn, transport.output,
                onClose = { transport.close() },
                maxConcurrency = muxConfig.concurrency,
                headerResult = headerResult,
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
        // v1.0.5 (kelompok D): tutup semua koneksi mux (lihat VmessClient).
        runCatching { muxPool?.close() }
        // M3: tear the DNSTT session down too (see VmessClient).
        runCatching { slowDns.close() }
    }
}

object VlessCrypto {

    const val VERSION: Byte = 0x00
    const val CMD_TCP: Byte = 0x01
    /**
     * v1.0.5 (kelompok D): command Mux (xray-core
     * common/protocol RequestCommandMux = 0x03). Header mux TIDAK
     * membawa port/address — sesudah command, langsung body (mux
     * frames); tiap session membawa targetnya di frame New.
     */
    const val CMD_MUX: Byte = 0x03

    /**
     * Request header. Command [CMD_MUX] menghilangkan port +
     * address dari header (lihat KDoc [CMD_MUX]) — [targetHost] /
     * [targetPort] diabaikan untuk mux.
     */
    fun buildRequestHeader(
        uuid: String,
        targetHost: String,
        targetPort: Int,
        command: Byte = CMD_TCP,
    ): ByteArray {
        val uuidBytes = AddrCodec.parseUuidBytes(uuid)
        val out = mutableListOf<Byte>()
        out.add(VERSION)
        out.addAll(uuidBytes.toList())
        out.add(0) // addon length
        out.add(command)
        if (command != CMD_MUX) {
            out.addAll(AddrCodec.encodeVmessTarget(targetHost, targetPort).toList())
        }
        return out.toByteArray()
    }

    /** Parse a request header back (tests). Returns UUID bytes + target (null untuk header mux). */
    data class ParsedRequest(val uuidBytes: ByteArray, val target: AddrCodec.Target?)

    fun parseRequestHeader(bytes: ByteArray): ParsedRequest {
        require(bytes.size >= 1 + 16 + 1 + 1) { "Header VLESS terlalu pendek" }
        require(bytes[0] == VERSION) { "Versi VLESS bukan 0: ${bytes[0]}" }
        val uuidBytes = bytes.copyOfRange(1, 17)
        val addonLen = bytes[17].toInt() and 0xFF
        val command = bytes[18]
        if (command == CMD_MUX) {
            // Header mux: tidak ada port/address; addon (bila ada)
            // duduk di akhir, sesudah command.
            require(19 + addonLen == bytes.size) {
                "Panjang header VLESS mux tidak konsisten"
            }
            return ParsedRequest(uuidBytes, null)
        }
        require(command == CMD_TCP) { "Command VLESS bukan TCP: $command" }
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
