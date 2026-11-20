package com.taptap.x.core.proto

import com.taptap.x.core.DialLog
import com.taptap.x.core.slowdns.SlowDnsSessionPool
import com.taptap.x.core.slowdns.SlowDnsTransport
import com.taptap.x.data.ProfileItem
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.AEADBadTagException

/**
 * VMess client — current AEAD design (Xray-core, alterId = 0), per the
 * v2fly protocol spec. No legacy MD5/CFB header, no alterId.
 *
 * Wire, request:
 *   AuthID (16) | AEAD(header length, 18) | connection nonce (8) |
 *   AEAD(logical header) | masked body chunks
 * - CmdKey = MD5(UUID bytes + "c48619fe-8f02-49e0-b9e9-edf763e17e21").
 * - AuthID = AES-128-ECB(KDF(CmdKey,"AES Auth ID Encryption")[:16],
 *   timestamp(8 BE) || random(4) || CRC32(first 12)(4 BE)).
 * - Header length/header are AES-128-GCM with KDF-derived key/nonce
 *   (paths "VMess Header AEAD Key[_Length]"/"VMess Header AEAD
 *   Nonce[_Length]", inputs CmdKey + AuthID + connection nonce),
 *   AAD = AuthID.
 * - Logical header: version(1) | body IV(16) | body key(16) |
 *   response V(1) | option(1) | padding-len(4b) + security(4b) |
 *   reserved(1) | command(1) | PORT(2 BE) + ATYP + address |
 *   random padding | FNV-1a(4 BE).
 * - Body security: 0x03 AES-128-GCM, 0x04 ChaCha20-Poly1305,
 *   0x06 Zero ("none" — raw stream, no chunking). "auto" = AES-128-GCM.
 * - Body chunks (AEAD modes): 2-byte size XOR-masked with a SHAKE128
 *   stream seeded by the body IV (padding length consumed FIRST, then
 *   the size mask — same order on both directions), then AEAD
 *   ciphertext (payload + 16-byte tag), then 0..63 clear padding
 *   bytes. Chunk nonce = 2-byte big-endian counter || body IV[2:12].
 *   An empty decrypted chunk is the end-of-stream signal; close()
 *   sends one.
 * - Response header: AEAD length (18) + AEAD header, keys from
 *   KDF(SHA256(body key/IV)[:16], "AEAD Resp Header ..."), no AAD.
 *   response V must match the request's.
 * - Response body key/IV = SHA256(request body key/IV)[:16].
 *
 * Transport: TCP or WS, optionally under TLS (TCP → TLS → WS).
 * Only TCP command (0x01) is supported; no Mux, no UDP.
 */
class VmessClient(
    private val item: ProfileItem,
    /** Test seam: a pool with a fake DNS transport (default: a real pool). */
    slowDnsPool: SlowDnsSessionPool? = null,
) : ProxyClient {

    // v1.0.6: every stream this client opened, so close() can close
    // them all — but a new dial NEVER closes the previous stream
    // (the old single `stream` field + leading close() killed the
    // first session whenever two apps dialled at once).
    private val openStreams = ConcurrentHashMap.newKeySet<ProxyStream>()

    // M3: one DNSTT session per client, shared by the probe + all
    // forwarder dials (see SlowDnsSessionPool). Unused when the
    // entry is not a SlowDNS entry.
    private val slowDns = slowDnsPool ?: SlowDnsSessionPool(item)

    override fun dial(
        targetHost: String,
        targetPort: Int,
        probeBody: ByteArray?,
        stats: SpeedStats? = null,
    ): ProxyStream {
        // M3: the ladder is a socket (TCP → TLS → WS) for a plain
        // entry, or a DNSTT smux stream (→ TLS → WS) for a SlowDNS
        // entry. Everything below is identical for both.
        val transport = SlowDnsTransport.open(item, slowDns, stats)
        try {
            val session = VmessCrypto.newSession(item, targetHost, targetPort)
            transport.output.write(session.requestBytes)
            transport.output.flush()
            // v1.0.8, fix B: the probe body goes out BEFORE the
            // response header is read. The xray-core server only
            // flushes its response header once data flows from the
            // dispatch target; without a body the probe deadlocks
            // into a 10 s read timeout. The body writer is created
            // here (not after the handshake) so the probe chunk
            // uses the same mask/nonce sequence as the relay that
            // follows — one stream, one state.
            // v1.0.12: on a RELAY dial the first chunk is the app's
            // own first data — log it ("VMess body 512B untuk ...")
            // so the phone log proves a body was sent. On a probe
            // dial the probe body already has its own line.
            val bodyOut = VmessBodyOutputStream(
                transport.output,
                session,
                onFirstChunk = if (probeBody == null) {
                    { n -> DialLog.log("VMess", "body ${n}B untuk $targetHost:$targetPort") }
                } else {
                    null
                },
                stats = stats,
            )
            if (probeBody != null) {
                bodyOut.write(probeBody)
                bodyOut.flush()
                DialLog.log("VMess", "probe body ${probeBody.size}B")
                // Fail fast: the server answers with its response header
                // right after dispatching; a bad UUID/header dies here.
                Transport.noteStage("VMess")
                VmessCrypto.readResponseHeader(transport.input, session)
                val bodyIn = VmessBodyInputStream(transport.input, session, stats = stats)
                transport.clearHandshakeTimeout()
                DialLog.log("VMess", "handshake ok")
                return TrackedProxyStream(
                    StreamProxyStream(bodyIn, bodyOut) { transport.close() },
                    openStreams,
                )
            }
            // v1.0.12: RELAY dial — the response header is read
            // LAZILY, on the relay thread's first read, NOT here.
            // The server holds the header in its BufferedWriter
            // until the app's first data reaches the target
            // (inbound.go transferResponse reads link.Reader first);
            // reading it here deadlocks: the forwarder only sends
            // the SYN-ACK — and the app only sends its data — after
            // dial() returns (taptapx-7.txt: 100% of forwarder
            // dials died at "VMess gagal: Read timed out", zero
            // "DIAL ... ok"). xray-core's client runs both
            // directions concurrently (outbound.go:
            // task.Run(requestDone, responseDone)) — the body write
            // and the header read are independent. The socket's 10 s
            // handshake timeout still bounds the lazy read; the hook
            // clears it once the header arrives, and a bad
            // UUID/header surfaces on the first read instead.
            val bodyIn = VmessBodyInputStream(transport.input, session, stats = stats)
            val lazyIn = LazyHeaderInputStream(bodyIn) {
                try {
                    Transport.noteStage("VMess")
                    VmessCrypto.readResponseHeader(transport.input, session)
                } catch (e: java.net.SocketTimeoutException) {
                    val failure = Transport.preferWatchdogFailure(
                        java.net.SocketTimeoutException("VMess gagal: ${e.message}"),
                    )
                    DialLog.failure("VMess", failure)
                    throw failure
                } catch (e: Exception) {
                    val failure = Transport.preferWatchdogFailure(e)
                    DialLog.failure("VMess", failure)
                    throw failure
                }
                transport.clearHandshakeTimeout()
                DialLog.log("VMess", "handshake ok")
            }
            return TrackedProxyStream(
                StreamProxyStream(lazyIn, bodyOut) { transport.close() },
                openStreams,
            )
        } catch (e: java.net.SocketTimeoutException) {
            // v1.0.5: tag the VMess stage — the dial got through
            // TCP/TLS/WS but the server never answered the VMess
            // header. The type stays a timeout, so
            // TunForwarder.dialFailureReason still maps it, now
            // with the stage tag in the message.
            transport.close()
            val failure = Transport.preferWatchdogFailure(
                java.net.SocketTimeoutException("VMess gagal: ${e.message}"),
            )
            DialLog.failure("VMess", failure)
            throw failure
        } catch (e: Exception) {
            transport.close()
            val failure = Transport.preferWatchdogFailure(e)
            DialLog.failure("VMess", failure)
            throw failure
        }
    }

    override fun close() {
        openStreams.toList().forEach { runCatching { it.close() } }
        // M3: tear the DNSTT session down too (stops the KCP/DNS
        // loops; a leaked session would keep polling the resolver).
        runCatching { slowDns.close() }
    }
}

enum class VmessSecurity(val nibble: Int) {
    AES_128_GCM(0x03),
    CHACHA20_POLY1305(0x04),
    NONE(0x06),
}

data class VmessSession(
    val requestBytes: ByteArray,
    val bodyKey: ByteArray,
    val bodyIV: ByteArray,
    val responseBodyKey: ByteArray,
    val responseBodyIV: ByteArray,
    val responseV: Byte,
    val security: VmessSecurity,
)

data class ParsedLogicalHeader(
    val bodyIV: ByteArray,
    val bodyKey: ByteArray,
    val responseV: Byte,
    val option: Int,
    val security: VmessSecurity,
    val command: Int,
    val target: AddrCodec.Target,
)

object VmessCrypto {

    const val VERSION: Byte = 0x01
    const val CMD_TCP: Byte = 0x01
    /**
     * Max plaintext per body chunk (v1.0.15: 16 KiB, was 8 KiB).
     * The xray-core server's ChunkStreamReader reads whatever
     * 2-byte size the peer sends (ReadAtMost(size), no upper-bound
     * check — only the server's own WRITER slices at 8192), so a
     * 16 KiB chunk is wire-legal and halves the AEAD ops per byte
     * on the upload direction. The download direction is still
     * chunked at 8 KiB by the server; the reader already accepts
     * any size. 16 KiB also matches the WS frame payload cap, so
     * one chunk is (almost) one WS frame.
     */
    const val MAX_CHUNK_PLAINTEXT = 16384
    const val TAG_LEN = 16

    private const val CMD_KEY_MAGIC = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

    /** Option bits: chunk stream (0x01) + masking (0x04) + global padding (0x08). */
    const val OPTION_AEAD: Int = 0x01 or 0x04 or 0x08

    fun resolveSecurity(security: String): VmessSecurity = when (security.lowercase()) {
        "auto", "aes-128-gcm" -> VmessSecurity.AES_128_GCM
        "chacha20-poly1305" -> VmessSecurity.CHACHA20_POLY1305
        "none" -> VmessSecurity.NONE
        else -> throw IllegalArgumentException("security VMess tidak dikenal: $security")
    }

    fun cmdKey(uuid: String): ByteArray =
        Crypto.md5(AddrCodec.parseUuidBytes(uuid) + CMD_KEY_MAGIC.toByteArray(Charsets.UTF_8))

    /** AuthID plaintext: timestamp(8 BE) || random(4) || CRC32(first 12)(4 BE). */
    fun createAuthId(cmdKey: ByteArray, timestampSec: Long, random4: ByteArray): ByteArray {
        require(random4.size == 4) { "AuthID random harus 4 byte" }
        val plain = ByteArray(16)
        for (i in 0 until 8) {
            plain[i] = ((timestampSec ushr (56 - 8 * i)) and 0xFF).toByte()
        }
        random4.copyInto(plain, 8)
        val crc = Crypto.crc32Ieee(plain.copyOfRange(0, 12))
        for (i in 0 until 4) {
            plain[12 + i] = ((crc ushr (24 - 8 * i)) and 0xFF).toByte()
        }
        val key = Crypto.kdf16(cmdKey, "AES Auth ID Encryption".toByteArray(Charsets.UTF_8))
        return Crypto.aesEcbEncrypt(key, plain)
    }

    fun createAuthId(cmdKey: ByteArray): ByteArray =
        createAuthId(cmdKey, System.currentTimeMillis() / 1000, Crypto.randomBytes(4))

    /** Logical (plaintext) request header, including the FNV-1a checksum. */
    fun buildLogicalHeader(
        bodyKey: ByteArray,
        bodyIV: ByteArray,
        responseV: Byte,
        security: VmessSecurity,
        targetHost: String,
        targetPort: Int,
    ): ByteArray {
        require(bodyKey.size == 16 && bodyIV.size == 16) { "Body key/IV VMess harus 16 byte" }
        val option = if (security == VmessSecurity.NONE) 0 else OPTION_AEAD
        val paddingLen = Crypto.randomBytes(1)[0].toInt() and 0x0F
        val out = mutableListOf<Byte>()
        fun add(b: Byte) = out.add(b)
        fun addAll(bs: ByteArray) = out.addAll(bs.toList())
        add(VERSION)
        addAll(bodyIV)
        addAll(bodyKey)
        add(responseV)
        add(option.toByte())
        add((((paddingLen shl 4) or security.nibble) and 0xFF).toByte())
        add(0) // reserved
        add(CMD_TCP)
        addAll(AddrCodec.encodeVmessTarget(targetHost, targetPort))
        if (paddingLen > 0) addAll(Crypto.randomBytes(paddingLen))
        val bytes = out.toByteArray()
        val fnv = Crypto.fnv1a32(bytes)
        val result = bytes + ByteArray(4) { i -> ((fnv ushr (24 - 8 * i)) and 0xFF).toByte() }
        return result
    }

    /** Parse + verify a logical header (checksum + version). Used by tests. */
    fun parseLogicalHeader(bytes: ByteArray): ParsedLogicalHeader {
        require(bytes.size >= 38 + 4) { "Logical header VMess terlalu pendek: ${bytes.size}" }
        val fnvRead = ((bytes[bytes.size - 4].toInt() and 0xFF) shl 24) or
            ((bytes[bytes.size - 3].toInt() and 0xFF) shl 16) or
            ((bytes[bytes.size - 2].toInt() and 0xFF) shl 8) or
            (bytes[bytes.size - 1].toInt() and 0xFF)
        val fnvCalc = Crypto.fnv1a32(bytes.copyOfRange(0, bytes.size - 4))
        if (fnvRead != fnvCalc) {
            throw IllegalArgumentException("Checksum FNV logical header VMess tidak cocok")
        }
        require(bytes[0] == VERSION) { "Versi VMess bukan 1: ${bytes[0]}" }
        val bodyIV = bytes.copyOfRange(1, 17)
        val bodyKey = bytes.copyOfRange(17, 33)
        val responseV = bytes[33]
        val option = bytes[34].toInt() and 0xFF
        val pSec = bytes[35].toInt() and 0xFF
        val paddingLen = (pSec ushr 4) and 0x0F
        val security = when (pSec and 0x0F) {
            0x03 -> VmessSecurity.AES_128_GCM
            0x04 -> VmessSecurity.CHACHA20_POLY1305
            0x05, 0x06 -> VmessSecurity.NONE
            else -> throw IllegalArgumentException("Security VMess tidak dikenal: ${pSec and 0x0F}")
        }
        require(bytes[36] == 0.toByte()) { "Reserved byte VMess bukan 0" }
        val command = bytes[37].toInt() and 0xFF
        val (target, afterAddr) = AddrCodec.parseVmessTarget(bytes, 38)
        require(afterAddr + paddingLen + 4 == bytes.size) {
            "Panjang logical header VMess tidak konsisten"
        }
        return ParsedLogicalHeader(bodyIV, bodyKey, responseV, option, security, command, target)
    }

    fun newSession(item: ProfileItem, targetHost: String, targetPort: Int): VmessSession {
        val security = resolveSecurity(item.security.ifBlank { "auto" })
        val key = cmdKey(item.uuid)
        val bodyKey = Crypto.randomBytes(16)
        val bodyIV = Crypto.randomBytes(16)
        val responseV = Crypto.randomBytes(1)[0]
        val logical = buildLogicalHeader(bodyKey, bodyIV, responseV, security, targetHost, targetPort)
        val authId = createAuthId(key)
        val nonce = Crypto.randomBytes(8)
        val lenKey = Crypto.kdf16(
            key, "VMess Header AEAD Key_Length".toByteArray(Charsets.UTF_8), authId, nonce,
        )
        val lenNonce = Crypto.kdf12(
            key, "VMess Header AEAD Nonce_Length".toByteArray(Charsets.UTF_8), authId, nonce,
        )
        val lenPlain = byteArrayOf(((logical.size ushr 8) and 0xFF).toByte(), (logical.size and 0xFF).toByte())
        val encLen = Crypto.aesGcmSeal(lenKey, lenNonce, lenPlain, authId)
        val payKey = Crypto.kdf16(
            key, "VMess Header AEAD Key".toByteArray(Charsets.UTF_8), authId, nonce,
        )
        val payNonce = Crypto.kdf12(
            key, "VMess Header AEAD Nonce".toByteArray(Charsets.UTF_8), authId, nonce,
        )
        val encHeader = Crypto.aesGcmSeal(payKey, payNonce, logical, authId)
        val requestBytes = authId + encLen + nonce + encHeader
        val responseBodyKey = Crypto.sha256(bodyKey).copyOfRange(0, 16)
        val responseBodyIV = Crypto.sha256(bodyIV).copyOfRange(0, 16)
        return VmessSession(
            requestBytes, bodyKey, bodyIV,
            responseBodyKey, responseBodyIV, responseV, security,
        )
    }

    /** ChaCha20-Poly1305 wants a 32-byte key: MD5(seed) || MD5(MD5(seed)). */
    fun expandChaChaKey(seed16: ByteArray): ByteArray {
        require(seed16.size == 16) { "Seed ChaCha VMess harus 16 byte" }
        val first = Crypto.md5(seed16)
        val second = Crypto.md5(first)
        return first + second
    }

    /** 12-byte chunk nonce: 2-byte big-endian counter || body IV[2:12]. */
    class ChunkNonce(private val iv16: ByteArray) {
        private var counter = 0
        fun next(): ByteArray {
            val nonce = ByteArray(12)
            nonce[0] = ((counter ushr 8) and 0xFF).toByte()
            nonce[1] = (counter and 0xFF).toByte()
            iv16.copyInto(nonce, 2, 2, 12)
            counter = (counter + 1) and 0xFFFF
            return nonce
        }
    }

    fun sealBodyChunk(
        security: VmessSecurity,
        bodyKey: ByteArray,
        nonce12: ByteArray,
        plaintext: ByteArray,
    ): ByteArray = when (security) {
        VmessSecurity.AES_128_GCM -> Crypto.aesGcmSeal(bodyKey, nonce12, plaintext, null)
        VmessSecurity.CHACHA20_POLY1305 ->
            ChaCha20Poly1305(expandChaChaKey(bodyKey)).seal(nonce12, plaintext, null)
        VmessSecurity.NONE -> plaintext
    }

    fun openBodyChunk(
        security: VmessSecurity,
        bodyKey: ByteArray,
        nonce12: ByteArray,
        sealed: ByteArray,
    ): ByteArray = when (security) {
        VmessSecurity.AES_128_GCM -> Crypto.aesGcmOpen(bodyKey, nonce12, sealed, null)
        VmessSecurity.CHACHA20_POLY1305 ->
            ChaCha20Poly1305(expandChaChaKey(bodyKey)).open(nonce12, sealed, null)
        VmessSecurity.NONE -> sealed
    }

    /**
     * Read + verify the AEAD response header. Returns the raw decrypted
     * header bytes (V | option | command | command length | content).
     */
    fun readResponseHeader(input: InputStream, session: VmessSession): ByteArray {
        val encLen = input.readExactBytes(18)
        val lenKey = Crypto.kdf16(
            session.responseBodyKey, "AEAD Resp Header Len Key".toByteArray(Charsets.UTF_8),
        )
        val lenNonce = Crypto.kdf12(
            session.responseBodyIV, "AEAD Resp Header Len IV".toByteArray(Charsets.UTF_8),
        )
        val lenPlain = try {
            Crypto.aesGcmOpen(lenKey, lenNonce, encLen, null)
        } catch (e: AEADBadTagException) {
            throw IOException("VMess response length gagal diverifikasi (UUID salah?)", e)
        }
        val rLen = ((lenPlain[0].toInt() and 0xFF) shl 8) or (lenPlain[1].toInt() and 0xFF)
        require(rLen in 4..1024) { "Panjang response header VMess tidak wajar: $rLen" }
        val encHeader = input.readExactBytes(rLen + TAG_LEN)
        val payKey = Crypto.kdf16(
            session.responseBodyKey, "AEAD Resp Header Key".toByteArray(Charsets.UTF_8),
        )
        val payNonce = Crypto.kdf12(
            session.responseBodyIV, "AEAD Resp Header IV".toByteArray(Charsets.UTF_8),
        )
        val header = try {
            Crypto.aesGcmOpen(payKey, payNonce, encHeader, null)
        } catch (e: AEADBadTagException) {
            throw IOException("VMess response header gagal diverifikasi", e)
        }
        if (header[0] != session.responseV) {
            throw IOException("VMess response_v tidak cocok (bukan sesi ini)")
        }
        return header
    }

    /**
     * Server-side open of a sealed request header (used by the fake server
     * in tests, and handy for debugging captures). Reads authID + sealed
     * length + nonce + sealed header from [input] and returns the parsed
     * logical header plus the raw authID/nonce.
     */
    data class OpenedRequest(val authId: ByteArray, val nonce: ByteArray, val header: ParsedLogicalHeader)

    fun openRequestHeader(cmdKey: ByteArray, input: InputStream): OpenedRequest {
        val authId = input.readExactBytes(16)
        val encLen = input.readExactBytes(18)
        val nonce = input.readExactBytes(8)
        val lenKey = Crypto.kdf16(
            cmdKey, "VMess Header AEAD Key_Length".toByteArray(Charsets.UTF_8), authId, nonce,
        )
        val lenNonce = Crypto.kdf12(
            cmdKey, "VMess Header AEAD Nonce_Length".toByteArray(Charsets.UTF_8), authId, nonce,
        )
        val lenPlain = Crypto.aesGcmOpen(lenKey, lenNonce, encLen, authId)
        val hLen = ((lenPlain[0].toInt() and 0xFF) shl 8) or (lenPlain[1].toInt() and 0xFF)
        require(hLen in 38..1024) { "Panjang logical header VMess tidak wajar: $hLen" }
        val encHeader = input.readExactBytes(hLen + TAG_LEN)
        val payKey = Crypto.kdf16(
            cmdKey, "VMess Header AEAD Key".toByteArray(Charsets.UTF_8), authId, nonce,
        )
        val payNonce = Crypto.kdf12(
            cmdKey, "VMess Header AEAD Nonce".toByteArray(Charsets.UTF_8), authId, nonce,
        )
        val logical = Crypto.aesGcmOpen(payKey, payNonce, encHeader, authId)
        return OpenedRequest(authId, nonce, parseLogicalHeader(logical))
    }

    /** Seal a response header (server side, used by the fake server in tests). */
    fun sealResponseHeader(session: VmessSession, responseV: Byte, command: Int = 0): ByteArray {
        val plain = byteArrayOf(responseV, 0, command.toByte(), 0)
        val lenKey = Crypto.kdf16(
            session.responseBodyKey, "AEAD Resp Header Len Key".toByteArray(Charsets.UTF_8),
        )
        val lenNonce = Crypto.kdf12(
            session.responseBodyIV, "AEAD Resp Header Len IV".toByteArray(Charsets.UTF_8),
        )
        val lenPlain = byteArrayOf(0, plain.size.toByte())
        val encLen = Crypto.aesGcmSeal(lenKey, lenNonce, lenPlain, null)
        val payKey = Crypto.kdf16(
            session.responseBodyKey, "AEAD Resp Header Key".toByteArray(Charsets.UTF_8),
        )
        val payNonce = Crypto.kdf12(
            session.responseBodyIV, "AEAD Resp Header IV".toByteArray(Charsets.UTF_8),
        )
        val encHeader = Crypto.aesGcmSeal(payKey, payNonce, plain, null)
        return encLen + encHeader
    }
}

/** VMess request body writer: buffers up to 8 KiB, emits masked AEAD chunks. */
class VmessBodyOutputStream(
    private val rawOut: OutputStream,
    private val session: VmessSession,
    /**
     * v1.0.12: called once with the plaintext size of the first
     * non-empty chunk — the relay's proof that the app's first data
     * went out as the body. Null on probe dials (the probe body
     * already has its own log line). The empty termination chunk
     * never fires it.
     */
    private val onFirstChunk: ((Int) -> Unit)? = null,
    /**
     * v1.0.16: per-connection speed stats (null = off). The seal
     * time of every chunk is timed into [SpeedStats.upVmessNs].
     */
    private val stats: SpeedStats? = null,
    /**
     * M3: the key/IV pair that masks + seals the chunks. Default is
     * the REQUEST pair (bodyKey/bodyIV) — the client writing the
     * request body. A server writing the RESPONSE body passes the
     * response pair (responseBodyKey/responseBodyIV).
     */
    private val key: ByteArray = session.bodyKey,
    private val iv: ByteArray = session.bodyIV,
) : OutputStream() {

    private val mask = Shake128(iv)
    private val nonce = VmessCrypto.ChunkNonce(iv)
    /**
     * v1.0.15: the pending bytes live in a reusable ByteArray, not
     * a MutableList<Byte> — the old list boxed EVERY byte into a
     * Byte object (1460 allocations per app segment, plus list
     * growth), the single worst allocation hotspot on the upload
     * path. Same chunking semantics, zero boxing: write() copies
     * into the buffer, flushChunk() copies it out once.
     */
    private val pendingBuf = ByteArray(VmessCrypto.MAX_CHUNK_PLAINTEXT)
    private var pendingLen = 0
    private var closed = false
    private val firstChunkLogged = java.util.concurrent.atomic.AtomicBoolean(false)
    /**
     * v1.0.13, fix A3: the first non-empty chunk was emitted by the
     * caller through flush() — the flush was load-bearing and
     * invisible. If a future change batches writes, the first chunk
     * sits in `pending`, the server never flushes its response
     * header, and the v1.0.12 deadlock returns silently. The first
     * chunk now goes out on write() itself (XVEON's Ly8 has no
     * buffer at all: every write() is one sealed chunk).
     */
    private val firstChunkEmitted = java.util.concurrent.atomic.AtomicBoolean(false)

    override fun write(b: Int) = write(byteArrayOf(b.toByte()))

    override fun write(b: ByteArray, off: Int, len: Int) {
        check(!closed) { "VMess body stream sudah ditutup" }
        var pos = off
        var remaining = len
        while (remaining > 0) {
            val take = minOf(VmessCrypto.MAX_CHUNK_PLAINTEXT - pendingLen, remaining)
            b.copyInto(pendingBuf, pendingLen, pos, pos + take)
            pendingLen += take
            pos += take
            remaining -= take
            if (pendingLen >= VmessCrypto.MAX_CHUNK_PLAINTEXT) flushChunk()
        }
        // First non-empty chunk: emit NOW, unbuffered — never wait
        // for a flush() the caller might forget.
        if (len > 0 && firstChunkEmitted.compareAndSet(false, true)) {
            flushChunk()
        }
    }

    override fun flush() {
        if (pendingLen > 0) flushChunk()
        rawOut.flush()
    }

    private fun flushChunk() {
        if (pendingLen == 0) return
        val data = pendingBuf.copyOf(pendingLen)
        pendingLen = 0
        writeChunk(data)
    }

    /**
     * One chunk: [masked size (2B)] [AEAD(data)] [clear padding].
     * Padding length is pulled from the Shake stream FIRST, then the
     * size mask — the reader must consume them in the same order.
     */
    fun writeChunk(data: ByteArray) {
        if (data.isNotEmpty() && firstChunkLogged.compareAndSet(false, true)) {
            onFirstChunk?.invoke(data.size)
        }
        if (session.security == VmessSecurity.NONE) {
            rawOut.write(data)
            return
        }
        val paddingLen = mask.nextPaddingLen()
        // v1.0.16: time the AEAD seal (upload side). One nanoTime
        // pair per chunk, only when stats is on.
        val t0 = if (stats != null) System.nanoTime() else 0L
        val sealed = VmessCrypto.sealBodyChunk(
            session.security, key, nonce.next(), data,
        )
        if (stats != null) stats.upVmessNs.addAndGet(System.nanoTime() - t0)
        val total = sealed.size + paddingLen
        val maskedSize = total xor mask.nextUint16()
        rawOut.write(byteArrayOf(((maskedSize ushr 8) and 0xFF).toByte(), (maskedSize and 0xFF).toByte()))
        rawOut.write(sealed)
        if (paddingLen > 0) rawOut.write(Crypto.randomBytes(paddingLen))
    }

    /**
     * Close: flush pending data, then send the empty termination chunk
     * (AEAD tag only + padding). Does NOT close the underlying stream.
     */
    override fun close() {
        if (closed) return
        closed = true
        runCatching {
            flushChunk()
            if (session.security != VmessSecurity.NONE) writeChunk(ByteArray(0))
            rawOut.flush()
        }
    }
}

/** VMess response body reader: unmasks sizes, verifies AEAD, strips padding. */
class VmessBodyInputStream(
    private val rawIn: InputStream,
    private val session: VmessSession,
    /**
     * v1.0.16: per-connection speed stats (null = off). The AEAD
     * open time of every chunk is timed into [SpeedStats.vmessNs];
     * the rawIn read time is timed by the layers below (WS /
     * TimedInputStream), never here — timing it here too would
     * double-count it.
     */
    private val stats: SpeedStats? = null,
    /**
     * M3: the key/IV pair that unmasks + opens the chunks. Default
     * is the RESPONSE pair (responseBodyKey/responseBodyIV) — the
     * client reading the response body. A server reading the REQUEST
     * body passes the request pair (bodyKey/bodyIV).
     */
    private val key: ByteArray = session.responseBodyKey,
    private val iv: ByteArray = session.responseBodyIV,
) : InputStream() {

    private val mask = Shake128(iv)
    private val nonce = VmessCrypto.ChunkNonce(iv)
    private var chunkBuf: ByteArray = ByteArray(0)
    private var chunkPos = 0
    private var eof = false
    private var closed = false

    /** Next decrypted chunk, or null on the empty termination chunk / EOF. */
    private fun readChunk(): ByteArray? {
        if (session.security == VmessSecurity.NONE) return null // raw passthrough
        val maskedBytes = rawIn.readExactBytes(2)
        val maskedSize = ((maskedBytes[0].toInt() and 0xFF) shl 8) or
            (maskedBytes[1].toInt() and 0xFF)
        // Same consumption order as the writer: padding first, size second.
        val paddingLen = mask.nextPaddingLen()
        val size = maskedSize xor mask.nextUint16()
        if (size < VmessCrypto.TAG_LEN + paddingLen) {
            throw IOException("VMess chunk size tidak valid: $size")
        }
        val wire = rawIn.readExactBytes(size)
        val sealed = wire.copyOfRange(0, size - paddingLen)
        // Response direction: response body key (SHA256 of request key).
        val plain = try {
            // v1.0.16: time the AEAD open only — the rawIn reads
            // above are timed by the WS / transport layers below.
            val t0 = if (stats != null) System.nanoTime() else 0L
            val p = VmessCrypto.openBodyChunk(session.security, key, nonce.next(), sealed)
            stats?.let {
                it.vmessNs.addAndGet(System.nanoTime() - t0)
                it.vmessChunks.incrementAndGet()
            }
            p
        } catch (e: AEADBadTagException) {
            throw IOException("VMess body chunk gagal diverifikasi", e)
        }
        if (plain.isEmpty()) return null // termination chunk
        return plain
    }

    override fun read(): Int {
        val b = ByteArray(1)
        return if (read(b, 0, 1) == -1) -1 else b[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (closed || eof) return -1
        if (session.security == VmessSecurity.NONE) {
            return rawIn.read(b, off, len)
        }
        if (chunkPos >= chunkBuf.size) {
            val chunk = readChunk() ?: run {
                eof = true
                return -1
            }
            chunkBuf = chunk
            chunkPos = 0
        }
        val take = minOf(len, chunkBuf.size - chunkPos)
        chunkBuf.copyInto(b, off, chunkPos, chunkPos + take)
        chunkPos += take
        return take
    }

    override fun available(): Int = chunkBuf.size - chunkPos

    override fun close() {
        closed = true
    }
}
