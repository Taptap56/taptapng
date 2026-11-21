package com.taptap.ng.core.proto

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.net.SocketAddress
import java.nio.channels.SocketChannel
import kotlin.random.Random

/**
 * TLS ClientHello fragmentation (v1.0.5, Fragment settings):
 * `fragmentEnabled` ON splits the ClientHello into several small
 * TLS records so a DPI cannot read the SNI in one go (xray-core
 * `fragment` with `packets: tlshello`).
 *
 * WHY record splitting, and why it is safe:
 * - TLS allows ONE handshake message to span MULTIPLE records
 *   (RFC 8446 §5.1): the peer's record layer reassembles the
 *   handshake message before the transcript hash is computed, so
 *   the handshake stays consistent — unlike patching ClientHello
 *   bytes after the fact (which breaks Finished, see OneringTls).
 *   Proven by the JVM SSLEngine experiment (2026-11-21): a
 *   ClientHello split into 50-100 byte records with 10-20 ms
 *   gaps completes the handshake against a peer SSLEngine on
 *   TLS 1.3 AND TLS 1.2, app data round-trips intact, and
 *   maxSplit is honoured (3 -> exactly 3 records, 1 -> byte
 *   identical to unfragmented).
 * - SSLSocket/Conscrypt generate the ClientHello internally, so
 *   the split happens BELOW them: [FragmentSocket] hands the
 *   SSLSocket a [FragmentingOutputStream] as the plain socket's
 *   output stream. Conscrypt's engine socket (used for EVERY
 *   wrapped socket — Platform.createEngineSocket) reads the
 *   transport streams via virtual `socket.getOutputStream()` /
 *   `socket.getInputStream()` (AbstractConscryptSocket delegates
 *   when wrapping), so the override is honoured; the Sun JDK
 *   SSLSocket does the same. The Onering path (BC) takes the
 *   same stream directly (see OneringTls.wrap).
 * - Only the FIRST handshake record of the connection is split
 *   (the ClientHello); everything after it — ServerHello,
 *   Finished, app data — passes through byte-identical. OFF
 *   (or an unsupported `fragmentPackets` value) = the v1.0.4
 *   path untouched: no wrapper, no extra thread, no timing change.
 *
 * The fragment stream is a pure record parser: it buffers until
 * one complete TLS record (5-byte header + payload) is present,
 * so it is correct no matter how the TLS stack chunks its
 * write() calls. A partial record is never emitted as a record;
 * flush() leaves it buffered and close() emits it raw so no
 * byte is ever dropped.
 */
data class FragmentConfig(
    /** Inclusive fragment payload range, in bytes. */
    val minLength: Int,
    val maxLength: Int,
    /** Inclusive sleep between fragments, in milliseconds. */
    val minIntervalMs: Int,
    val maxIntervalMs: Int,
    /** Maximum number of records the ClientHello is split into. */
    val maxSplit: Int,
) {
    init {
        require(minLength in MIN_FRAGMENT_LENGTH..MAX_RECORD_LENGTH) {
            "fragmentLength min di luar $MIN_FRAGMENT_LENGTH..$MAX_RECORD_LENGTH: $minLength"
        }
        require(maxLength in minLength..MAX_RECORD_LENGTH) {
            "fragmentLength max di luar $minLength..$MAX_RECORD_LENGTH: $maxLength"
        }
        require(minIntervalMs in 0..MAX_INTERVAL_MS) {
            "fragmentInterval min di luar 0..$MAX_INTERVAL_MS: $minIntervalMs"
        }
        require(maxIntervalMs in minIntervalMs..MAX_INTERVAL_MS) {
            "fragmentInterval max di luar $minIntervalMs..$MAX_INTERVAL_MS: $maxIntervalMs"
        }
        require(maxSplit in 1..MAX_SPLIT) { "fragmentMaxSplit di luar 1..$MAX_SPLIT: $maxSplit" }
    }

    /** Next fragment payload length (fixed when min == max). */
    fun nextLength(random: Random): Int =
        if (minLength == maxLength) minLength else random.nextInt(minLength, maxLength + 1)

    /** Next sleep between fragments, in milliseconds. */
    fun nextIntervalMs(random: Random): Int =
        if (minIntervalMs == maxIntervalMs) minIntervalMs
        else random.nextInt(minIntervalMs, maxIntervalMs + 1)

    companion object {
        /** Only this packets value is supported (xray `tlshello`). */
        const val PACKETS_TLSHELLO = "tlshello"

        /** A fragment must at least hold the 4-byte handshake header. */
        const val MIN_FRAGMENT_LENGTH = 4

        /** Largest TLS record payload (2^14 + 2048 slack, like TlsEngine). */
        const val MAX_RECORD_LENGTH = 18432

        const val MAX_INTERVAL_MS = 1000
        const val MAX_SPLIT = 64

        const val DEFAULT_MIN_LENGTH = 50
        const val DEFAULT_MAX_LENGTH = 100
        const val DEFAULT_MIN_INTERVAL_MS = 10
        const val DEFAULT_MAX_INTERVAL_MS = 20
        const val DEFAULT_MAX_SPLIT = 10

        val DEFAULT = FragmentConfig(
            DEFAULT_MIN_LENGTH,
            DEFAULT_MAX_LENGTH,
            DEFAULT_MIN_INTERVAL_MS,
            DEFAULT_MAX_INTERVAL_MS,
            DEFAULT_MAX_SPLIT,
        )

        /**
         * Build the config from the stored Fragment settings, or
         * null when fragmenting must stay OFF: any `packets`
         * value other than `tlshello` (blank = the default
         * `tlshello`). A single unparseable field falls back to
         * its default instead of killing the dial — the settings
         * are free text, and a typo must never break TLS.
         */
        fun fromSettings(
            packets: String,
            length: String,
            interval: String,
            maxSplit: String,
        ): FragmentConfig? {
            val p = packets.trim()
            if (p.isNotEmpty() && !p.equals(PACKETS_TLSHELLO, ignoreCase = true)) return null
            val (minLen, maxLen) = parseRange(
                length, DEFAULT_MIN_LENGTH, DEFAULT_MAX_LENGTH,
                MIN_FRAGMENT_LENGTH, MAX_RECORD_LENGTH,
            )
            val (minInt, maxInt) = parseRange(
                interval, DEFAULT_MIN_INTERVAL_MS, DEFAULT_MAX_INTERVAL_MS,
                0, MAX_INTERVAL_MS,
            )
            val split = maxSplit.trim().toIntOrNull()?.coerceIn(1, MAX_SPLIT)
                ?: DEFAULT_MAX_SPLIT
            return FragmentConfig(minLen, maxLen, minInt, maxInt, split)
        }

        /**
         * Parse "min-max" (or a single number) into a clamped
         * range; garbage -> the given defaults. A reversed range
         * ("100-50") is swapped, not rejected.
         */
        internal fun parseRange(
            text: String,
            defaultMin: Int,
            defaultMax: Int,
            minAllowed: Int,
            maxAllowed: Int,
        ): Pair<Int, Int> {
            val parts = text.trim().split("-").map { it.trim() }
            val (a, b) = when (parts.size) {
                1 -> {
                    val v = parts[0].toIntOrNull() ?: return defaultMin to defaultMax
                    v to v
                }
                2 -> {
                    val lo = parts[0].toIntOrNull() ?: return defaultMin to defaultMax
                    val hi = parts[1].toIntOrNull() ?: return defaultMin to defaultMax
                    lo to hi
                }
                else -> return defaultMin to defaultMax
            }
            val lo = a.coerceIn(minAllowed, maxAllowed)
            val hi = b.coerceIn(minAllowed, maxAllowed)
            return if (lo <= hi) lo to hi else hi to lo
        }
    }
}

/**
 * An OutputStream that splits the FIRST TLS handshake record
 * (the ClientHello) written through it into at most
 * [FragmentConfig.maxSplit] records, then becomes a plain
 * passthrough for the rest of the connection.
 *
 * The first fragment always carries the full 4-byte handshake
 * header (type + 3-byte length) so the peer can frame the
 * message; later fragments are pure continuations, which the
 * TLS record layer reassembles (RFC 8446 §5.1).
 */
class FragmentingOutputStream(
    private val out: OutputStream,
    private val config: FragmentConfig,
    private val random: Random = Random.Default,
    /** Injected for tests: real sleeps would make them slow. */
    private val sleeper: (Int) -> Unit = { ms -> if (ms > 0) Thread.sleep(ms.toLong()) },
) : OutputStream() {

    companion object {
        const val RECORD_HEADER_LEN = 5
        const val HANDSHAKE_RECORD_TYPE = 0x16
        const val MAX_RECORD_LENGTH = FragmentConfig.MAX_RECORD_LENGTH

        /** Defensive cap: a first record larger than this is passed through raw. */
        const val MAX_BUFFERED = 65536
    }

    private val pending = ByteArrayOutputStream()

    /** True once the first record has been handled (split or not). */
    @Volatile
    var passthrough = false
        private set

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (passthrough) {
            out.write(b, off, len)
            return
        }
        if (len == 0) return
        pending.write(b, off, len)
        processPending()
    }

    /**
     * Split complete records out of [pending]. Only the first
     * record is ever fragmented; after it the stream latches to
     * passthrough and any leftover bytes go out raw.
     */
    private fun processPending() {
        while (!passthrough) {
            val buf = pending.toByteArray()
            if (buf.size < RECORD_HEADER_LEN) return
            val recordLen = ((buf[3].toInt() and 0xFF) shl 8) or (buf[4].toInt() and 0xFF)
            if (recordLen > MAX_RECORD_LENGTH || buf.size > MAX_BUFFERED) {
                // Not a sane TLS record (or absurdly large): give up
                // fragmenting, emit everything raw, never corrupt.
                disarmRaw()
                return
            }
            if (buf.size < RECORD_HEADER_LEN + recordLen) return // wait for the rest
            val record = buf.copyOfRange(0, RECORD_HEADER_LEN + recordLen)
            pending.reset()
            if (buf.size > RECORD_HEADER_LEN + recordLen) {
                pending.write(buf, RECORD_HEADER_LEN + recordLen, buf.size - RECORD_HEADER_LEN - recordLen)
            }
            if ((record[0].toInt() and 0xFF) == HANDSHAKE_RECORD_TYPE && record.size - RECORD_HEADER_LEN >= 4) {
                fragmentRecord(record)
            } else {
                out.write(record)
            }
            passthrough = true
            if (pending.size() > 0) {
                out.write(pending.toByteArray())
                pending.reset()
            }
        }
    }

    /** Split one handshake record's payload into small records. */
    private fun fragmentRecord(record: ByteArray) {
        val versionHi = record[1]
        val versionLo = record[2]
        val payload = record.copyOfRange(RECORD_HEADER_LEN, record.size)
        var off = 0
        var frags = 0
        while (off < payload.size) {
            val remaining = payload.size - off
            val isFirst = off == 0
            val take = if (frags >= config.maxSplit - 1) {
                remaining
            } else {
                val n = config.nextLength(random)
                // First fragment must hold the 4-byte handshake header.
                (if (isFirst) maxOf(n, 4) else n).coerceAtMost(remaining)
            }.coerceAtLeast(1)
            val fragment = ByteArray(RECORD_HEADER_LEN + take)
            fragment[0] = HANDSHAKE_RECORD_TYPE.toByte()
            fragment[1] = versionHi
            fragment[2] = versionLo
            fragment[3] = (take shr 8).toByte()
            fragment[4] = take.toByte()
            payload.copyInto(fragment, RECORD_HEADER_LEN, off, off + take)
            out.write(fragment)
            off += take
            frags++
            if (off < payload.size) {
                val sleepMs = config.nextIntervalMs(random)
                if (sleepMs > 0) runCatching { sleeper(sleepMs) }
            }
        }
    }

    /** Stop fragmenting and emit everything buffered, unchanged. */
    private fun disarmRaw() {
        passthrough = true
        if (pending.size() > 0) {
            out.write(pending.toByteArray())
            pending.reset()
        }
    }

    /**
     * Flush the underlying stream. A partial record stays
     * buffered — emitting it would split a record mid-header
     * outside the fragmenter; the writer always completes the
     * record with later writes.
     */
    override fun flush() {
        processPending()
        out.flush()
    }

    /**
     * Never drop bytes: a partial record buffered at close is
     * emitted raw, then the underlying stream is closed.
     */
    override fun close() {
        if (!passthrough) {
            processPending()
            if (pending.size() > 0) {
                runCatching { out.write(pending.toByteArray()) }
                pending.reset()
            }
            passthrough = true
        }
        out.close()
    }
}

/**
 * A plain [Socket] that hands the TLS stack a fragmenting
 * output stream while delegating EVERYTHING else to the real
 * connected socket. Passed to `SSLSocketFactory.createSocket`
 * in place of the plain socket when fragmenting is on.
 *
 * Both stacks read the transport streams through virtual
 * `getInputStream()` / `getOutputStream()` calls on the
 * wrapped socket (Sun SSLSocketImpl, and Conscrypt's
 * AbstractConscryptSocket when delegating), so the override
 * below is what the TLS engine writes through. The SAME
 * [FragmentingOutputStream] instance is returned on every
 * call — the engine may ask for the stream more than once,
 * and a fresh instance would lose the armed state.
 *
 * Every other Socket method delegates to [real]: the wrapper
 * itself is never connected, so an undelegated method would
 * throw "Socket is not connected" from its own empty impl.
 */
class FragmentSocket(
    private val real: Socket,
    config: FragmentConfig,
    random: Random = Random.Default,
    sleeper: (Int) -> Unit = { ms -> if (ms > 0) Thread.sleep(ms.toLong()) },
) : Socket() {

    private val fragmentOut: FragmentingOutputStream by lazy {
        FragmentingOutputStream(real.getOutputStream(), config, random, sleeper)
    }

    override fun getInputStream(): InputStream = real.getInputStream()

    override fun getOutputStream(): OutputStream = fragmentOut

    override fun close() {
        runCatching { real.close() }
        runCatching { super.close() }
    }

    override fun connect(endpoint: SocketAddress) = real.connect(endpoint)

    override fun connect(endpoint: SocketAddress, timeout: Int) = real.connect(endpoint, timeout)

    override fun bind(bindpoint: SocketAddress) = real.bind(bindpoint)

    override fun getInetAddress(): InetAddress = real.inetAddress

    override fun getLocalAddress(): InetAddress = real.localAddress

    override fun getPort(): Int = real.port

    override fun getLocalPort(): Int = real.localPort

    override fun getRemoteSocketAddress(): SocketAddress = real.remoteSocketAddress

    override fun getLocalSocketAddress(): SocketAddress = real.localSocketAddress

    override fun getChannel(): SocketChannel? = real.channel

    override fun isConnected(): Boolean = real.isConnected

    override fun isBound(): Boolean = real.isBound

    override fun isClosed(): Boolean = real.isClosed

    override fun isInputShutdown(): Boolean = real.isInputShutdown

    override fun isOutputShutdown(): Boolean = real.isOutputShutdown

    override fun shutdownInput() = real.shutdownInput()

    override fun shutdownOutput() = real.shutdownOutput()

    override fun setSoTimeout(timeout: Int) = real.setSoTimeout(timeout)

    override fun getSoTimeout(): Int = real.soTimeout

    override fun setTcpNoDelay(on: Boolean) = real.setTcpNoDelay(on)

    override fun getTcpNoDelay(): Boolean = real.tcpNoDelay

    override fun setSoLinger(on: Boolean, linger: Int) = real.setSoLinger(on, linger)

    override fun getSoLinger(): Int = real.soLinger

    override fun setReuseAddress(on: Boolean) = real.setReuseAddress(on)

    override fun getReuseAddress(): Boolean = real.reuseAddress

    override fun setKeepAlive(on: Boolean) = real.setKeepAlive(on)

    override fun getKeepAlive(): Boolean = real.keepAlive

    override fun setTrafficClass(tc: Int) = real.setTrafficClass(tc)

    override fun getTrafficClass(): Int = real.trafficClass

    override fun setReceiveBufferSize(size: Int) = real.setReceiveBufferSize(size)

    override fun getReceiveBufferSize(): Int = real.receiveBufferSize

    override fun setSendBufferSize(size: Int) = real.setSendBufferSize(size)

    override fun getSendBufferSize(): Int = real.sendBufferSize

    override fun setPerformancePreferences(connectionTime: Int, latency: Int, bandwidth: Int) =
        real.setPerformancePreferences(connectionTime, latency, bandwidth)

    override fun setOOBInline(on: Boolean) = real.setOOBInline(on)

    override fun getOOBInline(): Boolean = real.oobInline

    override fun sendUrgentData(data: Int) = real.sendUrgentData(data)

    override fun toString(): String = "FragmentSocket[$real]"
}
