package com.taptap.x.core.slowdns

import com.taptap.x.core.DialLog
import com.taptap.x.core.proto.LadderStream
import com.taptap.x.core.proto.SpeedStats
import com.taptap.x.core.proto.TimedInputStream
import com.taptap.x.core.proto.Transport
import com.taptap.x.core.proto.WsTransport
import com.taptap.x.data.ProfileItem
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Transport ladder for a SlowDNS entry (M3): the inner VMess/VLESS
 * runs over a DNSTT smux stream instead of a TCP socket.
 *
 * Ladder: smux stream → TLS (via [TlsEngine], only when item.tls)
 * → WS (only when network == "ws"). The VMess/VLESS header is then
 * written over the resulting stream exactly like on the socket path
 * — the protocol clients ([com.taptap.x.core.proto.VmessClient] /
 * [com.taptap.x.core.proto.VlessClient]) do not know or care which
 * ladder produced the stream.
 *
 * The DNSTT server forwards every stream to ONE fixed TCP target
 * (the provider's), so the entry's address/port are used for the
 * TLS SNI / WS Host / protocol header — never for a TCP dial. The
 * session itself is owned by [SlowDnsSessionPool] (one per client
 * instance, shared by the probe + all forwarder dials).
 *
 * When [item.dnsttEnabled] is false this is just the plain socket
 * ladder ([Transport.open]) wrapped as a [LadderStream], so the
 * protocol clients have ONE call site for both paths.
 */
object SlowDnsTransport {

    fun open(item: ProfileItem, pool: SlowDnsSessionPool, stats: SpeedStats? = null): LadderStream {
        if (!item.dnsttEnabled) {
            val t = Transport.open(item, stats)
            return LadderStream(
                t.input,
                t.output,
                onClose = { t.close() },
                onHandshakeDone = {
                    t.socket.soTimeout = 0
                    Transport.clearWatchdogSocket()
                },
            )
        }
        var stream: SmuxStream? = null
        try {
            Transport.noteStage("SlowDNS")
            stream = pool.stream()
            var input: InputStream = stream.input
            var output: OutputStream = stream.output
            // Handshake read deadline (mirrors the socket's 10 s
            // SO_TIMEOUT); cleared once the protocol handshake has
            // succeeded. The watchdog can also kill a stuck read by
            // closing the stream.
            stream.readDeadlineMs = Transport.HANDSHAKE_TIMEOUT_MS.toLong()
            Transport.armWatchdogCloseable(Closeable { stream?.close() })
            val network = item.network.ifBlank { "tcp" }.lowercase()
            if (network != "tcp" && network != "ws") {
                runCatching { stream.close() }
                throw IllegalArgumentException("network $network belum didukung (hanya tcp/ws)")
            }
            if (item.tls) {
                Transport.noteStage("TLS")
                try {
                    val (tlsIn, tlsOut) = TlsEngine.wrap(input, output, item)
                    input = tlsIn
                    output = tlsOut
                } catch (e: Exception) {
                    throw IOException("TLS gagal: ${e.message}", e)
                }
                DialLog.log("TLS", "${item.address} ok (SlowDNS)")
            }
            // v1.0.16: same transport-read timing as the socket
            // ladder (see Transport.open) — the TlsEngine input /
            // smux input is timed as "tls+net" before the WS layer
            // reads from it. No WS: the body stream reads from the
            // wrapper directly.
            val timedIn = if (stats != null) TimedInputStream(input, stats) else input
            if (network == "ws") {
                Transport.noteStage("WS")
                try {
                    val ws = WsTransport.connect(timedIn, output, Transport.wsHost(item), Transport.wsPath(item), stats)
                    input = ws.input
                    output = ws.output
                } catch (e: Exception) {
                    throw IOException("WS gagal: ${e.message}", e)
                }
                DialLog.log("WS", "${Transport.wsHost(item)}${Transport.wsPath(item)} ok (SlowDNS)")
            } else {
                input = timedIn
            }
            DialLog.log("SlowDNS", "stream buka untuk ${item.address}:${item.port}")
            val s = stream
            return LadderStream(
                input,
                output,
                onClose = { runCatching { s.close() } },
                onHandshakeDone = {
                    s.readDeadlineMs = 0
                    Transport.clearWatchdogCloseable()
                },
            )
        } catch (e: Exception) {
            runCatching { stream?.close() }
            Transport.clearWatchdogCloseable()
            val failure = Transport.preferWatchdogFailure(e)
            DialLog.failure("DIAL", failure)
            throw failure
        }
    }
}
