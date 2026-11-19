package com.taptap.x.core.proto

import com.taptap.x.core.DnsResolver
import com.taptap.x.data.ProfileItem
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException

/**
 * Shared transport ladder for VMess/VLESS/Trojan (M2): TCP → TLS → WS.
 *
 * Order matters and matches v2rayNG: plain TCP first, TLS wraps the TCP
 * socket when item.tls is set, then the WebSocket handshake runs over
 * whatever stream is underneath (plain TCP or TLS).
 *
 * The returned socket keeps SO_TIMEOUT = [HANDSHAKE_TIMEOUT_MS] during
 * dial so a dead peer fails fast; clients reset it to 0 (blocking) once
 * the protocol handshake has succeeded. The socket is owned by the
 * returned [OpenStream] — closing the socket closes everything under it.
 */
object Transport {

    const val CONNECT_TIMEOUT_MS = 10_000
    const val HANDSHAKE_TIMEOUT_MS = 10_000

    /**
     * Hook set by [com.taptap.x.service.TaptapVpnService] so dial
     * sockets bypass the TUN (VpnService.protect). Null = no
     * protection (unit tests, direct use). Returning false aborts
     * the dial — a dial that cannot bypass the VPN would loop into
     * the tunnel forever.
     */
    @Volatile
    var protectSocket: ((Socket) -> Boolean)? = null

    class OpenStream(
        val socket: Socket,
        val input: InputStream,
        val output: OutputStream,
    ) {
        fun close() = runCatching { socket.close() }
    }

    /**
     * Open the transport ladder (TCP → TLS → WS). Every stage tags its
     * failure ("DNS gagal: ...", "TCP gagal: ...", "TLS gagal: ...",
     * "WS gagal: ...") so the phone status shows WHERE the dial died
     * instead of a bare "timeout" — v1.0.4 only ever showed that.
     * The exception types are preserved on purpose: [SocketTimeoutException]
     * stays a timeout and [SSLException] stays a TLS failure, so
     * `TunForwarder.dialFailureReason` keeps mapping them the same way.
     */
    fun open(item: ProfileItem): OpenStream {
        require(item.address.isNotBlank()) { "Address proxy kosong" }
        require(item.port in 1..65535) { "Port proxy di luar 1..65535: ${item.port}" }
        val plain = Socket()
        try {
            val protect = protectSocket
            if (protect != null && !protect(plain)) {
                throw IllegalStateException("protect() gagal — dial tidak bisa bypass VPN")
            }
            // Tahap DNS: resolve langsung (UDP ke 8.8.8.8, bypass TUN),
            // fallback ke resolver sistem bila gagal (relay DNS mungkin
            // jalan). JANGAN resolve lewat InetSocketAddress(host, port):
            // konstruktor itu memanggil resolver sistem TANPA timeout —
            // saat VPN naik lookup-nya masuk ke TUN dan menggantung
            // sampai resolver menyerah (gejala v1.0.4: status macet di
            // "Connecting..." selamanya). Di sini address sudah IP
            // hasil resolve, jadi connect() tidak lookup lagi.
            val target = DnsResolver.resolveWithSystemFallback(item.address, item.port)
            try {
                plain.connect(InetSocketAddress(target, item.port), CONNECT_TIMEOUT_MS)
            } catch (e: SocketTimeoutException) {
                throw SocketTimeoutException("TCP gagal: ${e.message}")
            } catch (e: ConnectException) {
                throw ConnectException("TCP gagal: ${e.message}")
            } catch (e: IOException) {
                throw IOException("TCP gagal: ${e.message}", e)
            }
            plain.soTimeout = HANDSHAKE_TIMEOUT_MS
        } catch (e: Exception) {
            runCatching { plain.close() }
            throw e
        }
        var socket: Socket = plain
        var input: InputStream = plain.getInputStream()
        var output: OutputStream = plain.getOutputStream()
        val network = item.network.ifBlank { "tcp" }.lowercase()
        if (network != "tcp" && network != "ws") {
            runCatching { socket.close() }
            throw IllegalArgumentException("network $network belum didukung (hanya tcp/ws)")
        }
        try {
            if (item.tls) {
                // Tahap TLS. SNI tetap domain asli (item.sni atau
                // item.address): TlsUtil.wrap menerima item apa adanya
                // — createSocket(plain, host, ...) tidak me-resolve
                // host karena socket sudah terkoneksi; SNI di-set
                // eksplisit dari item, bukan dari IP hasil resolve.
                try {
                    socket = TlsUtil.wrap(plain, item)
                } catch (e: SSLException) {
                    throw SSLException("TLS gagal: ${e.message}")
                } catch (e: Exception) {
                    throw IOException("TLS gagal: ${e.message}", e)
                }
                input = socket.getInputStream()
                output = socket.getOutputStream()
            }
            if (network == "ws") {
                // Tahap WS.
                try {
                    val ws = WsTransport.connect(input, output, wsHost(item), wsPath(item))
                    input = ws.input
                    output = ws.output
                } catch (e: Exception) {
                    throw IOException("WS gagal: ${e.message}", e)
                }
            }
        } catch (e: Exception) {
            runCatching { socket.close() }
            throw e
        }
        return OpenStream(socket, input, output)
    }

    /** WS Host header: item.host, else the proxy address (+ :port if unusual). */
    fun wsHost(item: ProfileItem): String {
        val host = item.host.ifBlank { item.address }
        return if (item.port == 80 || item.port == 443) host else "$host:${item.port}"
    }

    /** WS request path, default "/". */
    fun wsPath(item: ProfileItem): String {
        val path = item.path.ifBlank { "/" }
        return if (path.startsWith("/")) path else "/$path"
    }
}
