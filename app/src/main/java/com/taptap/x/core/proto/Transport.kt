package com.taptap.x.core.proto

import com.taptap.x.data.ProfileItem
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

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

    fun open(item: ProfileItem): OpenStream {
        require(item.address.isNotBlank()) { "Address proxy kosong" }
        require(item.port in 1..65535) { "Port proxy di luar 1..65535: ${item.port}" }
        val plain = Socket()
        try {
            val protect = protectSocket
            if (protect != null && !protect(plain)) {
                throw IllegalStateException("protect() gagal — dial tidak bisa bypass VPN")
            }
            plain.connect(InetSocketAddress(item.address, item.port), CONNECT_TIMEOUT_MS)
            plain.soTimeout = HANDSHAKE_TIMEOUT_MS
        } catch (e: Exception) {
            runCatching { plain.close() }
            throw e
        }
        var socket: Socket = plain
        var input: InputStream = plain.getInputStream()
        var output: OutputStream = plain.getOutputStream()
        try {
            if (item.tls) {
                socket = TlsUtil.wrap(plain, item)
                input = socket.getInputStream()
                output = socket.getOutputStream()
            }
            val network = item.network.ifBlank { "tcp" }.lowercase()
            if (network == "ws") {
                val ws = WsTransport.connect(input, output, wsHost(item), wsPath(item))
                input = ws.input
                output = ws.output
            } else if (network != "tcp") {
                throw IllegalArgumentException("network $network belum didukung (hanya tcp/ws)")
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
