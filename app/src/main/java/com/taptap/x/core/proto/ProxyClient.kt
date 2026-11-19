package com.taptap.x.core.proto

import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

/**
 * Common stream/client contract for the in-app proxy protocols (M2).
 *
 * A [ProxyClient] opens one proxied byte stream to [targetHost]:[targetPort]
 * per [dial] call. The target is sent inside the protocol header — it is
 * never resolved locally first. Each [dial] returns a fresh [ProxyStream];
 * dialing again closes the previous stream.
 *
 * Implementations must never log credentials (UUID, password, keys).
 */
interface ProxyStream {
    val input: InputStream
    val output: OutputStream
    fun close()
}

interface ProxyClient {
    fun dial(targetHost: String, targetPort: Int): ProxyStream
    fun close()
}

/**
 * A [ProxyStream] over one socket. Closing the output first lets
 * protocol streams emit their termination record / WS Close frame
 * before the socket goes away; the socket itself is closed last.
 */
class SocketProxyStream(
    private val socket: Socket,
    override val input: InputStream,
    override val output: OutputStream,
) : ProxyStream {
    override fun close() {
        runCatching { output.close() }
        runCatching { input.close() }
        runCatching { socket.close() }
    }
}

/** Read exactly [n] bytes or throw EOFException. Shared by all protocols. */
fun InputStream.readExactBytes(n: Int): ByteArray {
    val out = ByteArray(n)
    var filled = 0
    while (filled < n) {
        val r = read(out, filled, n - filled)
        if (r == -1) throw java.io.EOFException("Stream terpotong (EOF), butuh $n byte, dapat $filled")
        filled += r
    }
    return out
}
