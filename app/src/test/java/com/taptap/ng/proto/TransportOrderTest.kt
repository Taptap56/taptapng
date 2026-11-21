package com.taptap.ng.proto

import com.taptap.ng.core.Base64Util
import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.Transport
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * Dial-log order (v1.0.3): the Transport ladder logs the XVEON
 * connect-log lines in XVEON's order — "Connecting to Xray
 * outbound", TCP socket, WS handshake, 101 — with the DNS resolve
 * inside the TCP step (no separate DNS line before TCP), no "ok"
 * line per stage, no "[STAGE]" tag prefix, no "PROTECT TUN belum
 * naik" line and no "SOCKET rcv=... snd=..." line.
 * The fake server is plain TCP on loopback (::1, like
 * VmessClientTest — the dev VM blackholes JVM connects to IPv4
 * loopback). TLS is not exercised here (JVM SSLSocket loopback is
 * intercepted — the "TLS established" lines are covered by
 * OneringTlsTest / TlsEngineTest over in-memory channels).
 */
class TransportOrderTest {

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `ws dial logs the XVEON lines in XVEON order`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val serverThread = Thread({
            runCatching {
                val socket = server.accept()
                socket.soTimeout = 5_000
                val input = socket.getInputStream()
                // Read the WS handshake request headers.
                val headerBytes = ByteArrayOutputStream()
                val tail = ArrayDeque<Int>()
                while (true) {
                    val b = input.read()
                    if (b == -1) break
                    headerBytes.write(b)
                    tail.addLast(b)
                    if (tail.size > 4) tail.removeFirst()
                    if (tail.size == 4 &&
                        tail[0] == '\r'.code && tail[1] == '\n'.code &&
                        tail[2] == '\r'.code && tail[3] == '\n'.code
                    ) break
                }
                val header = headerBytes.toString(Charsets.UTF_8)
                val key = header.lines()
                    .firstOrNull { it.startsWith("Sec-WebSocket-Key:", ignoreCase = true) }
                    ?.substringAfter(":")?.trim() ?: ""
                val accept = Base64Util.encode(
                    MessageDigest.getInstance("SHA-1")
                        .digest(
                            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                                .toByteArray(Charsets.UTF_8),
                        ),
                )
                val response = "HTTP/1.1 101 Switching Protocols\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Accept: $accept\r\n\r\n"
                socket.getOutputStream().write(response.toByteArray(Charsets.UTF_8))
                socket.getOutputStream().flush()
                Thread.sleep(1_000)
                socket.close()
            }
        }, "order-test-ws-server").apply { isDaemon = true; start() }
        val logBefore = DialLog.lines().size
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
            network = "ws", host = "example.com", path = "/vmess",
            tls = false,
        )
        val stream = Transport.open(item)
        try {
            // The ladder is up; nothing more to do.
        } finally {
            runCatching { stream.close() }
            runCatching { server.close() }
        }
        serverThread.join(5_000)
        val lines = DialLog.lines().drop(logBefore)
        fun idx(fragment: String): Int = lines.indexOfFirst { it.contains(fragment) }
        val iOutbound = idx("Connecting to Xray outbound ::1:$port")
        val iTcp = idx("Connecting TCP socket to ::1:$port")
        // wsHost appends the non-standard port to the Host header.
        val iWs = idx("WebSocket (WS) handshake -> Host: example.com:$port, Path: /vmess")
        val i101 = idx("Server response: HTTP/1.1 101 Switching Protocols")
        assertTrue(iOutbound >= 0, "log harus ada outbound line: $lines")
        assertTrue(iTcp > iOutbound, "TCP socket harus sesudah outbound: $lines")
        assertTrue(iWs > iTcp, "WS handshake harus sesudah TCP socket: $lines")
        assertTrue(i101 > iWs, "101 harus sesudah WS handshake: $lines")
        // The removed lines must be gone.
        assertTrue(
            lines.none { it.contains("DNS ::1 ->") },
            "baris DNS sukses harus hilang: $lines",
        )
        assertTrue(
            lines.none { it.contains("TCP ::1:$port ok") },
            "baris TCP ok harus hilang: $lines",
        )
        assertTrue(
            lines.none { it.contains("WS example.com:$port/vmess ok") },
            "baris WS ok harus hilang: $lines",
        )
        // v1.0.3: no stage tag, no SOCKET line, no PROTECT line.
        assertTrue(
            lines.none { it.contains("rcv=") },
            "baris SOCKET rcv= harus hilang: $lines",
        )
        assertTrue(
            lines.none { it.contains("TUN belum naik") },
            "baris PROTECT TUN belum naik harus hilang: $lines",
        )
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `plain tcp dial has no dns line and no stage ok line`() {
        val server = ServerSocket(0)
        val port = server.localPort
        val serverThread = Thread({
            runCatching {
                val socket = server.accept()
                Thread.sleep(1_000)
                socket.close()
            }
        }, "order-test-tcp-server").apply { isDaemon = true; start() }
        val logBefore = DialLog.lines().size
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            network = "tcp",
            tls = false,
        )
        val stream = Transport.open(item)
        try {
            // Ladder up; nothing more to do.
        } finally {
            runCatching { stream.close() }
            runCatching { server.close() }
        }
        serverThread.join(5_000)
        val lines = DialLog.lines().drop(logBefore)
        fun idx(fragment: String): Int = lines.indexOfFirst { it.contains(fragment) }
        val iOutbound = idx("Connecting to Xray outbound ::1:$port")
        val iTcp = idx("Connecting TCP socket to ::1:$port")
        assertTrue(iOutbound >= 0, "log harus ada outbound line: $lines")
        assertTrue(iTcp > iOutbound, "TCP socket harus sesudah outbound: $lines")
        assertTrue(
            lines.none { it.contains("DNS ::1 ->") },
            "baris DNS sukses harus hilang: $lines",
        )
        assertTrue(
            lines.none { it.contains("TCP ::1:$port ok") },
            "baris TCP ok harus hilang: $lines",
        )
        // v1.0.3: no stage tag, no SOCKET line, no PROTECT line.
        assertTrue(
            lines.none { it.contains("rcv=") },
            "baris SOCKET rcv= harus hilang: $lines",
        )
        assertTrue(
            lines.none { it.contains("TUN belum naik") },
            "baris PROTECT TUN belum naik harus hilang: $lines",
        )
    }
}
