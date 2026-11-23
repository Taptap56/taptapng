package com.taptap.ng.service

import android.content.Context
import android.util.Log
import com.taptap.ng.BuildConfig
import com.taptap.ng.core.DialLog
import com.taptap.ng.core.ProxyGroup
import com.taptap.ng.core.RouteRule
import com.taptap.ng.core.ServerTester
import com.taptap.ng.data.GroupsStore
import com.taptap.ng.data.ProfileItem
import com.taptap.ng.data.ProfileStore
import com.taptap.ng.data.SettingsStore
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Clash external-controller HTTP server (M7, W3): raw HTTP/1.1 on
 * `java.net.ServerSocket`, thread-per-connection, JSON via Gson —
 * no new dependencies (no OkHttp / NanoHTTPD / Ktor in the module).
 * Serves the bundled yacd dashboard from `assets/yacd/` and the
 * Clash API the dashboard calls (see [ClashApiHandler]).
 *
 * Lifecycle: the server follows the APP PROCESS, not the tunnel —
 * it starts from [com.taptap.ng.TaptapNGApp.onCreate] so the
 * dashboard opens and shows groups before the VPN connects.
 * [restart] is called when the API settings change (port / secret /
 * enable) from Settings. A bind failure (port already taken — e.g.
 * the user kept 9090 while TaptapBox/TaptapClash owns it) is logged
 * clearly and NEVER crashes the app; the user picks another port in
 * Settings. The server stops when the process dies (no explicit
 * stop hook — the accept thread is a daemon).
 *
 * Auth decision (documented): when a secret is set, every API path
 * requires `Authorization: Bearer <secret>` (Clash standard) — the
 * WebView/dashboard must open as `/ui/?secret=<secret>` or have the
 * secret entered in yacd's API-config dialog. Static UI files are
 * served without auth (mihomo's external-ui behaves the same).
 * The secret is NEVER written to a log.
 */
object ClashApiServer {

    private const val TAG = "ClashApi"

    @Volatile
    var isRunning: Boolean = false
        private set

    /** Last bind failure, for the status text (null = no failure / not started). */
    @Volatile
    var bindError: String? = null
        private set

    @Volatile
    private var serverSocket: ServerSocket? = null

    private val started = AtomicBoolean(false)

    /** Start (or no-op when already running / disabled). Safe to call repeatedly. */
    @Synchronized
    fun start(context: Context) {
        if (started.get()) return
        val appContext = context.applicationContext
        val settings = SettingsStore(appContext)
        if (!settings.clashApiEnabled) {
            DialLog.log("CLASH", "API Clash mati (enable di Settings > Clash API)")
            return
        }
        val port = SettingsStore.clashApiPortInt(settings.clashApiPort)
        val bindAddr = bindAddress(settings.clashApiAllowLan)
        val socket = try {
            ServerSocket(port, 50, bindAddr)
        } catch (e: IOException) {
            bindError = "port $port sudah dipakai (${e.message}) — ganti port API di Settings > Clash API"
            DialLog.log("CLASH", "API Clash gagal start: $bindError")
            Log.w(TAG, "bind failed: $bindError")
            return
        }
        serverSocket = socket
        bindError = null
        started.set(true)
        isRunning = true
        DialLog.log(
            "CLASH",
            "API Clash jalan di ${bindAddr.hostAddress}:$port" +
                " (dashboard: http://127.0.0.1:$port/ui/)",
        )
        thread(name = "clash-api-accept", isDaemon = true) {
            while (!socket.isClosed) {
                val conn = try {
                    socket.accept()
                } catch (_: SocketException) {
                    break
                } catch (_: IOException) {
                    break
                }
                thread(name = "clash-api-conn", isDaemon = true) {
                    runCatching { handleConnection(conn, appContext) }
                        .onFailure { runCatching { conn.close() } }
                }
            }
            started.set(false)
            isRunning = false
        }
    }

    /**
     * Bind address for the Clash API listener (pure, JVM-testable).
     *
     * Non-LAN MUST be the IPv4 loopback `127.0.0.1`, never
     * `InetAddress.getLoopbackAddress()`: on the phone that resolves
     * to `::1` (IPv6 loopback) while the dashboard URL is hardcoded
     * `http://127.0.0.1:<port>/ui/`, so the WebView got
     * ERR_CONNECTION_REFUSED (regression v1.0.20). LAN keeps the
     * `0.0.0.0` wildcard, unchanged.
     */
    internal fun bindAddress(allowLan: Boolean): InetAddress =
        if (allowLan) InetAddress.getByName("0.0.0.0")
        else InetAddress.getByName("127.0.0.1")

    /** Stop the listener (called by [restart]; process death stops it anyway). */
    @Synchronized
    fun stop() {
        runCatching { serverSocket?.close() }
        serverSocket = null
        started.set(false)
        isRunning = false
    }

    /** Re-read settings and restart the listener (port / secret / enable changed). */
    @Synchronized
    fun restart(context: Context) {
        stop()
        start(context)
    }

    // ---- One connection ----

    private fun handleConnection(socket: Socket, appContext: Context) {
        socket.soTimeout = 30_000
        val input = BufferedInputStream(socket.getInputStream())
        val output = BufferedOutputStream(socket.getOutputStream())
        try {
            val head = readHead(input) ?: return
            val (method, rawTarget, headers) = parseHead(head) ?: run {
                writeSimple(output, 400, "Bad Request")
                return
            }
            val (path, queryRaw) = rawTarget.split('?', limit = 2)
                .let { it[0] to (it.getOrNull(1) ?: "") }
            val body = readBody(input, headers)
            val req = ApiRequest(
                method = method.uppercase(),
                path = normalizePath(path),
                query = ClashApiHandler.parseQuery(queryRaw),
                headers = headers.mapKeys { it.key.lowercase() },
                body = body,
            )
            val deps = LiveClashApiDeps(appContext)
            val response = ClashApiHandler(deps).handle(req)
            when (response) {
                is ApiResponse.Immediate -> writeImmediate(output, response)
                is ApiResponse.Stream -> {
                    if (isWebSocketUpgrade(req)) {
                        serveWebSocket(socket, input, output, req, response)
                    } else {
                        serveChunked(output, response)
                    }
                }
            }
        } catch (_: IOException) {
            // Client went away mid-request — nothing to report.
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun normalizePath(path: String): String {
        val decoded = runCatching {
            java.net.URLDecoder.decode(path, "UTF-8")
        }.getOrDefault(path)
        return if (decoded.length > 1) decoded.trimEnd('/') else decoded
    }

    /** Read request head up to \r\n\r\n (max 16 KB). Null on EOF. */
    private fun readHead(input: BufferedInputStream): String? {
        val buf = ByteArrayOutputStream()
        val window = ArrayDeque<Int>()
        while (buf.size() < 16_384) {
            val b = input.read()
            if (b == -1) return if (buf.size() == 0) null else buf.toString(Charsets.US_ASCII.name())
            buf.write(b)
            window.addLast(b)
            if (window.size > 4) window.removeFirst()
            if (window.size == 4 && window.toList() == listOf(13, 10, 13, 10)) {
                return buf.toString(Charsets.US_ASCII.name())
            }
        }
        return null
    }

    private fun parseHead(head: String): Triple<String, String, Map<String, String>>? {
        val lines = head.split("\r\n").filter { it.isNotEmpty() }
        if (lines.isEmpty()) return null
        val parts = lines[0].split(" ")
        if (parts.size < 2) return null
        val headers = LinkedHashMap<String, String>()
        for (line in lines.drop(1)) {
            val colon = line.indexOf(':')
            if (colon > 0) headers[line.substring(0, colon).trim()] = line.substring(colon + 1).trim()
        }
        return Triple(parts[0], parts[1], headers)
    }

    private fun readBody(input: BufferedInputStream, headers: Map<String, String>): String {
        val len = headers.entries.firstOrNull { it.key.equals("Content-Length", ignoreCase = true) }
            ?.value?.toIntOrNull()?.coerceIn(0, 1_048_576) ?: 0
        if (len == 0) return ""
        val buf = ByteArray(len)
        var filled = 0
        while (filled < len) {
            val r = input.read(buf, filled, len - filled)
            if (r == -1) break
            filled += r
        }
        return buf.copyOf(filled).toString(Charsets.UTF_8)
    }

    // ---- Responses ----

    internal fun corsHeaders(): Map<String, String> = mapOf(
        "Access-Control-Allow-Origin" to "*",
        "Access-Control-Allow-Methods" to "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers" to "Authorization, Content-Type",
    )

    private fun writeSimple(output: BufferedOutputStream, status: Int, text: String) {
        val body = text.toByteArray(Charsets.UTF_8)
        writeImmediate(output, ApiResponse.Immediate(status, "text/plain", body))
    }

    private fun statusLine(status: Int): String = when (status) {
        200 -> "200 OK"
        204 -> "204 No Content"
        302 -> "302 Found"
        400 -> "400 Bad Request"
        401 -> "401 Unauthorized"
        403 -> "403 Forbidden"
        404 -> "404 Not Found"
        405 -> "405 Method Not Allowed"
        504 -> "504 Gateway Timeout"
        else -> "$status"
    }

    private fun writeImmediate(output: BufferedOutputStream, response: ApiResponse.Immediate) {
        val head = StringBuilder()
        head.append("HTTP/1.1 ${statusLine(response.status)}\r\n")
        for ((k, v) in corsHeaders()) head.append("$k: $v\r\n")
        head.append("Content-Type: ${response.contentType}\r\n")
        head.append("Content-Length: ${response.body.size}\r\n")
        for ((k, v) in response.extraHeaders) head.append("$k: $v\r\n")
        head.append("Connection: close\r\n\r\n")
        output.write(head.toString().toByteArray(Charsets.US_ASCII))
        output.write(response.body)
        output.flush()
    }

    /** HTTP chunked streaming (yacd's fetch fallback for /traffic, /logs, /connections, /memory). */
    private fun serveChunked(output: BufferedOutputStream, response: ApiResponse.Stream) {
        val head = StringBuilder()
        head.append("HTTP/1.1 200 OK\r\n")
        for ((k, v) in corsHeaders()) head.append("$k: $v\r\n")
        head.append("Content-Type: application/json\r\n")
        head.append("Transfer-Encoding: chunked\r\n")
        head.append("Connection: close\r\n\r\n")
        output.write(head.toString().toByteArray(Charsets.US_ASCII))
        output.flush()
        while (true) {
            val line = try {
                response.produce()
            } catch (_: Exception) {
                null
            }
            if (line != null) {
                val bytes = (line + "\n").toByteArray(Charsets.UTF_8)
                output.write("${bytes.size.toString(16)}\r\n".toByteArray(Charsets.US_ASCII))
                output.write(bytes)
                output.write("\r\n".toByteArray(Charsets.US_ASCII))
                output.flush()
            }
            try {
                Thread.sleep(STREAM_INTERVAL_MS)
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    // ---- WebSocket (RFC 6455, minimal: text frames out, ping/pong/close in) ----

    private fun isWebSocketUpgrade(req: ApiRequest): Boolean {
        val upgrade = req.header("Upgrade") ?: return false
        if (!upgrade.equals("websocket", ignoreCase = true)) return false
        return req.header("Sec-WebSocket-Key") != null
    }

    private fun serveWebSocket(
        socket: Socket,
        input: BufferedInputStream,
        output: BufferedOutputStream,
        req: ApiRequest,
        response: ApiResponse.Stream,
    ) {
        val key = req.header("Sec-WebSocket-Key") ?: return
        val accept = ClashApiHandler.websocketAcceptKey(key)
        val head = "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Accept: $accept\r\n\r\n"
        output.write(head.toByteArray(Charsets.US_ASCII))
        output.flush()
        val closed = AtomicBoolean(false)
        // Reader: client frames (ping -> pong, close -> stop). yacd sends nothing else.
        // A read timeout only means "no client frame for 30 s" — keep waiting, do NOT
        // kill the stream (the sender pushes a frame every second anyway).
        thread(name = "clash-api-ws-read", isDaemon = true) {
            try {
                while (!closed.get()) {
                    try {
                        when (readWsFrame(input, output)) {
                            WsRead.CLOSE -> closed.set(true)
                            WsRead.EOF -> closed.set(true)
                            else -> Unit
                        }
                    } catch (_: java.net.SocketTimeoutException) {
                        // Idle client — keep waiting.
                    }
                }
            } catch (_: IOException) {
                closed.set(true)
            } finally {
                closed.set(true)
            }
        }
        try {
            while (!closed.get()) {
                val line = try {
                    response.produce()
                } catch (_: Exception) {
                    null
                }
                if (line != null && !closed.get()) {
                    try {
                        writeWsText(output, line)
                    } catch (_: IOException) {
                        break
                    }
                }
                try {
                    Thread.sleep(STREAM_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    break
                }
            }
        } finally {
            closed.set(true)
            runCatching { socket.close() }
        }
    }

    private enum class WsRead { FRAME, CLOSE, EOF }

    /**
     * Read one client frame. Masked payloads are unmasked and
     * discarded (yacd never sends a payload); ping gets a pong.
     */
    private fun readWsFrame(input: BufferedInputStream, output: BufferedOutputStream): WsRead {
        val b0 = input.read()
        if (b0 == -1) return WsRead.EOF
        val opcode = b0 and 0x0F
        val b1 = input.read()
        if (b1 == -1) return WsRead.EOF
        var len = (b1 and 0x7F).toLong()
        if (len == 126L) {
            val ext = ByteArray(2)
            if (readExact(input, ext) != 2) return WsRead.EOF
            len = ((ext[0].toInt() and 0xFF) shl 8 or (ext[1].toInt() and 0xFF)).toLong()
        } else if (len == 127L) {
            val ext = ByteArray(8)
            if (readExact(input, ext) != 8) return WsRead.EOF
            len = ext.fold(0L) { acc, b -> (acc shl 8) or (b.toInt() and 0xFF).toLong() }
        }
        val masked = (b1 and 0x80) != 0
        val mask = if (masked) ByteArray(4).also { if (readExact(input, it) != 4) return WsRead.EOF } else null
        var remaining = len
        val skip = ByteArray(8192)
        while (remaining > 0) {
            val n = input.read(skip, 0, minOf(skip.size.toLong(), remaining).toInt())
            if (n == -1) return WsRead.EOF
            remaining -= n
        }
        if (opcode == 0x8) return WsRead.CLOSE
        if (opcode == 0x9) {
            // Pong: empty payload.
            output.write(byteArrayOf(0x8A.toByte(), 0x00))
            output.flush()
        }
        return WsRead.FRAME
    }

    private fun readExact(input: BufferedInputStream, buf: ByteArray): Int {
        var filled = 0
        while (filled < buf.size) {
            val r = input.read(buf, filled, buf.size - filled)
            if (r == -1) break
            filled += r
        }
        return filled
    }

    /** One unfragmented, unmasked text frame. */
    private fun writeWsText(output: BufferedOutputStream, text: String) {
        val payload = text.toByteArray(Charsets.UTF_8)
        val head = ByteArrayOutputStream()
        head.write(0x81)
        when {
            payload.size < 126 -> head.write(payload.size)
            payload.size < 65536 -> {
                head.write(126)
                head.write((payload.size shr 8) and 0xFF)
                head.write(payload.size and 0xFF)
            }
            else -> {
                head.write(127)
                for (i in 7 downTo 0) head.write((payload.size shr (i * 8)) and 0xFF)
            }
        }
        output.write(head.toByteArray())
        output.write(payload)
        output.flush()
    }

    private const val STREAM_INTERVAL_MS = 1000L

    // ---- Live deps ----

    /**
     * Production [ClashApiDeps]: reads Settings, the shared
     * [ClashApiRuntime] state, profiles/groups from disk, and the
     * bundled yacd assets. Never logs the secret or full proxy URLs.
     */
    internal class LiveClashApiDeps(private val appContext: Context) : ClashApiDeps {

        override val versionName: String get() = BuildConfig.VERSION_NAME

        private fun settings() = SettingsStore(appContext)

        override fun secret(): String = settings().clashApiSecret

        override fun port(): Int = SettingsStore.clashApiPortInt(settings().clashApiPort)

        override fun baseUrl(): String = "http://127.0.0.1:${port()}"

        override fun allowLan(): Boolean = settings().clashApiAllowLan

        override fun mode(): String = settings().clashMode

        override fun setMode(mode: String) {
            settings().clashMode = mode
        }

        override fun groups(): List<ProxyGroup> =
            ClashApiRuntime.refreshGroups(appContext.filesDir).groups.toList()

        override fun mainGroup(): ProxyGroup? =
            ClashApiRuntime.refreshGroups(appContext.filesDir).mainGroup()

        override fun rules(): List<RouteRule> =
            ClashApiRuntime.refreshGroups(appContext.filesDir).rules.toList()

        override fun profiles(): List<ProfileItem> =
            ProfileStore(ProfileStore.defaultFile(appContext.filesDir))
                .apply { load() }.profiles.toList()

        override fun delays(): Map<String, Long?> =
            ClashApiRuntime.urlTestCache?.delays() ?: emptyMap()

        override fun delayMeasuredAtMs(guid: String): Long? =
            ClashApiRuntime.urlTestCache?.measuredAtMs(guid)

        override fun selectProxy(groupName: String, proxyName: String): Boolean {
            val store = ClashApiRuntime.refreshGroups(appContext.filesDir)
            val group = store.groups.firstOrNull { it.name == groupName } ?: return false
            // Display names are de-duplicated in the handler ("name #2");
            // match the same way here.
            val seen = HashMap<String, Int>()
            val unique = HashMap<String, String>()
            for (p in profiles()) {
                val base = p.displayName()
                val n = (seen[base] ?: 0) + 1
                seen[base] = n
                unique[p.guid] = if (n == 1) base else "$base #$n"
            }
            // v1.0.27: the name may be a nested group node ("tes"
            // inside "taptap") — the shared rule resolves it to
            // the nested group's id, a plain server name to its
            // guid, anything else to null (see ClashApiHandler).
            val ref = ClashApiHandler.selectMemberRef(store.groups, unique, groupName, proxyName)
                ?: return false
            store.updateGroup(group.copy(selectedMemberGuid = ref))
            val names = profiles().associateBy({ it.guid }, { it.displayName() })
            DialLog.log("CLASH", "pilih grup '$groupName' -> '${names[ref] ?: proxyName}'")
            return true
        }

        override fun delayTest(guid: String, url: String, timeoutMs: Int): Long? {
            val item = profiles().firstOrNull { it.guid == guid } ?: return null
            val result = runCatching {
                ServerTester.testRealPingThroughProxy(item, url, timeoutMs)
            }.getOrNull() ?: return null
            return result.ms.takeIf { it >= 0 }
        }

        override fun traffic(): Pair<Long, Long> =
            ClashApiRuntime.forwarder?.trafficTotals() ?: (0L to 0L)

        override fun connections(): List<ConnectionInfo> =
            ClashApiRuntime.forwarder?.activeConnections() ?: emptyList()

        override fun closeConnection(id: String): Boolean =
            ClashApiRuntime.forwarder?.closeConnection(id) ?: false

        override fun closeAllConnections() {
            ClashApiRuntime.forwarder?.activeConnections()
                ?.forEach { ClashApiRuntime.forwarder?.closeConnection(it.id) }
        }

        override fun logLines(): List<String> = DialLog.lines()

        override fun assetBytes(path: String): ByteArray? = runCatching {
            appContext.assets.open("yacd/$path").use { it.readBytes() }
        }.getOrNull()
    }
}
