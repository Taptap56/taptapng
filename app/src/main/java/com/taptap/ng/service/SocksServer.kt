package com.taptap.ng.service

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.ProxyStream
import com.taptap.ng.data.SettingsStore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.SequenceInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.UnknownHostException
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Local SOCKS5 proxy (v1.0.5, kelompok B). In-app, tanpa xray-core:
 * satu listener TCP melayani SOCKS5 dan — bila [SocksConfig.appendHttpProxy]
 * — HTTP CONNECT.
 *
 * Keputusan implementasi HTTP CONNECT (didokumentasikan di sini,
 * bukan diam-diam): TIDAK ada port terpisah. Listener yang sama
 * mendeteksi protokol dari byte pertama — 0x05 = SOCKS5, sisanya
 * dibaca sebagai request line HTTP. Alasannya: v2rayNG hanya punya
 * satu angka port di Settings ("Local proxy port"), jadi port kedua
 * tidak punya tempat di UI; deteksi byte pertama tidak ambigu
 * (request HTTP selalu diawali huruf metode, SOCKS5 selalu 0x05).
 * Bila appendHttpProxy OFF, byte non-SOCKS langsung menutup koneksi
 * tanpa balasan.
 *
 * TCP CONNECT dial lewat jalur proxy yang sama dengan TunForwarder:
 * [dial] adalah `ProxyClient.dial` milik entry yang sedang jalan
 * (transport ladder + protocol handshake yang sama, termasuk
 * protect() bypass TUN) — tidak ada mesin dial kedua.
 *
 * UDP ASSOCIATE (socksEnableUdp): SELALU DITOLAK dengan REP 0x07
 * (Command not supported), apa pun nilai settingnya. M2 hanya punya
 * jalur TCP — tidak ada jalur UDP lewat tunnel — jadi menerima
 * perintah itu lalu diam adalah kebohongan; penolakan eksplisit
 * adalah perilaku yang benar menurut RFC 1928. Setting
 * socksEnableUdp tetap disimpan (paritas Settings) dan dilaporkan
 * di log start sebagai "UDP: tidak didukung di M2".
 *
 * Lifecycle: hidup/mati mengikuti tunnel — service memanggil
 * [start] sesudah TUN naik dan [stop] saat teardown, hanya bila
 * local proxy efektif ([SettingsStore.isLocalProxyEffective]:
 * enableLocalProxy ON, atau useHevTun ON yang memaksanya).
 * Gagal bind (port sudah dipakai) TIDAK boleh membunuh tunnel:
 * service menangkapnya dan tunnel tetap jalan tanpa SOCKS.
 *
 * Kredensial tidak pernah di-log (hanya "auth: on/off").
 */
class SocksServer(
    private val config: SocksConfig,
    /** Satu stream proxied ke [host]:[port], jalur yang sama dengan forwarder. */
    private val dial: (host: String, port: Int) -> ProxyStream,
    /** Pabrik listener; default socket TCP nyata, diganti fake di test. */
    private val listenerFactory: (InetAddress, Int) -> SocksListener = { addr, port ->
        TcpSocksListener(addr, port)
    },
) {

    /** Port yang benar-benar ter-bind (dynamic = pilihan OS, dilaporkan ke log). */
    @Volatile
    var actualPort: Int = -1
        private set

    @Volatile
    var isRunning: Boolean = false
        private set

    private val stopped = AtomicBoolean(false)
    private var listener: SocksListener? = null
    private val sessions = ConcurrentHashSet<SocksConnection>()

    fun start() {
        check(!isRunning) { "SOCKS sudah jalan" }
        stopped.set(false)
        val bindAddr = config.bindAddress()
        val requested = config.requestedPort()
        val l = listenerFactory(bindAddr, requested)
        listener = l
        actualPort = l.localPort
        isRunning = true
        DialLog.log(
            "SOCKS",
            "SOCKS proxy jalan di ${l.localAddress.hostAddress}:$actualPort" +
                " (auth: ${if (config.requireAuth) "on" else "off"}" +
                ", HTTP CONNECT: ${if (config.appendHttpProxy) "on" else "off"}" +
                ", UDP: tidak didukung di M2)",
        )
        thread(name = "socks-accept", isDaemon = true) {
            while (!stopped.get()) {
                val conn = try {
                    l.accept()
                } catch (_: IOException) {
                    break
                } catch (_: Exception) {
                    break
                }
                sessions.add(conn)
                thread(name = "socks-conn", isDaemon = true) {
                    try {
                        handleConnection(conn.input, conn.output)
                    } catch (_: Exception) {
                        // Klien putus / handshake rusak: tutup saja,
                        // jangan bunuh accept loop.
                    } finally {
                        sessions.remove(conn)
                        runCatching { conn.close() }
                    }
                }
            }
        }
    }

    fun stop() {
        if (stopped.compareAndSet(false, true)) {
            isRunning = false
            runCatching { listener?.close() }
            listener = null
            // Tutup sesi aktif supaya relay thread bangun dan mati.
            sessions.toList().forEach { runCatching { it.close() } }
            sessions.clear()
            DialLog.log("SOCKS", "SOCKS proxy berhenti")
        }
    }

    /**
     * Satu koneksi klien, in-memory testable: [input]/[output] boleh
     * pipe pair — tidak ada socket di sini. Byte pertama menentukan
     * protokol (lihat header file).
     */
    fun handleConnection(input: InputStream, output: OutputStream) {
        val first = input.read()
        if (first == -1) return
        if (first == 0x05) {
            handleSocks5(input, output)
        } else if (config.appendHttpProxy) {
            val rest = SequenceInputStream(
                ByteArrayInputStream(byteArrayOf(first.toByte())),
                input,
            )
            handleHttpConnect(rest, output)
        }
        // appendHttpProxy OFF + byte non-SOCKS: tutup tanpa balasan.
    }

    // ---- SOCKS5 (RFC 1928) ----

    private fun handleSocks5(input: InputStream, output: OutputStream) {
        val nMethods = input.read()
        if (nMethods == -1) return
        val methods = input.readExactBytes(nMethods)
        val chosen: Int = when {
            config.requireAuth && methods.contains(0x02.toByte()) -> 0x02
            !config.requireAuth && methods.contains(0x00.toByte()) -> 0x00
            else -> 0xFF
        }
        output.write(byteArrayOf(0x05, chosen.toByte()))
        output.flush()
        if (chosen == 0xFF) return
        if (chosen == 0x02 && !authenticate(input, output)) return
        val request = readRequest(input) ?: return
        when (request.command) {
            CMD_CONNECT -> {
                val stream = try {
                    dial(request.host, request.port)
                } catch (e: Exception) {
                    writeReply(output, mapDialFailure(e), request)
                    return
                }
                writeReply(output, REP_SUCCESS, request)
                relay(input, output, stream)
            }
            // UDP ASSOCIATE + BIND: tidak ada jalurnya di M2 —
            // tolak eksplisit (REP 0x07), jangan pura-pura jalan.
            else -> writeReply(output, REP_COMMAND_NOT_SUPPORTED, request)
        }
    }

    /** Subnegosiasi user/pass (RFC 1929). True = kredensial cocok. */
    private fun authenticate(input: InputStream, output: OutputStream): Boolean {
        val ver = input.read()
        if (ver != 0x01) return false
        val uLen = input.read()
        if (uLen == -1) return false
        val user = input.readExactBytes(uLen).toString(Charsets.UTF_8)
        val pLen = input.read()
        if (pLen == -1) return false
        val pass = input.readExactBytes(pLen).toString(Charsets.UTF_8)
        val ok = user == config.socksUsername && pass == config.socksPassword
        output.write(byteArrayOf(0x01, if (ok) 0x00 else 0x01))
        output.flush()
        return ok
    }

    private data class SocksRequest(val command: Int, val host: String, val port: Int)

    private fun readRequest(input: InputStream): SocksRequest? {
        val ver = input.read()
        if (ver != 0x05) return null
        val cmd = input.read()
        if (cmd == -1) return null
        input.read() // RSV
        val atyp = input.read()
        val host = when (atyp) {
            ATYP_IPV4 -> {
                val b = input.readExactBytes(4)
                b.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }
            ATYP_DOMAIN -> {
                val len = input.read()
                if (len == -1) return null
                input.readExactBytes(len).toString(Charsets.UTF_8)
            }
            ATYP_IPV6 -> {
                val b = input.readExactBytes(16)
                InetAddress.getByAddress(b).hostAddress
            }
            else -> return null
        }
        val portBytes = input.readExactBytes(2)
        val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
        return SocksRequest(cmd, host, port)
    }

    private fun mapDialFailure(e: Exception): Int = when (e) {
        is UnknownHostException -> REP_HOST_UNREACHABLE
        is IOException -> REP_CONNECTION_REFUSED
        else -> REP_GENERAL_FAILURE
    }

    private fun writeReply(output: OutputStream, rep: Int, request: SocksRequest) {
        // BND.ADDR: alamat bind listener bila ada, else 0.0.0.0.
        val bind = listener?.localAddress ?: InetAddress.getByName("0.0.0.0")
        val addrBytes = bind.address
        val reply = ByteArrayOutputStream().apply {
            write(0x05)
            write(rep)
            write(0x00)
            write(ATYP_IPV4)
            write(addrBytes)
            val p = if (actualPort > 0) actualPort else 0
            write((p shr 8) and 0xFF)
            write(p and 0xFF)
        }
        output.write(reply.toByteArray())
        output.flush()
    }

    // ---- HTTP CONNECT (appendHttpProxy, listener yang sama) ----

    private fun handleHttpConnect(input: InputStream, output: OutputStream) {
        val head = readHttpHead(input) ?: return
        val lines = head.split("\r\n")
        val requestLine = lines.firstOrNull() ?: return
        val parts = requestLine.split(" ")
        if (parts.size < 3 || parts[0] != "CONNECT") {
            output.write("HTTP/1.1 405 Method Not Allowed\r\n\r\n".toByteArray(Charsets.US_ASCII))
            output.flush()
            return
        }
        if (config.requireAuth) {
            val auth = lines.firstOrNull { it.startsWith("Proxy-Authorization:", ignoreCase = true) }
                ?.substringAfter(":", "")
                ?.trim()
            val expected = "Basic " + Base64.getEncoder().encodeToString(
                "${config.socksUsername}:${config.socksPassword}".toByteArray(Charsets.UTF_8),
            )
            if (auth != expected) {
                output.write(
                    "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"
                        .toByteArray(Charsets.US_ASCII),
                )
                output.flush()
                return
            }
        }
        val target = parts[1]
        val host = target.substringBeforeLast(":")
        val port = target.substringAfterLast(":", "").toIntOrNull()
        if (host.isBlank() || port == null || port !in 1..65535) {
            output.write("HTTP/1.1 400 Bad Request\r\n\r\n".toByteArray(Charsets.US_ASCII))
            output.flush()
            return
        }
        val stream = try {
            dial(host, port)
        } catch (_: Exception) {
            output.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray(Charsets.US_ASCII))
            output.flush()
            return
        }
        output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII))
        output.flush()
        relay(input, output, stream)
    }

    /** Baca head HTTP sampai \r\n\r\n (dibatasi 8 KB supaya klien nakal tidak OOM). */
    private fun readHttpHead(input: InputStream): String? {
        val buf = ByteArrayOutputStream()
        val window = ArrayDeque<Int>()
        while (buf.size() < 8192) {
            val b = input.read()
            if (b == -1) return null
            buf.write(b)
            window.addLast(b)
            if (window.size > 4) window.removeFirst()
            if (window.size == 4 && window.toList() == listOf(13, 10, 13, 10)) {
                return buf.toString(Charsets.US_ASCII.name())
            }
        }
        return null
    }

    // ---- Relay dua arah ----

    /**
     * Pompa byte dua arah antara klien dan stream proxy. Satu arah
     * selesai (EOF/error) → keduanya ditutup, thread pasangannya
     * bangun dari read dan mati juga. Mirip relay TunForwarder,
     * tapi di atas stream, bukan paket TUN.
     */
    private fun relay(clientIn: InputStream, clientOut: OutputStream, stream: ProxyStream) {
        val done = AtomicBoolean(false)
        fun finish() {
            if (done.compareAndSet(false, true)) {
                runCatching { stream.close() }
                runCatching { clientIn.close() }
                runCatching { clientOut.close() }
            }
        }
        val t1 = thread(name = "socks-relay-up", isDaemon = true) {
            pump(clientIn, stream.output)
            finish()
        }
        val t2 = thread(name = "socks-relay-down", isDaemon = true) {
            pump(stream.input, clientOut)
            finish()
        }
        // handleConnection kembali hanya sesudah relay selesai —
        // thread koneksi milik sesi ini, jadi join di sini aman.
        t1.join()
        t2.join()
    }

    private fun pump(input: InputStream, output: OutputStream) {
        val buf = ByteArray(8192)
        try {
            while (true) {
                val n = input.read(buf)
                if (n == -1) break
                output.write(buf, 0, n)
                output.flush()
            }
        } catch (_: IOException) {
            // Sisi lain tutup duluan — finish() menutup sisanya.
        }
    }

    companion object {
        const val REP_SUCCESS = 0x00
        const val REP_GENERAL_FAILURE = 0x01
        const val REP_CONNECTION_REFUSED = 0x05
        const val REP_HOST_UNREACHABLE = 0x04
        const val REP_COMMAND_NOT_SUPPORTED = 0x07
        const val CMD_CONNECT = 0x01
        const val CMD_BIND = 0x02
        const val CMD_UDP_ASSOCIATE = 0x03
        const val ATYP_IPV4 = 0x01
        const val ATYP_DOMAIN = 0x03
        const val ATYP_IPV6 = 0x04
    }
}

/** Set sekali-tulis; dipakai untuk sesi aktif yang harus ditutup saat stop(). */
private class ConcurrentHashSet<T> {
    private val map = java.util.concurrent.ConcurrentHashMap<T, Boolean>()
    fun add(v: T) {
        map[v] = true
    }
    fun remove(v: T) {
        map.remove(v)
    }
    fun toList(): List<T> = map.keys.toList()
    fun clear() = map.clear()
}

/**
 * Konfigurasi SOCKS dari Settings — logika murni (tanpa Context),
 * jadi bisa dikunci test JVM.
 *
 * - Bind: proxySharing ATAU lanSharing ON → 0.0.0.0 (dengar di LAN);
 *   keduanya OFF → hanya 127.0.0.1.
 * - Port: dynamicSocksPort ON → 0 (OS yang pilih, dilaporkan di
 *   [SocksServer.actualPort]); OFF → socksPort, kosong / di luar
 *   1..65535 → 10808 (display default v2rayNG).
 * - Auth: hanya bila username DAN password sama-sama terisi.
 */
data class SocksConfig(
    val proxySharing: Boolean = false,
    val lanSharing: Boolean = false,
    val dynamicSocksPort: Boolean = false,
    val socksPort: String = "",
    val socksUsername: String = "",
    val socksPassword: String = "",
    val socksEnableUdp: Boolean = true,
    val appendHttpProxy: Boolean = false,
) {
    val requireAuth: Boolean
        get() = socksUsername.isNotBlank() && socksPassword.isNotBlank()

    fun bindAddress(): InetAddress =
        if (proxySharing || lanSharing) {
            InetAddress.getByName("0.0.0.0")
        } else {
            InetAddress.getLoopbackAddress()
        }

    fun requestedPort(): Int =
        if (dynamicSocksPort) {
            0
        } else {
            socksPort.trim().toIntOrNull()?.takeIf { it in 1..65535 } ?: 10808
        }

    companion object {
        fun fromSettings(settings: SettingsStore): SocksConfig = SocksConfig(
            proxySharing = settings.proxySharing,
            lanSharing = settings.lanSharing,
            dynamicSocksPort = settings.dynamicSocksPort,
            socksPort = settings.socksPort,
            socksUsername = settings.socksUsername,
            socksPassword = settings.socksPassword,
            socksEnableUdp = settings.socksEnableUdp,
            appendHttpProxy = settings.appendHttpProxy,
        )
    }
}

/** Abstraksi listener supaya test bisa start/stop tanpa socket nyata. */
interface SocksListener {
    val localPort: Int
    val localAddress: InetAddress
    fun accept(): SocksConnection
    fun close()
}

interface SocksConnection {
    val input: InputStream
    val output: OutputStream
    fun close()
}

/** Listener TCP nyata (produksi): ServerSocket + Socket biasa. */
class TcpSocksListener(bindAddr: InetAddress, port: Int) : SocksListener {
    private val serverSocket = ServerSocket(port, 50, bindAddr)

    override val localPort: Int get() = serverSocket.localPort
    override val localAddress: InetAddress get() = serverSocket.inetAddress

    override fun accept(): SocksConnection {
        val socket: Socket = serverSocket.accept()
        return object : SocksConnection {
            override val input: InputStream = socket.getInputStream()
            override val output: OutputStream = socket.getOutputStream()
            override fun close() {
                runCatching { socket.close() }
            }
        }
    }

    override fun close() {
        runCatching { serverSocket.close() }
    }
}

/** Baca tepat [n] byte atau lempar EOFException (dipakai handshake SOCKS). */
private fun InputStream.readExactBytes(n: Int): ByteArray {
    val out = ByteArray(n)
    var filled = 0
    while (filled < n) {
        val r = read(out, filled, n - filled)
        if (r == -1) throw EOFException("Stream terpotong (EOF), butuh $n byte, dapat $filled")
        filled += r
    }
    return out
}
