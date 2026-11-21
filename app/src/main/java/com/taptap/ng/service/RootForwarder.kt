package com.taptap.ng.service

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.OriginalDst
import com.taptap.ng.core.RootIptables
import com.taptap.ng.core.RouteOnlyGate
import com.taptap.ng.core.Sniffer
import com.taptap.ng.core.proto.ProxyClient
import java.io.FileDescriptor
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Root mode — forwarder kedua (v1.0.15, requiredChanges #3 dari
 * [com.taptap.ng.core.RootModeAssessment]).
 *
 * BUKAN TUN: dua [ServerSocket] lokal menerima trafik yang
 * di-REDIRECT iptables ke 127.0.0.1:[RootIptables.DEFAULT_PROXY_PORT_HTTP]
 * (port 80) dan :[RootIptables.DEFAULT_PROXY_PORT_HTTPS] (port 443).
 * Alamat tujuan asli dibaca dari socket lewat SO_ORIGINAL_DST
 * ([OriginalDstResolver]); port tujuan diketahui dari listener
 * mana yang menerima (REDIRECT tidak menyimpan port asli di
 * socket — lihat [RootIptables]).
 *
 * Dial memakai [ProxyClient] yang sama dengan TunForwarder
 * (VMess/VLESS/Trojan/SS + WS/httpupgrade + TLS, transport
 * ladder yang sama) — tidak ada mesin dial kedua. Dial socket
 * aplikasi sendiri dikecualikan dari REDIRECT oleh aturan owner
 * UID, jadi tidak ada loop.
 *
 * Route-only: bila nyala, tujuan yang tidak dikenal di map
 * known-hosts (diisi [RootDnsRelay] dari jawaban DNS) DITOLAK
 * (tutup tanpa dial) — semantik sama seperti TUN
 * ([RouteOnlyGate]).
 *
 * Fail-closed: tujuan asli tidak bisa dibaca (resolver gagal —
 * mis. refleksi fd diblokir ROM) → koneksi DITUTUP tanpa dial,
 * bukan dial ke alamat tebak-tebakan.
 *
 * UDP: TIDAK lewat sini — UDP (QUIC/DNS-UDP) di Root mode v1
 * hanya DNS via [RootDnsRelay]; UDP lain jalan direct (batasan,
 * lihat README v1.0.15).
 */
class RootForwarder(
    private val proxy: ProxyClient,
    private val httpPort: Int = RootIptables.DEFAULT_PROXY_PORT_HTTP,
    private val httpsPort: Int = RootIptables.DEFAULT_PROXY_PORT_HTTPS,
    private val resolveOriginalDst: OriginalDstResolver = OsOriginalDstResolver(),
    private val routeOnlyEnabled: Boolean = false,
    private val knownHosts4: Map<Int, String> = emptyMap(),
    private val knownHosts6: Map<String, String> = emptyMap(),
    /** Pabrik listener; default socket TCP nyata, diganti fake di test. */
    private val listenerFactory: (InetAddress, Int) -> ServerSocket = { addr, port ->
        ServerSocket(port, 128, addr)
    },
) {

    /** Membaca alamat tujuan asli dari socket yang di-REDIRECT. */
    fun interface OriginalDstResolver {
        fun resolve(socket: Socket): InetAddress?
    }

    private val running = AtomicBoolean(false)
    private val listeners = ConcurrentHashMap<Int, ServerSocket>()
    private var acceptThreads = listOf<Thread>()

    fun isRunning(): Boolean = running.get()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val loopback = InetAddress.getByName("127.0.0.1")
        try {
            val http = listenerFactory(loopback, httpPort)
            val https = listenerFactory(loopback, httpsPort)
            listeners[httpPort] = http
            listeners[httpsPort] = https
        } catch (e: Exception) {
            running.set(false)
            runCatching { listeners.values.forEach { it.close() } }
            listeners.clear()
            throw e
        }
        acceptThreads = listeners.entries.map { (port, server) ->
            thread(name = "root-accept-$port", isDaemon = true) {
                acceptLoop(server, port)
            }
        }
        DialLog.log("ROOT", "forwarder jalan — 127.0.0.1:$httpPort (80) + :$httpsPort (443)")
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { listeners.values.forEach { it.close() } }
        listeners.clear()
        DialLog.log("ROOT", "forwarder berhenti")
    }

    private fun acceptLoop(server: ServerSocket, listenerPort: Int) {
        // Port tujuan asli = port yang di-REDIRECT ke listener ini.
        val impliedDstPort = if (listenerPort == httpPort) 80 else 443
        while (running.get()) {
            val socket = try {
                server.accept()
            } catch (_: IOException) {
                break
            }
            thread(name = "root-conn-$impliedDstPort", isDaemon = true) {
                handleConnection(socket, impliedDstPort)
            }
        }
    }

    private fun handleConnection(socket: Socket, dstPort: Int) {
        try {
            val dstAddr = resolveOriginalDst.resolve(socket)
            if (dstAddr == null) {
                DialLog.log("ROOT", "tujuan asli tidak terbaca — tutup tanpa dial")
                runCatching { socket.close() }
                return
            }
            val dstIp = TcpPacket.IpAddr(dstAddr.address)
            val refused = if (dstIp.isV4) {
                val v4 = Sniffer.ipv4ToInt(dstAddr)
                v4 != null && RouteOnlyGate.decide(routeOnlyEnabled, v4, knownHosts4) ==
                    RouteOnlyGate.Decision.REFUSE
            } else {
                RouteOnlyGate.decideV6(routeOnlyEnabled, dstIp.toString(), knownHosts6) ==
                    RouteOnlyGate.Decision.REFUSE
            }
            if (refused) {
                DialLog.log("ROOT", "ROUTE-ONLY tolak $dstAddr:$dstPort")
                runCatching { socket.close() }
                return
            }
            val dialHost = dstAddr.hostAddress
            DialLog.log("ROOT", "dial $dialHost:$dstPort")
            val stream = try {
                proxy.dial(dialHost, dstPort)
            } catch (e: Exception) {
                DialLog.failure("ROOT DIAL $dialHost:$dstPort", e)
                runCatching { socket.close() }
                return
            }
            relay(socket, stream)
        } catch (_: Exception) {
            runCatching { socket.close() }
        }
    }

    /** Relay dua arah (pola yang sama dengan SocksServer.relay). */
    private fun relay(socket: Socket, stream: com.taptap.ng.core.proto.ProxyStream) {
        val done = AtomicBoolean(false)
        fun finish() {
            if (done.compareAndSet(false, true)) {
                runCatching { stream.close() }
                runCatching { socket.close() }
            }
        }
        val t1 = thread(name = "root-relay-up", isDaemon = true) {
            pump(socket.getInputStream(), stream.output)
            finish()
        }
        val t2 = thread(name = "root-relay-down", isDaemon = true) {
            pump(stream.input, socket.getOutputStream())
            finish()
        }
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
}

/**
 * Resolver nyata: SO_ORIGINAL_DST lewat android.system.Os.
 * `Os.getsockoptInetAddress` hanya mengembalikan alamat (bukan
 * port) — port didapat dari listener (lihat [RootForwarder]).
 * fd socket diambil lewat refleksi (`Socket.impl.fd`); bila ROM
 * memblokir refleksi, resolve mengembalikan null dan koneksi
 * ditutup fail-closed (bukan dial buta). Best-effort, tidak
 * pernah melempar.
 *
 * v1.0.15, perbaikan kompilasi: `getsockoptInetAddress` adalah
 * hidden API (tidak ada di stub android.jar) dan `SOL_IP` tidak
 * ada di OsConstants — keduanya dipanggil lewat refleksi
 * (`Class.forName("android.system.Os")`, level IPPROTO_IP = 0,
 * option SO_ORIGINAL_DST = 80). Bila metode tidak ada di runtime,
 * resolve mengembalikan null (fail-closed).
 */
class OsOriginalDstResolver : RootForwarder.OriginalDstResolver {
    override fun resolve(socket: Socket): InetAddress? {
        return runCatching {
            val fd = socketFd(socket) ?: return null
            val osClass = Class.forName("android.system.Os")
            val method = osClass.getMethod(
                "getsockoptInetAddress",
                FileDescriptor::class.java,
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
            )
            method.invoke(null, fd, IPPROTO_IP, OriginalDst.SO_ORIGINAL_DST) as? InetAddress
        }.getOrNull()
    }

    companion object {
        /** IPPROTO_IP (== SOL_IP di Linux) = 0. */
        const val IPPROTO_IP = 0
    }

    private fun socketFd(socket: Socket): FileDescriptor? {
        var cls: Class<*>? = socket.javaClass
        // Socket.impl (java.net.Socket) — cari di hierarki kelas.
        var impl: Any? = null
        var c: Class<*>? = Socket::class.java
        while (c != null && impl == null) {
            runCatching {
                val f = c.getDeclaredField("impl").apply { isAccessible = true }
                impl = f.get(socket)
            }
            c = c.superclass
        }
        impl ?: return null
        // SocketImpl.fd (java.net.SocketImpl).
        var ic: Class<*>? = impl.javaClass
        while (ic != null) {
            runCatching {
                val f = ic.getDeclaredField("fd").apply { isAccessible = true }
                return f.get(impl) as? FileDescriptor
            }
            ic = ic.superclass
        }
        return null
    }
}
