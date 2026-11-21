package com.taptap.ng.service

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.DnsResolver
import com.taptap.ng.core.RootIptables
import com.taptap.ng.core.Sniffer
import com.taptap.ng.core.proto.ProxyClient
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Root mode — relay DNS lokal (v1.0.15, requiredChanges #4 dari
 * [com.taptap.ng.core.RootModeAssessment]).
 *
 * iptables me-REDIRECT UDP 53 (lokal + tether) ke port ini.
 * Tiap query diteruskan lewat [ProxyClient.dialUdp] ke upstream
 * (default 8.8.8.8:53) — jadi jawaban DNS datang lewat tunnel,
 * bukan direct, dan tidak bocor ke operator. Jawaban dicatat ke
 * [recordHost] (IP → hostname) supaya gate route-only
 * [RootForwarder] mengenali tujuan yang baru di-resolve — sama
 * seperti relay DNS TunForwarder.
 *
 * Satu sesi dialUdp per query (sederhana; query DNS jarang dan
 * pendek — sesi per query lebih murah daripada cache sesi yang
 * harus disapu). Timeout 5 dtk; query yang timeout dibuang
 * tanpa balasan (klien DNS akan retry).
 */
class RootDnsRelay(
    private val proxy: ProxyClient,
    private val upstreamHost: String = "8.8.8.8",
    private val upstreamPort: Int = 53,
    private val port: Int = RootIptables.DEFAULT_DNS_PORT,
    private val recordHost: (InetAddress, String) -> Unit = { _, _ -> },
    /** Pabrik socket; default socket UDP nyata, diganti fake di test. */
    private val socketFactory: (Int) -> DatagramSocket = { p ->
        DatagramSocket(p, InetAddress.getByName("127.0.0.1"))
    },
) {

    private val running = AtomicBoolean(false)
    private var socket: DatagramSocket? = null
    private var loopThread: Thread? = null

    fun isRunning(): Boolean = running.get()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val s = socketFactory(port)
        socket = s
        loopThread = thread(name = "root-dns", isDaemon = true) { loop(s) }
        DialLog.log("ROOT", "relay DNS jalan — 127.0.0.1:$port -> $upstreamHost:$upstreamPort (lewat proxy)")
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { socket?.close() }
        socket = null
        DialLog.log("ROOT", "relay DNS berhenti")
    }

    private fun loop(socket: DatagramSocket) {
        val buf = ByteArray(2048)
        while (running.get()) {
            val pkt = DatagramPacket(buf, buf.size)
            try {
                socket.receive(pkt)
            } catch (_: Exception) {
                break
            }
            val query = pkt.data.copyOfRange(0, pkt.length)
            val src = InetSocketAddress(pkt.address, pkt.port)
            thread(name = "root-dns-q", isDaemon = true) {
                handleQuery(socket, query, src)
            }
        }
    }

    private fun handleQuery(socket: DatagramSocket, query: ByteArray, src: java.net.InetSocketAddress) {
        try {
            val session = proxy.dialUdp(upstreamHost, upstreamPort)
            try {
                session.send(query)
                val resp = session.receive(5000)
                if (resp != null) {
                    recordAnswers(query, resp)
                    val out = DatagramPacket(resp, resp.size, src.address, src.port)
                    socket.send(out)
                }
            } finally {
                runCatching { session.close() }
            }
        } catch (e: Exception) {
            DialLog.failure("ROOT DNS", e)
        }
    }

    /** Catat IP jawaban → hostname yang ditanya (route-only). */
    private fun recordAnswers(query: ByteArray, resp: ByteArray) {
        runCatching {
            val qName = Sniffer.parseDnsQueryName(query) ?: return
            val qId = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
            for (addr in DnsResolver.parseAnswers(resp, qId)) {
                recordHost(addr, qName)
            }
        }
    }
}
