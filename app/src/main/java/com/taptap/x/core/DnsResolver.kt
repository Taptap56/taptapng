package com.taptap.x.core

import com.taptap.x.core.proto.AddrCodec
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.ThreadLocalRandom
import kotlin.concurrent.thread

/**
 * Resolver DNS langsung yang TIDAK memakai resolver sistem Android.
 *
 * Masalah yang diperbaiki (laporan HP v1.0.4, 2026-11-20 01:50):
 * dial dan delay test menggantung di "Connecting..." / "Timeout" saat
 * VPN naik, padahal entry yang sama konek di v2rayNG. Penyebabnya:
 * `Transport.open` dan `ServerTester.testTcp` memakai
 * `InetSocketAddress(host, port)` — konstruktor itu memanggil resolver
 * sistem TANPA timeout. Saat VPN naik, query DNS sistem masuk ke TUN
 * dan harus dilayani relay DNS [com.taptap.x.service.TunForwarder]
 * (jalur yang belum pernah terbukti jalan di HP) — chicken-and-egg:
 * dial butuh DNS, DNS butuh relay yang butuh dial.
 *
 * Resolver ini mengirim query DNS (UDP) langsung ke 8.8.8.8:53 dari
 * [DatagramSocket] yang di-protect (bypass TUN), dengan timeout
 * tegas. v2rayNG tidak kena masalah ini karena xray-core resolve
 * sendiri lewat socket ter-protect — perilaku ini menirunya.
 *
 * Bila query langsung gagal, pemanggil memakai
 * [resolveWithSystemFallback]: fallback ke resolver sistem (relay DNS
 * TUN mungkin saja berfungsi), tapi lookup sistem itu pun dibatasi
 * thread + timeout agar dial tidak pernah menggantung tanpa batas lagi.
 */
object DnsResolver {

    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val CLASS_IN = 1
    const val DEFAULT_TIMEOUT_MS = 3000

    /** Server DNS untuk query langsung (IP literal, tanpa lookup). */
    @Volatile
    var dnsServer: String = "8.8.8.8"

    /** Port server DNS (53). Diubah tes untuk menunjuk server DNS palsu lokal. */
    @Volatile
    var dnsPort: Int = 53

    /**
     * Hook protect untuk socket DNS (VpnService.protect), dipasang
     * service saat VPN naik — pola yang sama dengan
     * `Transport.protectSocket`. Null = tanpa protect (unit test, atau
     * VPN mati). Bila hook menolak (false) DAN TUN sudah naik, query
     * TIDAK dikirim: query tanpa protect masuk lagi ke TUN dan
     * berputar di relay. Bila TUN belum naik ([TunnelState.up] false)
     * protect tidak dipaksakan — protect() mengembalikan false sebelum
     * establish(), jadi query langsung jalan tanpa protect (v1.0.7:
     * kalau tidak, dial probe untuk entry ber-domain mati di DNS
     * sebelum sempat mencoba resolver sistem). v1.0.9: penolakan juga
     * tidak fatal bila [TunnelState.appBypass] — aplikasi di-disallow
     * dari VPN, jadi query bypass di level routing (pola v2rayNG;
     * di HP ini protect() mengembalikan false begitu TUN naik).
     */
    @Volatile
    var protectUdp: ((DatagramSocket) -> Boolean)? = null

    /**
     * Resolve [host] ke [InetAddress] lewat query DNS langsung.
     * IP literal dikembalikan tanpa lookup apa pun. Tanya A dulu;
     * bila server menjawab tapi tanpa record A, coba AAAA.
     * @throws IOException bila timeout / tidak ada jawaban / protect gagal.
     */
    fun resolve(host: String, timeoutMs: Int = DEFAULT_TIMEOUT_MS): InetAddress {
        require(host.isNotBlank()) { "Host DNS kosong" }
        val clean = host.trim().trimEnd('.')
        if (AddrCodec.isIpLiteral(clean)) {
            // Literal: getByName tidak pernah lookup DNS untuk literal.
            return InetAddress.getByName(clean)
        }
        // Timeout di sini langsung dilempar — jangan buang waktu coba
        // AAAA bila servernya saja tidak menjawab.
        val aAnswers = queryOnce(clean, TYPE_A, timeoutMs)
        aAnswers.firstOrNull()?.let { return it }
        val aaaaAnswers = queryOnce(clean, TYPE_AAAA, timeoutMs)
        return aaaaAnswers.firstOrNull()
            ?: throw IOException("DNS $dnsServer tidak ada jawaban A/AAAA untuk $host")
    }

    /**
     * Resolve dengan fallback ke resolver sistem. Dipakai dial dan
     * delay test: bila query langsung gagal (mis. UDP 53 diblokir),
     * coba resolver sistem — relay DNS TUN mungkin berfungsi di HP
     * itu. Lookup sistem dibatasi [timeoutMs] lewat thread terpisah,
     * karena `InetSocketAddress(host, port)` memanggil resolver
     * sistem tanpa timeout.
     * @throws IOException bila kedua jalur gagal (pesan ber-tag "DNS gagal").
     */
    fun resolveWithSystemFallback(
        host: String,
        port: Int,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
    ): InetAddress {
        require(host.isNotBlank()) { "Host DNS kosong" }
        val clean = host.trim().trimEnd('.')
        if (AddrCodec.isIpLiteral(clean)) {
            return InetAddress.getByName(clean)
        }
        try {
            return resolve(clean, timeoutMs)
        } catch (e: IOException) {
            // Fallback: resolver sistem (relay DNS TUN mungkin jalan).
            try {
                val resolved = systemResolve(clean, port, timeoutMs)
                return resolved.address
                    ?: throw IOException("DNS gagal untuk $host: ${e.message}", e)
            } catch (e2: Exception) {
                throw IOException("DNS gagal untuk $host: ${e2.message ?: e.message}", e2)
            }
        }
    }

    /**
     * Satu query DNS (tipe [qtype]) ke server langsung. Mengembalikan
     * daftar alamat dari jawaban (A dulu, lalu AAAA) — kosong bila
     * server menjawab tanpa record yang cocok.
     * @throws IOException bila timeout / protect gagal.
     */
    private fun queryOnce(host: String, qtype: Int, timeoutMs: Int): List<InetAddress> {
        val id = ThreadLocalRandom.current().nextInt(0, 65536)
        val query = buildQuery(host, id, qtype)
        val socket = DatagramSocket()
        try {
            val protect = protectUdp
            if (protect != null && TunnelState.up && !protect(socket)) {
                if (TunnelState.appBypass) {
                    // v1.0.9: protect() refused, but the app is
                    // disallowed from the VPN — the query bypasses
                    // at the routing level and cannot loop back into
                    // the relay (v2rayNG pattern; on this phone
                    // protect() returns false once the TUN is up).
                    DialLog.log(
                        "PROTECT",
                        "protect() gagal — query DNS $host lanjut via disallow aplikasi",
                    )
                } else {
                    throw IOException("protect() gagal — query DNS tidak bisa bypass VPN")
                }
            }
            socket.soTimeout = timeoutMs
            socket.send(DatagramPacket(query, query.size, dnsServerAddress(), dnsPort))
            val buf = ByteArray(2048)
            val resp = DatagramPacket(buf, buf.size)
            try {
                socket.receive(resp)
            } catch (e: SocketTimeoutException) {
                throw IOException("DNS $dnsServer timeout untuk $host")
            }
            return parseAnswers(resp.data.copyOf(resp.length), id)
        } finally {
            socket.close()
        }
    }

    /**
     * Bangun pesan query DNS standar: header 12 byte, 1 pertanyaan,
     * RD=1. Diekspos untuk tes (bangun query lalu parse jawabannya
     * tanpa jaringan).
     */
    fun buildQuery(host: String, id: Int, qtype: Int = TYPE_A): ByteArray {
        require(host.isNotBlank()) { "Host DNS kosong" }
        val labels = host.trim().trimEnd('.').split(".")
        var size = 12 + 1 + 4 // header + byte root 0 + QTYPE/QCLASS
        val labelBytes = labels.map { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.isNotEmpty() && bytes.size <= 63) {
                "Label DNS tidak valid: $label"
            }
            size += 1 + bytes.size
            bytes
        }
        val buf = ByteArray(size)
        buf[0] = ((id ushr 8) and 0xFF).toByte()
        buf[1] = (id and 0xFF).toByte()
        buf[2] = 0x01 // RD=1 (minta recursive)
        buf[3] = 0x00
        buf[4] = 0x00 // QDCOUNT = 1
        buf[5] = 0x01
        // ANCOUNT/NSCOUNT/ARCOUNT = 0 (sudah nol dari ByteArray).
        var pos = 12
        for (bytes in labelBytes) {
            buf[pos++] = bytes.size.toByte()
            bytes.copyInto(buf, pos)
            pos += bytes.size
        }
        buf[pos++] = 0 // akhir QNAME (root)
        buf[pos++] = 0x00
        buf[pos++] = qtype.toByte() // QTYPE
        buf[pos++] = 0x00
        buf[pos] = 0x01 // QCLASS = IN
        return buf
    }

    /**
     * Parse jawaban DNS: lewati pertanyaan, baca semua answer, ambil
     * RDATA A (4 byte) dan AAAA (16 byte). Kompresi pointer 0xC0
     * ditangani. Mengembalikan record A dulu, lalu AAAA (pemanggil
     * memprioritaskan IPv4). Jawaban rusak / ID tidak cocok /
     * bukan response → daftar kosong.
     */
    fun parseAnswers(response: ByteArray, expectedId: Int? = null): List<InetAddress> {
        if (response.size < 12) return emptyList()
        val id = u16(response, 0)
        if (expectedId != null && id != expectedId) return emptyList()
        val flags = u16(response, 2)
        if (flags and 0x8000 == 0) return emptyList() // bukan response (QR=0)
        val qdCount = u16(response, 4)
        val anCount = u16(response, 6)
        var pos = 12
        repeat(qdCount) {
            pos = skipName(response, pos) ?: return emptyList()
            if (pos + 4 > response.size) return emptyList()
            pos += 4 // QTYPE + QCLASS
        }
        val a = mutableListOf<InetAddress>()
        val aaaa = mutableListOf<InetAddress>()
        repeat(anCount) {
            pos = skipName(response, pos) ?: return emptyList()
            if (pos + 10 > response.size) return emptyList()
            val type = u16(response, pos)
            val rdLen = u16(response, pos + 8)
            pos += 10 // TYPE + CLASS + TTL + RDLENGTH
            if (pos + rdLen > response.size) return emptyList()
            when (type) {
                TYPE_A -> if (rdLen == 4) {
                    a += InetAddress.getByAddress(response.copyOfRange(pos, pos + 4))
                }
                TYPE_AAAA -> if (rdLen == 16) {
                    aaaa += InetAddress.getByAddress(response.copyOfRange(pos, pos + 16))
                }
            }
            pos += rdLen
        }
        return a + aaaa
    }

    /**
     * Lewati satu nama DNS (label berurutan atau pointer kompresi
     * 0xC0). Mengembalikan posisi byte setelah nama, atau null bila
     * pesan terpotong / label tidak dikenal.
     */
    private fun skipName(msg: ByteArray, start: Int): Int? {
        var pos = start
        while (true) {
            if (pos >= msg.size) return null
            val len = msg[pos].toInt() and 0xFF
            when {
                len == 0 -> return pos + 1
                len and 0xC0 == 0xC0 -> {
                    // Pointer kompresi: 2 byte, nama berakhir di sini.
                    if (pos + 1 >= msg.size) return null
                    return pos + 2
                }
                len and 0xC0 != 0 -> return null // label 0x40/0x80 tidak dikenal
                else -> {
                    pos += 1 + len
                    if (pos > msg.size) return null
                }
            }
        }
    }

    /** Resolver sistem dengan batas waktu: konstruktor InetSocketAddress
     *  memanggil resolver sistem tanpa timeout, jadi jalankan di thread
     *  terpisah dan tunggu paling lama [timeoutMs]. Thread yang masih
     *  menggantung ditinggalkan (daemon) — dial sudah gagal cepat. */
    private fun systemResolve(host: String, port: Int, timeoutMs: Int): InetSocketAddress {
        var result: InetSocketAddress? = null
        var error: Throwable? = null
        val t = thread(name = "sys-dns", isDaemon = true) {
            try {
                result = InetSocketAddress(host, port)
            } catch (e: Throwable) {
                error = e
            }
        }
        t.join(timeoutMs.toLong())
        if (t.isAlive) throw SocketTimeoutException("DNS sistem timeout untuk $host")
        error?.let { throw it }
        return result ?: throw UnknownHostException(host)
    }

    /** Alamat server DNS. Literal IPv4 diparse manual (tanpa lookup);
     *  nilai lain (hanya untuk override tes, mis. "localhost") lewat
     *  resolver sistem. */
    private fun dnsServerAddress(): InetAddress {
        val s = dnsServer
        return if (AddrCodec.isIpv4(s)) {
            val parts = s.split(".")
            InetAddress.getByAddress(ByteArray(4) { parts[it].toInt().toByte() })
        } else {
            InetAddress.getByName(s)
        }
    }

    private fun u16(buf: ByteArray, pos: Int): Int =
        ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
}
