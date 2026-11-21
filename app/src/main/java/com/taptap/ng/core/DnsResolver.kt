package com.taptap.ng.core

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.taptap.ng.core.proto.AddrCodec
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap
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
 * dan harus dilayani relay DNS [com.taptap.ng.service.TunForwarder]
 * (jalur yang belum pernah terbukti jalan di HP) — chicken-and-egg:
 * dial butuh DNS, DNS butuh relay yang butuh dial.
 *
 * Resolver ini mengirim query DNS (UDP) langsung ke 8.8.8.8:53 dari
 * [DatagramSocket] yang di-protect (bypass TUN), dengan timeout
 * tegas. v2rayNG tidak kena masalah ini karena xray-core resolve
 * sendiri lewat socket ter-protect — perilaku ini menirunya.
 *
 * v1.0.4 (review Claude atas v1.0.3): jalur PERTAMA adalah resolver
 * jaringan fisik operator — `Network.getAllByName` pada jaringan
 * non-VPN, cara XVEON me-resolve host proxy. Hipotesisnya (BELUM
 * TERBUKTI): jendela operator terbuka lewat lookup DNS operator atau
 * lewat IP yang dikembalikan resolver operator; prime TaptapNG tidak
 * pernah menyentuh resolver itu. Fallback tetap UDP langsung lalu
 * sistem, jadi bila jaringan operator tidak menjawab, perilaku lama
 * dipertahankan. Dial utama juga merotasi ke alamat berikutnya di
 * cache setelah TLS timeout ([rotateAfterTlsFailure]).
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

    /**
     * Pemetaan host statis (v1.0.5, kelompok C — setting dnsHosts,
     * "domain:ip" per baris). Dicek PALING DULU di [resolve] dan
     * [resolveAll] — menang atas hook operator, UDP langsung, dan
     * sistem. Dipasang service dari Settings tiap tunnel naik;
     * dikosongkan lagi di teardown. Map key = domain lowercase
     * (lihat [DnsSettings.lookupStaticHost] — cocok persis lalu
     * subdomain).
     */
    @Volatile
    var staticHosts: Map<String, InetAddress> = emptyMap()

    /**
     * Metode resolve outbound (v1.0.5, kelompok C — setting
     * outboundResolveMethod; lihat [OutboundResolveMethod]).
     * Default [OutboundResolveMethod.OPERATOR_FIRST] = perilaku
     * v1.0.4, tidak berubah. Dipasang service dari Settings tiap
     * tunnel naik.
     */
    @Volatile
    var resolveMethod: OutboundResolveMethod = OutboundResolveMethod.OPERATOR_FIRST

    /**
     * Hook resolver sistem untuk tes (v1.0.5): (host, timeoutMs) ->
     * alamat. Null = [systemResolveAll] asli. Pola yang sama dengan
     * [operatorResolve] — produksi tidak pernah memasangnya.
     */
    @Volatile
    var systemResolveHook: ((String, Int) -> List<InetAddress>)? = null

    /** Port server DNS (53). Diubah tes untuk menunjuk server DNS palsu lokal. */
    @Volatile
    var dnsPort: Int = 53

    /**
     * Hook resolver jaringan fisik operator (v1.0.4, review Claude
     * atas v1.0.3): `Network.getAllByName` pada jaringan non-VPN —
     * cara XVEON me-resolve host proxy, dan kandidat terkuat kenapa
     * prime TaptapNG tidak bisa membuka jendela operator (hipotesis
     * BELUM TERBUKTI; jalur ini jalan pertama, fallback tetap UDP
     * langsung lalu sistem). Dipasang service dari
     * [ConnectivityManager] lewat [networkResolveAll]; null = tidak
     * ada jaringan operator yang bisa dipakai (unit test, atau CM
     * tidak tersedia) — resolve langsung loncat ke UDP 8.8.8.8.
     */
    @Volatile
    var operatorResolve: ((String, Int) -> List<InetAddress>)? = null

    /**
     * Offset rotasi per host (v1.0.4): setelah TLS timeout, dial
     * berikutnya memakai alamat berikutnya di daftar cache
     * ([rotateAfterTlsFailure]). Offset melekat — IP yang berhasil
     * dipakai terus sampai ia gagal — dan dihitung modulo panjang
     * daftar, jadi aman saat cache refresh mengubah panjang daftar.
     */
    private val rotateOffset = ConcurrentHashMap<String, Int>()

    /**
     * Resolve [host] lewat jaringan fisik operator: pilih jaringan
     * non-VPN pertama yang punya kapabilitas INTERNET (jaringan
     * operator fisik; jaringan VPN sendiri disaring keluar), lalu
     * `Network.getAllByName` di thread daemon + join(timeout) seperti
     * [systemResolve]. Kembalikan daftar kosong bila tidak ada
     * jaringan yang cocok — pemanggil lanjut ke fallback. Daftar
     * diurutkan IPv4 dulu, sama seperti jalur UDP langsung.
     *
     * Hanya dipanggil lewat hook [operatorResolve]; tes JVM tidak
     * memanggil fungsi ini (butuh ConnectivityManager Android).
     */
    fun networkResolveAll(
        cm: ConnectivityManager,
        host: String,
        timeoutMs: Int,
    ): List<InetAddress> {
        val networks = try {
            cm.allNetworks
        } catch (_: Exception) {
            return emptyList()
        }
        val physical = networks.firstOrNull { network ->
            val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull()
            caps != null &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        } ?: networks.firstOrNull { network ->
            val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull()
            caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } ?: return emptyList()
        var result: List<InetAddress>? = null
        var error: Throwable? = null
        val t = thread(name = "op-dns", isDaemon = true) {
            try {
                result = physical.getAllByName(host).sortedBy {
                    if (it is Inet4Address) 0 else 1
                }
            } catch (e: Throwable) {
                error = e
            }
        }
        t.join(timeoutMs.toLong())
        if (t.isAlive) {
            throw SocketTimeoutException("DNS operator timeout untuk $host")
        }
        error?.let { throw it }
        return result ?: emptyList()
    }

    /** Jalur operator lewat hook [operatorResolve]; kosong bila hook null. */
    private fun operatorResolveAll(host: String, timeoutMs: Int): List<InetAddress> {
        val hook = operatorResolve ?: return emptyList()
        return try {
            hook(host, timeoutMs)
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** Majukan offset rotasi [host] satu langkah (dipanggil saat TLS timeout). */
    fun rotateAfterTlsFailure(host: String) {
        rotateOffset.compute(host) { _, v -> (v ?: 0) + 1 }
    }

    /** Offset rotasi saat ini untuk [host] (tes). */
    internal fun rotationOffset(host: String): Int = rotateOffset[host] ?: 0

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
        // v1.0.5: pemetaan statis (dnsHosts) menang atas semua jalur.
        DnsSettings.lookupStaticHost(staticHosts, clean)?.let { return it }
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
     *
     * v1.0.4: memakai daftar lengkap dari [resolveAll] (jalur
     * pertama = resolver operator) + rotasi setelah TLS timeout
     * ([rotateAfterTlsFailure]) — dial berikutnya memakai alamat
     * berikutnya di cache, bukan alamat yang baru saja gagal TLS.
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
        // Stale-cache fallback tetap hidup di dalam resolveAll.
        val all = resolveAll(host, port, timeoutMs)
        if (all.isEmpty()) throw IOException("tidak dapat resolve $host")
        val offset = rotateOffset[clean.lowercase()] ?: 0
        return all[offset % all.size]
    }

    /**
     * Resolve [host] to ALL addresses (A then AAAA), for dials that
     * must try IPv4 first then IPv6 (prime dial, v2rayNG pattern:
     * getAllByName sorted v4-first). Direct UDP queries first
     * (bypass TUN, same as [resolve]); the system resolver is the
     * fallback, bounded by [timeoutMs]. Deduped, IPv4 first.
     *
     * v1.0.25: the result is cached for [addrCacheTtlMs] in the same
     * cache as [resolveWithSystemFallback] (which now holds the
     * full address list) — a prime dial runs every 15 s, so without
     * the cache each prime cost 2 fresh UDP queries + a radio
     * wakeup. On lookup failure the last good list is returned,
     * like the single-address path. @throws IOException bila kedua
     * jalur gagal dan tidak ada cache.
     */
    fun resolveAll(
        host: String,
        port: Int,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
    ): List<InetAddress> {
        require(host.isNotBlank()) { "Host DNS kosong" }
        val clean = host.trim().trimEnd('.')
        if (AddrCodec.isIpLiteral(clean)) {
            return listOf(InetAddress.getByName(clean))
        }
        val key = clean.lowercase()
        val now = System.currentTimeMillis()
        val cached = addrCache[key]
        if (cached != null && now - cached.atMs < addrCacheTtlMs) {
            return cached.addrs
        }
        try {
            val fresh = resolveAllUncached(host, clean, port, timeoutMs)
            addrCache[key] = CachedAddr(fresh, now)
            return fresh
        } catch (e: IOException) {
            if (cached != null) return cached.addrs
            throw e
        }
    }

    /** The uncached half of [resolveAll]: static hosts first, then
     *  the chain chosen by [resolveMethod] (see
     *  [OutboundResolveMethod]). Returns non-empty, or throws
     *  IOException when every path fails. */
    private fun resolveAllUncached(
        host: String,
        clean: String,
        port: Int,
        timeoutMs: Int,
    ): List<InetAddress> {
        // v1.0.5: pemetaan statis (dnsHosts) menang atas semua jalur,
        // di semua metode — tidak ada lookup untuk host yang dipetakan.
        DnsSettings.lookupStaticHost(staticHosts, clean)?.let { return listOf(it) }
        return when (resolveMethod) {
            // "0": tanpa pre-resolve aplikasi — resolver sistem saja.
            OutboundResolveMethod.SYSTEM_ONLY -> {
                val all = systemResolveAllOrHook(clean, port, timeoutMs)
                if (all.isEmpty()) throw IOException("DNS gagal untuk $host")
                all
            }
            // "2": UDP langsung (dnsServer) lalu sistem — hook
            // operator dilewati; hasil resolve menggantikan domain.
            OutboundResolveMethod.DIRECT_ONLY -> {
                directResolveAll(clean, timeoutMs)?.let { return it }
                val all = systemResolveAllOrHook(clean, port, timeoutMs)
                if (all.isEmpty()) throw IOException("DNS gagal untuk $host")
                all
            }
            // "1" (default): perilaku v1.0.4 — operator dulu, lalu
            // UDP langsung (A + AAAA), lalu resolver sistem.
            OutboundResolveMethod.OPERATOR_FIRST -> {
                val viaOperator = operatorResolveAll(clean, timeoutMs)
                if (viaOperator.isNotEmpty()) return viaOperator
                directResolveAll(clean, timeoutMs)?.let { return it }
                val all = systemResolveAllOrHook(clean, port, timeoutMs)
                if (all.isEmpty()) throw IOException("DNS gagal untuk $host")
                all
            }
        }
    }

    /**
     * Query A + AAAA lewat UDP langsung ([dnsServer]). Mengembalikan
     * daftar (IPv4 dulu, dedup) bila server menjawab dengan record,
     * atau null bila server tidak menjawab / menjawab tanpa record —
     * pemanggil lanjut ke fallback sistem.
     */
    private fun directResolveAll(host: String, timeoutMs: Int): List<InetAddress>? {
        return try {
            // A dulu; bila servernya saja tidak menjawab (timeout),
            // jangan buang waktu coba AAAA — langsung fallback sistem.
            val a = queryOnce(host, TYPE_A, timeoutMs)
            val aaaa = runCatching { queryOnce(host, TYPE_AAAA, timeoutMs) }
                .getOrElse { emptyList() }
            val out = (a + aaaa).distinctBy { it.hostAddress }
            if (out.isNotEmpty()) out else null
            // Server menjawab tapi tanpa record A/AAAA → fallback sistem.
        } catch (_: IOException) {
            // Jalur langsung gagal → fallback sistem di pemanggil.
            null
        }
    }

    /** Resolver sistem lewat hook tes ([systemResolveHook]) atau [systemResolveAll] asli. */
    private fun systemResolveAllOrHook(
        host: String,
        port: Int,
        timeoutMs: Int,
    ): List<InetAddress> {
        val hook = systemResolveHook
        if (hook != null) {
            return try {
                hook(host, timeoutMs)
            } catch (_: Exception) {
                emptyList()
            }
        }
        return runCatching { systemResolveAll(host, port, timeoutMs) }
            .getOrElse { emptyList() }
    }

    /** Hapus cache resolve + offset rotasi (dipakai tes). */
    fun clearAddrCache() {
        addrCache.clear()
        rotateOffset.clear()
    }

    /**
     * One cached address list (IPv4 first, then IPv6) + the time it
     * was stored. Only non-empty lists are ever cached
     * ([resolveAllUncached] returns non-empty or throws), so
     * [CachedAddr.addrs] always has a first element.
     */
    private class CachedAddr(val addrs: List<InetAddress>, val atMs: Long)

    private val addrCache = java.util.concurrent.ConcurrentHashMap<String, CachedAddr>()

    /** TTL cache DNS (120 dtk). Diubah tes untuk menguji fallback
     *  cache kedaluwarsa (pola yang sama dengan [dnsServer] /
     *  [dnsPort]); produksi tidak pernah mengubahnya. */
    @Volatile
    var addrCacheTtlMs: Long = 120_000L

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
     * Satu pertanyaan DNS dari pesan wire: ID + nama (dotted,
     * lowercase) + QTYPE. Null bila pesan terlalu pendek, QDCOUNT
     * bukan 1, atau namanya tidak bisa dibaca. Murni — dipakai
     * relay untuk memutuskan rute query tanpa meneruskannya dulu.
     */
    data class DnsQuery(val id: Int, val name: String, val qtype: Int)

    /** Parse pertanyaan pertama dari pesan query DNS (lihat [DnsQuery]). */
    fun parseQuery(msg: ByteArray): DnsQuery? {
        if (msg.size < 12) return null
        if (u16(msg, 4) != 1) return null // QDCOUNT harus 1
        val (labels, afterName) = readNameLabels(msg, 12) ?: return null
        if (afterName + 4 > msg.size) return null
        val qtype = u16(msg, afterName)
        val name = labels.joinToString(".").lowercase()
        if (name.isEmpty()) return null
        return DnsQuery(u16(msg, 0), name, qtype)
    }

    /**
     * Bangun jawaban DNS untuk [query]: echo pertanyaan asli +
     * jawaban A/AAAA dari [answers] (nama jawaban = pointer
     * kompresi 0xC00C ke nama pertanyaan). Hanya jawaban yang
     * keluarganya cocok dengan QTYPE yang dimasukkan (A→IPv4,
     * AAAA→IPv6); bila tidak ada yang cocok, null — pemanggil
     * meneruskan query ke upstream, bukan menjawab kosong.
     * TTL jawaban = [ttlSeconds]. Null juga bila query tidak bisa
     * diparse. Murni — dipakai relay untuk jawaban lokal (dnsHosts,
     * FakeDNS, local, DoH).
     */
    fun buildResponse(
        query: ByteArray,
        answers: List<InetAddress>,
        ttlSeconds: Int = 60,
    ): ByteArray? {
        val parsed = parseQuery(query) ?: return null
        val matching = answers.filter {
            val isV4 = it is Inet4Address
            (parsed.qtype == TYPE_A && isV4) || (parsed.qtype == TYPE_AAAA && !isV4)
        }
        if (matching.isEmpty()) return null
        // Panjang pertanyaan = nama + QTYPE/QCLASS (4 byte).
        val (_, afterName) = readNameLabels(query, 12) ?: return null
        val questionEnd = afterName + 4
        if (questionEnd > query.size) return null
        val out = mutableListOf<Byte>()
        fun u16(v: Int) {
            out += ((v ushr 8) and 0xFF).toByte()
            out += (v and 0xFF).toByte()
        }
        fun u32(v: Long) {
            out += ((v ushr 24) and 0xFF).toByte()
            out += ((v ushr 16) and 0xFF).toByte()
            out += ((v ushr 8) and 0xFF).toByte()
            out += (v and 0xFF).toByte()
        }
        u16(parsed.id)
        u16(0x8180) // QR=1, RD=1, RA=1, RCODE=0
        u16(1) // QDCOUNT
        u16(matching.size) // ANCOUNT
        u16(0) // NSCOUNT
        u16(0) // ARCOUNT
        out += query.copyOfRange(12, questionEnd).toList()
        for (addr in matching) {
            val rdata = addr.address
            out += 0xC0.toByte()
            out += 0x0C.toByte() // pointer ke nama pertanyaan (offset 12)
            u16(if (rdata.size == 4) TYPE_A else TYPE_AAAA)
            u16(CLASS_IN)
            u32(ttlSeconds.toLong())
            u16(rdata.size)
            out += rdata.toList()
        }
        return out.toByteArray()
    }

    /**
     * Baca satu nama DNS di [pos] (label berurutan / pointer
     * kompresi 0xC0, maks. 10 pointer). Mengembalikan (label,
     * posisi-setelah-nama) atau null bila pesan terpotong.
     */
    private fun readNameLabels(msg: ByteArray, start: Int): Pair<List<String>, Int>? {
        val labels = mutableListOf<String>()
        var pos = start
        var pointers = 0
        var afterPointer: Int? = null
        while (true) {
            if (pos >= msg.size) return null
            val len = msg[pos].toInt() and 0xFF
            when {
                len == 0 -> return labels to (afterPointer ?: (pos + 1))
                len and 0xC0 == 0xC0 -> {
                    if (pos + 1 >= msg.size) return null
                    if (afterPointer == null) afterPointer = pos + 2
                    pointers++
                    if (pointers > 10) return null
                    val offset = ((len and 0x3F) shl 8) or (msg[pos + 1].toInt() and 0xFF)
                    if (offset >= msg.size) return null
                    pos = offset
                }
                len and 0xC0 != 0 -> return null
                else -> {
                    if (pos + 1 + len > msg.size) return null
                    labels += String(msg, pos + 1, len, Charsets.US_ASCII)
                    pos += 1 + len
                }
            }
        }
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

    /** Seperti [systemResolve], tapi mengembalikan SEMUA alamat
     *  (getAllByName), IPv4 dulu lalu IPv6 — untuk dial yang harus
     *  mencoba v4 dulu baru v6 (prime dial). */
    private fun systemResolveAll(host: String, port: Int, timeoutMs: Int): List<InetAddress> {
        var result: List<InetAddress>? = null
        var error: Throwable? = null
        val t = thread(name = "sys-dns-all", isDaemon = true) {
            try {
                result = InetAddress.getAllByName(host)
                    .sortedBy { if (it is Inet4Address) 0 else 1 }
            } catch (e: Throwable) {
                error = e
            }
        }
        t.join(timeoutMs.toLong())
        if (t.isAlive) throw SocketTimeoutException("DNS sistem timeout untuk $host")
        error?.let { throw it }
        return result ?: emptyList()
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
