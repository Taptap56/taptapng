package com.taptap.ng.core.proto

import com.taptap.ng.data.SettingsStore
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.SocketTimeoutException
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Mux in-app (v1.0.5, kelompok D): beberapa stream logis berbagi
 * satu koneksi fisik VMess/VLESS ke server yang sama, interoperabel
 * dengan mux server xray-core.
 *
 * Sumber wire format (kode publik xray-core, dibaca 2026-11-21):
 * - common/mux/frame.go — FrameMetadata: status New=0x01, Keep=0x02,
 *   End=0x03, KeepAlive=0x04; option Data=0x01, Error=0x02; target
 *   network TCP=0x01, UDP=0x02; metaLen (2B BE) hanya menutup
 *   metadata (sessionID 2B + status 1B + option 1B + target),
 *   Unmarshal menolak metaLen > 512.
 * - common/mux/writer.go — writeMetaWithFrame: sesudah metadata
 *   ditulis 2B panjang data (BE) lalu datanya; stream dipecah max
 *   8 KiB per frame; frame New pertama membawa target; Close()
 *   mengirim End (meta saja, tanpa panjang data).
 * - common/mux/reader.go — NewStreamReader = chunk reader: sesudah
 *   metadata, bila OptionData, baca 2B panjang lalu data.
 * - common/mux/client.go / proxy/vmess/outbound/outbound.go /
 *   proxy/vless/outbound/outbound.go — klien mux dial dengan target
 *   v1.mux.cool:666; outbound memetakan domain itu ke command Mux
 *   (0x03, common/protocol RequestCommandMux). VLESS: header mux
 *   TIDAK membawa port/address (command saja); VMess: header tetap
 *   membawa target v1.mux.cool:666.
 * - Project X docs (Outbound Proxy / MuxObject): mux hanya perlu
 *   dinyalakan di sisi klien; server menyesuaikan otomatis.
 *
 * Yang TIDAK diimplementasikan di sini:
 * - XUDP (UDP di atas mux): M2 tidak punya jalur UDP sama sekali
 *   (TunForwarder TCP saja), jadi muxXudpConcurrency /
 *   muxXudpQuic hanya disimpan di [MuxConfig] dan tidak pernah
 *   dipakai — lihat [MuxConfig.xudpSupported].
 * - KeepAlive: klien ini tidak mengirim frame KeepAlive; koneksi
 *   idle boleh ditutup server dan dibuka lagi saat perlu (pool
 *   membuang koneksi mati).
 * - SlowDNS: mux dimatikan untuk entry SlowDNS (fail-safe OFF) —
 *   ladder DNSTT sudah berupa smux; mux xray di atasnya belum
 *   teruji.
 * - Trojan/SS: mux hanya untuk VMess/VLESS.
 *
 * Interop dengan server xray-core ASLI belum terverifikasi tanpa
 * server live — tes JVM di sini memakai stub server in-memory yang
 * mengimplementasikan framing yang sama (lihat MuxTest /
 * VmessMuxTest / VlessMuxTest). Rencana uji HP ada di laporan
 * kelompok D.
 */
object Mux {

    /** Target semu yang dipakai klien mux xray-core (lihat KDoc di atas). */
    const val TARGET_HOST = "v1.mux.cool"
    const val TARGET_PORT = 666

    // Status frame (common/mux/frame.go).
    const val STATUS_NEW = 0x01
    const val STATUS_KEEP = 0x02
    const val STATUS_END = 0x03
    const val STATUS_KEEP_ALIVE = 0x04

    // Option frame (common/mux/frame.go).
    const val OPTION_DATA = 0x01
    const val OPTION_ERROR = 0x02

    // Target network di frame New (common/mux/frame.go).
    const val TARGET_NETWORK_TCP = 0x01
    const val TARGET_NETWORK_UDP = 0x02

    /** Panjang metadata maksimum yang diterima (xray Unmarshal: > 512 ditolak). */
    const val MAX_META_LEN = 512

    /** Data stream dipecah max 8 KiB per frame (writer.go SplitSize). */
    const val MAX_FRAME_DATA = 8 * 1024

    /** Satu frame metadata yang sudah di-decode. */
    data class FrameMeta(
        val sessionId: Int,
        val status: Int,
        val option: Int,
        /** Target — hanya ada di frame New (TCP/UDP); null di Keep/End/KeepAlive. */
        val target: AddrCodec.Target?,
        /** [TARGET_NETWORK_TCP] / [TARGET_NETWORK_UDP]; 0 bila tidak ada target. */
        val targetNetwork: Int,
    )

    /**
     * Encode satu metadata frame: [2B metaLen][2B sessionID][1B
     * status][1B option][target]. [targetHost] null = tanpa target
     * (Keep/End/KeepAlive). Target memakai urutan yang sama dengan
     * VMess/VLESS: network 1B, PORT 2B BE, lalu ATYP + address
     * ([AddrCodec.encodeVmessTarget]).
     */
    fun encodeMeta(
        sessionId: Int,
        status: Int,
        option: Int,
        targetHost: String? = null,
        targetPort: Int = 0,
    ): ByteArray {
        require(sessionId in 0..0xFFFF) { "Mux session id di luar 0..65535: $sessionId" }
        val meta = mutableListOf<Byte>()
        meta += ((sessionId ushr 8) and 0xFF).toByte()
        meta += (sessionId and 0xFF).toByte()
        meta += status.toByte()
        meta += option.toByte()
        if (targetHost != null) {
            meta += TARGET_NETWORK_TCP.toByte()
            meta += AddrCodec.encodeVmessTarget(targetHost, targetPort).toList()
        }
        require(meta.size <= MAX_META_LEN) { "Mux metadata terlalu panjang: ${meta.size}" }
        val out = ByteArray(2 + meta.size)
        out[0] = ((meta.size ushr 8) and 0xFF).toByte()
        out[1] = (meta.size and 0xFF).toByte()
        meta.forEachIndexed { i, b -> out[2 + i] = b }
        return out
    }

    /** Decode satu metadata frame dari [input] (2B metaLen + metadata). */
    fun decodeMeta(input: InputStream): FrameMeta {
        val lenBytes = input.readExactBytes(2)
        val metaLen = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        if (metaLen < 4 || metaLen > MAX_META_LEN) {
            throw IOException("Mux metaLen tidak valid: $metaLen")
        }
        val meta = input.readExactBytes(metaLen)
        val sessionId = ((meta[0].toInt() and 0xFF) shl 8) or (meta[1].toInt() and 0xFF)
        val status = meta[2].toInt() and 0xFF
        val option = meta[3].toInt() and 0xFF
        var target: AddrCodec.Target? = null
        var targetNetwork = 0
        // Frame New membawa target; frame Keep UDP juga (lihat
        // frame.go UnmarshalFromBuffer) — di sini hanya TCP yang
        // dipakai, jadi Keep tanpa target adalah kasus normal.
        if (status == STATUS_NEW || (status == STATUS_KEEP && metaLen > 4)) {
            require(metaLen >= 8) { "Mux metadata New terlalu pendek: $metaLen" }
            targetNetwork = meta[4].toInt() and 0xFF
            require(targetNetwork == TARGET_NETWORK_TCP || targetNetwork == TARGET_NETWORK_UDP) {
                "Mux target network tidak dikenal: $targetNetwork"
            }
            val (parsed, after) = AddrCodec.parseVmessTarget(meta, 5)
            require(after == metaLen) {
                "Mux metadata New tidak konsisten (target berakhir di $after dari $metaLen)"
            }
            target = parsed
        }
        return FrameMeta(sessionId, status, option, target, targetNetwork)
    }

    /** Baca 2B panjang data (BE) sesudah metadata frame Data. */
    fun readDataLength(input: InputStream): Int {
        val b = input.readExactBytes(2)
        return ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
    }
}

/**
 * Konfigurasi mux dari Settings (v2rayNG: mux_enabled,
 * mux_concurrency, mux_xudp_concurrency, mux_xudp_quic — lihat
 * [SettingsStore]). Default = [DISABLED]: perilaku lama (satu
 * koneksi per stream), tanpa regresi.
 */
data class MuxConfig(
    val enabled: Boolean = false,
    val concurrency: Int = DEFAULT_CONCURRENCY,
    val xudpConcurrency: Int = DEFAULT_XUDP_CONCURRENCY,
    val xudpQuic: String = DEFAULT_XUDP_QUIC,
) {
    companion object {
        const val DEFAULT_CONCURRENCY = 8
        const val DEFAULT_XUDP_CONCURRENCY = 8
        const val DEFAULT_XUDP_QUIC = "reject"

        /** Mux mati: semua dial memakai jalur lama. */
        val DISABLED = MuxConfig()

        /** Baca dari SettingsStore (butuh Context — lewat store). */
        fun fromSettings(settings: SettingsStore): MuxConfig = fromSettingsValues(
            enabled = settings.muxEnabled,
            concurrency = settings.muxConcurrency,
            xudpConcurrency = settings.muxXudpConcurrency,
            xudpQuic = settings.muxXudpQuic,
        )

        /**
         * Murni (tanpa Context) supaya bisa diuji di JVM.
         * Concurrency di luar 1..64 dijepit; string bukan angka /
         * kosong memakai default. Menonaktifkan hanya lewat
         * [enabled] — concurrency -1 TIDAK mematikan mux di sini
         * (v2rayNG memakai switch mux_enabled untuk itu).
         */
        fun fromSettingsValues(
            enabled: Boolean,
            concurrency: String,
            xudpConcurrency: String,
            xudpQuic: String,
        ): MuxConfig = MuxConfig(
            enabled = enabled,
            concurrency = concurrency.trim().toIntOrNull()?.coerceIn(1, 64) ?: DEFAULT_CONCURRENCY,
            xudpConcurrency = xudpConcurrency.trim().toIntOrNull()?.coerceIn(1, 64)
                ?: DEFAULT_XUDP_CONCURRENCY,
            xudpQuic = xudpQuic.trim().ifBlank { DEFAULT_XUDP_QUIC },
        )
    }

    /**
     * XUDP (UDP di atas mux) TIDAK diimplementasikan: M2 tidak
     * punya jalur UDP (TunForwarder TCP saja), jadi
     * [xudpConcurrency] / [xudpQuic] hanya disimpan dan tidak
     * pernah dipakai. Selalu false sampai ada jalur UDP.
     */
    val xudpSupported: Boolean get() = false
}

/**
 * Hasil baca response header protokol (VMess/VLESS) di satu koneksi
 * mux. Dibaca sekali oleh thread pembaca mux (lazy hook di klien);
 * dial probe menunggu hasilnya supaya UUID salah gagal cepat,
 * dial relay tidak menunggu (header tiba sesudah data pertama
 * mengalir — sama seperti jalur TCP lama, v1.0.12).
 */
class MuxHeaderResult {
    private val latch = CountDownLatch(1)

    @Volatile
    var error: Exception? = null
        private set

    fun complete(error: Exception?) {
        this.error = error
        latch.countDown()
    }

    /**
     * Tunggu header selesai dibaca (null = sukses). False bila
     * timeout habis sebelum latch — pemanggil melempar timeout
     * sendiri.
     */
    fun await(timeoutMs: Long): Boolean =
        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
}

/**
 * Satu koneksi fisik mux: satu VMess/VLESS session (command Mux)
 * yang membawa banyak [MuxSession]. Satu thread pembaca ([readLoop])
 * mendemux frame ke session yang dituju; semua penulisan frame
 * diserialkan lewat [writeLock] supaya frame dari session berbeda
 * tidak tercampur di tengah jalan.
 *
 * [input] adalah stream body protokol (VMess/VLESS) yang SUDAH
 * dibungkus lazy-header oleh pemanggil: baca pertama dari thread
 * ini memicu baca response header. [onClose] menutup transport
 * di bawahnya (socket / ladder).
 */
class MuxConnection(
    private val input: InputStream,
    private val output: OutputStream,
    private val onClose: () -> Unit,
    val maxConcurrency: Int = MuxConfig.DEFAULT_CONCURRENCY,
    /** Hasil baca response header; null bila tidak ada header (tes pipa mentah). */
    private val headerResult: MuxHeaderResult? = null,
) {
    private val closed = AtomicBoolean(false)

    private val sessionsLock = Object()
    private val sessions = HashMap<Int, MuxSession>()

    private val nextId = AtomicInteger(0)
    private val writeLock = Any()

    private val readerThread: Thread

    init {
        require(maxConcurrency >= 1) { "Mux concurrency harus >= 1: $maxConcurrency" }
        readerThread = Thread({ readLoop() }, "mux-recv").apply {
            isDaemon = true
            start()
        }
    }

    val isClosed: Boolean get() = closed.get()

    /** Jumlah session aktif (dipakai pool untuk batas concurrency). */
    val activeSessions: Int
        get() = synchronized(sessionsLock) { sessions.size }

    val isFull: Boolean get() = activeSessions >= maxConcurrency

    /**
     * Tunggu response header protokol selesai dibaca (probe dial).
     * Null = sukses (atau tidak ada header yang ditunggu);
     * [SocketTimeoutException] bila latch tidak selesai dalam
     * [timeoutMs].
     */
    fun awaitHeader(timeoutMs: Long): Exception? {
        val result = headerResult ?: return null
        if (!result.await(timeoutMs)) {
            return SocketTimeoutException("Mux response header tidak tiba dalam ${timeoutMs}ms")
        }
        return result.error
    }

    /**
     * Buka satu session logis ke [targetHost]:[targetPort], atau
     * null bila koneksi ini sudah penuh / sudah ditutup (pool lalu
     * membuat koneksi baru). Alokasi id + registrasi atomik.
     */
    fun tryOpenSession(targetHost: String, targetPort: Int): MuxSession? {
        synchronized(sessionsLock) {
            if (closed.get() || sessions.size >= maxConcurrency) return null
            val id = allocateId()
            val session = MuxSession(id, targetHost, targetPort, this)
            sessions[id] = session
            return session
        }
    }

    /**
     * Id session: 1..65535 berurutan, membungkus ke 1, melewati id
     * yang masih dipakai. Id 0 tidak pernah dipakai (server
     * memakai 0 untuk KeepAlive tingkat koneksi).
     */
    private fun allocateId(): Int {
        var guard = 0
        while (guard++ <= 0xFFFF + 1) {
            var id = (nextId.incrementAndGet() and 0xFFFF)
            if (id == 0) id = 1
            if (!sessions.containsKey(id)) return id
        }
        throw IOException("Mux kehabisan session id")
    }

    internal fun removeSession(id: Int) {
        synchronized(sessionsLock) { sessions.remove(id) }
    }

    /**
     * Tulis satu frame data: metadata (New untuk frame pertama
     * session ini, Keep sesudahnya) + 2B panjang data + data.
     * Satu frame max [Mux.MAX_FRAME_DATA]; pemanggil memecah
     * tulisan yang lebih besar. [isFirst] = frame pertama session
     * (New + target); sesudahnya Keep tanpa target.
     */
    internal fun writeDataFrame(
        sessionId: Int,
        data: ByteArray,
        isFirst: Boolean,
        targetHost: String,
        targetPort: Int,
    ) {
        require(data.isNotEmpty() && data.size <= Mux.MAX_FRAME_DATA) {
            "Mux frame data harus 1..${Mux.MAX_FRAME_DATA} byte: ${data.size}"
        }
        synchronized(writeLock) {
            if (closed.get()) throw IOException("mux connection is closed")
            val meta = if (isFirst) {
                Mux.encodeMeta(sessionId, Mux.STATUS_NEW, Mux.OPTION_DATA, targetHost, targetPort)
            } else {
                Mux.encodeMeta(sessionId, Mux.STATUS_KEEP, Mux.OPTION_DATA)
            }
            output.write(meta)
            output.write(byteArrayOf(((data.size ushr 8) and 0xFF).toByte(), (data.size and 0xFF).toByte()))
            output.write(data)
            output.flush()
        }
    }

    /** Tulis satu frame meta saja (End). Best-effort bila koneksi sudah mati. */
    internal fun writeEndFrame(sessionId: Int, withError: Boolean = false) {
        val option = if (withError) Mux.OPTION_ERROR else 0
        runCatching {
            synchronized(writeLock) {
                if (closed.get()) return
                output.write(Mux.encodeMeta(sessionId, Mux.STATUS_END, option))
                output.flush()
            }
        }
    }

    /** Tutup koneksi + semua session; unblock semua pembaca/penulis. */
    fun close() {
        if (!closed.compareAndSet(false, true)) return
        val snapshot: List<MuxSession>
        synchronized(sessionsLock) {
            snapshot = sessions.values.toList()
            sessions.clear()
        }
        for (s in snapshot) s.sessionClose()
        runCatching { input.close() }
        runCatching { output.close() }
        runCatching { onClose() }
        readerThread.interrupt()
    }

    private fun failConnection(e: Throwable) {
        if (!closed.compareAndSet(false, true)) return
        val snapshot: List<MuxSession>
        synchronized(sessionsLock) {
            snapshot = sessions.values.toList()
            sessions.clear()
        }
        for (s in snapshot) s.sessionClose()
        runCatching { input.close() }
        runCatching { output.close() }
        runCatching { onClose() }
    }

    private fun readLoop() {
        try {
            while (!closed.get()) {
                val meta = Mux.decodeMeta(input)
                val data: ByteArray? = if ((meta.option and Mux.OPTION_DATA) != 0) {
                    val len = Mux.readDataLength(input)
                    if (len < 0 || len > Mux.MAX_FRAME_DATA) {
                        throw IOException("Mux frame data terlalu besar: $len")
                    }
                    input.readExactBytes(len)
                } else {
                    null
                }
                when (meta.status) {
                    Mux.STATUS_KEEP -> {
                        val session = synchronized(sessionsLock) { sessions[meta.sessionId] }
                        // Frame data kosong (len 0) dibuang — chunk
                        // kosong membuat InputStream.read() mengembalikan
                        // 0 dan bisa memutar relay tanpa henti.
                        if (session != null && data != null && data.isNotEmpty()) session.onData(data)
                        // Keep tanpa data, atau session tak dikenal: buang.
                    }
                    Mux.STATUS_END -> {
                        val session = synchronized(sessionsLock) {
                            sessions.remove(meta.sessionId)
                        }
                        session?.onEnd((meta.option and Mux.OPTION_ERROR) != 0)
                    }
                    Mux.STATUS_NEW, Mux.STATUS_KEEP_ALIVE -> {
                        // Server tidak pernah membuka session ke klien;
                        // KeepAlive tingkat koneksi diabaikan.
                    }
                    else -> {
                        // Status tak dikenal: abaikan frame-nya.
                    }
                }
            }
        } catch (e: Exception) {
            // EOF / timeout / transport mati: gagalkan koneksi.
            // Thread yang menutup (close()) sudah menandai closed,
            // jadi failConnection di sini no-op untuk penutupan normal.
            if (!closed.get()) failConnection(e)
        }
    }
}

/**
 * Satu stream logis di dalam [MuxConnection]: input/output stream
 * biasa untuk pemakai (forwarder / probe). Frame New dikirim pada
 * tulisan pertama; penulisan sesudahnya memakai Keep; close()
 * mengirim End.
 */
class MuxSession internal constructor(
    val id: Int,
    val targetHost: String,
    val targetPort: Int,
    private val connection: MuxConnection,
) {
    private class Chunk(val data: ByteArray, var pos: Int = 0) {
        val remaining: Int get() = data.size - pos
    }

    private val lock = Object()
    private val buffers = ArrayDeque<Chunk>()
    private var peerEnded = false
    private var peerError = false
    private var closed = false
    private var inputClosed = false
    private var writeClosed = false
    private var opened = false
    private var endSent = false
    private val closeOnce = AtomicBoolean(false)
    private val writeLock = Object()

    val input: InputStream = SessionInputStream()
    val output: OutputStream = SessionOutputStream()

    /** Tutup penuh: kirim End (sekali), buang buffer, unblock pembaca. */
    fun close() {
        if (!closeOnce.compareAndSet(false, true)) return
        synchronized(lock) {
            closed = true
            (lock as Object).notifyAll()
        }
        sendEnd()
        connection.removeSession(id)
    }

    /** Half-close sisi tulis: kirim End; sisi baca tetap bisa dikuras. */
    fun closeOutput() {
        synchronized(lock) {
            if (writeClosed) return
            writeClosed = true
            (lock as Object).notifyAll()
        }
        sendEnd()
    }

    private fun sendEnd() {
        synchronized(lock) {
            if (endSent) return
            endSent = true
        }
        connection.writeEndFrame(id)
    }

    // ---- dipanggil thread pembaca koneksi ----

    internal fun onData(data: ByteArray) {
        synchronized(lock) {
            if (closed) return
            buffers.addLast(Chunk(data))
            (lock as Object).notifyAll()
        }
    }

    internal fun onEnd(error: Boolean) {
        synchronized(lock) {
            peerEnded = true
            peerError = error
            (lock as Object).notifyAll()
        }
    }

    /** Koneksi mati: unblock semua, buang data yang belum dibaca. */
    internal fun sessionClose() {
        synchronized(lock) {
            closed = true
            buffers.clear()
            (lock as Object).notifyAll()
        }
    }

    // ---- sisi baca ----

    private inner class SessionInputStream : InputStream() {
        override fun read(): Int {
            val one = ByteArray(1)
            val n = read(one, 0, 1)
            return if (n < 0) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            while (true) {
                synchronized(lock) {
                    if (buffers.isNotEmpty()) {
                        var remaining = len
                        var copied = 0
                        while (remaining > 0 && buffers.isNotEmpty()) {
                            val first = buffers.first()
                            val take = minOf(remaining, first.remaining)
                            first.data.copyInto(b, off + copied, first.pos, first.pos + take)
                            first.pos += take
                            copied += take
                            remaining -= take
                            if (first.remaining == 0) buffers.removeFirst()
                        }
                        return copied
                    }
                    if (inputClosed || closed) return -1
                    if (peerEnded) {
                        if (peerError) throw IOException("Mux session ditutup server (error)")
                        return -1
                    }
                }
                synchronized(lock) {
                    try {
                        (lock as Object).wait(100)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        return -1
                    }
                }
            }
        }

        override fun available(): Int {
            synchronized(lock) {
                var n = 0
                for (c in buffers) n += c.remaining
                return n
            }
        }

        override fun close() {
            synchronized(lock) {
                inputClosed = true
                (lock as Object).notifyAll()
            }
        }
    }

    // ---- sisi tulis ----

    private inner class SessionOutputStream : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()))

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len == 0) return
            synchronized(writeLock) {
                synchronized(lock) {
                    if (writeClosed) throw IOException("mux session output is closed")
                    if (closed) throw IOException("mux session is closed")
                    if (peerEnded) throw IOException("mux session closed by peer")
                }
                var pos = off
                val end = off + len
                while (pos < end) {
                    val take = minOf(Mux.MAX_FRAME_DATA, end - pos)
                    val chunk = b.copyOfRange(pos, pos + take)
                    val first: Boolean
                    synchronized(lock) {
                        first = !opened
                        opened = true
                    }
                    connection.writeDataFrame(id, chunk, first, targetHost, targetPort)
                    pos += take
                }
            }
        }

        override fun flush() {
            // Frame dikirim langsung tiap write(); tidak ada buffer.
        }

        override fun close() = closeOutput()
    }
}

/**
 * Pool koneksi mux per klien (per sesi VPN): dial memilih koneksi
 * yang masih punya kapasitas ([MuxConfig.concurrency] stream);
 * bila semua penuh, dibuat koneksi fisik baru — perilaku yang sama
 * dengan ClientManager xray-core (WorkerPicker).
 */
class MuxConnectionPool(
    private val maxConcurrency: Int,
    private val createConnection: (SpeedStats?) -> MuxConnection,
) {
    private val lock = Object()
    private val connections = mutableListOf<MuxConnection>()

    /**
     * Buka satu session ke [targetHost]:[targetPort] pada koneksi
     * yang punya kapasitas (atau koneksi baru bila semua penuh).
     * [stats] diteruskan ke pembuatan koneksi baru.
     */
    fun openSession(
        targetHost: String,
        targetPort: Int,
        stats: SpeedStats? = null,
    ): Pair<MuxConnection, MuxSession> {
        repeat(4) {
            val candidate = synchronized(lock) {
                connections.removeAll { it.isClosed }
                connections.firstOrNull { !it.isFull && !it.isClosed }
            }
            if (candidate != null) {
                val session = candidate.tryOpenSession(targetHost, targetPort)
                if (session != null) return candidate to session
                // Penuh di antara cek dan buka — coba lagi (nanti
                // membuat koneksi baru bila semua penuh).
                return@repeat
            }
            // Tidak ada kapasitas: dial koneksi fisik baru (di luar
            // lock — dial jaringan tidak boleh menahan pool).
            val fresh = createConnection(stats)
            val added = synchronized(lock) {
                connections.removeAll { it.isClosed }
                val raced = connections.firstOrNull { !it.isFull && !it.isClosed }
                if (raced == null) {
                    connections.add(fresh)
                    true
                } else {
                    false
                }
            }
            if (!added) {
                // Thread lain sudah menambah kapasitas selagi dial.
                fresh.close()
                return@repeat
            }
            val session = fresh.tryOpenSession(targetHost, targetPort)
                ?: throw IOException("mux: koneksi baru langsung penuh")
            return fresh to session
        }
        throw IOException("mux: tidak bisa membuka session (4x coba)")
    }

    /** Jumlah koneksi fisik yang masih hidup (tes + diagnostik). */
    fun connectionCount(): Int = synchronized(lock) {
        connections.removeAll { it.isClosed }
        connections.size
    }

    fun close() {
        val snapshot = synchronized(lock) {
            val copy = connections.toList()
            connections.clear()
            copy
        }
        for (c in snapshot) runCatching { c.close() }
    }
}
