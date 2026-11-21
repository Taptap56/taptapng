package com.taptap.ng.core

import com.taptap.ng.data.ProfileItem
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Observatory (v1.0.5, kelompok F): probing berkala di background
 * dengan memakai ulang core [ServerTester.testRealPingThroughProxy]
 * (real ping = dial penuh lewat proxy + HTTP ke delay-test URL).
 *
 * KEPUTUSAN DESAIN (didokumentasikan, sesuai tugas):
 * - TIDAK PERNAH mencabut tunnel yang sedang hidup. Hasil probe
 *   hanya dicatat; entry terbaik adalah SARAN untuk koneksi
 *   berikutnya — service me-log-nya ("OBSERVATORY saran: ...") dan
 *   user tetap yang memilih entry (ketuk baris server). Alasannya:
 *   auto-switch saat konek berarti memutus semua koneksi aplikasi
 *   yang sedang jalan + probe-dial ulang + risiko jendela operator
 *   tertutup di tengah jalan; keuntungan (pindah ke entry beberapa
 *   ms lebih cepat) tidak sebanding.
 * - Interval mengikuti setting: least-ping → ronde ping (1 sampel
 *   per entry), least-load → ronde load (sampling sampel per entry,
 *   dirata-rata, metode HEAD/GET mengikuti setting).
 * - Timeout mengikuti observatoryLeastLoadTimeout untuk kedua ronde
 *   (setting timeout ping terpisah tidak ada di v2rayNG).
 * - Probe jalan HANYA saat tunnel hidup (butuh proxy yang jalan —
 *   testRealPingThroughProxy mendial entry; tanpa tunnel yang jalan,
 *   probe adalah delay test biasa dan sudah ada testAll).
 * - Hasil gagal (-1) TIDAK pernah mengalahkan hasil sukses: entry
 *   yang gagal di ronde terakhir tetap kalah dari entry sukses
 *   berapa pun lambatnya, dan entry tanpa hasil tidak dipilih.
 */
object Observatory {

    /** Satu ronde probe untuk satu entry. */
    data class ProbeResult(
        val guid: String,
        /** ms rata-rata sampel sukses; -1 bila semua sampel gagal. */
        val ms: Long,
        val atMs: Long,
        val method: String,
        val samples: Int,
        val failureStage: String?,
    )

    /** Konfigurasi prober, diparse dari string setting v2rayNG. */
    data class Config(
        val leastPingIntervalMs: Long,
        val leastLoadIntervalMs: Long,
        /** "HEAD" atau "GET" (nilai lain → HEAD, default setting). */
        val leastLoadMethod: String,
        /** Jumlah sampel per entry per ronde load, clamp 1..10. */
        val sampling: Int,
        /** Timeout per probe, clamp 1 s..120 s. */
        val timeoutMs: Int,
        val delayTestUrl: String,
    ) {
        companion object {
            const val DEFAULT_PING_INTERVAL_MS = 15L * 60_000
            const val DEFAULT_LOAD_INTERVAL_MS = 30L * 60_000
            const val DEFAULT_TIMEOUT_MS = 30_000
            const val DEFAULT_SAMPLING = 2

            fun fromSettings(
                leastPing: String,
                leastLoad: String,
                method: String,
                sampling: String,
                timeout: String,
                delayTestUrl: String,
            ): Config = Config(
                leastPingIntervalMs = parseDurationMs(leastPing, DEFAULT_PING_INTERVAL_MS),
                leastLoadIntervalMs = parseDurationMs(leastLoad, DEFAULT_LOAD_INTERVAL_MS),
                leastLoadMethod = if (method.trim().equals("GET", ignoreCase = true)) "GET" else "HEAD",
                sampling = sampling.trim().toIntOrNull()?.coerceIn(1, 10) ?: DEFAULT_SAMPLING,
                timeoutMs = parseDurationMs(timeout, DEFAULT_TIMEOUT_MS.toLong())
                    .coerceIn(1_000, 120_000).toInt(),
                delayTestUrl = delayTestUrl,
            )
        }
    }

    /**
     * Parse durasi v2rayNG ("3m", "5m", "30s", "500ms", "2h", angka
     * polos = ms). Tidak valid / kosong / <= 0 → [defaultMs].
     */
    fun parseDurationMs(text: String, defaultMs: Long): Long {
        val t = text.trim().lowercase()
        if (t.isEmpty()) return defaultMs
        val (numPart, mult) = when {
            t.endsWith("ms") -> t.dropLast(2) to 1L
            t.endsWith("h") -> t.dropLast(1) to 3_600_000L
            t.endsWith("m") -> t.dropLast(1) to 60_000L
            t.endsWith("s") -> t.dropLast(1) to 1_000L
            else -> t to 1L
        }
        val n = numPart.toLongOrNull() ?: return defaultMs
        if (n <= 0) return defaultMs
        return n * mult
    }

    private val results = ConcurrentHashMap<String, ProbeResult>()

    /** Hasil probe terakhir per guid (salinan). */
    fun results(): Map<String, ProbeResult> = results.toMap()

    fun record(result: ProbeResult) {
        results[result.guid] = result
    }

    fun clear() = results.clear()

    /** Entry terbaik menurut least-ping: ms sukses terendah; null bila tak ada yang sukses. */
    fun bestLeastPing(items: List<ProfileItem>): ProfileItem? =
        bestOf(items)

    /** Entry terbaik menurut least-load: sama — ms di sini sudah rata-rata sampling. */
    fun bestLeastLoad(items: List<ProfileItem>): ProfileItem? =
        bestOf(items)

    private fun bestOf(items: List<ProfileItem>): ProfileItem? {
        var best: ProfileItem? = null
        var bestMs = Long.MAX_VALUE
        for (item in items) {
            val r = results[item.guid] ?: continue
            if (r.ms < 0) continue
            if (r.ms < bestMs) {
                bestMs = r.ms
                best = item
            }
        }
        return best
    }

    /** Saran entry terbaik untuk koneksi BERIKUTNYA (log saja, bukan auto-switch). */
    fun bestGuidForNextStart(items: List<ProfileItem>): String? =
        (bestLeastPing(items) ?: bestLeastLoad(items))?.guid
}

/**
 * Satu ronde probe atas semua entry (testable, tanpa thread):
 * [tester] menerima (item, method, timeoutMs) dan mengembalikan
 * [ServerTester.TestResult] — produksi memakai
 * [ServerTester.testRealPingThroughProxy], tes memakai stub.
 * Mode PING = 1 sampel, metode GET; mode LOAD = [Config.sampling]
 * sampel dengan [Config.leastLoadMethod], ms = rata-rata sampel
 * sukses (bila ada yang sukses) atau -1.
 */
class ObservatoryProber(
    private val config: Observatory.Config,
    private val tester: (ProfileItem, String, Int) -> ServerTester.TestResult = { item, method, timeoutMs ->
        ServerTester.testRealPingThroughProxy(
            item, config.delayTestUrl, timeoutMs, method = method,
        )
    },
) {
    enum class Mode { PING, LOAD }

    fun probeOnce(items: List<ProfileItem>, mode: Mode): Map<String, Observatory.ProbeResult> {
        val out = LinkedHashMap<String, Observatory.ProbeResult>()
        for (item in items) {
            val method = if (mode == Mode.LOAD) config.leastLoadMethod else "GET"
            val samples = if (mode == Mode.LOAD) config.sampling else 1
            var sum = 0L
            var ok = 0
            var lastStage: String? = null
            repeat(samples) {
                val r = try {
                    tester(item, method, config.timeoutMs)
                } catch (e: Exception) {
                    ServerTester.TestResult(-1, ServerTester.stageOf(e))
                }
                if (r.ms >= 0) {
                    sum += r.ms
                    ok++
                } else {
                    lastStage = r.failureStage
                }
            }
            val result = Observatory.ProbeResult(
                guid = item.guid,
                ms = if (ok > 0) sum / ok else -1,
                atMs = System.currentTimeMillis(),
                method = method,
                samples = samples,
                failureStage = if (ok > 0) null else lastStage,
            )
            Observatory.record(result)
            out[item.guid] = result
        }
        return out
    }
}

/**
 * Loop background prober (jalan di service saat tunnel hidup):
 * ronde PING tiap [Observatory.Config.leastPingIntervalMs], ronde
 * LOAD tiap [Observatory.Config.leastLoadIntervalMs]. Tiap ronde
 * selesai, [onBestChanged] dipanggil bila entry terbaik BERUBAH
 * (service me-log-nya sebagai saran — tidak ada auto-switch).
 * [itemsProvider] dipanggil tiap ronde agar entry baru ikut ter-probe.
 */
class ObservatoryRunner(
    private val config: Observatory.Config,
    private val itemsProvider: () -> List<ProfileItem>,
    private val prober: ObservatoryProber = ObservatoryProber(config),
    private val onBestChanged: (ProfileItem, Observatory.ProbeResult) -> Unit = { _, _ -> },
    /**
     * v1.0.16 (battery): false = ronde ditunda (mis. layar mati).
     * Probe menembus proxy dan membangunkan radio; hasilnya hanya
     * saran, jadi tidak ada gunanya jalan saat HP tidak dipakai.
     */
    private val isActive: () -> Boolean = { true },
) {
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null
    @Volatile private var lastPingMs = 0L
    @Volatile private var lastLoadMs = 0L
    @Volatile private var lastBestGuid: String? = null

    private companion object {
        const val MIN_SLEEP_MS = 5_000L
        const val MAX_SLEEP_MS = 30L * 60_000
        const val INACTIVE_RETRY_MS = 60_000L
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        lastPingMs = System.currentTimeMillis()
        lastLoadMs = lastPingMs
        worker = thread(name = "observatory", isDaemon = true) {
            // v1.0.16 (battery): tidur sampai ronde berikutnya JATUH
            // TEMPO. Sebelumnya thread bangun tiap 1 detik dan memanggil
            // itemsProvider() — membaca + mem-parse file profil dari disk
            // 86.400×/hari — padahal ronde hanya tiap beberapa menit.
            while (running.get()) {
                val now = System.currentTimeMillis()
                val untilDue = minOf(
                    lastPingMs + config.leastPingIntervalMs,
                    lastLoadMs + config.leastLoadIntervalMs,
                ) - now
                try {
                    Thread.sleep(untilDue.coerceIn(MIN_SLEEP_MS, MAX_SLEEP_MS))
                } catch (_: InterruptedException) {
                    break
                }
                if (!running.get()) break
                val t = System.currentTimeMillis()
                val pingDue = t - lastPingMs >= config.leastPingIntervalMs
                val loadDue = t - lastLoadMs >= config.leastLoadIntervalMs
                if (!pingDue && !loadDue) continue
                if (!isActive()) {
                    // Layar mati: tunda, cek lagi nanti — tanpa baca profil.
                    if (pingDue) lastPingMs = t - config.leastPingIntervalMs + INACTIVE_RETRY_MS
                    if (loadDue) lastLoadMs = t - config.leastLoadIntervalMs + INACTIVE_RETRY_MS
                    continue
                }
                val items = try {
                    itemsProvider()
                } catch (_: Exception) {
                    emptyList()
                }
                if (items.size < 2) {
                    // Satu entry (atau kosong): tidak ada yang dibandingkan.
                    lastPingMs = t
                    lastLoadMs = t
                    continue
                }
                try {
                    if (pingDue) {
                        lastPingMs = t
                        prober.probeOnce(items, ObservatoryProber.Mode.PING)
                        reportBest(items)
                    }
                    if (loadDue) {
                        lastLoadMs = t
                        prober.probeOnce(items, ObservatoryProber.Mode.LOAD)
                        reportBest(items)
                    }
                } catch (_: Exception) {
                    // Satu ronde gagal tidak boleh membunuh loop.
                }
            }
        }
    }

    fun stop() {
        running.set(false)
        worker?.interrupt()
        worker = null
    }

    private fun reportBest(items: List<ProfileItem>) {
        val best = Observatory.bestLeastPing(items) ?: return
        if (best.guid == lastBestGuid) return
        lastBestGuid = best.guid
        val result = Observatory.results()[best.guid] ?: return
        try {
            onBestChanged(best, result)
        } catch (_: Exception) {
            // Callback log tidak boleh membunuh loop.
        }
    }
}
