package com.taptap.ng.core

import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

/**
 * v1.0.16 (koreksi review Claude): runner Observatory.
 * Sebelumnya thread bangun tiap 1 detik dan memanggil
 * itemsProvider() — boros baterai saat layar mati. Sekarang:
 * tidur sampai ronde jatuh tempo (batas bawah 5 detik),
 * lewati ronde bila layar mati (isActive false) TANPA memanggil
 * itemsProvider(), dan lewati bila item < 2. Tes-tes ini GAGAL
 * pada kode lama (provider dipanggil dalam ~1 detik meski layar
 * mati) dan lolos pada kode baru. Interval dibuat kecil supaya
 * tes cepat, tapi batas bawah tidur 5 detik tetap berlaku.
 */
class ObservatoryRunnerTest {

    private fun item(guid: String) = ProfileItem(
        guid = guid,
        remarks = guid,
        configType = ConfigType.VMESS,
        address = "1.2.3.4",
        port = 443,
        uuid = "00000000-0000-0000-0000-000000000000",
    )

    /** Interval kecil (100/200 ms) — tidur tetap dijepit ke >= 5 detik. */
    private fun tinyConfig() = Observatory.Config(
        leastPingIntervalMs = 100L,
        leastLoadIntervalMs = 200L,
        leastLoadMethod = "HEAD",
        sampling = 1,
        timeoutMs = 5_000,
        delayTestUrl = "",
    )

    private fun waitFor(
        timeoutMs: Long = 12_000,
        what: String,
        condition: () -> Boolean,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(100)
        }
        return condition().also { ok -> if (!ok) println("timeout menunggu: $what") }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    fun `isActive false — tidak ada probe dan itemsProvider tidak dipanggil`() {
        Observatory.clear()
        try {
            val providerCalls = AtomicInteger(0)
            val probeCalls = AtomicInteger(0)
            val isActiveCalls = AtomicInteger(0)
            val prober = ObservatoryProber(
                tinyConfig(),
                tester = { _, _, _ ->
                    probeCalls.incrementAndGet()
                    ServerTester.TestResult(100, null)
                },
            )
            val runner = ObservatoryRunner(
                config = tinyConfig(),
                itemsProvider = {
                    providerCalls.incrementAndGet()
                    listOf(item("a"), item("b"))
                },
                prober = prober,
                onBestChanged = { _, _ -> },
                isActive = {
                    isActiveCalls.incrementAndGet()
                    false
                },
            )
            runner.start()
            try {
                // Tunggu sampai satu ronde jatuh tempo (isActive
                // dipanggil = ronde terjadi) — tanpa itu tes lolos
                // hampa bila thread belum sempat jalan.
                assertTrue(
                    waitFor(what = "ronde jatuh tempo (isActive dipanggil)") { isActiveCalls.get() >= 1 },
                    "runner tidak pernah mencapai ronde jatuh tempo",
                )
                assertEquals(0, providerCalls.get(), "layar mati: itemsProvider tidak boleh dipanggil")
                assertEquals(0, probeCalls.get(), "layar mati: tidak boleh ada probe")
            } finally {
                runner.stop()
            }
        } finally {
            Observatory.clear()
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    fun `kurang dari 2 item — ronde dilewati tanpa probe`() {
        Observatory.clear()
        try {
            val providerCalls = AtomicInteger(0)
            val probeCalls = AtomicInteger(0)
            val prober = ObservatoryProber(
                tinyConfig(),
                tester = { _, _, _ ->
                    probeCalls.incrementAndGet()
                    ServerTester.TestResult(100, null)
                },
            )
            val runner = ObservatoryRunner(
                config = tinyConfig(),
                itemsProvider = {
                    providerCalls.incrementAndGet()
                    listOf(item("a"))
                },
                prober = prober,
                onBestChanged = { _, _ -> },
                isActive = { true },
            )
            runner.start()
            try {
                // Ronde terjadi (provider dipanggil) tapi probe dilewati.
                assertTrue(
                    waitFor(what = "ronde jatuh tempo (provider dipanggil)") { providerCalls.get() >= 1 },
                    "runner tidak pernah mencapai ronde jatuh tempo",
                )
                Thread.sleep(500)
                assertEquals(0, probeCalls.get(), "1 item: tidak boleh ada probe")
            } finally {
                runner.stop()
            }
        } finally {
            Observatory.clear()
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    fun `tidur sampai jatuh tempo — provider tidak dipanggil sebelum 5 detik`() {
        Observatory.clear()
        try {
            val providerCalls = AtomicInteger(0)
            val firstCallMs = AtomicInteger(-1)
            val startMs = System.currentTimeMillis()
            val prober = ObservatoryProber(
                tinyConfig(),
                tester = { _, _, _ -> ServerTester.TestResult(100, null) },
            )
            val runner = ObservatoryRunner(
                config = tinyConfig(),
                itemsProvider = {
                    if (firstCallMs.get() == -1) {
                        firstCallMs.set((System.currentTimeMillis() - startMs).toInt())
                    }
                    providerCalls.incrementAndGet()
                    listOf(item("a"), item("b"))
                },
                prober = prober,
                onBestChanged = { _, _ -> },
                isActive = { true },
            )
            runner.start()
            try {
                // Kode lama memanggil provider dalam ~1 detik;
                // kode baru tidur sampai jatuh tempo (>= 5 detik).
                Thread.sleep(2_000)
                assertEquals(0, providerCalls.get(), "provider dipanggil sebelum 2 detik — masih bangun tiap detik?")
                assertTrue(
                    waitFor(what = "ronde pertama jatuh tempo") { providerCalls.get() >= 1 },
                    "runner tidak pernah mencapai ronde pertama",
                )
                val first = firstCallMs.get()
                assertTrue(first >= 4_000, "ronde pertama jatuh tempo terlalu cepat: ${first}ms (batas bawah 5 detik, toleransi 1 detik)")
            } finally {
                runner.stop()
            }
        } finally {
            Observatory.clear()
        }
    }
}
