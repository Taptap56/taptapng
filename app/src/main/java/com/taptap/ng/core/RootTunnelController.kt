package com.taptap.ng.core

/**
 * Root mode — lifecycle aturan iptables (v1.0.15).
 *
 * Menjawab requiredChanges #1, #2, #5 dari [RootModeAssessment]:
 * eksekutor root + fallback, aturan lengkap dari generator murni,
 * dan cleanup yang dijamin di tiga tempat — saat stop, saat start
 * (aturan basi dibersihkan SEBELUM pasang yang baru), dan saat
 * boot ([BootReceiver] memanggil [cleanupStale]).
 *
 * Prinsip fail-closed:
 * - `su` tidak ada / bukan uid 0 → [StartResult.NoRoot]: service
 *   kembali ke VpnService (bukan setengah jalan, tanpa aturan).
 * - Satu perintah install gagal → rollback penuh (cleanup) lalu
 *   [StartResult.Failed]: service GAGAL dengan pesan jelas, bukan
 *   fallback diam-diam — aturan setengah pasang lebih berbahaya
 *   daripada tidak jalan.
 * - Cleanup best-effort: kegagalan satu perintah `-D` (aturan
 *   sudah tidak ada) TIDAK menggagalkan stop — daftar perintah
 *   yang gagal dikembalikan supaya service bisa me-log-nya.
 *   Cleanup TIDAK PERNAH melempar.
 */
class RootTunnelController {

    sealed class StartResult {
        /** Aturan terpasang + terverifikasi. */
        data object Ok : StartResult()

        /** Root tidak tersedia — service boleh fallback ke VpnService. */
        data class NoRoot(val reason: String) : StartResult()

        /** Install gagal — aturan sudah di-rollback; JANGAN fallback diam-diam. */
        data class Failed(val reason: String) : StartResult()
    }

    fun start(executor: RootExecutor, config: RootIptables.Config): StartResult {
        if (!RootAvailability.isRoot(executor)) {
            return StartResult.NoRoot(
                "Root tidak tersedia (su tidak ada / bukan uid 0) — kembali ke VpnService",
            )
        }
        // Aturan basi dari crash sebelumnya dibersihkan dulu —
        // start yang kedua tidak boleh gagal karena rantai sudah ada.
        cleanupStale(executor, config)
        for (cmd in RootIptables.installCommands(config)) {
            val r = runCatching { executor.run(cmd) }.getOrNull()
            if (r == null || !r.ok) {
                val failed = cleanupStale(executor, config)
                return StartResult.Failed(
                    "iptables gagal: $cmd (exit ${r?.exitCode}) — " +
                        "aturan di-rollback (${failed.size} perintah cleanup gagal)",
                )
            }
        }
        val check = runCatching {
            executor.run(RootIptables.chainCheckCommand(config))
        }.getOrNull()
        if (check == null || !check.ok) {
            cleanupStale(executor, config)
            return StartResult.Failed(
                "iptables terpasang tapi rantai ${RootIptables.CHAIN} tidak terverifikasi — di-rollback",
            )
        }
        return StartResult.Ok
    }

    /**
     * Hapus semua aturan milik TaptapNG. Mengembalikan perintah
     * cleanup yang gagal (kosong = bersih total). Tidak melempar.
     */
    fun stop(executor: RootExecutor, config: RootIptables.Config): List<String> =
        cleanupStale(executor, config)

    /** Alias [stop]: bersihkan aturan basi (dipakai saat start + boot). */
    fun cleanupStale(executor: RootExecutor, config: RootIptables.Config): List<String> {
        val failed = ArrayList<String>()
        for (cmd in RootIptables.cleanupCommands(config)) {
            val r = runCatching { executor.run(cmd) }.getOrNull()
            if (r == null || !r.ok) failed += cmd
        }
        return failed
    }
}
