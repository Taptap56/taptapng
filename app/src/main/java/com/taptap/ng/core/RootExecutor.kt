package com.taptap.ng.core

/**
 * Eksekutor root (v1.0.15) — menjalankan satu perintah shell
 * lewat `su -c`. Interface supaya controller bisa diuji di JVM
 * dengan executor palsu; implementasi nyata hanya
 * [SuExecutor] (ProcessBuilder, tanpa API Android).
 *
 * Aturan keamanan: perintah yang dijalankan HANYA yang
 * dihasilkan [RootIptables] (+ `id -u` untuk deteksi root) —
 * tidak ada interpolasi input user ke shell (UID/port adalah
 * Int dari config, bukan string bebas).
 */
interface RootExecutor {
    fun run(command: String): ExecResult
}

data class ExecResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
) {
    val ok: Boolean get() = exitCode == 0
}

/** Eksekutor nyata: `su -c <perintah>`, timeout [timeoutMs]. */
class SuExecutor(
    private val timeoutMs: Long = 10_000,
) : RootExecutor {
    override fun run(command: String): ExecResult {
        return try {
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            val finished = process.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            if (!finished) {
                process.destroyForcibly()
                return ExecResult(-1, "", "timeout ${timeoutMs}ms: su -c $command")
            }
            val out = process.inputStream.bufferedReader().readText()
            ExecResult(process.exitValue(), out.trim(), "")
        } catch (e: Exception) {
            ExecResult(-1, "", e.message ?: e.javaClass.simpleName)
        }
    }
}

/** Deteksi root: `su` ada dan `id -u` == 0. */
object RootAvailability {
    fun isRoot(executor: RootExecutor): Boolean {
        val r = runCatching { executor.run("id -u") }.getOrNull() ?: return false
        return r.ok && r.stdout.trim() == "0"
    }
}
