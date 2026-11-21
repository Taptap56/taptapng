package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootTunnelControllerTest {

    private val cfg = RootIptables.Config(appUid = 10123)

    private class FakeExecutor(
        var root: Boolean = true,
        var failOn: String? = null,
        var failCleanup: Boolean = false,
    ) : RootExecutor {
        val commands = mutableListOf<String>()

        override fun run(command: String): ExecResult {
            commands += command
            if (command == "id -u") {
                return if (root) ExecResult(0, "0", "") else ExecResult(1, "", "su tidak ada")
            }
            if (failCleanup && command.contains(" -D ") || failCleanup && command.contains(" -F ") ||
                failCleanup && command.contains(" -X ")
            ) {
                return ExecResult(1, "", "aturan tidak ada")
            }
            if (failOn != null && command.contains(failOn!!)) {
                return ExecResult(1, "", "gagal")
            }
            return ExecResult(0, "", "")
        }
    }

    @Test
    fun `no root returns NoRoot and installs nothing`() {
        val exec = FakeExecutor(root = false)
        val result = RootTunnelController().start(exec, cfg)
        assertTrue(result is RootTunnelController.StartResult.NoRoot, "got $result")
        assertTrue(
            exec.commands.none { it.startsWith("iptables") },
            "tanpa root tidak boleh ada iptables: ${exec.commands}",
        )
    }

    @Test
    fun `start cleans stale rules first then installs all`() {
        val exec = FakeExecutor()
        val result = RootTunnelController().start(exec, cfg)
        assertEquals(RootTunnelController.StartResult.Ok, result)
        val install = RootIptables.installCommands(cfg)
        val cleanup = RootIptables.cleanupCommands(cfg)
        assertEquals(cleanup, exec.commands.subList(1, 1 + cleanup.size))
        assertEquals(
            install,
            exec.commands.subList(1 + cleanup.size, 1 + cleanup.size + install.size),
        )
        assertTrue(exec.commands.last().startsWith("iptables -t nat -S TAPTAPNG"))
    }

    @Test
    fun `install failure rolls back and returns Failed`() {
        val exec = FakeExecutor(failOn = "--dport 443 -j REDIRECT")
        val result = RootTunnelController().start(exec, cfg)
        assertTrue(result is RootTunnelController.StartResult.Failed, "got $result")
        val cleanup = RootIptables.cleanupCommands(cfg)
        // Cleanup berjalan dua kali: basi di awal + rollback sesudah gagal.
        val tail = exec.commands.takeLast(cleanup.size)
        assertEquals(cleanup, tail, "rollback harus menjalankan cleanup penuh: ${exec.commands}")
        assertTrue(
            (result as RootTunnelController.StartResult.Failed).reason.contains("443"),
            "alasan harus menyebut perintah gagal: ${result.reason}",
        )
    }

    @Test
    fun `stop removes every rule and reports empty when all succeed`() {
        val exec = FakeExecutor()
        val failed = RootTunnelController().stop(exec, cfg)
        assertTrue(failed.isEmpty(), "gagal: $failed")
        assertEquals(RootIptables.cleanupCommands(cfg), exec.commands)
    }

    @Test
    fun `stop tolerates missing rules and reports them`() {
        val exec = FakeExecutor(failCleanup = true)
        val failed = RootTunnelController().stop(exec, cfg)
        assertEquals(RootIptables.cleanupCommands(cfg).size, failed.size)
    }

    @Test
    fun `cleanup stale never throws even when the executor throws`() {
        val throwing = RootExecutor { throw RuntimeException("su mati") }
        val failed = RootTunnelController().cleanupStale(throwing, cfg)
        assertEquals(RootIptables.cleanupCommands(cfg).size, failed.size)
    }
}
