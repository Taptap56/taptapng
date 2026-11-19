package com.taptap.x

import com.taptap.x.core.SshClient
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.command.AbstractCommand
import org.apache.sshd.server.command.CommandFactory
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * End-to-end SSH proof-of-concept: an in-process MINA SSHD server
 * (pure Java, no system sshd) + the app's JSch client. This is the
 * Phase 1 protocol proof — SSH runs over a real SSH2 handshake,
 * channel exec, and exit status, with no native core involved.
 */
class SshClientTest {

    private lateinit var server: SshServer
    private var port: Int = 0

    @BeforeEach
    fun setUp() {
        val tmpDir = Files.createTempDirectory("sshd-test")
        server = SshServer.setUpDefaultServer()
        server.port = 0 // ephemeral port
        server.keyPairProvider =
            SimpleGeneratorHostKeyProvider(tmpDir.resolve("hostkey.ser"))
        server.passwordAuthenticator = PasswordAuthenticator { username, password, _ ->
            username == "test" && password == "test"
        }
        server.commandFactory = CommandFactory { command ->
            object : AbstractCommand() {
                override fun run() {
                    // Minimal "echo <text>" — enough to prove exec works.
                    val text = command.removePrefix("echo ").trim()
                    outputStream.write((text + "\n").toByteArray(Charsets.UTF_8))
                    outputStream.flush()
                    exitCallback?.onExit(0)
                }
            }
        }
        server.start()
        port = server.port
    }

    @AfterEach
    fun tearDown() {
        runCatching { server.stop(true) }
    }

    @Test
    fun `ssh exec returns echo output`() {
        val outcome = SshClient.runCommand(
            host = "127.0.0.1",
            port = port,
            username = "test",
            password = "test",
            command = "echo hello-taptapx",
        )
        assertEquals(0, outcome.exitStatus)
        assertEquals("hello-taptapx", outcome.output.trim())
    }

    @Test
    fun `ssh wrong password fails`() {
        val failed = runCatching {
            SshClient.runCommand(
                host = "127.0.0.1",
                port = port,
                username = "test",
                password = "wrong",
                command = "echo hi",
            )
        }
        assertTrue(failed.isFailure)
    }

    @Test
    fun `clampPort defaults and clamps`() {
        assertEquals(22, SshClient.clampPort(null))
        assertEquals(22, SshClient.clampPort(0))
        assertEquals(22, SshClient.clampPort(70000))
        assertEquals(2222, SshClient.clampPort(2222))
    }
}
