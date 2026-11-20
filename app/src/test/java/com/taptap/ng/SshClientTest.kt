package com.taptap.ng

import com.taptap.ng.core.SshClient
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPairGenerator
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.Environment
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * End-to-end SSH proof-of-concept: an in-process MINA SSHD server
 * (pure Java, no system sshd) + the app's JSch client. This is the
 * Phase 1 protocol proof — SSH runs over a real SSH2 handshake,
 * channel exec, and exit status, with no native core involved.
 *
 * MINA SSHD 2.12.0 API notes (verified against the published jar):
 * - No `AbstractCommand` — [Command] is implemented directly (6 methods:
 *   setExitCallback + start/destroy + setInputStream/setOutputStream/
 *   setErrorStream).
 * - [CommandFactory] is a SAM: createCommand(ChannelSession, String).
 * - No `SimpleGeneratorHostKeyProvider` in sshd-core — the host key is a
 *   JDK-generated RSA pair wrapped with [KeyPairProvider.wrap].
 * - [PasswordAuthenticator] is a SAM (authenticate only;
 *   handleClientPasswordChangeRequest is a default method).
 */
class SshClientTest {

    private lateinit var server: SshServer
    private var port: Int = 0

    @BeforeEach
    fun setUp() {
        val hostKey = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }.generateKeyPair()
        server = SshServer.setUpDefaultServer()
        server.port = 0 // ephemeral port
        server.keyPairProvider = KeyPairProvider.wrap(hostKey)
        server.passwordAuthenticator = PasswordAuthenticator { username, password, _ ->
            username == "test" && password == "test"
        }
        server.commandFactory = CommandFactory { _, command -> EchoCommand(command) }
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
            command = "echo hello-taptapng",
        )
        assertEquals(0, outcome.exitStatus)
        assertEquals("hello-taptapng", outcome.output.trim())
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

    /** Minimal echo command: writes back the argument of `echo <text>`. */
    private class EchoCommand(private val commandLine: String) : Command {
        private var out: OutputStream? = null
        private var exitCallback: ExitCallback? = null

        override fun setInputStream(`in`: InputStream) {}
        override fun setOutputStream(out: OutputStream) {
            this.out = out
        }

        override fun setErrorStream(err: OutputStream) {}
        override fun setExitCallback(callback: ExitCallback) {
            this.exitCallback = callback
        }

        override fun start(channel: ChannelSession, env: Environment) {
            val text = commandLine.removePrefix("echo ").trim()
            out?.write((text + "\n").toByteArray(Charsets.UTF_8))
            out?.flush()
            exitCallback?.onExit(0)
        }

        override fun destroy(channel: ChannelSession) {}
    }
}
