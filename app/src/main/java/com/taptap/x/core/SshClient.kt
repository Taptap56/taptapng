package com.taptap.x.core

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.taptap.x.AppConfig
import java.io.ByteArrayOutputStream

/**
 * SSH client built on JSch (pure Java, no native code) — the Phase 1
 * proof-of-concept protocol. Same approach as XVEON: the protocol lives
 * in the app's own code instead of a bundled native core.
 *
 * Later milestones add VMess/VLESS/Trojan/Shadowsocks + SlowDNS/DNSTT +
 * Onering + Pemicu on top of this same in-app pattern.
 */
object SshClient {

    data class ExecResult(
        val output: String,
        val exitStatus: Int,
    )

    /** Result of a single command run. Kept separate so tests can assert it. */
    data class RunOutcome(
        val output: String,
        val exitStatus: Int,
    )

    /** Build a connected, authenticated session. Caller must [disconnect].
     *
     * [socketFactory] (v1.0.30): when set, JSch builds its socket
     * through it — the SSH payload chain ([SshChainSocketFactory])
     * runs on the raw socket before the SSH handshake. Null = a
     * plain direct socket (the old exec / delay-test path).
     * [keepAliveMs] (v1.0.30): server-alive interval for a
     * long-lived tunnel session; 0 = off (short-lived uses).
     */
    fun connect(
        host: String,
        port: Int,
        username: String,
        password: String = "",
        privateKey: String = "",
        connectTimeoutMs: Int = AppConfig.SSH_CONNECT_TIMEOUT_MS,
        socketFactory: com.jcraft.jsch.SocketFactory? = null,
        keepAliveMs: Int = 0,
    ): Session {
        val jsch = JSch()
        if (privateKey.isNotBlank()) {
            jsch.addIdentity("taptapx", privateKey.toByteArray(), null, null)
        }
        val session = jsch.getSession(username, host, port)
        if (password.isNotBlank()) {
            session.setPassword(password)
        }
        // Same hardening as the TaptapBox/TaptapClash SSH backends:
        // explicit client version + host-key algorithms, ssh-rsa LAST
        // (old Dropbear servers).
        session.setConfig("StrictHostKeyChecking", "no")
        session.setConfig(
            "server_host_key",
            "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384," +
                "ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,ssh-rsa"
        )
        if (socketFactory != null) {
            session.setSocketFactory(socketFactory)
        }
        if (keepAliveMs > 0) {
            session.setServerAliveInterval(keepAliveMs)
            session.setServerAliveCountMax(3)
        }
        session.connect(connectTimeoutMs)
        return session
    }

    /** Run one command on an open session and return its stdout + exit code. */
    fun exec(
        session: Session,
        command: String,
        timeoutMs: Int = AppConfig.SSH_CHANNEL_TIMEOUT_MS,
    ): ExecResult {
        val channel = session.openChannel("exec") as ChannelExec
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        channel.outputStream = out
        channel.setErrStream(err)
        channel.setCommand(command)
        channel.connect(timeoutMs)
        try {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (!channel.isClosed) {
                if (System.currentTimeMillis() > deadline) break
                Thread.sleep(50)
            }
        } finally {
            channel.disconnect()
        }
        return ExecResult(
            output = out.toString(Charsets.UTF_8),
            exitStatus = channel.exitStatus,
        )
    }

    /** One-shot: connect, run, disconnect. Used by the delay test + UI. */
    fun runCommand(
        host: String,
        port: Int,
        username: String,
        password: String = "",
        privateKey: String = "",
        command: String,
    ): RunOutcome {
        val session = connect(host, port, username, password, privateKey)
        try {
            val result = exec(session, command)
            return RunOutcome(result.output, result.exitStatus)
        } finally {
            disconnect(session)
        }
    }

    fun disconnect(session: Session?) {
        runCatching { session?.disconnect() }
    }

    /** Pure helper: clamp a port into 1..65535 (invalid -> default 22). */
    fun clampPort(port: Int?, default: Int = AppConfig.SSH_DEFAULT_PORT): Int {
        if (port == null) return default
        return if (port in 1..65535) port else default
    }
}
