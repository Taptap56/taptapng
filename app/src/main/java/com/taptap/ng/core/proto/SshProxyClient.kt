package com.taptap.ng.core.proto

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import com.taptap.ng.AppConfig
import com.taptap.ng.core.DialLog
import com.taptap.ng.core.SshClient
import com.taptap.ng.data.ProfileItem
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * One SSH channel to a target (a direct-tcpip channel on the shared
 * session — the SSH-level mechanism a SOCKS dynamic forward uses,
 * without the local loopback listener).
 */
interface SshChannel {
    val input: InputStream
    val output: OutputStream
    fun close()
}

/** Opens [SshChannel]s on a shared SSH session. Test seam for [SshProxyClient]. */
interface SshChannelOpener {
    fun openChannel(targetHost: String, targetPort: Int): SshChannel
    fun close()
}

/**
 * SSH as a [ProxyClient] (v1.0.30): the entry can finally ride the
 * TUN. One JSch session is shared by the probe + all forwarder
 * dials; each [dial] opens a direct-tcpip channel to its target
 * (the same mechanism TB/TC's Go SSH client and xray-core's SSH
 * outbound use — `client.Dial("tcp", target)`).
 *
 * Why direct-tcpip and not JSch `setPortForwardingD`: the mwiede
 * JSch 0.2.21 bundled here has NO such method at all (verified
 * against the published jar — only L/R forwarding exist), and a
 * local SOCKS listener would need a port of its own (a collision
 * between the VPN client and the delay-test client, both of which
 * build an [SshProxyClient]) plus a localhost hop per dial. The
 * channel path has neither problem and is testable in-memory via
 * the [SshChannelOpener] seam (no loopback sockets in JVM tests).
 *
 * [probeBody] is ignored on purpose: the session connect + channel
 * open IS the probe (there is no response header to unblock, and
 * writing an HTTP body into a channel aimed at the SSH daemon
 * itself would only corrupt its banner wait).
 */
class SshProxyClient(
    private val item: ProfileItem,
    /** Test seam: a fake opener (default: the real JSch opener). */
    private val channelOpener: SshChannelOpener? = null,
) : ProxyClient {

    // v1.0.6: every stream this client opened, so close() can close
    // them all — but a new dial NEVER closes the previous stream.
    private val openStreams = ConcurrentHashMap.newKeySet<ProxyStream>()

    private val realOpener: SshChannelOpener by lazy { JschSshChannelOpener(item) }

    private fun opener(): SshChannelOpener = channelOpener ?: realOpener

    override fun dial(
        targetHost: String,
        targetPort: Int,
        probeBody: ByteArray?,
        stats: SpeedStats?,
    ): ProxyStream {
        try {
            val channel = opener().openChannel(targetHost, targetPort)
            DialLog.log("SSH", "channel $targetHost:$targetPort ok")
            return TrackedProxyStream(
                StreamProxyStream(channel.input, channel.output) { channel.close() },
                openStreams,
            )
        } catch (e: IOException) {
            val failure = Transport.preferWatchdogFailure(e)
            DialLog.failure("SSH", failure)
            throw failure
        } catch (e: Exception) {
            val failure = Transport.preferWatchdogFailure(
                IOException("SSH gagal: ${e.message}", e),
            )
            DialLog.failure("SSH", failure)
            throw failure
        }
    }

    override fun close() {
        openStreams.toList().forEach { runCatching { it.close() } }
        runCatching { opener().close() }
    }
}

/** Production [SshChannelOpener]: one lazy JSch session, one direct-tcpip channel per dial. */
internal class JschSshChannelOpener(
    private val item: ProfileItem,
) : SshChannelOpener {

    private val lock = Any()

    @Volatile
    private var session: Session? = null

    /** The session, connected on first use (and reconnected when dead). */
    private fun ensureSession(): Session {
        session?.takeIf { it.isConnected }?.let { return it }
        synchronized(lock) {
            session?.takeIf { it.isConnected }?.let { return it }
            val connected = SshClient.connect(
                host = item.address,
                port = SshClient.clampPort(item.port),
                username = item.username,
                password = item.password,
                privateKey = item.privateKey,
                socketFactory = SshChainSocketFactory(item),
                keepAliveMs = AppConfig.SSH_KEEPALIVE_MS,
            )
            session = connected
            DialLog.log("SSH", "sesi ok (${item.address}:${item.port})")
            return connected
        }
    }

    override fun openChannel(targetHost: String, targetPort: Int): SshChannel {
        val s = ensureSession()
        val channel = try {
            s.openChannel("direct-tcpip") as ChannelDirectTCPIP
        } catch (e: JSchException) {
            throw IOException("SSH gagal: buka channel direct-tcpip: ${e.message}", e)
        }
        channel.setHost(targetHost)
        channel.setPort(targetPort)
        try {
            channel.connect(AppConfig.SSH_CHANNEL_TIMEOUT_MS)
        } catch (e: JSchException) {
            runCatching { channel.disconnect() }
            throw IOException("SSH gagal: channel ke $targetHost:$targetPort: ${e.message}", e)
        }
        return JschSshChannel(channel)
    }

    override fun close() {
        synchronized(lock) {
            runCatching { session?.disconnect() }
            session = null
        }
    }
}

/** An [SshChannel] over one JSch direct-tcpip channel. */
private class JschSshChannel(
    private val channel: ChannelDirectTCPIP,
) : SshChannel {
    override val input: InputStream get() = channel.inputStream
    override val output: OutputStream get() = channel.outputStream
    override fun close() {
        runCatching { channel.disconnect() }
    }
}

/**
 * JSch [SocketFactory] that runs the SSH payload chain (v1.0.30).
 * JSch calls [createSocket] with the SSH host/port; the chain dials
 * the remote proxy when `sshRemoteProxy` is set, else the SSH server
 * itself. The TCP→TLS ladder is [Transport.open] (same protect/DNS/
 * buffer/watchdog as the other protocols — the ladder item is a copy
 * with the chain target + the SSH TLS settings), then the payload
 * runs on top, then framing is detected and the stream is wrapped
 * in WS frames when needed. The negotiated streams are returned by
 * [getInputStream]/[getOutputStream] — JSch never sees the raw
 * socket streams once the chain has wrapped them.
 */
internal class SshChainSocketFactory(
    private val item: ProfileItem,
    private val stats: SpeedStats? = null,
) : SocketFactory {

    private var negotiatedIn: InputStream? = null
    private var negotiatedOut: OutputStream? = null

    override fun createSocket(host: String, port: Int): Socket {
        val (targetHost, targetPort) = SshPayload.chainTarget(item, host, port)
        val ladderItem = item.copy(
            address = targetHost,
            port = targetPort,
            network = "tcp",
            tls = item.sshUseTls,
            sni = item.sshSni.ifBlank { host },
            insecure = item.sshInsecure,
            alpn = "",
        )
        val open = try {
            Transport.open(ladderItem, stats, tlsProtocols = SshPayload.tlsProtocols(item.sshSniVersion))
        } catch (e: IOException) {
            // Transport already tags its stages ("TCP gagal",
            // "TLS gagal", ...) — keep them verbatim.
            throw e
        } catch (e: Exception) {
            throw IOException("SSH gagal: ${e.message}", e)
        }
        try {
            val bufferedIn = BufferedInputStream(open.input)
            var input: InputStream = bufferedIn
            var output: OutputStream = open.output
            if (item.sshUsePayload && item.sshPayload.isNotBlank()) {
                val result = SshPayload.sendRequests(bufferedIn, output, item)
                // Framing peek with a short deadline (TB: 2 s) —
                // the socket still has the 10 s handshake timeout
                // from Transport.open; the peek must not wait that
                // long when the server sends nothing yet.
                open.socket.soTimeout = SshPayload.PEEK_PERIOD_MS
                val detected = SshPayload.peekFraming(bufferedIn)
                val framing = SshPayload.chooseFraming(
                    detected, result.wasWsUpgrade, result.lastStatus,
                )
                if (framing == SshPayload.Framing.WS) {
                    val ws = WsTransport.WsStream(bufferedIn, output, stats)
                    input = ws.input
                    output = ws.output
                    DialLog.log("SSH", "framing WebSocket")
                } else {
                    DialLog.log("SSH", "framing mentah (banner SSH)")
                }
            }
            // Handshake done: a blocking socket for JSch (the other
            // clients clear the handshake timeout the same way), and
            // the watchdog must never kill this live session socket.
            open.socket.soTimeout = 0
            Transport.clearWatchdogSocket()
            negotiatedIn = input
            negotiatedOut = output
            return open.socket
        } catch (e: Exception) {
            runCatching { open.close() }
            DialLog.failure("SSH", e)
            throw when (e) {
                is IOException -> e
                else -> IOException("SSH gagal: ${e.message}", e)
            }
        }
    }

    override fun getInputStream(socket: Socket): InputStream =
        negotiatedIn ?: socket.getInputStream()

    override fun getOutputStream(socket: Socket): OutputStream =
        negotiatedOut ?: socket.getOutputStream()
}
