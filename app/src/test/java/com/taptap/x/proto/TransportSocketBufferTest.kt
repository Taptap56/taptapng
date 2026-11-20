package com.taptap.x.proto

import com.taptap.x.core.DialLog
import com.taptap.x.core.proto.Transport
import com.taptap.x.data.ConfigType
import com.taptap.x.data.ProfileItem
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.18 phone log (2026-11-20 16:01,
 * Speedtest ~25 Mbps): the TUN write was fixed (TunWriter), but
 * the relay then spent 93-95% of its time WAITING for data
 * (tls+net=15170ms of 16,0 s, 0,50 MB/s per connection) while
 * every app-side stage was tiny. Throughput per connection ≈ TCP
 * window / RTT — and the proxy socket was never tuned (plain
 * Socket() defaults). v1.0.19 raises the buffers before connect()
 * and logs the effective values the kernel grants.
 *
 * Linux doubles SO_RCVBUF/SO_SNDBUF on read-back and clamps them
 * to net.core.rmem_max/wmem_max, so a test that requests 1 MB on
 * a runner with rmem_max=212992 would see only ~425984 back.
 * The mechanism tests therefore tune with values below the clamp
 * and assert >= (never ==); the production constants are locked
 * separately, and the open() test compares against a plain-socket
 * baseline instead of an absolute number.
 *
 * These tests FAIL on v1.0.18 code: no buffer is ever set
 * (tcpNoDelay stays false, buffers stay at the defaults).
 */
class TransportSocketBufferTest {

    @Test
    fun `tuning raises the buffers and enables TCP_NODELAY`() {
        val socket = Socket()
        try {
            Transport.tuneSocketBuffers(socket, recvSize = 64 * 1024, sendSize = 32 * 1024)
            assertTrue(
                socket.receiveBufferSize >= 64 * 1024,
                "receive buffer must be at least the requested 64 KiB, got ${socket.receiveBufferSize}",
            )
            assertTrue(
                socket.sendBufferSize >= 32 * 1024,
                "send buffer must be at least the requested 32 KiB, got ${socket.sendBufferSize}",
            )
            assertTrue(socket.tcpNoDelay, "TCP_NODELAY must be on after tuning")
        } finally {
            runCatching { socket.close() }
        }
    }

    @Test
    fun `tuning a closed socket never throws`() {
        val socket = Socket()
        socket.close()
        assertDoesNotThrow {
            Transport.tuneSocketBuffers(socket)
        }
    }

    @Test
    fun `production buffer constants are 1 MB receive and 256 KB send`() {
        assertEquals(1024 * 1024, Transport.SOCKET_RECV_BUFFER_SIZE)
        assertEquals(256 * 1024, Transport.SOCKET_SEND_BUFFER_SIZE)
    }

    @Test
    fun `open() applies the tuning and logs the effective values`() {
        val server = ServerSocket(0, 50, InetAddress.getByName("::1"))
        val port = server.localPort
        val acceptThread = Thread {
            try {
                while (!server.isClosed) {
                    val accepted = server.accept()
                    accepted.soTimeout = 5_000
                    Thread.sleep(200)
                    runCatching { accepted.close() }
                }
            } catch (_: Exception) {
                // Server closed.
            }
        }
        acceptThread.isDaemon = true
        acceptThread.start()
        try {
            // Baseline: a plain socket with no tuning, same server.
            val baselineRcv = Socket().use { plain ->
                plain.connect(InetSocketAddress(InetAddress.getByName("::1"), port), 5_000)
                plain.receiveBufferSize
            }
            val item = ProfileItem(
                configType = ConfigType.VMESS,
                address = "::1", port = port,
                uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
                network = "tcp", tls = false,
            )
            val dialLogBefore = DialLog.lines().size
            val stream = Transport.open(item)
            try {
                val socket = stream.socket
                assertTrue(socket.tcpNoDelay, "open() must enable TCP_NODELAY on the proxy socket")
                assertTrue(
                    socket.receiveBufferSize >= baselineRcv,
                    "tuning must never shrink the receive buffer: " +
                        "got ${socket.receiveBufferSize}, baseline $baselineRcv",
                )
                assertTrue(
                    DialLog.lines().drop(dialLogBefore).any { it.contains("SOCKET rcv=") },
                    "DialLog must record the effective socket buffers",
                )
            } finally {
                stream.close()
            }
        } finally {
            runCatching { server.close() }
        }
    }
}
