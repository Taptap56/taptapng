package com.taptap.ng.proto

import com.taptap.ng.core.DialLog
import com.taptap.ng.core.proto.DialWatchdog
import com.taptap.ng.core.proto.Transport
import com.taptap.ng.data.ConfigType
import com.taptap.ng.data.ProfileItem
import java.net.InetAddress
import java.net.ServerSocket
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.5 phone report (2026-11-20 02:49–02:53):
 * the status stayed "Connecting: Zoom onering..." for 4+ minutes with
 * no failure reported — a dial stage blocked past every socket
 * timeout (or no dial ever ran). v1.0.6 arms a watchdog around every
 * dial: a stage that blocks past 30 s is killed by closing the socket
 * and reported with the stage it was stuck in.
 *
 * These tests FAIL on v1.0.5 code: without the watchdog the stuck TLS
 * dial only dies at the 10 s socket timeout, with no "watchdog" tag.
 */
class DialWatchdogTest {

    /** A server that accepts TCP and then never says anything — the
     * closed-window behaviour: TCP connects, TLS never answers. */
    private fun blackhole(): Pair<ServerSocket, Int> {
        val server = ServerSocket(0, 50, InetAddress.getByName("::1"))
        val port = server.localPort
        val t = Thread {
            try {
                val socket = server.accept()
                socket.soTimeout = 0
                try {
                    Thread.sleep(60_000)
                } catch (_: InterruptedException) {
                    // Test is over.
                } finally {
                    runCatching { socket.close() }
                }
            } catch (_: Exception) {
                // Server closed.
            }
        }
        t.isDaemon = true
        t.start()
        return server to port
    }

    @Test
    fun `watchdog kills a stuck TLS dial and tags the stage`() {
        val (server, port) = blackhole()
        try {
            val item = ProfileItem(
                configType = ConfigType.VMESS,
                address = "::1", port = port,
                uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
                network = "ws", tls = true,
            )
            val watchdog = DialWatchdog(timeoutMs = 2_000)
            Transport.setThreadWatchdog(watchdog)
            val dialLogBefore = DialLog.lines().size
            val start = System.nanoTime()
            val e = assertThrows(Exception::class.java) {
                try {
                    watchdog.start()
                    Transport.open(item)
                } finally {
                    watchdog.stop()
                    Transport.setThreadWatchdog(null)
                }
            }
            val elapsedMs = (System.nanoTime() - start) / 1_000_000
            assertTrue(watchdog.fired, "watchdog must have fired")
            assertTrue(elapsedMs < 8_000, "dial hung $elapsedMs ms despite the watchdog")
            val msg = e.message ?: ""
            assertTrue(msg.contains("TLS gagal"), "message must name the TLS stage: $msg")
            assertTrue(msg.contains("watchdog"), "message must name the watchdog: $msg")
            assertTrue(
                DialLog.lines().drop(dialLogBefore).any { it.contains("TLS") },
                "DialLog must record the stuck TLS stage",
            )
        } finally {
            runCatching { server.close() }
        }
    }

    @Test
    fun `watchdog does not fire on a fast successful dial`() {
        val server = ServerSocket(0, 50, InetAddress.getByName("::1"))
        val port = server.localPort
        val t = Thread {
            try {
                val socket = server.accept()
                socket.soTimeout = 5_000
                Thread.sleep(500)
                socket.close()
            } catch (_: Exception) {
                // Server closed.
            }
        }
        t.isDaemon = true
        t.start()
        val item = ProfileItem(
            configType = ConfigType.VMESS,
            address = "::1", port = port,
            uuid = "de305d54-75b4-431b-adb2-eb6b9e546014",
            network = "tcp", tls = false,
        )
        val watchdog = DialWatchdog(timeoutMs = 30_000)
        Transport.setThreadWatchdog(watchdog)
        try {
            watchdog.start()
            val stream = Transport.open(item)
            try {
                assertFalse(watchdog.fired, "watchdog must not fire on a fast dial")
            } finally {
                stream.close()
            }
        } finally {
            watchdog.stop()
            Transport.setThreadWatchdog(null)
            runCatching { server.close() }
        }
    }
}
