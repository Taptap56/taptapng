package com.taptap.x.core.proto

import java.net.Socket
import kotlin.concurrent.thread

/**
 * Backstop watchdog for one dial (v1.0.6, fix A).
 *
 * Every dial stage already has a socket timeout (10 s), but the
 * phone proved a dial can still hang past every timeout: v1.0.5
 * stayed on "Connecting..." for 4+ minutes with no failure reported.
 * Whatever the underlying stall is, a dial must never hang forever.
 * The watchdog closes the live socket after [timeoutMs]; the blocked
 * read then throws, and the caller reports the stage the dial was
 * stuck in (see [Transport.preferWatchdogFailure]).
 *
 * One watchdog per dial, owned by the dialling thread: the caller
 * (probe / forwarder dial) creates it, installs it with
 * [Transport.setThreadWatchdog], starts it, and stops it in a
 * `finally` right after the dial returns. [Transport] registers the
 * live socket ([arm]) and the current stage at each step; protocol
 * clients clear the socket ([clearSocket]) once their handshake has
 * succeeded, so the timer can never kill a live relay socket.
 */
class DialWatchdog(val timeoutMs: Long = DEFAULT_TIMEOUT_MS) {

    companion object {
        const val DEFAULT_TIMEOUT_MS = 30_000L
    }

    /** Stage the dial was in when the timer fired ("TCP", "TLS", ...). */
    @Volatile
    var stage: String = "dial"

    @Volatile
    var fired: Boolean = false
        private set

    @Volatile
    private var socket: Socket? = null

    @Volatile
    private var done = false

    private var timer: Thread? = null

    fun start() {
        if (timer != null) return
        timer = thread(name = "dial-watchdog", isDaemon = true) {
            try {
                Thread.sleep(timeoutMs)
            } catch (_: InterruptedException) {
                return@thread
            }
            if (!done) {
                fired = true
                runCatching { socket?.close() }
            }
        }
    }

    /** The socket to close if the timer fires (re-armed per stage). */
    fun arm(socket: Socket) {
        this.socket = socket
    }

    /** The dial succeeded: the timer must not touch this socket again. */
    fun clearSocket() {
        socket = null
    }

    /** Disarm the timer (dial finished, one way or the other). */
    fun stop() {
        done = true
        timer?.interrupt()
        socket = null
    }

    /** Alias for teardown paths (stop + unblock the dial right now). */
    fun cancel() = stop()
}
