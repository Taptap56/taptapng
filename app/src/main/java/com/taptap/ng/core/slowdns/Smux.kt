package com.taptap.ng.core.slowdns

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.SocketTimeoutException
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * smux v2 client port (Kotlin, JDK only).
 *
 * Faithful port of github.com/metacubex/smux (v0.0.0-20260105030934-d0c8756d3141):
 * frame.go / session.go / stream.go / mux.go — client side, plus the session
 * accept loop so two sessions can talk to each other (SYN creates a stream
 * queued for [SmuxSession.acceptStream]).
 *
 * Wire format (8-byte header, little-endian):
 *   ver(1) | cmd(1) | length(2 LE) | sid(4 LE)
 * Commands: SYN=0 (open), FIN=1 (close/EOF), PSH=2 (data), NOP=3 (keepalive),
 * UPD=4 (v2 window update; 8-byte payload: consumed(4 LE) + window(4 LE)).
 *
 * Flow control (v2): per-stream sliding window, peer window starts at
 * [INITIAL_PEER_WINDOW] (262144); the reader sends UPD(consumed, window)
 * when bytes-consumed-since-last-update >= MaxStreamBuffer/2, or on the
 * first read. The session also has a global token bucket starting at
 * MaxReceiveBuffer; recvLoop blocks while the bucket is empty and tokens
 * are returned as streams are read.
 *
 * No Android imports, no payload logging.
 */

private const val CMD_SYN = 0
private const val CMD_FIN = 1
private const val CMD_PSH = 2
private const val CMD_NOP = 3
private const val CMD_UPD = 4

private const val HEADER_SIZE = 8
private const val UPD_PAYLOAD_SIZE = 8
private const val INITIAL_PEER_WINDOW = 262144
private const val OPEN_CLOSE_TIMEOUT_MS = 30_000L

private val EMPTY_PAYLOAD = ByteArray(0)

private fun u16Le(b: ByteArray, off: Int): Int =
    (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

private fun u32Le(b: ByteArray, off: Int): Int =
    (b[off].toInt() and 0xFF) or
        ((b[off + 1].toInt() and 0xFF) shl 8) or
        ((b[off + 2].toInt() and 0xFF) shl 16) or
        ((b[off + 3].toInt() and 0xFF) shl 24)

private fun putU16Le(b: ByteArray, off: Int, v: Int) {
    b[off] = (v and 0xFF).toByte()
    b[off + 1] = ((v ushr 8) and 0xFF).toByte()
}

private fun putU32Le(b: ByteArray, off: Int, v: Int) {
    b[off] = (v and 0xFF).toByte()
    b[off + 1] = ((v ushr 8) and 0xFF).toByte()
    b[off + 2] = ((v ushr 16) and 0xFF).toByte()
    b[off + 3] = ((v ushr 24) and 0xFF).toByte()
}

/**
 * smux session config. Defaults are the TaptapBox overrides of the smux
 * upstream defaults: version 2, 2-minute keepalive timeout, 1 MB stream
 * buffer (upstream: version 1, 30 s timeout, 64 KB stream buffer).
 */
data class SmuxConfig(
    val version: Int = 2,
    val keepAliveIntervalMs: Long = 10_000,
    val keepAliveTimeoutMs: Long = 120_000,
    val maxFrameSize: Int = 32768,
    val maxReceiveBuffer: Int = 4194304,
    val maxStreamBuffer: Int = 1024 * 1024,
)

/** One queued outbound frame, completed by the send loop. */
private class WriteRequest(
    val header: ByteArray,
    val payload: ByteArray,
) {
    val latch = CountDownLatch(1)
    @Volatile var resultErr: Throwable? = null
}

class SmuxSession(
    private val input: InputStream,
    private val output: OutputStream,
    internal val config: SmuxConfig = SmuxConfig(),
    /** true = client (odd stream IDs from 1); false = server (even IDs from 2). */
    private val isClient: Boolean = true,
) {
    private val closed = AtomicBoolean(false)
    @Volatile private var closeReason: Throwable? = null

    /** Global receive token bucket (smux session.go `bucket`). */
    private val bucket = AtomicInteger(config.maxReceiveBuffer)
    private val bucketMonitor = Object()

    private val streamsLock = Object()
    private val streams = HashMap<Int, SmuxStream>()
    private val accepts = LinkedBlockingQueue<SmuxStream>()

    private val nextIdLock = Object()
    private var nextStreamId: Int = if (isClient) 1 else 0
    private var goAway = false

    private val writeQueue = LinkedBlockingQueue<WriteRequest>()
    @Volatile private var lastActiveMs: Long = System.currentTimeMillis()

    private val recvThread: Thread
    private val sendThread: Thread
    private val keepaliveThread: Thread

    init {
        recvThread = Thread({ recvLoop() }, "smux-recv").apply { isDaemon = true }
        sendThread = Thread({ sendLoop() }, "smux-send").apply { isDaemon = true }
        keepaliveThread = Thread({ keepaliveLoop() }, "smux-keepalive").apply { isDaemon = true }
        recvThread.start()
        sendThread.start()
        keepaliveThread.start()
    }

    val isClosed: Boolean
        get() = closed.get()

    /**
     * Opens a new stream: allocates an odd (client) stream ID, sends SYN
     * (30 s timeout, as in smux `openCloseTimeout`), then registers the
     * stream. Throws [IOException] if the session is closed and
     * [SocketTimeoutException] if the SYN write times out.
     */
    fun openStream(): SmuxStream {
        if (isClosed) throw IOException("smux session is closed")
        val sid: Int
        synchronized(nextIdLock) {
            if (goAway) throw IOException("smux: stream id overflows, should start a new connection")
            // Overflow check, as in smux OpenStream.
            if (nextStreamId + 2 < nextStreamId) {
                goAway = true
                throw IOException("smux: stream id overflows, should start a new connection")
            }
            // NOTE: upstream smux increments BEFORE taking the id, so its
            // first client stream is 3. The TaptapNG spec requires odd IDs
            // starting at 1, so we allocate first, then increment.
            sid = nextStreamId
            nextStreamId += 2
        }
        val stream = SmuxStream(sid, this)
        writeFrame(CMD_SYN, sid, EMPTY_PAYLOAD, OPEN_CLOSE_TIMEOUT_MS)
        synchronized(streamsLock) {
            if (isClosed) throw IOException("smux session is closed")
            streams[sid] = stream
        }
        return stream
    }

    /**
     * Blocks until the peer opens a stream (SYN) and returns it.
     * Throws [SocketTimeoutException] after [timeoutMs] with no stream,
     * [IOException] if the session closes while waiting.
     */
    fun acceptStream(timeoutMs: Long = 30_000): SmuxStream {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0) throw SocketTimeoutException("smux accept timeout")
            val s = accepts.poll(minOf(remaining, 100L), java.util.concurrent.TimeUnit.MILLISECONDS)
            if (s != null) return s
            if (isClosed && accepts.isEmpty()) throw IOException("smux session is closed")
        }
    }

    /** Closes the session and all its streams; unblocks pending reads/writes. */
    fun close() {
        if (!closed.compareAndSet(false, true)) return
        // Unblock the loops first, then close the underlying streams.
        recvThread.interrupt()
        sendThread.interrupt()
        keepaliveThread.interrupt()
        synchronized(bucketMonitor) { (bucketMonitor as Object).notifyAll() }
        val snapshot: List<SmuxStream>
        synchronized(streamsLock) {
            snapshot = streams.values.toList()
            streams.clear()
        }
        for (s in snapshot) s.sessionClose()
        try { input.close() } catch (_: Exception) { }
        try { output.close() } catch (_: Exception) { }
    }

    // ---- internal API used by SmuxStream ----

    internal fun returnTokens(n: Int) {
        if (n <= 0) return
        if (bucket.addAndGet(n) > 0) notifyBucket()
    }

    internal fun notifyBucket() {
        synchronized(bucketMonitor) { (bucketMonitor as Object).notifyAll() }
    }

    /** Removes a stream from the session, returning its unread bytes as tokens. */
    internal fun streamClosed(sid: Int) {
        var recycled = 0
        synchronized(streamsLock) {
            val s = streams.remove(sid) ?: return
            recycled = s.recycleBufferedBytes()
        }
        if (recycled > 0) returnTokens(recycled)
    }

    /**
     * Sends one frame. [deadlineMs] <= 0 means wait indefinitely (still
     * aborts promptly when the session closes). Returns the payload bytes
     * written. Throws [SocketTimeoutException] on deadline expiry.
     */
    internal fun writeFrame(cmd: Int, sid: Int, payload: ByteArray, deadlineMs: Long): Int {
        if (isClosed) throw IOException("smux session is closed")
        val header = ByteArray(HEADER_SIZE)
        header[0] = config.version.toByte()
        header[1] = cmd.toByte()
        putU16Le(header, 2, payload.size)
        putU32Le(header, 4, sid)
        val req = WriteRequest(header, payload)
        writeQueue.offer(req)
        val deadline = if (deadlineMs > 0) System.currentTimeMillis() + deadlineMs else Long.MAX_VALUE
        while (true) {
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0) throw SocketTimeoutException("smux write timeout")
            val done = req.latch.await(minOf(remaining, 100L), java.util.concurrent.TimeUnit.MILLISECONDS)
            if (done) break
            if (isClosed) throw IOException("smux session is closed")
        }
        val err = req.resultErr
        if (err != null) {
            if (err is IOException) throw err
            throw IOException("smux write failed", err)
        }
        return payload.size
    }

    internal fun sendWindowUpdate(sid: Int, consumed: Int, window: Int) {
        val payload = ByteArray(UPD_PAYLOAD_SIZE)
        putU32Le(payload, 0, consumed)
        putU32Le(payload, 4, window)
        writeFrame(CMD_UPD, sid, payload, OPEN_CLOSE_TIMEOUT_MS)
    }

    // ---- background loops ----

    private fun failSession(e: Throwable) {
        if (closeReason == null) closeReason = e
        close()
    }

    private fun readFully(buf: ByteArray, off: Int = 0, len: Int = buf.size - off) {
        var p = off
        val end = off + len
        while (p < end) {
            val r = input.read(buf, p, end - p)
            if (r < 0) throw EOFException("smux: unexpected EOF")
            p += r
        }
    }

    private fun recvLoop() {
        val header = ByteArray(HEADER_SIZE)
        while (!isClosed) {
            // Wait for receive tokens, as in smux recvLoop.
            while (bucket.get() <= 0 && !isClosed) {
                synchronized(bucketMonitor) {
                    try { (bucketMonitor as Object).wait(100) } catch (_: InterruptedException) { return }
                }
            }
            if (isClosed) return
            try {
                readFully(header)
            } catch (e: Exception) {
                if (!isClosed) failSession(e)
                return
            }
            lastActiveMs = System.currentTimeMillis()
            if ((header[0].toInt() and 0xFF) != config.version) {
                failSession(IOException("smux: invalid protocol version ${header[0].toInt() and 0xFF}"))
                return
            }
            val cmd = header[1].toInt() and 0xFF
            val length = u16Le(header, 2)
            val sid = u32Le(header, 4)
            when (cmd) {
                CMD_NOP -> { /* keepalive, nothing to do */ }
                CMD_SYN -> {
                    var accepted: SmuxStream? = null
                    synchronized(streamsLock) {
                        if (!streams.containsKey(sid)) {
                            val s = SmuxStream(sid, this)
                            streams[sid] = s
                            accepted = s
                        }
                    }
                    if (accepted != null) accepts.offer(accepted)
                }
                CMD_FIN -> {
                    val s: SmuxStream?
                    synchronized(streamsLock) { s = streams[sid] }
                    s?.onFin()
                }
                CMD_PSH -> {
                    if (length == 0) continue
                    val payload = ByteArray(length)
                    try {
                        readFully(payload)
                    } catch (e: Exception) {
                        if (!isClosed) failSession(e)
                        return
                    }
                    val s: SmuxStream?
                    synchronized(streamsLock) { s = streams[sid] }
                    if (s != null) {
                        s.pushBytes(payload)
                        bucket.addAndGet(-payload.size)
                    }
                    // Data for a missing/closed stream is dropped (smux recycles it).
                }
                CMD_UPD -> {
                    val upd = ByteArray(UPD_PAYLOAD_SIZE)
                    try {
                        readFully(upd)
                    } catch (e: Exception) {
                        if (!isClosed) failSession(e)
                        return
                    }
                    val s: SmuxStream?
                    synchronized(streamsLock) { s = streams[sid] }
                    s?.update(u32Le(upd, 0), u32Le(upd, 4))
                }
                else -> {
                    failSession(IOException("smux: invalid protocol command $cmd"))
                    return
                }
            }
        }
    }

    private fun sendLoop() {
        while (!isClosed) {
            val req: WriteRequest
            try {
                req = writeQueue.take()
            } catch (_: InterruptedException) {
                return
            }
            try {
                output.write(req.header)
                if (req.payload.isNotEmpty()) output.write(req.payload)
                output.flush()
            } catch (e: Exception) {
                req.resultErr = e
                req.latch.countDown()
                if (!isClosed) failSession(e)
                return
            }
            req.latch.countDown()
        }
    }

    private fun keepaliveLoop() {
        var nextPing = System.currentTimeMillis() + config.keepAliveIntervalMs
        while (!isClosed) {
            val now = System.currentTimeMillis()
            if (now - lastActiveMs > config.keepAliveTimeoutMs && bucket.get() > 0) {
                // Inactive for KeepAliveTimeout (and recvLoop is not token-starved).
                close()
                return
            }
            val waitMs = nextPing - now
            if (waitMs <= 0) {
                try {
                    writeFrame(CMD_NOP, 0, EMPTY_PAYLOAD, config.keepAliveIntervalMs)
                } catch (_: Exception) {
                    // NOP failure is non-fatal here; recv/send errors close the session.
                }
                notifyBucket() // force a wakeup signal to recvLoop, as in smux
                nextPing = System.currentTimeMillis() + config.keepAliveIntervalMs
            } else {
                try {
                    Thread.sleep(minOf(waitMs, 200L))
                } catch (_: InterruptedException) {
                    return
                }
            }
        }
    }
}

class SmuxStream internal constructor(
    internal val id: Int,
    private val session: SmuxSession,
) {
    private class Chunk(val data: ByteArray, var pos: Int = 0) {
        val remaining: Int get() = data.size - pos
    }

    private val lock = Object()
    private val buffers = ArrayDeque<Chunk>()
    private var finReceived = false
    private var writeClosed = false
    private var closed = false
    private var inputClosed = false
    private var finSent = false
    private val closeOnce = AtomicBoolean(false)

    // v2 flow control (uint32 bit patterns held in Int; arithmetic wraps mod 2^32,
    // exactly as in smux stream.go writeV2).
    private val numWritten = AtomicInteger(0)
    private val peerConsumed = AtomicInteger(0)
    private val peerWindow = AtomicInteger(INITIAL_PEER_WINDOW)
    private var numRead: Long = 0
    private var incr: Long = 0

    private val writeLock = Object()

    /** Read side of the stream. See [SmuxStream] docs for EOF/deadline behaviour. */
    val input: InputStream = StreamInputStream()

    /** Write side of the stream; blocks on the peer window. close() sends FIN. */
    val output: OutputStream = StreamOutputStream()

    /**
     * Per-read() deadline in milliseconds. 0 = infinite (default).
     * Applies to each read() call; expiry throws [SocketTimeoutException].
     */
    @Volatile var readDeadlineMs: Long = 0

    /** Full close: sends FIN (once), discards unread data, unblocks readers/writers. */
    fun close() {
        if (!closeOnce.compareAndSet(false, true)) return
        synchronized(lock) {
            closed = true
            (lock as Object).notifyAll()
        }
        sendFin()
        session.streamClosed(id)
    }

    /** Half-close of the write side: sends FIN; the read side stays open for draining. */
    internal fun closeOutput() {
        synchronized(lock) {
            if (writeClosed) return
            writeClosed = true
            (lock as Object).notifyAll()
        }
        sendFin()
    }

    private fun sendFin() {
        synchronized(lock) {
            if (finSent) return
            finSent = true
        }
        try {
            session.writeFrame(CMD_FIN, id, EMPTY_PAYLOAD, OPEN_CLOSE_TIMEOUT_MS)
        } catch (_: Exception) {
            // FIN best-effort on a dying session; the stream is closed regardless.
        }
    }

    // ---- called by the session recvLoop ----

    internal fun pushBytes(data: ByteArray) {
        synchronized(lock) {
            buffers.addLast(Chunk(data))
            (lock as Object).notifyAll()
        }
    }

    internal fun onFin() {
        synchronized(lock) {
            finReceived = true
            (lock as Object).notifyAll()
        }
    }

    internal fun update(consumed: Int, window: Int) {
        peerConsumed.set(consumed)
        peerWindow.set(window)
        synchronized(lock) { (lock as Object).notifyAll() }
    }

    /** Session is dying: unblock everything and drop buffered data. */
    internal fun sessionClose() {
        synchronized(lock) {
            closed = true
            buffers.clear()
            (lock as Object).notifyAll()
        }
    }

    /** Discards unread buffered data, returning its byte count (tokens to recycle). */
    internal fun recycleBufferedBytes(): Int {
        synchronized(lock) {
            var n = 0
            for (c in buffers) n += c.remaining
            buffers.clear()
            return n
        }
    }

    // ---- read path (v2, cf. smux stream.go tryReadV2) ----

    private inner class StreamInputStream : InputStream() {
        override fun read(): Int {
            val one = ByteArray(1)
            val n = read(one, 0, 1)
            return if (n < 0) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            val deadlineMs = readDeadlineMs
            val deadline = if (deadlineMs > 0) System.currentTimeMillis() + deadlineMs else Long.MAX_VALUE
            var notifyConsumed: Long = -1
            var n = 0
            // 0 = data copied, 1 = EOF, 2 = wait for data
            while (true) {
                val action: Int
                synchronized(lock) {
                    if (buffers.isNotEmpty()) {
                        var remaining = len
                        var copied = 0
                        while (remaining > 0 && buffers.isNotEmpty()) {
                            val first = buffers.first()
                            val take = minOf(remaining, first.remaining)
                            System.arraycopy(first.data, first.pos, b, off + copied, take)
                            first.pos += take
                            copied += take
                            remaining -= take
                            if (first.remaining == 0) buffers.removeFirst()
                        }
                        n = copied
                        // v2 accounting: UPD when consumed-since-last-update
                        // >= MaxStreamBuffer/2, or on the first read.
                        numRead += n
                        incr += n
                        if (incr >= session.config.maxStreamBuffer / 2 || numRead == n.toLong()) {
                            notifyConsumed = numRead
                            incr = 0
                        }
                        action = 0
                    } else if (inputClosed || closed) {
                        action = 1
                    } else if (finReceived) {
                        action = 1
                    } else {
                        action = 2
                    }
                }
                when (action) {
                    0 -> break
                    1 -> return -1
                    else -> {
                        val waitLeft = deadline - System.currentTimeMillis()
                        if (waitLeft <= 0) throw SocketTimeoutException("smux read timeout")
                        // Bounded wait; a notify arriving between the check
                        // above and this wait costs at most 100 ms.
                        synchronized(lock) {
                            try {
                                (lock as Object).wait(minOf(waitLeft, 100L))
                            } catch (_: InterruptedException) {
                                Thread.currentThread().interrupt()
                                return -1
                            }
                        }
                    }
                }
            }
            if (n > 0) {
                session.returnTokens(n)
                if (notifyConsumed >= 0) {
                    try {
                        // consumed is a uint32 on the wire; Long wraps identically.
                        session.sendWindowUpdate(id, notifyConsumed.toInt(), session.config.maxStreamBuffer)
                    } catch (_: Exception) {
                        // UPD is best-effort: the data was already delivered.
                    }
                }
                return n
            }
            return -1
        }

        override fun available(): Int {
            synchronized(lock) {
                var n = 0
                for (c in buffers) n += c.remaining
                return n
            }
        }

        /** Marks the read side closed locally; blocked readers return -1. Does not send FIN. */
        override fun close() {
            synchronized(lock) {
                inputClosed = true
                (lock as Object).notifyAll()
            }
        }
    }

    // ---- write path (v2 sliding window, cf. smux stream.go writeV2) ----

    private inner class StreamOutputStream : OutputStream() {
        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len == 0) return
            synchronized(writeLock) {
                var pos = off
                val end = off + len
                while (pos < end) {
                    synchronized(lock) {
                        if (writeClosed) throw IOException("smux stream output is closed")
                        if (closed) throw IOException("smux stream is closed")
                        if (finReceived) throw IOException("smux stream closed by peer")
                    }
                    // Modular uint32 arithmetic, as in smux writeV2:
                    // inflight = numWritten - peerConsumed; win = peerWindow - inflight.
                    val inflight = numWritten.get() - peerConsumed.get()
                    if (inflight < 0) throw IOException("smux: peer consumed more than sent")
                    val win = peerWindow.get() - inflight
                    if (win > 0) {
                        var chunk = minOf(end - pos, win)
                        while (chunk > 0) {
                            val size = minOf(chunk, session.config.maxFrameSize)
                            val payload = b.copyOfRange(pos, pos + size)
                            session.writeFrame(CMD_PSH, id, payload, 0)
                            numWritten.addAndGet(size)
                            pos += size
                            chunk -= size
                        }
                    } else {
                        // No window: wait for an UPD (or close/FIN) before retrying.
                        synchronized(lock) {
                            try {
                                (lock as Object).wait(100)
                            } catch (_: InterruptedException) {
                                Thread.currentThread().interrupt()
                                throw IOException("smux stream write interrupted")
                            }
                            if (closed) throw IOException("smux stream is closed")
                            if (finReceived) throw IOException("smux stream closed by peer")
                        }
                        if (session.isClosed) throw IOException("smux session is closed")
                    }
                }
            }
        }

        override fun flush() { /* frames are sent immediately */ }

        /** Half-close: sends FIN. The read side stays open. */
        override fun close() {
            closeOutput()
        }
    }
}
