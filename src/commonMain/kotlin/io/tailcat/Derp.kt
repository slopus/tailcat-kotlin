package io.tailcat

import io.tailcat.platform.*

internal data class DerpPacket(val source: NodePublicKey, val payload: ByteArray)
internal data class DerpFrame(val type: Int, val payload: ByteArray) {
    fun encode(): ByteArray {
        require(payload.size <= MAXIMUM)
        return byteArrayOf(type.toByte()) + be32(payload.size.toLong()) + payload
    }
    companion object { const val MAXIMUM = (1 shl 20) + 64 }
}

/** One reader and one bounded writer, with node failover and authenticated reconnect. */
internal class DerpTransport(
    nodes: List<DERPNode>,
    private val privateKey: NodePrivateKey,
    private val testOnlyPlaintext: Boolean = false,
    private val trace: StartupTrace? = null,
    /**
     * Each time the connection is up again after one failed or was found silent by a check; not on
     * the first connect. What went out the old connection meanwhile was lost, and is owed again.
     */
    private val recovered: () -> Unit = {},
    private val incoming: (DerpPacket) -> Unit,
) : NetworkRelay {
    private val nodes = nodes.filter { !it.stunOnly }
    private val lock = PlatformLock()
    private val writes = PlatformLock()
    private var closed = false
    private var stream: PlatformStream? = null
    private var ready = false
    private var generation = 0L
    private var lastReceived = monotonicMillis()
    private var phaseStarted = monotonicMillis()
    private var nodeIndex = 0
    private var lastPing = 0L
    private var rate = 0.0
    private var burst = 0.0
    private var tokens = 0.0
    private var tokenAt = monotonicMillis()
    private val queue = ArrayDeque<DerpFrame>()
    private val resetMarkers = linkedMapOf<NodePublicKey, DerpFrame>()
    private val resetBarriers = mutableSetOf<NodePublicKey>()
    private var reader: PlatformThread? = null
    private var writer: PlatformThread? = null
    private var reconnectRequested = false
    // A check: if nothing arrives after checkSince by checkBy, the stream is replaced.
    private var checkSince = 0L
    private var checkBy = 0L
    private var lastTick = 0L
    // A failed advertised fast-start capability falls back on the next fresh connection only.
    private var fastStartAllowed = true
    private var recovering = false
    /** The relay's round trip, smoothed (RFC 6298's 1/8), from our pings to their pongs. */
    private var smoothedRTT: Long? = null
    private val pings = mutableMapOf<BytesKey, Long>()

    override val connectionGeneration: Long? get() = lock.withLock { if (ready && !closed) generation else null }

    override fun start(timeoutMillis: Long) {
        lock.withLock {
            check(reader == null) { "DERP already started" }
            require(nodes.isNotEmpty()) { "No DERP nodes" }
            if (closed) throw TailcatClosedException()
            reader = startThread("tailcat-derp-read") { runReader() }
            writer = startThread("tailcat-derp-write") { runWriter() }
            val deadline = monotonicMillis() + timeoutMillis
            while (!ready && !closed) {
                val remaining = deadline - monotonicMillis()
                if (remaining <= 0) throw TailcatTimeoutException()
                lock.await(remaining)
            }
            if (closed) throw TailcatClosedException()
        }
    }
    override fun send(key: NodePublicKey, packet: ByteArray) {
        require(packet.size <= 65536)
        enqueue(DerpFrame(4, key.raw + packet))
    }
    override fun setResetBarrier(key: NodePublicKey, blocked: Boolean) = lock.withLock {
        if (closed) return@withLock
        if (blocked) { require(key in resetBarriers || resetBarriers.size < 1024); resetBarriers.add(key) }
        else resetBarriers.remove(key)
        lock.signalAll()
    }
    override fun queueResetMarker(key: NodePublicKey, packet: ByteArray) = lock.withLock {
        if (closed) throw TailcatClosedException()
        require(packet.size == 32 && io.tailcat.wireguard.WireGuard.packetType(packet) == 4)
        require(key in resetMarkers || resetMarkers.size < 1024)
        resetMarkers[key] = DerpFrame(4, key.raw + packet)
        resetBarriers.remove(key); lock.signalAll()
    }
    override fun hasResetMarker(key: NodePublicKey): Boolean = lock.withLock { key in resetMarkers }
    override fun discardResetMarker(key: NodePublicKey) = lock.withLock {
        resetMarkers.remove(key); resetBarriers.remove(key); lock.signalAll()
    }
    /** Handshakes, meow, discovery and other peers must progress even without a usable marker key. */
    private fun blocked(frame: DerpFrame): Boolean = frame.type == 4 && frame.payload.size >= 36 &&
        frame.payload[32] == 4.toByte() && frame.payload[33] == 0.toByte() && frame.payload[34] == 0.toByte() && frame.payload[35] == 0.toByte() &&
        NodePublicKey(frame.payload.copyOfRange(0, 32)) in resetBarriers
    private fun nextWrite(): DerpFrame? = resetMarkers.values.firstOrNull() ?: queue.firstOrNull { !blocked(it) }
    private fun enqueue(frame: DerpFrame) {
        lock.withLock {
            if (closed) throw TailcatClosedException()
            if (queue.size >= 256) throw TailcatException("DERP send queue full")
            queue.addLast(frame); lock.signalAll()
        }
    }
    override fun tick(now: Long) {
        var close: PlatformStream? = null
        lock.withLock {
            if (closed) return
            if (lastTick != 0L && now - lastTick > 5_000) {
                // Ticks stopped: the process was frozen. The time away is no one's silence; a check decides.
                val away = now - lastTick
                phaseStarted += away; lastReceived = minOf(lastReceived + away, now - 1); lastPing = now
                if (ready) { checkSince = now; checkBy = now + checkDeadline(2_000); ping(now) }
            }
            lastTick = now
            if ((!ready && now - phaseStarted > 25_000) || (ready && now - lastReceived > 120_000)) close = stream
            if (checkBy != 0L && now >= checkBy) {
                // A silent stream is replaced at once, without the failure backoff.
                if (ready && lastReceived < checkSince) { close = stream; reconnectRequested = true; recovering = true }
                checkBy = 0
            }
            if (ready && now - lastPing >= 30_000) { lastPing = now; ping(now) }
        }
        close?.close()
    }
    /** Under the lock. */
    private fun ping(now: Long) {
        if (queue.size >= 256) return
        val payload = secureRandom(8)
        if (pings.size >= 8) pings.clear()
        pings[BytesKey(payload)] = now
        queue.addLast(DerpFrame(0x12, payload)); lock.signalAll()
    }
    /**
     * Three of the relay's round trips, at least a second, or before one is measured [requested],
     * at most 1.5 s. Anything heard counts, so a busy connection whose pong queues behind its traffic stays.
     */
    private fun checkDeadline(requested: Long): Long = smoothedRTT?.let { maxOf(1000, 3 * it) } ?: minOf(requested, 1500)
    override fun check(deadlineMillis: Long) = lock.withLock {
        if (closed) return@withLock
        if (!ready) {
            // Between connections: one waiting out its backoff tries now.
            if (stream == null) { reconnectRequested = true; lock.signalAll() }
            return@withLock
        }
        val now = monotonicMillis()
        checkSince = now; checkBy = now + checkDeadline(deadlineMillis)
        ping(now)
    }
    override fun reconnect() {
        val old = lock.withLock {
            if (closed) return
            generation++; ready = false; reconnectRequested = true; recovering = true; lock.signalAll()
            stream.also { stream = null }
        }
        old?.close()
    }
    override fun close() {
        val old = lock.withLock {
            if (closed) return
            closed = true; ready = false; generation++; queue.clear(); resetMarkers.clear(); resetBarriers.clear(); lock.signalAll()
            stream.also { stream = null }
        }
        old?.close()
    }
    private fun runReader() {
        var delay = 0L
        while (true) {
            lock.withLock {
                if (closed) return
                val retryAt = monotonicMillis() + delay
                while (!closed && !reconnectRequested && monotonicMillis() < retryAt) lock.await((retryAt - monotonicMillis()).coerceAtLeast(1))
                if (closed) return
                reconnectRequested = false
            }
            val connection = PlatformStream()
            try {
                val id = lock.withLock {
                    if (closed) { connection.close(); return }
                    generation++; phaseStarted = monotonicMillis(); stream = connection; ready = false
                    generation
                }
                val node = nodes[nodeIndex]
                trace?.mark("derpAttempt", id)
                establish(connection, node)
                val recovery = lock.withLock {
                    if (closed || stream !== connection) throw TailcatClosedException()
                    ready = true; lastReceived = monotonicMillis(); lastPing = lastReceived; lock.signalAll()
                    trace?.mark("derpReady", id)
                    recovering.also { recovering = false }
                }
                if (recovery) recovered()
                delay = 250
                while (true) {
                    val frame = readFrame(connection)
                    lock.withLock {
                        if (closed || generation != id) throw TailcatClosedException()
                        lastReceived = monotonicMillis()
                    }
                    when (frame.type) {
                        5 -> {
                            require(frame.payload.size in 32..65568)
                            incoming(DerpPacket(NodePublicKey(frame.payload.copyOfRange(0, 32)), frame.payload.copyOfRange(32, frame.payload.size)))
                        }
                        6 -> require(frame.payload.isEmpty())
                        0x12 -> { require(frame.payload.size == 8); enqueue(DerpFrame(0x13, frame.payload)) }
                        0x13 -> {
                            require(frame.payload.size == 8)
                            lock.withLock {
                                pings.remove(BytesKey(frame.payload))?.let { sent ->
                                    val sample = monotonicMillis() - sent
                                    smoothedRTT = smoothedRTT?.let { (7 * it + sample) / 8 } ?: sample
                                }
                            }
                        }
                        8 -> require(frame.payload.size >= 32)
                        0x15 -> {
                            require(frame.payload.size == 8)
                            delay = frame.payload.be32(0).coerceIn(250, 60_000)
                            throw TailcatException("DERP restarting")
                        }
                    }
                }
            } catch (_: Exception) {
                connection.close()
                lock.withLock {
                    if (stream === connection) { ready = false; stream = null; lock.signalAll() }
                    if (closed) return
                    recovering = true; pings.clear()
                    nodeIndex = (nodeIndex + 1) % nodes.size
                }
                delay = (if (delay == 0L) 250 else delay * 2).coerceAtMost(30_000)
            }
        }
    }
    private fun runWriter() {
        while (true) {
            val work = lock.withLock {
                while (!closed && (!ready || nextWrite() == null)) lock.await(1000)
                if (closed) return
                Triple(stream!!, generation, nextWrite()!!)
            }
            try {
                val size = work.third.payload.size + 5
                while (true) {
                    val wait = lock.withLock {
                        if (closed) return
                        if (generation != work.second || !ready || nextWrite() !== work.third) return@withLock -1L
                        if (rate <= 0 || burst <= 0) 0L else {
                            require(size <= burst) { "DERP frame exceeds relay burst limit" }
                            val now = monotonicMillis()
                            tokens = minOf(burst, tokens + (now - tokenAt).coerceAtLeast(0) * rate / 1000); tokenAt = now
                            if (tokens >= size) { tokens -= size; 0L } else ((size - tokens) * 1000 / rate).toLong().coerceAtLeast(1)
                        }
                    }
                    if (wait < 0) break
                    if (wait == 0L) {
                        // Commit selection before I/O without holding the state lock across a socket write.
                        // A reset can cancel a not-yet-committed write; already committed prior work may finish.
                        val current = lock.withLock { !closed && ready && generation == work.second && nextWrite() === work.third }
                        if (!current) break
                        writes.withLock { work.first.write(work.third.encode()) }
                        if (trace != null && work.third.type == 4 && work.third.payload.size >= 36 &&
                            work.third.payload.copyOfRange(32, 36).contentEquals("meow".encodeToByteArray())) trace.markOnce("meowWritten")
                        lock.withLock {
                            val marker = resetMarkers.entries.firstOrNull { it.value === work.third }?.key
                            if (marker != null) resetMarkers.remove(marker) else queue.remove(work.third)
                            lock.signalAll()
                        }
                        break
                    }
                    lock.withLock { if (!closed) lock.await(wait.coerceAtMost(1000)) }
                }
            } catch (_: Exception) { work.first.close() }
        }
    }
    private fun establish(connection: PlatformStream, node: DERPNode) {
        val host = node.ipv4.takeIf { it.isNotEmpty() && it != "none" }
            ?: node.ipv6.takeIf { it.isNotEmpty() && it != "none" } ?: node.hostName
        require(node.hostName.none { it == '\r' || it == '\n' })
        if (testOnlyPlaintext) require(host in listOf("127.0.0.1", "::1", "localhost", "10.0.2.2")) { "Plain DERP requires explicit local fixture" }
        connection.connect(host, node.derpPort.takeIf { it > 0 } ?: 443, !testOnlyPlaintext,
            serverName = node.hostName, certificateName = node.certName.ifEmpty { node.hostName }, insecureForTests = node.insecureForTests, startupTrace = trace)
        val metadata = connection.derpTlsMetadata.takeIf { fastStartAllowed && !testOnlyPlaintext && !node.insecureForTests }
        val info = try {
            DerpHandshake(privateKey, node.hostName, metadata, trace, connection::read, { connection.write(it) }).authenticate()
        } catch (failure: Exception) {
            if (metadata != null) { fastStartAllowed = false; trace?.mark("derpFastStartFailed") }
            throw failure
        }
        lock.withLock {
            rate = info.rate
            burst = info.burst
            tokens = burst; tokenAt = monotonicMillis()
        }
        connection.write(DerpFrame(7, byteArrayOf(1)).encode())
    }
    private fun readExact(connection: PlatformStream, count: Int): ByteArray {
        val bytes = ByteArray(count); var offset = 0
        while (offset < count) {
            val n = connection.read(bytes, offset, count - offset)
            if (n <= 0) throw TailcatClosedException()
            offset += n
        }
        return bytes
    }
    private fun readFrame(connection: PlatformStream): DerpFrame {
        val header = readExact(connection, 5)
        val length = header.be32(1); require(length <= DerpFrame.MAXIMUM)
        return DerpFrame(header[0].u(), readExact(connection, length.toInt()))
    }
}
