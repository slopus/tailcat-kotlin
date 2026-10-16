package io.tailcat

import io.tailcat.crypto.NaClBox
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
    private val incoming: (DerpPacket) -> Unit,
) {
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
    private var reader: PlatformThread? = null
    private var writer: PlatformThread? = null
    private var restartDelay = 250L

    fun start(timeoutMillis: Long = 30_000) {
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
    fun send(key: NodePublicKey, packet: ByteArray) {
        require(packet.size <= 65536)
        enqueue(DerpFrame(4, key.raw + packet))
    }
    private fun enqueue(frame: DerpFrame) {
        lock.withLock {
            if (closed) throw TailcatClosedException()
            if (queue.size >= 256) throw TailcatException("DERP send queue full")
            queue.addLast(frame); lock.signalAll()
        }
    }
    fun tick(now: Long) {
        var close: PlatformStream? = null
        lock.withLock {
            if (closed) return
            if ((!ready && now - phaseStarted > 25_000) || (ready && now - lastReceived > 120_000)) close = stream
            if (ready && now - lastPing >= 30_000) {
                lastPing = now
                if (queue.size < 256) { queue.addLast(DerpFrame(0x12, secureRandom(8))); lock.signalAll() }
            }
        }
        close?.close()
    }
    fun reconnect() { lock.withLock { stream }?.close() }
    fun close() {
        val old = lock.withLock {
            if (closed) return
            closed = true; ready = false; generation++; queue.clear(); lock.signalAll()
            stream.also { stream = null }
        }
        old?.close()
    }
    private fun runReader() {
        var delay = 0L
        while (true) {
            lock.withLock {
                if (closed) return
                if (delay > 0) lock.await(delay)
                if (closed) return
            }
            val connection = PlatformStream()
            val id = lock.withLock {
                generation++; phaseStarted = monotonicMillis(); stream = connection; ready = false
                generation
            }
            try {
                val node = nodes[nodeIndex]
                establish(connection, node)
                lock.withLock {
                    if (closed || stream !== connection) throw TailcatClosedException()
                    ready = true; lastReceived = monotonicMillis(); lastPing = lastReceived; lock.signalAll()
                }
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
                        0x13 -> require(frame.payload.size == 8)
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
                    nodeIndex = (nodeIndex + 1) % nodes.size
                }
                delay = (if (delay == 0L) 250 else delay * 2).coerceAtMost(30_000)
            }
        }
    }
    private fun runWriter() {
        while (true) {
            val work = lock.withLock {
                while (!closed && (!ready || queue.isEmpty())) lock.await(1000)
                if (closed) return
                Triple(stream!!, generation, queue.first())
            }
            try {
                val size = work.third.payload.size + 5
                while (true) {
                    val wait = lock.withLock {
                        if (closed) return
                        if (generation != work.second || !ready) return@withLock -1L
                        if (rate <= 0 || burst <= 0) 0L else {
                            require(size <= burst) { "DERP frame exceeds relay burst limit" }
                            val now = monotonicMillis()
                            tokens = minOf(burst, tokens + (now - tokenAt).coerceAtLeast(0) * rate / 1000); tokenAt = now
                            if (tokens >= size) { tokens -= size; 0L } else ((size - tokens) * 1000 / rate).toLong().coerceAtLeast(1)
                        }
                    }
                    if (wait < 0) break
                    if (wait == 0L) {
                        writes.withLock { work.first.write(work.third.encode()) }
                        lock.withLock { if (queue.firstOrNull() === work.third) queue.removeFirst() }
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
            serverName = node.hostName, certificateName = node.certName.ifEmpty { node.hostName }, insecureForTests = node.insecureForTests)
        connection.write("GET /derp HTTP/1.1\r\nHost: ${node.hostName}\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".encodeToByteArray())
        // Read the header exactly, preserving subsequent DERP bytes in the socket.
        val header = ArrayList<Byte>()
        val one = ByteArray(1)
        while (true) {
            require(header.size < 16384)
            if (connection.read(one) != 1) throw TailcatClosedException()
            header.add(one[0])
            if (header.size >= 4 && header.takeLast(4) == listOf<Byte>(13, 10, 13, 10)) break
        }
        val lines = header.toByteArray().decodeToString(throwOnInvalidSequence = true).split("\r\n")
        require(lines.first().startsWith("HTTP/1.1 101 ") || lines.first() == "HTTP/1.1 101")
        val headers = lines.drop(1).filter { it.isNotEmpty() }.associate { line ->
            val colon = line.indexOf(':'); require(colon > 0)
            line.substring(0, colon).lowercase() to line.substring(colon + 1).trim().lowercase()
        }
        require(headers["upgrade"] == "derp" && headers["connection"]?.split(',')?.any { it.trim() == "upgrade" } == true)
        val greeting = readFrame(connection)
        require(greeting.type == 1 && greeting.payload.size in 40..1024 && greeting.payload.startsWith("DERP🔑".encodeToByteArray()))
        val serverKey = greeting.payload.copyOfRange(8, 40); val nonce = secureRandom(24)
        val info = "{\"version\":2,\"CanAckPings\":true}".encodeToByteArray()
        connection.write(DerpFrame(2, privateKey.publicKey.raw + nonce + NaClBox.seal(info, nonce, serverKey, privateKey.raw)).encode())
        val frame = readFrame(connection)
        require(frame.type == 3 && frame.payload.size in 40..65536)
        val serverInfo = NaClBox.open(frame.payload.copyOfRange(24, frame.payload.size), frame.payload.copyOfRange(0, 24), serverKey, privateKey.raw)
        val json = Json.parse(serverInfo.decodeToString(throwOnInvalidSequence = true)) as? Map<*, *> ?: error("Expected DERP server info")
        require(((json["version"] as? Number)?.toInt() ?: 0) >= 2)
        lock.withLock {
            rate = ((json["TokenBucketBytesPerSecond"] as? Number)?.toDouble() ?: 0.0).coerceAtLeast(0.0)
            burst = ((json["TokenBucketBytesBurst"] as? Number)?.toDouble() ?: 0.0).coerceAtLeast(0.0)
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
