package io.tailcat

import io.tailcat.platform.*
import io.tailcat.stack.IPStack
import io.tailcat.stack.TailcatTransportException
import kotlin.test.*

class StackTest {
    private val a = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 1 }
    private val b = a.copyOf().also { it[15] = 2 }
    private class Job<T>(body: () -> T) {
        private val lock = PlatformLock(); private var done = false; private var result: T? = null; private var error: Throwable? = null
        init { startThread("test-job") { try { val value = body(); lock.withLock { result = value } } catch (failure: Throwable) { lock.withLock { error = failure } } finally { lock.withLock { done = true; lock.signalAll() } } } }
        fun isDone() = lock.withLock { done }
        fun await(timeout: Long = 60000): T = lock.withLock {
            val end = monotonicMillis() + timeout
            while (!done) { val left = end-monotonicMillis(); check(left > 0) { "Test worker timeout" }; lock.await(left) }
            error?.let { throw it }; @Suppress("UNCHECKED_CAST") (result as T)
        }
    }
    private data class Faults(var syn: Boolean = false, var synack: Boolean = false, var data: Boolean = false,
        var ack: Boolean = false, var fin: Boolean = false, var reorder: Boolean = false, var duplicate: Boolean = false,
        var reorderAck: Boolean = false, var reopen: Boolean = false, var finAck: Boolean = false)
    private data class Packet(val fromA: Boolean, val bytes: ByteArray)
    private inner class Link(private val faults: Faults = Faults(), capacity: Int = 1 shl 20) {
        private val lock = PlatformLock(); private val queue = ArrayDeque<Packet>(); private var running = true
        private var zero = false; private var data = false; private var fin = false; private var held: ByteArray? = null; private var heldAck: ByteArray? = null
        private var deliveredResets = 0
        private var deliveredACKs = 0; private var lastClientFIN: ByteArray? = null
        var drops = 0
            private set
        val first = IPStack(a, { enqueue(true,it) }, receiveCapacity = capacity); val second = IPStack(b, { enqueue(false,it) }, receiveCapacity = capacity)
        /** Every TCP packet offered to the link, in order, before faults. */
        val seen = ArrayList<Packet>()
        private val worker = Job {
            while (true) {
                val packet = lock.withLock { if (queue.isEmpty() && running) lock.await(25); if (!running) return@Job; queue.removeFirstOrNull() }
                if (packet != null) {
                    val deliveries = lock.withLock { transform(packet) }
                    for (bytes in deliveries) {
                        (if (packet.fromA) second else first).receive(bytes)
                        if (bytes.size >= 60 && bytes[6] == 6.toByte() && bytes[53].u() and 4 != 0) {
                            lock.withLock { deliveredResets++; lock.signalAll() }
                        }
                        if (bytes.size >= 60 && bytes[6] == 6.toByte() && bytes[53].u() == 0x10) lock.withLock { deliveredACKs++; lock.signalAll() }
                    }
                }
                first.tick(); second.tick()
            }
        }
        private fun enqueue(fromA: Boolean, bytes: ByteArray) { lock.withLock { if (running && queue.size < 8192) { queue.addLast(Packet(fromA,bytes.copyOf())); lock.signalAll() } } }
        private fun transform(packet: Packet): List<ByteArray> {
            val bytes = packet.bytes
            if (bytes.size >= 60 && bytes[6] == 6.toByte()) seen.add(packet)
            if (bytes.size < 60 || bytes[6] != 6.toByte()) return listOf(bytes)
            val flags = bytes[53].u(); val size = bytes.size-40-(bytes[52].u() ushr 4)*4; val window = bytes.be16(54)
            if (window == 0) zero = true
            if (packet.fromA && flags and 1 != 0) { fin = true; lastClientFIN = bytes }
            fun drop(): List<ByteArray> { drops++; return emptyList() }
            if (flags and 0x12 == 2 && faults.syn) { faults.syn = false; return drop() }
            if (flags and 0x12 == 0x12 && faults.synack) { faults.synack = false; return drop() }
            if (size > 0) data = true
            if (size > 0 && packet.fromA && faults.data) { faults.data = false; return drop() }
            if (size == 0 && flags == 0x10 && !packet.fromA && data && faults.ack) { faults.ack = false; return drop() }
            if (flags and 1 != 0 && faults.fin) { faults.fin = false; return drop() }
            if (flags == 0x10 && !packet.fromA && zero && window > 0 && faults.reopen) { faults.reopen = false; return drop() }
            if (flags == 0x10 && !packet.fromA && fin && faults.finAck) { faults.finAck = false; return drop() }
            if (flags == 0x10 && !packet.fromA && data && faults.reorderAck) {
                val old = heldAck; if (old == null) { heldAck = bytes; return emptyList() }
                heldAck = null; faults.reorderAck = false; return listOf(bytes,old)
            }
            if (size > 0 && packet.fromA && faults.reorder) {
                val old = held; if (old == null) { held = bytes; return emptyList() }
                held = null; faults.reorder = false; return listOf(bytes,old)
            }
            return if (size > 0 && faults.duplicate) listOf(bytes,bytes) else listOf(bytes)
        }
        fun waitZero() { val end = monotonicMillis()+10000; while (!lock.withLock { zero }) { check(monotonicMillis() < end); platformSleep(5) } }
        fun waitReset() = lock.withLock {
            val end = monotonicMillis()+10000
            while (deliveredResets == 0) { val left = end-monotonicMillis(); check(left > 0); lock.await(left) }
        }
        fun acks() = lock.withLock { deliveredACKs }
        fun seenSnapshot(): List<Packet> = lock.withLock { seen.toList() }
        fun resets() = lock.withLock { deliveredResets }
        fun replayClientFIN() { lock.withLock { lastClientFIN }?.let(second::receive) }
        fun close() { first.close(); second.close(); lock.withLock { running = false; lock.signalAll() }; worker.await() }
    }
    private fun drain(stream: TailcatConnection): ByteArray {
        val chunks = mutableListOf<ByteArray>(); var count = 0
        while (true) { val data = stream.read(7777,30000); if (data.isEmpty()) break; chunks.add(data); count += data.size }
        val out = ByteArray(count); var offset = 0; for (data in chunks) { data.copyInto(out,offset); offset += data.size }; return out
    }
    @Test fun windowsScalePastSixtyFourKilobytes() {
        val link = Link()
        try {
            val listener = link.second.listen(80); val client = link.first.connect(b,80); val server = listener.accept(10000)
            // The server writes a megabyte the client doesn't read yet: more than 64 KB must be in flight.
            val writer = Job { server.write(ByteArray(900_000) { it.toByte() }, timeoutMillis = 30000) }
            val end = monotonicMillis() + 10000
            fun seen() = link.seenSnapshot()
            while (seen().count { !it.fromA && it.bytes.size > 60 } * 1220 < 200_000) { check(monotonicMillis() < end) { "Stuck at a 64 KB window" }; platformSleep(10) }
            val packets = seen()
            fun option(bytes: ByteArray, kind: Int): Int? { var i = 60; val end2 = 40 + (bytes[52].u() ushr 4) * 4
                while (i < end2) { val k = bytes[i].u(); if (k == 0) break; if (k == 1) { i++; continue }; if (k == kind) return i; i += bytes[i + 1].u() }; return null }
            val syn = packets.first { it.fromA && it.bytes[53].u() and 0x12 == 0x02 }.bytes
            val synAck = packets.first { !it.fromA && it.bytes[53].u() and 0x12 == 0x12 }.bytes
            assertEquals(5, syn[checkNotNull(option(syn, 3)) + 2].toInt(), "A 1 MiB buffer offers shift 5")
            assertEquals(5, synAck[checkNotNull(option(synAck, 3)) + 2].toInt())
            val ack = packets.first { it.fromA && it.bytes[53].u() == 0x10 }.bytes
            assertEquals(32768, ack.be16(54), "1 MiB, scaled by 32")
            var total = 0; while (total < 900_000) total += client.read(65536, 10000).size
            writer.await(); assertEquals(900_000, total)
        } finally { link.close() }
    }
    @Test fun aPeerThatOffersNoWindowScaleGetsUnscaledWindows() {
        val sent = ArrayList<ByteArray>()
        val stack = IPStack(b, { sent.add(it) })
        try {
            stack.listen(80)
            // A SYN with only an MSS option, from a peer that doesn't scale.
            val body = ByteArray(24); body[1] = 0x30; body[3] = 80; body[7] = 1; body[12] = 0x60; body[13] = 2; body[14] = 0xff.toByte(); body[15] = 0xff.toByte()
            body[20] = 2; body[21] = 4; body[22] = 0x04; body[23] = 0xc4.toByte()
            var sum = body.size.toLong() + 6
            for (i in 0 until 16 step 2) sum += a.be16(i) + b.be16(i)
            for (i in body.indices step 2) sum += body.be16(i)
            while (sum ushr 16 != 0L) sum = (sum and 65535) + (sum ushr 16)
            val checksum = sum.toInt().inv() and 65535; body[16] = (checksum ushr 8).toByte(); body[17] = checksum.toByte()
            val packet = ByteArray(40 + body.size); packet[0] = 0x60; packet[5] = body.size.toByte(); packet[6] = 6; packet[7] = 64
            a.copyInto(packet, 8); b.copyInto(packet, 24); body.copyInto(packet, 40)
            stack.receive(packet)
            val synAck = sent.single()
            assertEquals(0x12, synAck[53].u() and 0x12)
            assertEquals(24, (synAck[52].u() ushr 4) * 4, "No window scale option in the SYN-ACK")
            assertEquals(65535, synAck.be16(54))
        } finally { stack.close() }
    }
    @Test fun abortStopsThePeersWriteAtOnce() {
        val link = Link()
        try {
            val listener = link.second.listen(80); val client = link.first.connect(b,80); val server = listener.accept(10000)
            val response = Job { server.write(ByteArray(4 * 1024 * 1024), timeoutMillis = 30000) }
            assertTrue(client.read(1000, 10000).isNotEmpty())
            val aborted = monotonicMillis()
            client.abort()
            val failure = assertFailsWith<TailcatTransportException> { response.await(10000) }
            assertEquals(TailcatTransportException.Reason.CONNECTION_RESET, failure.reason)
            assertTrue(monotonicMillis() - aborted < 2000, "The response stopped at once, not after 4 MiB")
            assertFailsWith<TailcatTransportException> { client.read(100, 1000) }
        } finally { link.close() }
    }
    @Test fun halfCloseAndResponse() {
        val link = Link()
        try {
            val listener = link.second.listen(80); val client = link.first.connect(b,80); val server = listener.accept(10000)
            val payload = ByteArray(180000) { it.toByte() }; val response = ByteArray(91000) { (it*31).toByte() }
            val writer = Job { client.write(payload,timeoutMillis=30000); client.shutdownOutput(10000) }
            assertContentEquals(payload,drain(server)); writer.await()
            val reply = Job { server.write(response,timeoutMillis=30000); server.shutdownOutput(10000) }
            assertContentEquals(response,drain(client)); reply.await(); assertTrue(client.read(100,1000).isEmpty())
        } finally { link.close() }
    }
    @Test fun lossReorderDuplicates() {
        val link = Link(Faults(syn=true,synack=true,data=true,ack=true,fin=true,reorder=true,duplicate=true,reorderAck=true))
        try {
            val listener = link.second.listen(81); val client = link.first.connect(b,81); val server = listener.accept(10000)
            val payload = ByteArray(400000) { (it*13).toByte() }; val writer = Job { client.write(payload,timeoutMillis=30000); client.shutdownOutput(10000) }
            assertContentEquals(payload,drain(server)); writer.await(); assertEquals(5,link.drops)
        } finally { link.close() }
    }
    @Test fun orderlyClosureKeepsEOFAfterLateReset() {
        val link = Link()
        try {
            val listener = link.second.listen(85); val client = link.first.connect(b,85); val server = listener.accept(10000)
            val request = "small request".encodeToByteArray(); val response = ByteArray(4096) { (it*19).toByte() }
            client.write(request,timeoutMillis=10000); client.shutdownOutput(10000)
            assertContentEquals(request,server.read(request.size,10000)); assertTrue(server.read(1,10000).isEmpty())
            server.write(response,timeoutMillis=10000); server.shutdownOutput(10000)
            server.abort() // Forget the completed peer; the next window ACK elicits RST.
            assertContentEquals(response.copyOfRange(0,1024),client.read(1024,10000))
            link.waitReset()
            assertContentEquals(response.copyOfRange(1024,response.size),client.read(response.size,10000))
            assertTrue(client.read(1,10000).isEmpty())
        } finally { link.close() }
    }
    @Test fun zeroWindowAndLostFinAck() {
        val link = Link(Faults(reopen=true,finAck=true), capacity = 65535)
        try {
            val listener = link.second.listen(82); val client = link.first.connect(b,82); val server = listener.accept(10000)
            val payload = ByteArray(90000) { 0x37 }; val writer = Job { client.write(payload,timeoutMillis=30000); client.shutdownOutput(10000) }
            link.waitZero(); val first = server.read(65535,10000); assertEquals(65535,first.size); writer.await()
            assertContentEquals(payload,first+drain(server)); assertEquals(2,link.drops)
        } finally { link.close() }
    }
    @Test fun fourConcurrentTwoMiBStreams() {
        val link = Link()
        try {
            val listener = link.second.listen(83); val payload = ByteArray(2*1024*1024) { (it*29).toByte() }
            val writers = List(4) { Job { val connection = link.first.connect(b,83); connection.write(payload,timeoutMillis=60000); connection.shutdownOutput(10000) } }
            val readers = List(4) { val connection = listener.accept(10000); Job { assertContentEquals(payload,drain(connection)) } }
            writers.forEach { it.await() }; readers.forEach { it.await() }
        } finally { link.close() }
    }
    @Test fun drainGracefulCloseAndTimeouts() {
        val link = Link(capacity = 65535)
        try {
            val listener = link.second.listen(84); val client = link.first.connect(b,84); val server = listener.accept(10000)
            val payload = ByteArray(100000) { 0x32 }; val writer = Job { client.write(payload,timeoutMillis=30000) }
            link.waitZero(); val drainer = Job { client.drain(30000) }; platformSleep(10); assertFalse(drainer.isDone())
            val bytes = ByteArray(payload.size); var offset = 0
            while (offset < bytes.size) offset += server.read(bytes,offset,bytes.size-offset,10000)
            assertContentEquals(payload,bytes); writer.await(); drainer.await(); client.close(); assertTrue(server.read(3,10000).isEmpty())
            assertFails { link.first.connect(b,9,1000) }; assertFails { listener.accept(20) }
            val accepting = Job { assertFails { listener.accept(10000) } }; listener.close(); accepting.await()
        } finally { link.close() }
        val blackhole = IPStack(a,{})
        assertFails { blackhole.connect(b,80,30) }; assertEquals(0,blackhole.connectionCount); blackhole.close()
    }
    @Test fun thousandsOfShortRequestsKeepEventStreamAlive() {
        val link = Link()
        try {
            val listener = link.second.listen(80)
            val events = link.first.connect(b, 80); val eventServer = listener.accept(10000)
            val ready = "event: ready\ndata: {}\n\n".encodeToByteArray()
            eventServer.write(ready, timeoutMillis = 10000); assertContentEquals(ready, events.read(65536, 10000))
            var firstPort = -1; var lastPort = -1
            for (index in 0 until 1300) {
                val client = link.first.connect(b, 80, 10000); val server = listener.accept(10000)
                if (firstPort < 0) firstPort = client.localPort
                lastPort = client.localPort
                val request = "GET /kv/entry?key=$index HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n".encodeToByteArray()
                client.write(request, timeoutMillis = 10000); assertContentEquals(request, server.read(65536, 10000))
                val response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".encodeToByteArray()
                server.write(response, timeoutMillis = 10000); server.close()
                assertContentEquals(response, drain(client)); client.close()
                if (index % 50 == 0) {
                    val event = "event: change\ndata: $index\n\n".encodeToByteArray()
                    eventServer.write(event, timeoutMillis = 10000); assertContentEquals(event, events.read(65536, 10000))
                }
            }
            assertFalse(link.first.hasTCPFlow(b, firstPort, 80), "Closing state evicts oldest flows instead of refusing new requests")
            assertTrue(link.first.hasTCPFlow(b, lastPort, 80), "Recent closing flows remain available for late FINs")
            assertEquals(1025, link.first.connectionCount, "One active SSE connection and at most 1024 closing flows")
            val final = "event: change\ndata: after-bulk\n\n".encodeToByteArray()
            eventServer.write(final, timeoutMillis = 10000); assertContentEquals(final, events.read(65536, 10000))
            events.close(); eventServer.close()
        } finally { link.close() }
    }
    @Test fun closingFlowsAcknowledgeLateFINAndDisconnectRemovesThem() {
        val link = Link()
        try {
            val listener = link.second.listen(80); val client = link.first.connect(b, 80); val server = listener.accept(10000)
            client.shutdownOutput(10000); assertTrue(server.read(1, 10000).isEmpty())
            server.shutdownOutput(10000); server.close(); client.close()
            val before = link.acks(); link.replayClientFIN()
            val end = monotonicMillis() + 10000
            while (link.acks() <= before) { check(monotonicMillis() < end); platformSleep(1) }
            assertEquals(0, link.resets(), "Retained closing state ACKs a retransmitted FIN without resetting")
            link.first.disconnect(b)
            assertEquals(0, link.first.connectionCount); assertFalse(link.first.hasTCPFlow(b, client.localPort, 80))
        } finally { link.close() }
    }
    @Test fun activeConnectionBudgetsStillApply() {
        val link = Link()
        try {
            val streams = mutableListOf<TailcatConnection>()
            for (port in 80 until 84) {
                val listener = link.second.listen(port)
                repeat(256) { streams.add(link.first.connect(b, port, 10000)); listener.accept(10000) }
                if (port == 80) {
                    val refused = assertFails { link.first.connect(b, 80, 10000) }
                    assertEquals(TailcatTransportException.Reason.CONNECTION_REFUSED, (refused as TailcatTransportException).reason, "The live per-listener budget must remain bounded")
                }
            }
            val limited = assertFails { link.first.connect(b, 84, 10000) }
            assertEquals(TailcatTransportException.Reason.RESOURCE_LIMIT, (limited as TailcatTransportException).reason, "The live global budget must remain bounded")
            assertEquals(1024, link.first.connectionCount)
        } finally { link.close() }
    }
    @Test fun udpFlowsAndEmptyDatagrams() {
        val link = Link()
        try {
            val listener = link.second.listenUDP(53); val client = link.first.connectUDP(b,53)
            client.send(byteArrayOf()); val server = listener.accept(10000); assertTrue(server.receive(10000).isEmpty())
            for (size in listOf(0,1,31,1232)) {
                val bytes = ByteArray(size) { it.toByte() }; client.send(bytes); assertContentEquals(bytes,server.receive(10000)); server.send(bytes); assertContentEquals(bytes,client.receive(10000))
            }
            assertFails { client.send(ByteArray(1233)) }; listener.close(); client.send(byteArrayOf(7)); assertContentEquals(byteArrayOf(7),server.receive(10000))
            val replacement = link.second.listenUDP(53); val second = link.first.connectUDP(b,53); second.send(byteArrayOf(9))
            val accepted = replacement.accept(10000); assertNotEquals(server.remotePort,accepted.remotePort); assertContentEquals(byteArrayOf(9),accepted.receive(10000))
            link.second.tick(monotonicMillis()+120001); assertFails { server.receive(20) }; assertTrue(link.second.hasUDPSocket(53))
        } finally { link.close() }
    }
    @Test fun packetValidation() {
        var captured: ByteArray? = null; val first = IPStack(a,{ captured = it.copyOf() }); val second = IPStack(b,{})
        try {
            val sender = first.udp(); val receiver = second.udp(53,null); sender.send(byteArrayOf(1,2,3),b,53); val valid = captured!!
            second.receive(valid.copyOf().also { it[48] = (it[48].toInt() xor 255).toByte() }); second.receive(valid.copyOf().also { it[39] = 3 })
            second.receive(valid.copyOf(valid.size-1)); second.receive(valid.copyOf().also { it[46] = 0; it[47] = 0 })
            sender.send(byteArrayOf(4,5,6),b,53); second.receive(captured!!); assertContentEquals(byteArrayOf(4,5,6),receiver.receive(1000).data)
            assertFails { receiver.receive(20) }
        } finally { first.close(); second.close() }
    }
}
