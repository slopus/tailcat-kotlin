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
    private inner class Link(private val faults: Faults = Faults()) {
        private val lock = PlatformLock(); private val queue = ArrayDeque<Packet>(); private var running = true
        private var zero = false; private var data = false; private var fin = false; private var held: ByteArray? = null; private var heldAck: ByteArray? = null
        private var deliveredResets = 0
        var drops = 0
            private set
        val first = IPStack(a, { enqueue(true,it) }); val second = IPStack(b, { enqueue(false,it) })
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
                    }
                }
                first.tick(); second.tick()
            }
        }
        private fun enqueue(fromA: Boolean, bytes: ByteArray) { lock.withLock { if (running && queue.size < 8192) { queue.addLast(Packet(fromA,bytes.copyOf())); lock.signalAll() } } }
        private fun transform(packet: Packet): List<ByteArray> {
            val bytes = packet.bytes
            if (bytes.size < 60 || bytes[6] != 6.toByte()) return listOf(bytes)
            val flags = bytes[53].u(); val size = bytes.size-40-(bytes[52].u() ushr 4)*4; val window = bytes.be16(54)
            if (window == 0) zero = true
            if (packet.fromA && flags and 1 != 0) fin = true
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
        fun close() { first.close(); second.close(); lock.withLock { running = false; lock.signalAll() }; worker.await() }
    }
    private fun drain(stream: TailcatConnection): ByteArray {
        val chunks = mutableListOf<ByteArray>(); var count = 0
        while (true) { val data = stream.read(7777,30000); if (data.isEmpty()) break; chunks.add(data); count += data.size }
        val out = ByteArray(count); var offset = 0; for (data in chunks) { data.copyInto(out,offset); offset += data.size }; return out
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
        val link = Link(Faults(reopen=true,finAck=true))
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
        val link = Link()
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
