// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package io.tailcat.stack

import io.tailcat.NodePublicKey
import io.tailcat.TailcatConnection
import io.tailcat.TailcatDatagram
import io.tailcat.TailcatListener
import io.tailcat.TailcatUDPSocket
import io.tailcat.TailcatUDPConnection
import io.tailcat.TailcatUDPListener
import io.tailcat.platform.PlatformLock
import io.tailcat.platform.monotonicMillis
import io.tailcat.platform.secureRandom

class TailcatTransportException(val reason: Reason) : Exception(reason.name) {
    enum class Reason { INVALID_ADDRESS, INVALID_PORT, ADDRESS_IN_USE, CLOSED, CONNECTION_REFUSED, CONNECTION_RESET, TIMED_OUT, DATAGRAM_TOO_LARGE, RESOURCE_LIMIT }
}

/** Common userspace IPv6 TCP/UDP. Call tick every 100ms or faster; sendPacket only enqueues. */
class IPStack(
    localAddress: ByteArray,
    private val sendPacket: (ByteArray) -> Unit,
    private val peer: NodePublicKey? = null,
    private val peerForAddress: ((ByteArray) -> NodePublicKey?)? = null,
) {
    private class Address(raw: ByteArray) {
        val bytes = raw.copyOf()
        override fun equals(other: Any?): Boolean = other is Address && bytes.contentEquals(other.bytes)
        override fun hashCode(): Int = bytes.contentHashCode()
    }
    private data class FlowKey(val peer: Address, val localPort: Int, val remotePort: Int)
    private enum class Phase { SYN_SENT, SYN_RECEIVED, ESTABLISHED }
    private data class Segment(val sequence: Long, val flags: Int, val payload: ByteArray, var sent: Long, var retries: Int = 0) {
        val end: Long get() = add(sequence, payload.size + if (flags and 3 != 0) 1 else 0)
    }
    private data class Incoming(val sequence: Long, val payload: ByteArray, val fin: Boolean)
    private class WriteTicket(val id: Long, val data: ByteArray) { var offset = 0; var end: Long? = null; var done = false }
    private class ByteQueue(private val capacity: Int) {
        private val bytes = ByteArray(capacity)
        private var head = 0
        var size = 0
            private set
        fun append(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
            check(length <= capacity - size)
            for (index in 0 until length) bytes[(head + size + index) % capacity] = data[offset + index]
            size += length
        }
        fun read(target: ByteArray, offset: Int, maximum: Int): Int {
            val count = minOf(size, maximum)
            for (index in 0 until count) target[offset + index] = bytes[(head + index) % capacity]
            head = (head + count) % capacity; size -= count; return count
        }
        fun clear() { head = 0; size = 0 }
    }
    private class TCPState(val id: Long, val key: FlowKey, var phase: Phase, sequence: Long, val listener: Long?, now: Long) {
        var sendUnacknowledged = sequence; var sendNext = sequence; var receiveNext = 0L
        var remoteWindow = 65535; var windowSequence = 0L; var windowAck = 0L; var mss = 1220
        var congestionWindow = 4880; var slowStartThreshold = 65535; var duplicateACKs = 0; var retransmitDelay = 500L
        val segments = ArrayList<Segment>(); val incoming = ArrayList<Incoming>(); val buffer = ByteQueue(65535); val writes = ArrayList<WriteTicket>()
        var writeClosed = false; var applicationClosedAt: Long? = null; var finSequence: Long? = null
        var finAcknowledged = false; var readEOF = false; var lastActivity = now; var persistSent = now - 1000
        var finishedAt: Long? = null; var error: Throwable? = null
    }
    private class ListenerState(val id: Long, val port: Int) { val pending = ArrayDeque<Long>() }
    private enum class UDPMode { RAW, LISTENER, CONNECTED }
    private class UDPState(val id: Long, val port: Int, val idleTimeout: Long?, now: Long,
        val mode: UDPMode = UDPMode.RAW, val flowTimeout: Long = 120000) {
        val pending = ArrayDeque<TailcatDatagram>(); val pendingFlows = ArrayDeque<Long>(); var activity = now
    }
    private class UDPFlowState(val id: Long, val socket: Long, val key: FlowKey, val idleTimeout: Long, var activity: Long, val ownedSocket: Boolean) {
        val pending = ArrayDeque<ByteArray>()
    }
    private val address = localAddress.copyOf()
    private val lock = PlatformLock()
    private val connections = mutableMapOf<Long, TCPState>(); private val flows = mutableMapOf<FlowKey, Long>()
    private val listeners = mutableMapOf<Long, ListenerState>(); private val listenPorts = mutableMapOf<Int, Long>()
    private val udpSockets = mutableMapOf<Long, UDPState>(); private val udpPorts = mutableMapOf<Int, Long>()
    private val udpFlowStates = mutableMapOf<Long, UDPFlowState>(); private val udpFlows = mutableMapOf<FlowKey, Long>()
    private val terminalErrors = mutableMapOf<Long, Throwable>(); private val terminalOrder = ArrayDeque<Long>()
    private var nextId = 1L; private var nextPort = 49152 + (u16(secureRandom(2), 0) % 16384); private var closed = false
    private inline fun <T> locked(block: () -> T): T { lock.lock(); try { return block() } finally { lock.unlock() } }
    private fun error(reason: TailcatTransportException.Reason): TailcatTransportException = TailcatTransportException(reason)
    private fun closedError(id: Long): Throwable = terminalErrors[id] ?: error(TailcatTransportException.Reason.CLOSED)
    private fun deadline(timeoutMillis: Long): Long? {
        require(timeoutMillis >= 0)
        if (timeoutMillis == 0L) return null
        val now = monotonicMillis(); return if (now > Long.MAX_VALUE - timeoutMillis) Long.MAX_VALUE else now + timeoutMillis
    }
    private fun await(deadline: Long?) {
        if (deadline == null) { lock.await(0); return }
        val remaining = deadline - monotonicMillis(); if (remaining <= 0) throw error(TailcatTransportException.Reason.TIMED_OUT)
        lock.await(remaining)
    }
    private fun validate(peer: ByteArray, port: Int) {
        if (closed) throw error(TailcatTransportException.Reason.CLOSED)
        if (address.size != 16 || peer.size != 16) throw error(TailcatTransportException.Reason.INVALID_ADDRESS)
        if (port !in 1..65535) throw error(TailcatTransportException.Reason.INVALID_PORT)
    }
    private fun allocatePort(udp: Boolean): Int {
        repeat(16384) {
            val port = nextPort; nextPort = if (nextPort == 65535) 49152 else nextPort + 1
            if (udp) { if (port !in udpPorts && udpFlows.keys.none { it.localPort == port }) return port }
            else if (port !in listenPorts && flows.keys.none { it.localPort == port }) return port
        }
        throw error(TailcatTransportException.Reason.ADDRESS_IN_USE)
    }
    private fun connection(state: TCPState) = TailcatConnection(this, state.id, address, state.key.peer.bytes, state.key.localPort, state.key.remotePort,
        peer ?: peerForAddress?.invoke(state.key.peer.bytes))
    private fun state(id: Long): TCPState = connections[id] ?: throw closedError(id)
    fun connect(peer: ByteArray, port: Int, timeoutMillis: Long = 30000): TailcatConnection = locked {
        validate(peer, port); val until = deadline(timeoutMillis)
        if (connections.size >= 1024) throw error(TailcatTransportException.Reason.RESOURCE_LIMIT)
        val state = TCPState(nextId++, FlowKey(Address(peer), allocatePort(false), port), Phase.SYN_SENT, u32(secureRandom(4), 0), null, monotonicMillis())
        connections[state.id] = state; flows[state.key] = state.id; transmit(state, 0x02)
        try {
            while (state.phase != Phase.ESTABLISHED) { state.error?.let { throw it }; await(until) }
            state.error?.let { throw it }; connection(state)
        } catch (failure: Throwable) { fail(state.id, failure, true); throw failure }
    }
    fun listen(port: Int): TailcatListener = locked {
        val bound = if (port == 0) allocatePort(false) else port
        validate(address, bound)
        if (bound in listenPorts) throw error(TailcatTransportException.Reason.ADDRESS_IN_USE)
        val state = ListenerState(nextId++, bound); listeners[state.id] = state; listenPorts[bound] = state.id
        TailcatListener(this, state.id, bound, address)
    }
    fun hasTCPListener(port: Int): Boolean = locked { port in listenPorts }
    fun hasUDPSocket(port: Int): Boolean = locked { port in udpPorts }
    fun hasTCPFlow(peer: ByteArray, localPort: Int, remotePort: Int): Boolean = locked { FlowKey(Address(peer), localPort, remotePort) in flows }
    fun hasUDPFlow(peer: ByteArray, localPort: Int, remotePort: Int): Boolean = locked { FlowKey(Address(peer), localPort, remotePort) in udpFlows }
    val udpConnectionCount: Int get() = locked { udpFlowStates.size }
    val connectionCount: Int get() = locked { connections.size }
    fun udp(port: Int = 0, idleTimeoutMillis: Long? = 120000): TailcatUDPSocket = locked {
        if (closed) throw error(TailcatTransportException.Reason.CLOSED)
        if (address.size != 16) throw error(TailcatTransportException.Reason.INVALID_ADDRESS)
        require(idleTimeoutMillis == null || idleTimeoutMillis > 0)
        val bound = if (port == 0) allocatePort(true) else port; validate(address, bound)
        if (bound in udpPorts) throw error(TailcatTransportException.Reason.ADDRESS_IN_USE)
        val state = UDPState(nextId++, bound, idleTimeoutMillis, monotonicMillis()); udpSockets[state.id] = state; udpPorts[bound] = state.id
        TailcatUDPSocket(this, state.id, bound)
    }
    fun listenUDP(port: Int, idleTimeoutMillis: Long = 120000): TailcatUDPListener = locked {
        val bound = if (port == 0) allocatePort(true) else port
        validate(address, bound); require(idleTimeoutMillis > 0)
        if (bound in udpPorts) throw error(TailcatTransportException.Reason.ADDRESS_IN_USE)
        val state = UDPState(nextId++, bound, null, monotonicMillis(), UDPMode.LISTENER, idleTimeoutMillis)
        udpSockets[state.id] = state; udpPorts[bound] = state.id
        TailcatUDPListener(this, state.id, bound, address)
    }
    fun connectUDP(peer: ByteArray, port: Int, idleTimeoutMillis: Long = 120000): TailcatUDPConnection = locked {
        validate(peer, port); require(idleTimeoutMillis > 0)
        if (udpFlowStates.size >= 1024) throw error(TailcatTransportException.Reason.RESOURCE_LIMIT)
        val localPort = allocatePort(true); val now = monotonicMillis()
        val socket = UDPState(nextId++, localPort, null, now, UDPMode.CONNECTED, idleTimeoutMillis)
        udpSockets[socket.id] = socket; udpPorts[localPort] = socket.id
        val flow = UDPFlowState(nextId++, socket.id, FlowKey(Address(peer), localPort, port), idleTimeoutMillis, now, true)
        udpFlowStates[flow.id] = flow; udpFlows[flow.key] = flow.id; udpConnection(flow)
    }
    private fun udpConnection(flow: UDPFlowState) = TailcatUDPConnection(this, flow.id, address, flow.key.peer.bytes, flow.key.localPort, flow.key.remotePort,
        peer ?: peerForAddress?.invoke(flow.key.peer.bytes.copyOf()))
    fun close() = locked {
        if (!closed) {
            closed = true
            for (id in connections.keys.toList()) fail(id, error(TailcatTransportException.Reason.CLOSED), true)
            listeners.clear(); listenPorts.clear()
            for (id in udpSockets.keys.toList()) closeUDPInternal(id, error(TailcatTransportException.Reason.CLOSED))
            for (id in udpFlowStates.keys.toList()) closeUDPFlowInternal(id, error(TailcatTransportException.Reason.CLOSED))
            lock.signalAll()
        }
    }
    fun disconnect(peer: ByteArray) = locked {
        for (state in connections.values.filter { it.key.peer.bytes.contentEquals(peer) }.toList()) fail(state.id, error(TailcatTransportException.Reason.CLOSED), true)
        for (state in udpSockets.values) state.pending.removeAll { it.peer.contentEquals(peer) }
        for (state in udpFlowStates.values.filter { it.key.peer.bytes.contentEquals(peer) }.toList()) closeUDPFlowInternal(state.id, error(TailcatTransportException.Reason.CLOSED))
        lock.signalAll()
    }
    fun receive(packet: ByteArray) = locked {
        if (closed || packet.size < 40 || unsigned(packet[0]) ushr 4 != 6) return@locked
        if (!packet.copyOfRange(24, 40).contentEquals(address)) return@locked
        val length = u16(packet, 4); if (length == 0 || packet.size < 40 + length) return@locked
        val peer = packet.copyOfRange(8, 24)
        if (peer.all { it == 0.toByte() } || unsigned(peer[0]) == 255) return@locked
        var protocol = unsigned(packet[6]); var offset = 40; val end = 40 + length; var extensions = 0
        while (protocol == 0 || protocol == 60 || protocol == 43 || protocol == 44) {
            if (++extensions > 8 || offset + 8 > end) return@locked
            val next = unsigned(packet[offset])
            if (protocol == 44) { if (u16(packet, offset + 2) != 0) return@locked; offset += 8 }
            else { if (protocol == 43 && packet[offset + 3] != 0.toByte()) return@locked; offset += (unsigned(packet[offset + 1]) + 1) * 8 }
            if (offset > end) return@locked; protocol = next
        }
        val body = packet.copyOfRange(offset, end)
        if (checksum(peer, address, protocol, body) != 0) return@locked
        when (protocol) { 6 -> receiveTCP(peer, body); 17 -> receiveUDP(peer, body) }
        lock.signalAll()
    }
    private fun receiveTCP(peer: ByteArray, body: ByteArray) {
        if (body.size < 20) return
        val headerLength = (unsigned(body[12]) ushr 4) * 4; if (headerLength < 20 || headerLength > body.size) return
        val key = FlowKey(Address(peer), u16(body, 2), u16(body, 0)); if (key.localPort == 0 || key.remotePort == 0) return
        val sequence = u32(body, 4); val acknowledgement = u32(body, 8); val flags = unsigned(body[13]); val payload = body.copyOfRange(headerLength, body.size)
        val state = flows[key]?.let { connections[it] }
        if (state == null) {
            val listenerId = listenPorts[key.localPort]; val listener = listenerId?.let { listeners[it] }
            if (flags and 0x17 == 0x02 && listener != null && listener.pending.size < 128 && connections.size < 1024 && connections.values.count { it.listener == listenerId } < 256) {
                val incoming = TCPState(nextId++, key, Phase.SYN_RECEIVED, u32(secureRandom(4), 0), listenerId, monotonicMillis())
                incoming.receiveNext = add(sequence, 1); incoming.windowSequence = sequence; incoming.remoteWindow = u16(body, 14); incoming.mss = parseMSS(body, headerLength)
                connections[incoming.id] = incoming; flows[key] = incoming.id; transmit(incoming, 0x12)
            } else reset(key, sequence, acknowledgement, flags, payload.size)
            return
        }
        state.lastActivity = monotonicMillis()
        if (state.phase == Phase.SYN_SENT) {
            if (flags and 0x10 == 0 || acknowledgement != state.sendNext) return
            if (flags and 0x04 != 0) { fail(state.id, error(TailcatTransportException.Reason.CONNECTION_REFUSED)); return }
            if (flags and 0x02 == 0) return
            state.receiveNext = add(sequence, 1); state.remoteWindow = u16(body, 14); state.windowSequence = sequence; state.windowAck = acknowledgement
            state.mss = parseMSS(body, headerLength); state.phase = Phase.ESTABLISHED; acknowledge(state, acknowledgement); sendACK(state); return
        }
        if (flags and 0x04 != 0) {
            // Both FINs are complete. Preserve buffered bytes and orderly EOF
            // through TIME-WAIT rather than accepting a late reset (RFC 1337).
            if (state.readEOF && state.finAcknowledged) return
            if (sequence == state.receiveNext) fail(state.id, error(TailcatTransportException.Reason.CONNECTION_RESET)) else sendACK(state); return
        }
        if (state.phase == Phase.SYN_RECEIVED && flags and 0x02 != 0 && add(sequence, 1) == state.receiveNext) { state.segments.firstOrNull()?.let { retransmit(state, it) }; return }
        if (flags and 0x02 != 0) { sendACK(state); return }
        if (flags and 0x10 == 0) return
        val available = receiveWindow(state); val segmentLength = payload.size + if (flags and 1 != 0) 1 else 0
        val intersects = sequence == state.receiveNext || (available > 0 && before(sequence, add(state.receiveNext, available)) && !before(add(sequence, segmentLength), state.receiveNext))
        if (!intersects) { sendACK(state); return }
        if (before(state.sendNext, acknowledgement)) { sendACK(state); return }
        if (state.phase == Phase.SYN_RECEIVED) {
            if (acknowledgement != state.sendNext) return
            val listener = state.listener?.let { listeners[it] }
            if (listener == null) { fail(state.id, error(TailcatTransportException.Reason.CLOSED), true); return }
            state.phase = Phase.ESTABLISHED; listener.pending.addLast(state.id)
        }
        val oldWindow = state.remoteWindow
        if (before(state.windowSequence, sequence) || (state.windowSequence == sequence && !before(acknowledgement, state.windowAck))) {
            state.remoteWindow = u16(body, 14); state.windowSequence = sequence; state.windowAck = acknowledgement
        }
        if (acknowledgement == state.sendUnacknowledged && payload.isEmpty() && flags and 1 == 0 && oldWindow == state.remoteWindow && state.segments.isNotEmpty()) {
            state.duplicateACKs++
            if (state.duplicateACKs == 3) { state.slowStartThreshold = maxOf(state.mss * 2, state.congestionWindow / 2); state.congestionWindow = state.slowStartThreshold; retransmit(state, state.segments.first()) }
        } else if (before(state.sendUnacknowledged, acknowledgement)) acknowledge(state, acknowledgement)
        if (payload.isNotEmpty() || flags and 1 != 0) { ingest(state, sequence, payload, flags and 1 != 0); sendACK(state) }
        flush(state)
    }
    fun rejectTCP(peer: ByteArray, body: ByteArray) = locked {
        if (closed || address.size != 16 || peer.size != 16 || body.size !in 20..65535 || peer.all { it == 0.toByte() } || unsigned(peer[0]) == 255) return@locked
        val headerLength = (unsigned(body[12]) ushr 4) * 4
        if (headerLength !in 20..body.size || checksum(peer, address, 6, body) != 0) return@locked
        val key = FlowKey(Address(peer), u16(body, 2), u16(body, 0))
        if (key.localPort != 0 && key.remotePort != 0) reset(key, u32(body, 4), u32(body, 8), unsigned(body[13]), body.size - headerLength)
    }
    private fun reset(key: FlowKey, sequence: Long, acknowledgement: Long, flags: Int, payloadLength: Int) {
        if (flags and 0x04 != 0) return
        if (flags and 0x10 != 0) emit(tcpPacket(key, acknowledgement, 0, 0x04, 0))
        else { val consumed = payloadLength + (if (flags and 0x02 != 0) 1 else 0) + (if (flags and 0x01 != 0) 1 else 0); emit(tcpPacket(key, 0, add(sequence, consumed), 0x14, 0)) }
    }
    private fun parseMSS(body: ByteArray, headerLength: Int): Int {
        var offset = 20; var result = 1220
        while (offset < headerLength) {
            val kind = unsigned(body[offset]); if (kind == 0) break; if (kind == 1) { offset++; continue }
            if (offset + 1 >= headerLength) break
            val length = unsigned(body[offset + 1]); if (length < 2 || offset + length > headerLength) break
            if (kind == 2 && length == 4) result = u16(body, offset + 2).coerceIn(1, 1220); offset += length
        }
        return result
    }
    private fun acknowledge(state: TCPState, ack: Long) {
        if (before(ack, state.sendUnacknowledged) || before(state.sendNext, ack)) return
        val advanced = distance(ack, state.sendUnacknowledged).toInt(); state.sendUnacknowledged = ack; state.duplicateACKs = 0; state.retransmitDelay = 500
        state.segments.removeAll { !before(ack, it.end) }
        val first = state.segments.firstOrNull()
        if (first != null && before(first.sequence, ack) && first.payload.isNotEmpty()) {
            val count = distance(ack, first.sequence).toInt()
            if (count < first.payload.size) state.segments[0] = first.copy(sequence = ack, payload = first.payload.copyOfRange(count, first.payload.size))
        }
        if (advanced > 0) {
            val increment = if (state.congestionWindow < state.slowStartThreshold) minOf(advanced, state.mss) else maxOf(1, state.mss * minOf(advanced, state.mss) / maxOf(1, state.congestionWindow))
            state.congestionWindow = minOf(65535, state.congestionWindow + increment)
        }
        while (state.writes.isNotEmpty()) { val write = state.writes.first(); val end = write.end ?: break; if (before(ack, end)) break; write.done = true; state.writes.removeAt(0) }
        state.finSequence?.let { if (before(it, ack)) { state.finAcknowledged = true; if (state.readEOF) state.finishedAt = monotonicMillis() } }
    }
    private fun receiveWindow(state: TCPState): Int = maxOf(0, 65535 - state.buffer.size - state.incoming.sumOf { it.payload.size })
    private fun ingest(state: TCPState, sequence: Long, payload: ByteArray, fin: Boolean) {
        if (state.readEOF) return
        var seq = sequence; var data = payload
        if (before(seq, state.receiveNext)) {
            val skip = distance(state.receiveNext, seq); if (skip > data.size) return
            data = data.copyOfRange(skip.toInt(), data.size); seq = state.receiveNext
        }
        val delta = distance(seq, state.receiveNext); val capacity = receiveWindow(state)
        if (delta > capacity) return
        val accepted = minOf(data.size, maxOf(0, capacity - delta.toInt())); val acceptedFIN = fin && accepted == data.size && delta + accepted < capacity
        data = data.copyOf(accepted)
        if (seq == state.receiveNext) {
            if (state.applicationClosedAt == null) state.buffer.append(data)
            state.receiveNext = add(state.receiveNext, data.size)
            if (acceptedFIN) { state.readEOF = true; state.receiveNext = add(state.receiveNext, 1) }
        } else if (data.isNotEmpty() || acceptedFIN) {
            if (state.incoming.size < 256 && state.incoming.none { it.sequence == seq && it.payload.size >= data.size }) state.incoming.add(Incoming(seq, data, acceptedFIN))
        }
        state.incoming.sortWith(Comparator { a, b -> if (a.sequence == b.sequence) 0 else if (before(a.sequence, b.sequence)) -1 else 1 })
        while (state.incoming.isNotEmpty() && !state.readEOF) {
            val first = state.incoming.first(); if (before(state.receiveNext, first.sequence)) break; state.incoming.removeAt(0)
            val skip = distance(state.receiveNext, first.sequence)
            if (skip <= first.payload.size) {
                val count = first.payload.size - skip.toInt()
                if (state.applicationClosedAt == null) state.buffer.append(first.payload, skip.toInt(), count)
                state.receiveNext = add(state.receiveNext, count)
                if (first.fin) { state.readEOF = true; state.receiveNext = add(state.receiveNext, 1) }
            }
        }
        if (state.readEOF) { state.incoming.clear(); if (state.finAcknowledged) state.finishedAt = monotonicMillis() }
    }
    private fun emit(packet: ByteArray) { try { sendPacket(packet) } catch (_: Exception) { } }
    private fun transmit(state: TCPState, flags: Int, payload: ByteArray = ByteArray(0)) {
        val segment = Segment(state.sendNext, flags, payload, monotonicMillis()); state.sendNext = segment.end; state.segments.add(segment); retransmit(state, segment)
    }
    private fun retransmit(state: TCPState, segment: Segment) = emit(tcpPacket(state.key, segment.sequence, state.receiveNext, segment.flags, receiveWindow(state), segment.payload))
    private fun sendACK(state: TCPState) = emit(tcpPacket(state.key, state.sendNext, state.receiveNext, 0x10, receiveWindow(state)))
    private fun flush(state: TCPState) {
        if (state.phase != Phase.ESTABLISHED) return
        for (write in state.writes) {
            while (write.offset < write.data.size) {
                val inFlight = distance(state.sendNext, state.sendUnacknowledged).toInt(); val allowed = minOf(state.remoteWindow, state.congestionWindow) - inFlight
                if (allowed <= 0) return
                val count = minOf(state.mss, allowed, write.data.size - write.offset); val bytes = write.data.copyOfRange(write.offset, write.offset + count)
                write.offset += count; transmit(state, 0x18, bytes)
            }
            if (write.end == null) write.end = state.sendNext
        }
        if (state.writeClosed && state.finSequence == null && state.remoteWindow.toLong() > distance(state.sendNext, state.sendUnacknowledged)) { state.finSequence = state.sendNext; transmit(state, 0x11) }
    }
    internal fun read(id: Long, buffer: ByteArray, offset: Int, length: Int, timeoutMillis: Long): Int = locked {
        checkBounds(buffer, offset, length); if (length == 0) return@locked 0; val until = deadline(timeoutMillis)
        while (true) {
            val state = state(id); if (state.applicationClosedAt != null) throw error(TailcatTransportException.Reason.CLOSED)
            if (state.buffer.size > 0) { val count = state.buffer.read(buffer, offset, length); sendACK(state); return@locked count }
            if (state.readEOF) return@locked -1; await(until)
        }
        @Suppress("UNREACHABLE_CODE") -1
    }
    internal fun write(id: Long, data: ByteArray, offset: Int, length: Int, timeoutMillis: Long) = locked {
        checkBounds(data, offset, length); val state = state(id); if (state.writeClosed) throw error(TailcatTransportException.Reason.CLOSED)
        if (length == 0) return@locked; val until = deadline(timeoutMillis)
        if (length > 4 * 1024 * 1024 || state.writes.sumOf { it.data.size } > 4 * 1024 * 1024 - length) throw error(TailcatTransportException.Reason.RESOURCE_LIMIT)
        val ticket = WriteTicket(nextId++, data.copyOfRange(offset, offset + length)); state.writes.add(ticket); flush(state)
        try { while (!ticket.done) { state.error?.let { throw it }; await(until) } } catch (failure: Throwable) { fail(id, failure, true); throw failure }
    }
    internal fun drain(id: Long, timeoutMillis: Long) = locked {
        val state = state(id); if (state.applicationClosedAt != null) throw error(TailcatTransportException.Reason.CLOSED)
        val pending = state.writes.toList(); val until = deadline(timeoutMillis)
        while (pending.any { !it.done }) { state.error?.let { throw it }; await(until) }
    }
    internal fun closeWrite(id: Long, timeoutMillis: Long) = locked {
        val state = state(id); if (state.applicationClosedAt != null) throw error(TailcatTransportException.Reason.CLOSED)
        val until = deadline(timeoutMillis); state.writeClosed = true; flush(state)
        while (!state.finAcknowledged) { state.error?.let { throw it }; await(until) }
    }
    internal fun closeConnection(id: Long) = locked {
        val state = connections[id] ?: return@locked; if (state.applicationClosedAt != null) return@locked
        state.applicationClosedAt = monotonicMillis(); state.writeClosed = true; state.buffer.clear(); sendACK(state); flush(state); lock.signalAll()
    }
    internal fun abortConnection(id: Long) = locked { fail(id, error(TailcatTransportException.Reason.CLOSED), true) }
    private fun fail(id: Long, failure: Throwable, reset: Boolean = false) {
        val state = connections.remove(id) ?: return; flows.remove(state.key); state.error = failure; rememberError(id, failure)
        if (reset && !(state.readEOF && state.finAcknowledged)) emit(tcpPacket(state.key, state.sendNext, state.receiveNext, 0x14, 0))
        state.listener?.let { listeners[it]?.pending?.remove(id) }; lock.signalAll()
    }
    private fun rememberError(id: Long, failure: Throwable) { terminalErrors[id] = failure; terminalOrder.addLast(id); if (terminalOrder.size > 1024) terminalErrors.remove(terminalOrder.removeFirst()) }
    internal fun accept(id: Long, timeoutMillis: Long): TailcatConnection = locked {
        val until = deadline(timeoutMillis)
        while (true) {
            val listener = listeners[id] ?: throw error(TailcatTransportException.Reason.CLOSED)
            while (listener.pending.isNotEmpty()) { val state = connections[listener.pending.removeFirst()] ?: continue; return@locked connection(state) }
            await(until)
        }
        @Suppress("UNREACHABLE_CODE") throw error(TailcatTransportException.Reason.CLOSED)
    }
    internal fun closeListener(id: Long) = locked {
        val listener = listeners.remove(id) ?: return@locked; listenPorts.remove(listener.port)
        val unfinished = connections.values.filter { it.listener == id && (it.phase != Phase.ESTABLISHED || it.id in listener.pending) }.map { it.id }
        for (connection in unfinished) fail(connection, error(TailcatTransportException.Reason.CLOSED), true); lock.signalAll()
    }
    internal fun sendUDP(id: Long, data: ByteArray, peer: ByteArray, port: Int) = locked {
        validate(peer, port); val state = udpSockets[id] ?: throw closedError(id)
        val packet = udpPacket(state.port, data, peer, port); state.activity = monotonicMillis(); sendPacket(packet)
    }
    private fun udpPacket(localPort: Int, data: ByteArray, peer: ByteArray, port: Int): ByteArray {
        if (data.size > 1232) throw error(TailcatTransportException.Reason.DATAGRAM_TOO_LARGE)
        val body = ByteArray(8 + data.size); put16(body, 0, localPort); put16(body, 2, port); put16(body, 4, body.size); data.copyInto(body, 8)
        val sum = checksum(address, peer, 17, body); put16(body, 6, if (sum == 0) 65535 else sum); return ipv6(peer, 17, body)
    }
    private fun receiveUDP(peer: ByteArray, body: ByteArray) {
        if (body.size !in 8..1240 || u16(body, 4) != body.size || u16(body, 6) == 0 || u16(body, 0) == 0) return
        val key = FlowKey(Address(peer), u16(body, 2), u16(body, 0))
        val existing = udpFlows[key]?.let { udpFlowStates[it] }
        if (existing != null) {
            existing.activity = monotonicMillis()
            if (existing.pending.size < 128) existing.pending.addLast(body.copyOfRange(8, body.size))
            return
        }
        val state = udpPorts[u16(body, 2)]?.let { udpSockets[it] } ?: return; state.activity = monotonicMillis()
        if (state.mode == UDPMode.LISTENER) {
            if (state.pendingFlows.size >= 128 || udpFlowStates.size >= 1024) return
            val flow = UDPFlowState(nextId++, state.id, key, state.flowTimeout, monotonicMillis(), false)
            flow.pending.addLast(body.copyOfRange(8, body.size)); udpFlowStates[flow.id] = flow; udpFlows[key] = flow.id; state.pendingFlows.addLast(flow.id)
        } else if (state.mode == UDPMode.RAW && state.pending.size < 128) state.pending.addLast(TailcatDatagram(body.copyOfRange(8, body.size), peer, u16(body, 0)))
    }
    internal fun receiveUDP(id: Long, timeoutMillis: Long): TailcatDatagram = locked {
        val until = deadline(timeoutMillis)
        while (true) { val state = udpSockets[id] ?: throw closedError(id); if (state.pending.isNotEmpty()) return@locked state.pending.removeFirst(); await(until) }
        @Suppress("UNREACHABLE_CODE") throw error(TailcatTransportException.Reason.CLOSED)
    }
    internal fun closeUDP(id: Long) = locked { closeUDPInternal(id, error(TailcatTransportException.Reason.CLOSED)) }
    private fun closeUDPInternal(id: Long, failure: Throwable) {
        val state = udpSockets.remove(id) ?: return; udpPorts.remove(state.port); rememberError(id, failure)
        for (flow in udpFlowStates.values.filter { it.socket == id }.toList()) closeUDPFlowInternal(flow.id, failure)
        lock.signalAll()
    }
    internal fun acceptUDP(id: Long, timeoutMillis: Long): TailcatUDPConnection = locked {
        val until = deadline(timeoutMillis)
        while (true) {
            val listener = udpSockets[id] ?: throw closedError(id)
            if (listener.mode != UDPMode.LISTENER) throw error(TailcatTransportException.Reason.CLOSED)
            while (listener.pendingFlows.isNotEmpty()) { val flow = udpFlowStates[listener.pendingFlows.removeFirst()] ?: continue; return@locked udpConnection(flow) }
            await(until)
        }
        @Suppress("UNREACHABLE_CODE") throw error(TailcatTransportException.Reason.CLOSED)
    }
    internal fun closeUDPListener(id: Long) = locked {
        val listener = udpSockets.remove(id) ?: return@locked; udpPorts.remove(listener.port); rememberError(id, error(TailcatTransportException.Reason.CLOSED))
        for (flow in listener.pendingFlows.toList()) closeUDPFlowInternal(flow, error(TailcatTransportException.Reason.CLOSED))
        lock.signalAll()
    }
    internal fun receiveUDPFlow(id: Long, timeoutMillis: Long): ByteArray = locked {
        val until = deadline(timeoutMillis)
        while (true) { val flow = udpFlowStates[id] ?: throw closedError(id); if (flow.pending.isNotEmpty()) return@locked flow.pending.removeFirst(); await(until) }
        @Suppress("UNREACHABLE_CODE") throw error(TailcatTransportException.Reason.CLOSED)
    }
    internal fun sendUDPFlow(id: Long, data: ByteArray) = locked {
        val flow = udpFlowStates[id] ?: throw closedError(id)
        val packet = udpPacket(flow.key.localPort, data, flow.key.peer.bytes, flow.key.remotePort); flow.activity = monotonicMillis(); sendPacket(packet)
    }
    internal fun closeUDPFlow(id: Long) = locked { closeUDPFlowInternal(id, error(TailcatTransportException.Reason.CLOSED)) }
    private fun closeUDPFlowInternal(id: Long, failure: Throwable) {
        val flow = udpFlowStates.remove(id) ?: return; udpFlows.remove(flow.key); rememberError(id, failure); udpSockets[flow.socket]?.pendingFlows?.remove(id)
        if (flow.ownedSocket) { udpSockets.remove(flow.socket); udpPorts.remove(flow.key.localPort) }
        lock.signalAll()
    }
    fun tick(now: Long = monotonicMillis()) = locked {
        if (closed) return@locked
        for (state in connections.values.toList()) {
            val finished = state.finishedAt
            if (finished != null) { if (now - finished > 120000 && state.buffer.size == 0) fail(state.id, error(TailcatTransportException.Reason.CLOSED)); continue }
            val closedAt = state.applicationClosedAt
            if (closedAt != null && now - closedAt > 120000) { fail(state.id, error(TailcatTransportException.Reason.CLOSED), true); continue }
            val first = state.segments.firstOrNull()
            if (first != null && now - first.sent >= state.retransmitDelay) {
                if (first.retries >= 8) { fail(state.id, error(TailcatTransportException.Reason.TIMED_OUT)); continue }
                state.slowStartThreshold = maxOf(state.mss * 2, state.congestionWindow / 2); state.congestionWindow = state.mss
                state.retransmitDelay = minOf(8000L, state.retransmitDelay * 2); first.sent = now; first.retries++; retransmit(state, first)
            }
            if (state.remoteWindow == 0 && (state.writes.isNotEmpty() || state.writeClosed) && now - state.persistSent >= 1000) {
                state.persistSent = now; emit(tcpPacket(state.key, add(state.sendNext, -1), state.receiveNext, 0x10, receiveWindow(state)))
                if (now - state.lastActivity > 120000) fail(state.id, error(TailcatTransportException.Reason.TIMED_OUT))
            }
        }
        for (state in udpSockets.values.toList()) { val timeout = state.idleTimeout; if (timeout != null && now - state.activity >= timeout) closeUDPInternal(state.id, error(TailcatTransportException.Reason.TIMED_OUT)) }
        for (flow in udpFlowStates.values.toList()) if (now - flow.activity >= flow.idleTimeout) closeUDPFlowInternal(flow.id, error(TailcatTransportException.Reason.TIMED_OUT))
        lock.signalAll()
    }
    private fun tcpPacket(key: FlowKey, sequence: Long, ack: Long, flags: Int, window: Int, payload: ByteArray = ByteArray(0)): ByteArray {
        val headerLength = if (flags and 0x02 != 0) 24 else 20; val body = ByteArray(headerLength + payload.size)
        put16(body, 0, key.localPort); put16(body, 2, key.remotePort); put32(body, 4, sequence); put32(body, 8, ack)
        body[12] = ((headerLength / 4) shl 4).toByte(); body[13] = flags.toByte(); put16(body, 14, window)
        if (flags and 0x02 != 0) { body[20] = 2; body[21] = 4; put16(body, 22, 1220) }
        payload.copyInto(body, headerLength); put16(body, 16, checksum(address, key.peer.bytes, 6, body)); return ipv6(key.peer.bytes, 6, body)
    }
    private fun ipv6(peer: ByteArray, protocol: Int, body: ByteArray): ByteArray {
        val packet = ByteArray(40 + body.size); packet[0] = 0x60; put16(packet, 4, body.size); packet[6] = protocol.toByte(); packet[7] = 64
        address.copyInto(packet, 8); peer.copyInto(packet, 24); body.copyInto(packet, 40); return packet
    }
    private companion object {
        const val MASK = 0xffffffffL
        fun unsigned(value: Byte): Int = value.toInt() and 255
        fun add(value: Long, count: Int): Long = (value + count) and MASK
        fun distance(a: Long, b: Long): Long = (a - b) and MASK
        fun before(a: Long, b: Long): Boolean = (a - b).toInt() < 0
        fun u16(bytes: ByteArray, offset: Int): Int = (unsigned(bytes[offset]) shl 8) or unsigned(bytes[offset + 1])
        fun u32(bytes: ByteArray, offset: Int): Long = (u16(bytes, offset).toLong() shl 16) or u16(bytes, offset + 2).toLong()
        fun put16(bytes: ByteArray, offset: Int, value: Int) { bytes[offset] = (value ushr 8).toByte(); bytes[offset + 1] = value.toByte() }
        fun put32(bytes: ByteArray, offset: Int, value: Long) { put16(bytes, offset, (value ushr 16).toInt()); put16(bytes, offset + 2, value.toInt()) }
        fun checksum(source: ByteArray, destination: ByteArray, protocol: Int, body: ByteArray): Int {
            var sum = body.size.toLong() + protocol
            for (index in 0 until 16 step 2) sum += u16(source, index) + u16(destination, index)
            for (index in body.indices step 2) { sum += unsigned(body[index]) shl 8; if (index + 1 < body.size) sum += unsigned(body[index + 1]) }
            while (sum ushr 16 != 0L) sum = (sum and 65535) + (sum ushr 16)
            return sum.toInt().inv() and 65535
        }
        fun checkBounds(data: ByteArray, offset: Int, length: Int) { require(offset >= 0 && length >= 0 && offset <= data.size && length <= data.size - offset) }
    }
}
