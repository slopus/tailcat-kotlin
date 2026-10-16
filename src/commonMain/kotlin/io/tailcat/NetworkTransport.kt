package io.tailcat

import io.tailcat.platform.*

sealed class ConnectionPath {
    data object Relay : ConnectionPath()
    data class Direct(val endpoint: String) : ConnectionPath()
}

internal class NetworkTransport(
    private val identity: NodePrivateKey,
    private val nodes: List<DERPNode>,
    testOnlyPlaintextDERP: Boolean = false,
    private val incoming: (NodePublicKey, ByteArray, Boolean) -> Unit,
) {
    private class Peer(val disco: ByteArray) {
        val endpoints = mutableSetOf<Endpoint>()
        val inbound = mutableMapOf<Endpoint, Long>()
        var direct: Endpoint? = null
        var verified = 0L
        var lastProbe = -100_000L
        var lastCall = -100_000L
        var lastInvitation = -100_000L
        var probeCursor = 0
    }
    private data class Probe(val peer: NodePublicKey, val endpoint: Endpoint, val sent: Long)
    private data class Event(val key: NodePublicKey?, val endpoint: Endpoint?, val packet: ByteArray)
    private val lock = PlatformLock()
    private val peers = mutableMapOf<NodePublicKey, Peer>()
    private val probes = mutableMapOf<BytesKey, Probe>()
    private val stun = mutableMapOf<BytesKey, Pair<Endpoint, Long>>()
    private val observed = mutableMapOf<Endpoint, Long>()
    private val events = ArrayDeque<Event>()
    private var closed = false
    private var udp4: PlatformUdp? = null
    private var udp6: PlatformUdp? = null
    private var lastMaintenance = -100_000L
    private var lastStun = -100_000L
    private var addressSignature = emptyList<String>()
    private val stunServers = mutableListOf<Endpoint>()
    private val discoPrivate = identity.discoPrivateKey
    private val discoPublic = identity.discoPublicKey
    private val nodePublic = identity.publicKey.raw
    private var probeBudget = 32
    private var probeBudgetAt = monotonicMillis()
    private val relay = DerpTransport(nodes, identity, testOnlyPlaintextDERP) { offer(Event(it.source, null, it.payload)) }

    fun start(timeoutMillis: Long = 30_000) {
        lock.withLock { if (closed) throw TailcatClosedException() }
        val created4 = try { PlatformUdp() } catch (_: Exception) { null }
        val created6 = try { PlatformUdp(ipv6 = true) } catch (_: Exception) { null }
        lock.withLock {
            if (closed) { created4?.close(); created6?.close(); throw TailcatClosedException() }
            udp4 = created4; udp6 = created6
        }
        startThread("tailcat-network") { consume() }
        udp4?.let { socket -> startThread("tailcat-udp4") { readUdp(socket) } }
        udp6?.let { socket -> startThread("tailcat-udp6") { readUdp(socket) } }
        try { relay.start(timeoutMillis) } catch (error: Exception) { close(); throw error }
        lock.withLock { if (closed) throw TailcatClosedException() }
        startThread("tailcat-stun-resolve") {
            for (node in nodes.filter { it.stunPort >= 0 }.take(16)) {
                lock.withLock { if (closed) return@startThread }
                val host = node.ipv4.takeIf { it.isNotEmpty() && it != "none" } ?: node.hostName
                try {
                    val resolved = resolveHost(host).take(4).map { Endpoint(it, node.stunPort.takeIf { p -> p > 0 } ?: 3478) }
                    lock.withLock { if (closed) return@startThread; stunServers.addAll(resolved) }
                } catch (_: Exception) { }
                if (node.ipv6.isNotEmpty() && node.ipv6 != "none") lock.withLock { stunServers.add(Endpoint(node.ipv6, node.stunPort.takeIf { it > 0 } ?: 3478)) }
            }
        }
    }
    private fun readUdp(socket: PlatformUdp) {
        while (!lock.withLock { closed }) {
            try {
                val datagram = socket.receive() ?: continue
                if (datagram.data.size <= 2048) offer(Event(null, normalize(datagram.source), datagram.data))
            } catch (_: Exception) { if (lock.withLock { closed }) return }
        }
    }
    private fun normalize(endpoint: Endpoint): Endpoint = try { endpointFromWire(endpoint.wireBytes()) } catch (_: Exception) { endpoint }
    private fun offer(event: Event) { lock.withLock { if (!closed && events.size < 256) { events.addLast(event); lock.signalAll() } } }
    private fun consume() {
        while (true) {
            lock.withLock {
                if (closed) return
                if (events.isEmpty()) lock.await(50)
                if (closed) return
                repeat(minOf(64, events.size)) {
                    val event = events.removeFirst()
                    try { receive(event) } catch (_: Exception) { /* Malformed packets cannot terminate ingress. */ }
                }
                val now = monotonicMillis()
                relay.tick(now)
                if (now - lastMaintenance >= 1000) { lastMaintenance = now; maintain(now) }
            }
        }
    }
    fun configurePeer(key: NodePublicKey, disco: ByteArray) {
        require(disco.size == 32 && disco.any { it != 0.toByte() } && key.raw.any { it != 0.toByte() })
        lock.withLock {
            require(peers.none { it.key != key && it.value.disco.contentEquals(disco) }) { "Discovery key already belongs to another node" }
            val previous = peers[key]
            if (previous == null || !previous.disco.contentEquals(disco)) peers[key] = Peer(disco.copyOf())
            invite(key); probe(key)
        }
    }
    fun removePeer(key: NodePublicKey) { lock.withLock { peers.remove(key); probes.entries.removeAll { it.value.peer == key } } }
    fun path(key: NodePublicKey): ConnectionPath = lock.withLock {
        val peer = peers[key]
        if (peer?.direct != null && monotonicMillis() - peer.verified < 30_000) ConnectionPath.Direct(peer.direct.toString()) else ConnectionPath.Relay
    }
    fun send(key: NodePublicKey, packet: ByteArray) {
        lock.withLock {
            if (closed) throw TailcatClosedException()
            val peer = peers[key]
            val endpoint = peer?.direct
            if (!packet.startsWith("meow".encodeToByteArray()) && endpoint != null && monotonicMillis() - peer.verified < 30_000) {
                try { sendUdp(endpoint, packet); return } catch (_: Exception) { peer.direct = null }
            }
            relay.send(key, packet)
        }
    }
    fun invalidate(key: NodePublicKey) { lock.withLock { peers[key]?.direct = null } }
    fun networkChanged() { lock.withLock { resetPaths(); relay.reconnect() } }
    fun close() {
        lock.withLock { if (closed) return; closed = true; events.clear(); lock.signalAll() }
        udp4?.close(); udp6?.close(); relay.close()
    }
    private fun receive(event: Event) {
        val packet = event.packet; val endpoint = event.endpoint; val relaySource = event.key
        if (endpoint != null && packet.size >= 20 && packet[0] == 1.toByte() && packet[1] == 1.toByte() && packet.copyOfRange(4, 8).contentEquals(Stun.cookie)) {
            val transaction = BytesKey(packet.copyOfRange(8, 20))
            val pending = stun.remove(transaction) ?: return
            if (pending.first != endpoint || monotonicMillis() - pending.second > 10_000) return
            rememberObserved(Stun.response(packet, transaction.bytes))
            peers.keys.forEach { invite(it) }
            return
        }
        val discoSource = Discovery.sourceKey(packet)
        if (discoSource != null) {
            val entry = peers.entries.firstOrNull { it.value.disco.contentEquals(discoSource) } ?: return
            val key = entry.key; val peer = entry.value
            if (relaySource != null && relaySource != key) return
            val (_, message) = Discovery.open(packet, discoPrivate)
            val now = monotonicMillis()
            when (message) {
                is DiscoveryMessage.Ping -> {
                    if (message.nodeKey != null && !message.nodeKey.contentEquals(key.raw)) return
                    if (endpoint != null) {
                        bind(peer, endpoint, now)
                        if (peer.endpoints.size < 128) peer.endpoints.add(endpoint)
                        sendUdp(endpoint, Discovery.seal(DiscoveryMessage.Pong(message.transaction, endpoint), peer.disco, discoPrivate, discoPublic))
                        if (now - peer.lastProbe >= 1000) probe(key)
                    }
                }
                is DiscoveryMessage.Pong -> {
                    val pending = probes.remove(BytesKey(message.transaction)) ?: return
                    if (pending.peer != key || pending.endpoint != endpoint || now - pending.sent > 10_000 || endpoint == null) return
                    bind(peer, endpoint, now); peer.direct = endpoint; peer.verified = now
                    rememberObserved(message.observed)
                }
                is DiscoveryMessage.CallMeMaybe -> {
                    if (relaySource != key || endpoint != null) return
                    for (address in message.endpoints) if (address.port != 0 && peer.endpoints.size < 128) peer.endpoints.add(address)
                    if (now - peer.lastInvitation >= 1000) { peer.lastInvitation = now; probe(key) }
                }
            }
            return
        }
        if (packet.startsWith(Discovery.magic)) return
        if (relaySource != null) incoming(relaySource, packet, true)
        else if (endpoint != null) {
            val now = monotonicMillis()
            for ((key, peer) in peers) if (peer.inbound[endpoint]?.let { now - it < 120_000 } == true) incoming(key, packet, false)
        }
    }
    private fun bind(peer: Peer, endpoint: Endpoint, now: Long) {
        peer.inbound.entries.removeAll { now - it.value > 120_000 }
        if (!peer.inbound.containsKey(endpoint) && peer.inbound.size >= 128) peer.inbound.minByOrNull { it.value }?.key?.let { peer.inbound.remove(it) }
        peer.inbound[endpoint] = now
    }
    private fun rememberObserved(endpoint: Endpoint) {
        if (!observed.containsKey(endpoint) && observed.size >= 128) observed.minByOrNull { it.value }?.key?.let { observed.remove(it) }
        observed[endpoint] = monotonicMillis()
    }
    private fun sendUdp(endpoint: Endpoint, packet: ByteArray) {
        val socket = if (IpAddress.parse4(endpoint.host) != null) udp4 else udp6
        (socket ?: throw TailcatException("UDP family unavailable")).send(endpoint, packet)
    }
    private fun probe(key: NodePublicKey) {
        val peer = peers[key] ?: return
        val now = monotonicMillis(); peer.lastProbe = now
        if (now - probeBudgetAt >= 1000) { probeBudget = 32; probeBudgetAt = now }
        val endpoints = peer.endpoints.toList()
        val count = minOf(8, probeBudget, endpoints.size)
        repeat(count) {
            val endpoint = endpoints[peer.probeCursor % endpoints.size]; peer.probeCursor = (peer.probeCursor + 1) % endpoints.size; probeBudget--
            val transaction = secureRandom(12)
            probes[BytesKey(transaction)] = Probe(key, endpoint, now)
            try { sendUdp(endpoint, Discovery.seal(DiscoveryMessage.Ping(transaction, nodePublic), peer.disco, discoPrivate, discoPublic)) } catch (_: Exception) { }
        }
    }
    private fun invite(key: NodePublicKey) {
        val peer = peers[key] ?: return
        val now = monotonicMillis()
        if (now - peer.lastCall < 1000) return
        peer.lastCall = now
        try { relay.send(key, Discovery.seal(DiscoveryMessage.CallMeMaybe(localEndpoints().take(128)), peer.disco, discoPrivate, discoPublic)) } catch (_: Exception) { }
    }
    private fun localEndpoints(): List<Endpoint> {
        val addresses = localAddresses()
        val endpoints = addresses.mapNotNull { host ->
            val port = if (IpAddress.parse4(host) != null) udp4?.localPort else udp6?.localPort
            port?.let { Endpoint(host, it) }
        }.toMutableSet()
        endpoints.addAll(observed.keys)
        return endpoints.toList()
    }
    private fun resetPaths() {
        peers.values.forEach { it.direct = null; it.inbound.clear(); it.lastProbe = -100_000; it.lastCall = -100_000 }
        probes.clear(); stun.clear(); observed.clear(); lastStun = -100_000
    }
    private fun maintain(now: Long) {
        probes.entries.removeAll { now - it.value.sent > 10_000 }
        stun.entries.removeAll { now - it.value.second > 10_000 }
        observed.entries.removeAll { now - it.value > 120_000 }
        peers.values.forEach { it.inbound.entries.removeAll { entry -> now - entry.value > 120_000 } }
        val signature = localAddresses().sorted()
        if (addressSignature.isNotEmpty() && signature != addressSignature) resetPaths()
        addressSignature = signature
        if (now - lastStun >= 30_000) {
            lastStun = now
            for (endpoint in stunServers.take(64)) {
                val transaction = secureRandom(12); stun[BytesKey(transaction)] = endpoint to now
                try { sendUdp(endpoint, Stun.request(transaction)) } catch (_: Exception) { }
            }
        }
        for ((key, peer) in peers) {
            try { if (now - peer.lastProbe >= 10_000) probe(key); if (now - peer.lastCall >= 25_000) invite(key) } catch (_: Exception) { }
        }
    }
}
