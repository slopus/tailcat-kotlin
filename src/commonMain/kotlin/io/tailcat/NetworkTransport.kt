package io.tailcat

import io.tailcat.platform.*
import io.tailcat.wireguard.WireGuard

sealed class ConnectionPath {
    data object Relay : ConnectionPath()
    data class Direct(val endpoint: String) : ConnectionPath()
}

internal class NetworkTransport(
    private val identity: NodePrivateKey,
    private val nodes: List<DERPNode>,
    testOnlyPlaintextDERP: Boolean = false,
    private val relayFirst: Boolean = false,
    private val environment: NetworkEnvironment = NetworkEnvironment(),
    relayFactory: (((DerpPacket) -> Unit) -> NetworkRelay)? = null,
    private val trace: StartupTrace? = null,
    /** A peer's authenticated invitation moved every advertised port: a new socket, as when it restarted. */
    private val restarted: (NodePublicKey) -> Unit = {},
    /** The relay connection is up again after a failure: what went out the old one is owed again. */
    relayRecovered: () -> Unit = {},
    private val incoming: (NodePublicKey, ByteArray, Boolean) -> Unit,
) {
    private class Peer(val disco: ByteArray, var directEnabled: Boolean) {
        val endpoints = mutableSetOf<Endpoint>()
        val inbound = mutableMapOf<Endpoint, Long>()
        var direct: Endpoint? = null
        var verified = 0L
        var lastProbe = -100_000L
        var lastCall = -100_000L
        var advertisementPending = true
        var probeCursor = 0
        var probeInterval = 1000L
        var nextProbe = 0L
        var probePending = false
        val priorityEndpoints = mutableSetOf<Endpoint>()
        var advertisedEndpoints: Set<Endpoint>? = null
        var authenticated = false
        var resetMarker: Long? = null
        // A check (wake): unless a Pong arrives after checkSince, by checkBy the direct route is dropped.
        var checkSince = 0L
        var checkBy = 0L
    }
    private data class Probe(val peer: NodePublicKey, val endpoint: Endpoint, val sent: Long)
    private data class Event(val key: NodePublicKey?, val endpoint: Endpoint?, val packet: ByteArray, val generation: Long? = null)
    private val lock = PlatformLock()
    private val peers = mutableMapOf<NodePublicKey, Peer>()
    private val probes = mutableMapOf<BytesKey, Probe>()
    private val stun = mutableMapOf<BytesKey, Pair<Endpoint, Long>>()
    private val observed = mutableMapOf<Endpoint, Long>()
    private val events = ArrayDeque<Event>()
    private var dropped = 0
    private var closed = false
    private var started = false
    private var generation = 0L
    private var nextResetMarker = 1L
    private var udp4: NetworkUdp? = null
    private var udp6: NetworkUdp? = null
    private var bindNeeded = true
    private var discoveryRequested = true
    private var nextDiscovery = 0L
    private var bindBackoff = 1000L
    private var nextBind = 0L
    private var lastSocketFailure = -100_000L
    private var resolvedGeneration = -1L
    private var cachedAddresses = emptyList<String>()
    private var signatureKnown = false
    private var relayGeneration: Long? = null
    private var lastMaintenance = -100_000L
    private var lastStun = -100_000L
    private var addressSignature = emptyList<String>()
    private val stunServers = mutableListOf<Endpoint>()
    private val discoPrivate = identity.discoPrivateKey
    private val discoPublic = identity.discoPublicKey
    private val nodePublic = identity.publicKey.raw
    private var probeBudget = 32
    private var probeBudgetAt = environment.now()
    private val relay = (relayFactory ?: { callback -> DerpTransport(nodes, identity, testOnlyPlaintextDERP, trace, relayRecovered, callback) }) {
        offer(Event(it.source, null, it.payload))
    }

    fun start(timeoutMillis: Long = 30_000) {
        lock.withLock {
            if (closed) throw TailcatClosedException()
            check(!started) { "Network already started" }; started = true
        }
        try {
            // Preserve the default's eager UDP setup. Opt-in startup never waits for it.
            if (!relayFirst) bindSockets(lock.withLock { generation })
            startThread("tailcat-network") { consume() }
            relay.start(timeoutMillis)
            lock.withLock { if (closed) throw TailcatClosedException() }
            startThread("tailcat-discovery") { discover() }
        } catch (error: Exception) { close(); throw error }
    }
    private fun current(id: Long): Boolean = lock.withLock { !closed && generation == id }
    private fun bindSockets(id: Long) {
        trace?.mark("udpBindStart", id)
        val created4 = try { environment.udp(false) } catch (_: Exception) { null }
        if (!current(id)) { created4?.close(); return }
        val created6 = try { environment.udp(true) } catch (_: Exception) { null }
        val installed = lock.withLock {
            if (closed || generation != id) false else {
                udp4 = created4; udp6 = created6
                bindNeeded = created4 == null && created6 == null
                if (bindNeeded) {
                    nextBind = environment.now() + bindBackoff; bindBackoff = (bindBackoff * 2).coerceAtMost(30_000)
                } else {
                    nextBind = 0
                    if (environment.now() - lastSocketFailure >= 30_000) bindBackoff = 1000
                }
                true
            }
        }
        if (!installed) { created4?.close(); created6?.close(); return }
        created4?.let { trace?.mark("udp4Bound", it.localPort.toLong()) }
        created6?.let { trace?.mark("udp6Bound", it.localPort.toLong()) }
        trace?.mark("udpBindDone", id)
        created4?.let { startThread("tailcat-udp4") { readUdp(it, id) } }
        created6?.let { startThread("tailcat-udp6") { readUdp(it, id) } }
    }
    /** One coalescing worker: platform enumeration, binding and DNS never hold the transport lock. */
    private fun discover() {
        while (true) {
            val work = lock.withLock {
                while (!closed) {
                    val due = maxOf(if (discoveryRequested) 0 else nextDiscovery, if (bindNeeded) nextBind else 0)
                    if (environment.now() >= due) break
                    lock.await((due - environment.now()).coerceIn(1, 5000))
                }
                if (closed) return
                discoveryRequested = false
                generation to bindNeeded
            }
            val id = work.first
            if (work.second) bindSockets(id)
            if (!current(id)) continue
            val addresses = try { environment.addresses().sorted() } catch (_: Exception) { null }
            if (!current(id)) continue
            val changed = lock.withLock {
                if (closed || generation != id) false else if (addresses != null) {
                    val changed = signatureKnown && addressSignature != addresses
                    val advertise = cachedAddresses != addresses || work.second
                    signatureKnown = true; addressSignature = addresses; cachedAddresses = addresses
                    if (advertise) peers.values.forEach { it.advertisementPending = true }
                    changed
                } else false
            }
            // New addresses are advertised; what still answers is kept. Only a socket failure rebinds.
            if (changed) { try { recheck(2000) } catch (_: TailcatClosedException) { return }; continue }
            if (lock.withLock { resolvedGeneration != id }) {
                for (node in nodes.filter { it.stunPort >= 0 }.take(16)) {
                    if (!current(id)) break
                    val host = node.ipv4.takeIf { it.isNotEmpty() && it != "none" } ?: node.hostName
                    val port = node.stunPort.takeIf { it > 0 } ?: 3478
                    val resolved = try { environment.resolve(host).take(4).map { Endpoint(it, port) } } catch (_: Exception) { emptyList() }
                    lock.withLock {
                        if (!closed && generation == id) {
                            stunServers.addAll(resolved)
                            if (node.ipv6.isNotEmpty() && node.ipv6 != "none") stunServers.add(Endpoint(node.ipv6, port))
                            lastStun = -100_000
                        }
                    }
                }
            }
            lock.withLock {
                if (!closed && generation == id) {
                    resolvedGeneration = id
                    nextDiscovery = if (bindNeeded) nextBind else environment.now() + 5000
                }
            }
        }
    }
    private fun readUdp(socket: NetworkUdp, id: Long) {
        while (current(id)) {
            try {
                val datagram = socket.receive() ?: continue
                if (datagram.data.size <= 2048) offer(Event(null, normalize(datagram.source), datagram.data, id))
            } catch (_: Exception) { networkChanged(id, socketFailure = true); return }
        }
    }
    private fun normalize(endpoint: Endpoint): Endpoint = try { endpointFromWire(endpoint.wireBytes()) } catch (_: Exception) { endpoint }
    /**
     * Received packets wait here while the engine decrypts the ones before them. A burst is at most what
     * the peer may have in flight: a full 1 MiB receive window is 860 segments.
     */
    private fun offer(event: Event) {
        lock.withLock {
            if (closed) return
            if (events.size >= RECEIVE_CAPACITY) { dropped++; return }
            events.addLast(event); lock.signalAll()
        }
    }
    /** Received packets dropped because the reader fell [RECEIVE_CAPACITY] behind. */
    val receiveDrops: Int get() = lock.withLock { dropped }
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
                val now = environment.now()
                relay.tick(now)
                for ((key, peer) in peers) if (peer.checkBy != 0L && now >= peer.checkBy) {
                    if (peer.direct != null && peer.verified < peer.checkSince) { peer.direct = null; markReset(key, peer) }
                    peer.checkBy = 0
                }
                if (now - lastMaintenance >= 1000) { lastMaintenance = now; maintain(now) }
                // Service coalesced endpoint changes at their deadline, not the next one-second maintenance tick.
                if (probeBudget > 0 || now - probeBudgetAt >= 1000) {
                    for ((key, peer) in peers) if (peer.probePending && now >= peer.nextProbe && now - peer.lastProbe >= 1000) {
                        try { probe(key) } catch (_: Exception) { }
                    }
                }
            }
        }
    }
    fun configurePeer(key: NodePublicKey, disco: ByteArray) {
        require(disco.size == 32 && disco.any { it != 0.toByte() } && key.raw.any { it != 0.toByte() })
        lock.withLock {
            if (closed) throw TailcatClosedException()
            require(peers.none { it.key != key && it.value.disco.contentEquals(disco) }) { "Discovery key already belongs to another node" }
            val previous = peers[key]
            if (previous == null || !previous.disco.contentEquals(disco)) {
                probes.entries.removeAll { it.value.peer == key }
                peers[key] = Peer(disco.copyOf(), !relayFirst)
            }
            invite(key); probe(key)
        }
    }
    /** Relay-first peers may upgrade only after the encrypted session has been established. */
    fun authenticated(key: NodePublicKey) {
        lock.withLock {
            if (closed) return
            peers[key]?.let {
                it.authenticated = true
                if (!it.directEnabled) {
                    it.directEnabled = true; it.probePending = true; it.nextProbe = 0; it.lastCall = -100_000
                    trace?.markOnce("directAllowed")
                    // First authentication opens the gate once; repeated callbacks retain all rate limits.
                    invite(key); probe(key)
                }
            }
        }
    }
    /** A fresh authenticated empty WG transport packet is a discrete remote path-reset hint. */
    fun authenticatedRelayReset(key: NodePublicKey) {
        lock.withLock {
            if (closed) return
            val peer = peers[key] ?: return
            val selected = peer.direct
            peer.direct = null
            probes.entries.removeAll { it.value.peer == key }
            // Never mark an outgoing reset here: peer-induced fallback must not echo markers back.
            // A probe just before the marker (a wake's) was cancelled with the route.
            reprobe(key, peer, selected)
        }
    }
    /** A route just dropped: probe it now, without the spacing, and once more after it in case that one is lost too. */
    private fun reprobe(key: NodePublicKey, peer: Peer, route: Endpoint?) {
        peer.lastProbe = -100_000
        requestProbe(key, listOfNotNull(route))
        peer.probePending = true; peer.nextProbe = environment.now() + 1000
    }
    /** Under the lock. The probes that would renew it are what it waits on, so one goes again now. */
    private fun expire(key: NodePublicKey, peer: Peer) {
        val route = peer.direct ?: return
        peer.direct = null; markReset(key, peer)
        reprobe(key, peer, route)
    }
    private fun markReset(key: NodePublicKey, peer: Peer) {
        if (!peer.authenticated) return
        peer.resetMarker = nextResetMarker++
        relay.discardResetMarker(key)
        relay.setResetBarrier(key, true)
    }
    fun pendingResetMarker(key: NodePublicKey): Long? = lock.withLock {
        if (closed) return@withLock null
        val peer = peers[key] ?: return@withLock null
        if (peer.direct != null && environment.now() - peer.verified >= 30_000) expire(key, peer)
        peer.resetMarker
    }
    /** The engine prepares crypto outside this lock. Generation tokens reject stale/closed completions. */
    fun completeResetMarker(key: NodePublicKey, token: Long, packet: ByteArray?): Boolean = lock.withLock {
        if (closed) return@withLock false
        val peer = peers[key] ?: return@withLock false
        if (peer.resetMarker != token) return@withLock false
        if (packet != null) relay.queueResetMarker(key, packet) else relay.discardResetMarker(key)
        peer.resetMarker = null
        relay.setResetBarrier(key, false)
        true
    }
    fun removePeer(key: NodePublicKey) {
        lock.withLock { peers.remove(key); probes.entries.removeAll { it.value.peer == key }; relay.discardResetMarker(key) }
    }
    fun path(key: NodePublicKey): ConnectionPath = lock.withLock {
        val peer = peers[key]
        if (peer?.direct != null && peer.directEnabled && environment.now() - peer.verified < 30_000) ConnectionPath.Direct(peer.direct.toString()) else ConnectionPath.Relay
    }
    fun send(key: NodePublicKey, packet: ByteArray) {
        if (!trySend(key, packet)) throw TailcatException("Path reset marker must precede transport data")
    }
    fun trySend(key: NodePublicKey, packet: ByteArray): Boolean {
        lock.withLock {
            if (closed) throw TailcatClosedException()
            val peer = peers[key]
            val transport = WireGuard.packetType(packet) == 4
            if (peer != null && peer.direct != null && environment.now() - peer.verified >= 30_000) expire(key, peer)
            if (transport && peer?.resetMarker != null) return false
            val endpoint = peer?.direct
            if (!packet.startsWith("meow".encodeToByteArray()) && endpoint != null && peer.directEnabled &&
                !(transport && relay.hasResetMarker(key))) {
                try { sendUdp(endpoint, packet); return true } catch (_: Exception) {
                    peer.direct = null; peer.nextProbe = 0; peer.probeInterval = 1000
                    probes.entries.removeAll { it.value.peer == key }; markReset(key, peer)
                    if (transport && peer.resetMarker != null) return false
                }
            }
            relay.send(key, packet)
            return true
        }
    }
    fun invalidate(key: NodePublicKey) {
        lock.withLock { peers[key]?.let { if (it.direct != null) { it.direct = null; markReset(key, it) } }; probes.entries.removeAll { it.value.peer == key } }
    }
    /**
     * After a suspension or a network change: every way to every peer is
     * checked and only what doesn't answer within [deadlineMillis] is
     * replaced. The relay is pinged and reconnected only if silent; the
     * direct route is probed first and kept if it answers, every other
     * candidate is probed, addresses are advertised again and STUN asked
     * again. A reset marker goes over the relay at once: a peer that
     * restarted meanwhile answers it, not only after the direct check.
     * Sockets and sessions stay.
     */
    fun recheck(deadlineMillis: Long = 2000) {
        lock.withLock {
            if (closed) throw TailcatClosedException()
            val now = environment.now()
            for ((key, peer) in peers) {
                peer.direct?.let { peer.checkSince = now; peer.checkBy = now + deadlineMillis }
                peer.lastCall = -100_000; invite(key)
                requestProbe(key, listOfNotNull(peer.direct))
                markReset(key, peer)
            }
            lastStun = -100_000; discoveryRequested = true; lock.signalAll()
        }
        relay.check(deadlineMillis)
    }
    /** Coalesce requests into the existing maintenance/discovery workers, retaining the live route. */
    fun retryDirect(key: NodePublicKey? = null) {
        lock.withLock {
            if (closed) throw TailcatClosedException()
            for ((peerKey, peer) in peers) if (key == null || peerKey == key) {
                peer.probePending = true; peer.nextProbe = 0; peer.probeInterval = 1000; peer.lastCall = -100_000
            }
            discoveryRequested = true; lock.signalAll()
        }
    }
    /** Forced reset: old candidates go, UDP rebinds and DERP reconnects. Only for sockets known unusable; a network change is [recheck]. */
    fun networkChanged() {
        lock.withLock { if (closed) throw TailcatClosedException() }
        networkChanged(null)
    }
    private fun networkChanged(expectedGeneration: Long?, socketFailure: Boolean = false) {
        val old = lock.withLock {
            if (closed || expectedGeneration != null && generation != expectedGeneration) return
            generation++; resetPaths()
            peers.forEach { (key, peer) -> markReset(key, peer) }
            val sockets = udp4 to udp6; udp4 = null; udp6 = null
            bindNeeded = true; discoveryRequested = true; cachedAddresses = emptyList(); stunServers.clear()
            if (socketFailure) {
                lastSocketFailure = environment.now(); nextBind = lastSocketFailure + bindBackoff
                bindBackoff = (bindBackoff * 2).coerceAtMost(30_000)
            } else { nextBind = 0; bindBackoff = 1000 }
            lock.signalAll()
            // Invalidate even an in-flight reconnect: the newest network notification wins.
            // DerpTransport coalesces these requests in its existing reader, not new workers.
            if (!socketFailure) relay.reconnect()
            sockets
        }
        old.first?.close(); old.second?.close()
    }
    fun close() {
        val old = lock.withLock {
            if (closed) return
            closed = true; generation++; events.clear(); peers.clear(); probes.clear(); stun.clear(); observed.clear(); lock.signalAll()
            (udp4 to udp6).also { udp4 = null; udp6 = null }
        }
        old.first?.close(); old.second?.close(); relay.close()
    }
    private fun receive(event: Event) {
        if (event.generation != null && event.generation != generation) return
        val packet = event.packet; val endpoint = event.endpoint; val relaySource = event.key
        if (endpoint != null && packet.size >= 20 && packet[0] == 1.toByte() && packet[1] == 1.toByte() && packet.copyOfRange(4, 8).contentEquals(Stun.cookie)) {
            val transaction = BytesKey(packet.copyOfRange(8, 20))
            val pending = stun[transaction] ?: return
            if (pending.first != endpoint || environment.now() - pending.second > 10_000) return
            stun.remove(transaction)
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
            val now = environment.now()
            when (message) {
                is DiscoveryMessage.Ping -> {
                    if (!peer.directEnabled) return
                    if (message.nodeKey != null && !message.nodeKey.contentEquals(key.raw)) return
                    if (endpoint != null) {
                        bind(peer, endpoint, now)
                        val fresh = rememberEndpoint(peer, endpoint)
                        sendUdp(endpoint, Discovery.seal(DiscoveryMessage.Pong(message.transaction, endpoint), peer.disco, discoPrivate, discoPublic))
                        if (fresh || peer.direct == null) requestProbe(key, listOf(endpoint))
                        else if (now - peer.lastProbe >= 1000) probe(key)
                    }
                }
                is DiscoveryMessage.Pong -> {
                    val transaction = BytesKey(message.transaction)
                    val pending = probes[transaction] ?: return
                    if (endpoint == null || pending.peer != key || pending.endpoint != endpoint || now - pending.sent > 10_000) return
                    probes.remove(transaction)
                    bind(peer, endpoint, now); peer.direct = endpoint; peer.verified = now
                    trace?.markOnce("directValidated")
                    peer.probeInterval = 1000
                    // A late Pong from an old round must not postpone a fresh-candidate request.
                    peer.nextProbe = if (peer.probePending) minOf(peer.nextProbe, peer.lastProbe + 1000) else now + 10_000
                    rememberObserved(message.observed)
                }
                is DiscoveryMessage.CallMeMaybe -> {
                    if (relaySource != key || endpoint != null) return
                    trace?.mark("callMeMaybeReceived", message.endpoints.size.toLong())
                    val advertised = message.endpoints.filter { it.port != 0 }
                    val advertisedSet = advertised.toSet()
                    val previous = peer.advertisedEndpoints
                    val direct = peer.direct
                    if (advertisedSet.isNotEmpty()) {
                        val withdrawn = previous.orEmpty() - advertisedSet
                        // Retire these transactions even if a relay fallback already cleared direct, or
                        // a new port's Pong won the race before this advertisement was processed.
                        probes.entries.removeAll { it.value.peer == key && it.value.endpoint in withdrawn }
                        peer.endpoints.removeAll(withdrawn); peer.priorityEndpoints.removeAll(withdrawn)
                        if (direct != null && previous?.contains(direct) == true && direct !in advertisedSet) {
                            // The authenticated peer explicitly withdrew the selected port. Use DERP while
                            // validating replacements; an old in-flight Pong cannot restore that old route.
                            peer.direct = null
                            peer.endpoints.clear(); peer.priorityEndpoints.clear()
                            probes.entries.removeAll { it.value.peer == key }
                        }
                        // Every port moved: a new socket, as when the peer restarted, so none of the sessions it had.
                        if (!previous.isNullOrEmpty() && previous.none { old -> advertised.any { it.port == old.port } }) restarted(key)
                        peer.advertisedEndpoints = advertisedSet
                    }
                    val fresh = advertised.filter { rememberEndpoint(peer, it) }
                    // Coalesce requests inside the limiter instead of dropping the new generation's endpoints.
                    requestProbe(key, fresh.ifEmpty { advertised })
                }
            }
            return
        }
        if (packet.startsWith(Discovery.magic)) return
        if (relaySource != null) incoming(relaySource, packet, true)
        else if (endpoint != null) {
            val now = environment.now()
            for ((key, peer) in peers) if (peer.inbound[endpoint]?.let { now - it < 120_000 } == true) incoming(key, packet, false)
        }
    }
    private fun bind(peer: Peer, endpoint: Endpoint, now: Long) {
        peer.inbound.entries.removeAll { now - it.value > 120_000 }
        if (!peer.inbound.containsKey(endpoint) && peer.inbound.size >= 128) peer.inbound.minByOrNull { it.value }?.key?.let { peer.inbound.remove(it) }
        peer.inbound[endpoint] = now
    }
    private fun rememberObserved(endpoint: Endpoint) {
        if (!observed.containsKey(endpoint)) peers.values.forEach { it.advertisementPending = true }
        if (!observed.containsKey(endpoint) && observed.size >= 128) observed.minByOrNull { it.value }?.key?.let { observed.remove(it) }
        observed[endpoint] = environment.now()
    }
    private fun sendUdp(endpoint: Endpoint, packet: ByteArray) {
        val socket = if (IpAddress.parse4(endpoint.host) != null) udp4 else udp6
        (socket ?: throw TailcatException("UDP family unavailable")).send(endpoint, packet)
    }
    private fun rememberEndpoint(peer: Peer, endpoint: Endpoint): Boolean {
        if (endpoint in peer.endpoints) return false
        if (peer.endpoints.size >= 128) {
            // Remote rebinding must not be blocked forever by a full cache of old ports.
            val old = peer.endpoints.first { it != peer.direct }
            peer.endpoints.remove(old); peer.priorityEndpoints.remove(old)
        }
        peer.endpoints.add(endpoint)
        return true
    }
    private fun requestProbe(key: NodePublicKey, priority: List<Endpoint>) {
        val peer = peers[key] ?: return
        val preferred = priority.filter { it in peer.endpoints }
        val previous = peer.priorityEndpoints.filter { it !in preferred }
        peer.priorityEndpoints.clear()
        peer.priorityEndpoints.addAll(preferred); peer.priorityEndpoints.addAll(previous)
        peer.probePending = true
        peer.probeInterval = 1000
        peer.nextProbe = minOf(peer.nextProbe, peer.lastProbe + 1000)
        probe(key)
    }
    private fun probe(key: NodePublicKey) {
        val peer = peers[key] ?: return
        if (!peer.directEnabled) return
        val now = environment.now()
        if (now - peer.lastProbe < 1000) return
        if (now - probeBudgetAt >= 1000) { probeBudget = 32; probeBudgetAt = now }
        val endpoints = peer.endpoints.toList()
        if (endpoints.isEmpty()) {
            // No challenge was sent. A first candidate arriving shortly afterwards gets the first
            // real probe immediately, rather than inheriting a one-second empty-round penalty.
            peer.probePending = false
            peer.nextProbe = now + 1000
            return
        }
        if (endpoints.isNotEmpty() && probeBudget == 0) {
            peer.probePending = true
            peer.nextProbe = minOf(peer.nextProbe, now + 1000)
            return
        }
        peer.lastProbe = now
        val rotated = endpoints.indices.map { endpoints[(peer.probeCursor + it) % endpoints.size] }
        val candidates = peer.priorityEndpoints.toList() + rotated.filter { it !in peer.priorityEndpoints }
        val count = minOf(8, probeBudget, candidates.size)
        trace?.mark("discoProbeStarted", count.toLong())
        repeat(count) {
            val endpoint = candidates[it]
            peer.priorityEndpoints.remove(endpoint)
            peer.probeCursor = (endpoints.indexOf(endpoint) + 1) % endpoints.size
            probeBudget--
            val transaction = secureRandom(12)
            probes[BytesKey(transaction)] = Probe(key, endpoint, now)
            try { sendUdp(endpoint, Discovery.seal(DiscoveryMessage.Ping(transaction, nodePublic), peer.disco, discoPrivate, discoPublic)) } catch (_: Exception) { }
        }
        peer.probePending = peer.priorityEndpoints.isNotEmpty()
        peer.nextProbe = now + if (peer.probePending) 1000 else if (peer.direct != null && now - peer.verified < 30_000) 10_000 else peer.probeInterval
        peer.probeInterval = (peer.probeInterval * 2).coerceAtMost(30_000)
    }
    private fun invite(key: NodePublicKey) {
        val peer = peers[key] ?: return
        if (!peer.directEnabled) return
        val now = environment.now()
        if (now - peer.lastCall < 1000) return
        peer.lastCall = now
        try {
            relay.send(key, Discovery.seal(DiscoveryMessage.CallMeMaybe(localEndpoints().take(128)), peer.disco, discoPrivate, discoPublic))
            peer.advertisementPending = false
        } catch (_: Exception) { peer.advertisementPending = true }
    }
    private fun localEndpoints(): List<Endpoint> {
        val endpoints = cachedAddresses.mapNotNull { host ->
            val port = if (IpAddress.parse4(host) != null) udp4?.localPort else udp6?.localPort
            port?.let { Endpoint(host, it) }
        }.toMutableSet()
        endpoints.addAll(observed.keys)
        return endpoints.toList()
    }
    private fun resetPaths() {
        peers.values.forEach {
            it.direct = null; it.endpoints.clear(); it.inbound.clear(); it.lastProbe = -100_000; it.lastCall = -100_000
            it.nextProbe = 0; it.probeInterval = 1000; it.probeCursor = 0
            it.advertisementPending = true
            it.probePending = false; it.priorityEndpoints.clear()
            it.advertisedEndpoints = null
        }
        probes.clear(); stun.clear(); observed.clear(); lastStun = -100_000
    }
    private fun maintain(now: Long) {
        probes.entries.removeAll { now - it.value.sent > 10_000 }
        stun.entries.removeAll { now - it.value.second > 10_000 }
        observed.entries.removeAll { now - it.value > 120_000 }
        peers.values.forEach { it.inbound.entries.removeAll { entry -> now - entry.value > 120_000 } }
        val connected = relay.connectionGeneration
        if (connected != null && connected != relayGeneration) {
            // Refresh advertisements on recovery without discarding a healthy direct route.
            peers.values.forEach { it.lastCall = -100_000; it.probePending = true; it.nextProbe = 0 }
        }
        relayGeneration = connected
        if (now - lastStun >= 30_000) {
            lastStun = now
            for (endpoint in stunServers.take(64)) {
                val transaction = secureRandom(12); stun[BytesKey(transaction)] = endpoint to now
                try { sendUdp(endpoint, Stun.request(transaction)) } catch (_: Exception) { }
            }
        }
        for ((key, peer) in peers) {
            try { if (now >= peer.nextProbe) probe(key); if (peer.advertisementPending || now - peer.lastCall >= 25_000) invite(key) } catch (_: Exception) { }
        }
    }
}

internal const val RECEIVE_CAPACITY = 1024
