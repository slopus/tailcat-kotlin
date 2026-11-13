package io.tailcat

import io.tailcat.platform.*
import io.tailcat.stack.IPStack
import io.tailcat.wireguard.WireGuard

typealias TailcatTCPHandler = (TailcatConnection) -> Unit
typealias TailcatUDPHandler = (TailcatUDPConnection) -> Unit

data class ServerConfiguration(
    val privateKey: NodePrivateKey? = null,
    val presharedKey: PresharedKey? = null,
    val disablePresharedKey: Boolean = false,
    val region: DERPRegion? = null,
    val regionID: Int = 0,
    val mapProvider: DERPMapProvider = DERPMapProvider(),
    val allowClient: ((NodePublicKey) -> Boolean)? = null,
    val onTCP: ((Int) -> TailcatTCPHandler?)? = null,
    val onUDP: ((Int) -> TailcatUDPHandler?)? = null,
    val onTCPForward: ((TailcatEndpoint) -> TailcatTCPHandler?)? = null,
    val onUDPForward: ((TailcatEndpoint) -> TailcatUDPHandler?)? = null,
    val allowProxy: ((TailcatEndpoint) -> Boolean)? = null,
    val servedTCPPorts: Set<Int>? = null,
    val servedUDPPorts: Set<Int>? = null,
    val udpIdleTimeoutMillis: Long = 120_000,
    /** Explicit local integration fixture option. Never inferred from address x. */
    val testOnlyPlaintextDERP: Boolean = false,
    /** Establish encrypted sessions through DERP before upgrading to validated direct paths. */
    val relayFirst: Boolean = false,
)
data class ClientConfiguration(
    val privateKey: NodePrivateKey? = null,
    val mapProvider: DERPMapProvider = DERPMapProvider(),
    val connectTimeoutMillis: Long = 30_000,
    val testOnlyPlaintextDERP: Boolean = false,
    /** Do not wait for UDP setup, interface enumeration or STUN before connecting through DERP. */
    val relayFirst: Boolean = false,
)

/** Embedded server. Blocking methods may be used from an application executor. */
class TailcatServer(private val configuration: ServerConfiguration = ServerConfiguration()) {
    private val lock = PlatformLock()
    private var engine: TailcatEngine? = null
    private var closed = false
    private var starting = false
    val address: TailcatAddress get() = current().address
    val publicKey: NodePublicKey get() = current().publicKey
    fun start(): TailcatAddress {
        lock.withLock { if (closed) throw TailcatClosedException(); check(!starting && engine == null); starting = true }
        try {
            require(configuration.udpIdleTimeoutMillis > 0)
            val identity = configuration.privateKey ?: NodePrivateKey.generate()
            val psk = if (configuration.disablePresharedKey) null else configuration.presharedKey?.takeUnless { it.isZero } ?: PresharedKey.generate()
            val cancelled = { lock.withLock { closed } }
            val region = configuration.region ?: configuration.mapProvider.regions(cancelled, forServer = true).let { regions ->
                if (configuration.regionID > 0) regions.firstOrNull { it.regionID == configuration.regionID } ?: error("Unknown DERP region")
                else configuration.mapProvider.select(regions,cancelled)
            }
            val address = TailcatAddress(identity.publicKey, identity.discoPublicKey, psk, listOf(region))
            val prepared = TailcatEngine(identity, address, true, configuration)
            lock.withLock { if (closed) { prepared.close(); throw TailcatClosedException() }; engine = prepared }
            prepared.start()
            lock.withLock { if (closed) throw TailcatClosedException() }
            return address
        } catch (failure: Exception) { lock.withLock { engine }?.close(); throw failure }
        finally { lock.withLock { starting = false; lock.signalAll() } }
    }
    private fun current(): TailcatEngine = lock.withLock { if (closed) throw TailcatClosedException(); engine ?: error("Server has not started") }
    fun listenTCP(port: Int = 0): TailcatListener = current().listenTCP(port)
    fun listen(port: Int = 0): TailcatListener = listenTCP(port)
    fun listenUDP(port: Int = 0): TailcatUDPListener = current().listenUDP(port)
    fun peerKey(connection: TailcatConnection): NodePublicKey? = connection.peer ?: current().peerKey(connection.remoteAddress)
    fun peerKey(connection: TailcatUDPConnection): NodePublicKey? = connection.peer ?: current().peerKey(connection.remoteAddress)
    fun disconnectClient(key: NodePublicKey) = current().disconnect(key)
    internal fun inviteForTesting(key: NodePublicKey, disco: ByteArray) = current().inviteForTesting(key, disco)
    fun path(key: NodePublicKey): ConnectionPath = current().path(key)
    /** Request background probing without interrupting established sessions or validated paths. */
    fun retryDirect(key: NodePublicKey? = null) = current().retryDirect(key)
    /** Notify an interface/route change: the relay and every path are checked, and only what doesn't answer is replaced. */
    fun notifyNetworkChanged() = current().recheck()
    /** Forced reset: discard old candidates, rebind UDP and reconnect DERP. Only when the sockets are known unusable. */
    fun resetNetworkPaths() = current().resetNetworkPaths()
    fun close() { val old = lock.withLock { closed = true; engine }; old?.close() }
}

class TailcatClient private constructor(private val engine: TailcatEngine) {
    val publicKey: NodePublicKey get() = engine.publicKey
    val serverAddress: TailcatAddress get() = engine.address
    val path: ConnectionPath get() = engine.path(serverAddress.serverPublicKey)
    fun dialTCP(port: Int, timeoutMillis: Long = 30_000): TailcatConnection = engine.dialTCP(TailcatEndpoint.fromRaw(serverAddress.serverPublicKey.address, port), timeoutMillis)
    fun dialTCP(endpoint: TailcatEndpoint, timeoutMillis: Long = 30_000): TailcatConnection = engine.dialTCP(endpoint, timeoutMillis)
    fun dialUDP(port: Int): TailcatUDPConnection = engine.dialUDP(TailcatEndpoint.fromRaw(serverAddress.serverPublicKey.address, port))
    fun dialUDP(endpoint: TailcatEndpoint): TailcatUDPConnection = engine.dialUDP(endpoint)
    fun openTCP(port: Int): TailcatConnection = dialTCP(port)
    fun openUDP(port: Int): TailcatUDPConnection = dialUDP(port)
    /** Request background probing without interrupting the current session or validated path. */
    fun retryDirect() = engine.retryDirect(serverAddress.serverPublicKey)
    /**
     * Notify an interface/route change. A change doesn't mean the old
     * connections broke: the relay and every path are checked, and only
     * what doesn't answer is replaced, as in [wake].
     */
    fun notifyNetworkChanged() = engine.recheck()
    /** Forced reset: discard old candidates, rebind UDP and reconnect DERP. Only when the sockets are known unusable. */
    fun resetNetworkPaths() = engine.resetNetworkPaths()
    /**
     * Back from a suspension: ping the relay and probe every direct path,
     * replacing only what doesn't answer within two seconds. The session
     * and a route that still works are kept.
     */
    fun wake() = engine.recheck()
    fun close() = engine.close()
    companion object {
        fun connect(text: String, configuration: ClientConfiguration = ClientConfiguration()): TailcatClient = connect(TailcatAddress.parse(text), configuration)
        fun connect(address: TailcatAddress, configuration: ClientConfiguration = ClientConfiguration()): TailcatClient {
            return connectTraced(address, configuration, null)
        }
        internal fun connectTraced(address: TailcatAddress, configuration: ClientConfiguration, trace: StartupTrace?): TailcatClient {
            trace?.mark("connectStart")
            require(configuration.connectTimeoutMillis > 0)
            val deadline = monotonicMillis() + configuration.connectTimeoutMillis
            val disco = address.serverDiscoPublicKey
            require(disco != null && disco.any { it != 0.toByte() }) { "Missing server discovery key" }
            val regions = try {
                trace?.mark("mapExpandStart")
                configuration.mapProvider.expand(address) { monotonicMillis() >= deadline }
            } catch (failure: Exception) {
                if (monotonicMillis() >= deadline) throw TailcatTimeoutException()
                throw failure
            }
            require(regions.isNotEmpty()) { "No relay region" }
            trace?.mark("mapExpandDone")
            val expanded = TailcatAddress(address.serverPublicKey, disco, address.presharedKey, regions, address.regionID)
            val prepared = TailcatEngine(configuration.privateKey ?: NodePrivateKey.generate(), expanded, false,
                ServerConfiguration(testOnlyPlaintextDERP = configuration.testOnlyPlaintextDERP, relayFirst = configuration.relayFirst), trace)
            trace?.mark("engineCreated")
            try {
                prepared.start((deadline-monotonicMillis()).coerceAtLeast(1))
                prepared.awaitConnected((deadline-monotonicMillis()).coerceAtLeast(1))
                trace?.mark("connectReturn")
                return TailcatClient(prepared)
            } catch (failure: Exception) { prepared.close(); if (monotonicMillis() >= deadline) throw TailcatTimeoutException(); throw failure }
        }
    }
}

internal class TailcatEngine(private val identity: NodePrivateKey, val address: TailcatAddress,
    private val server: Boolean, private val configuration: ServerConfiguration, private val trace: StartupTrace? = null) {
    val publicKey = identity.publicKey
    private class Peer(val wg: WireGuard, val disco: ByteArray, val created: Long) {
        var acknowledged = false; var authenticated = false; var admitted = false; var admissionPending = false
        var token = 0L; var lastReceived = created; var lastSend = created; var lastMeow = -100_000L; var lastHandshake = -100_000L
        val pending = ArrayDeque<ByteArray>(); var pendingBytes = 0
        val resetCounters = linkedMapOf<Long, ULong>()
        /** Meowing and handshaking again on a session the server may have lost, until a new one is made. */
        var rejoining = false
        /** When data first went out with nothing authenticated back since, counted from a wake. */
        var sentSinceReceived: Long? = null
        /** Data came in with nothing sent since: WireGuard's passive keepalive answers it. */
        var receivedSinceSent: Long? = null
    }
    private sealed class Event {
        class Incoming(val key: NodePublicKey, val packet: ByteArray, val relay: Boolean) : Event()
        class Outgoing(val packet: ByteArray) : Event()
        class Admitted(val key: NodePublicKey, val token: Long, val allowed: Boolean) : Event()
        class Restarted(val key: NodePublicKey) : Event()
    }
    private data class ServiceKey(val destination: BytesKey, val port: Int, val udp: Boolean)
    private data class FlowKey(val destination: BytesKey, val source: BytesKey, val localPort: Int, val remotePort: Int)
    private data class Selected(val handler: TailcatTCPHandler, val time: Long)
    private val lock = PlatformLock()
    private val queueLock = PlatformLock()
    private val bindingsLock = PlatformLock()
    private val bindings = mutableMapOf<BytesKey, NodePublicKey>()
    private val peers = mutableMapOf<NodePublicKey, Peer>()
    private val events = ArrayDeque<Event>()
    private val targets = mutableMapOf<BytesKey, IPStack>()
    private val targetActivity = mutableMapOf<BytesKey, Long>()
    private val tcpServices = mutableMapOf<ServiceKey, TailcatListener>()
    private val udpServices = mutableMapOf<ServiceKey, TailcatUDPListener>()
    private val selected = mutableMapOf<FlowKey, Selected>()
    /** When each client the server holds no session for was last told to meow again. */
    private val askedToMeow = mutableMapOf<NodePublicKey, Long>()
    private var closed = false
    private var queueClosed = false
    private var nextToken = 1L
    private var admissionJobs = 0
    private var handlerJobs = 0
    private val network = NetworkTransport(identity, address.regions.first().nodes, configuration.testOnlyPlaintextDERP,
        relayFirst = configuration.relayFirst, trace = trace, restarted = { key -> try { offer(Event.Restarted(key)) } catch (_: Exception) { } }) {
        key, packet, relay -> offer(Event.Incoming(key, packet, relay))
    }
    private val stack = newStack(publicKey.address)
    private fun newStack(address: ByteArray): IPStack = IPStack(address, { offer(Event.Outgoing(it)) },
        if (server) null else this.address.serverPublicKey, { raw -> peerKey(raw) })
    private fun newPeer(key: NodePublicKey, disco: ByteArray): Peer = Peer(WireGuard(identity.raw, key.raw, address.presharedKey?.raw ?: ByteArray(32)), disco.copyOf(), monotonicMillis())
    private fun offer(event: Event) { queueLock.withLock { if (queueClosed) throw TailcatClosedException(); if (events.size >= 512) throw TailcatException("Tunnel queue full"); events.addLast(event); queueLock.signalAll() } }
    fun start(timeoutMillis: Long = 30_000) {
        lock.withLock {
            if (closed) throw TailcatClosedException()
            if (!server) {
                val key = address.serverPublicKey; val peer = newPeer(key, address.serverDiscoPublicKey!!); peer.admitted = true
                peers[key] = peer; bindingsLock.withLock { bindings[BytesKey(key.address)] = key }; network.configurePeer(key, peer.disco)
            }
        }
        startThread("tailcat-engine") { run() }
        network.start(timeoutMillis)
    }
    private fun run() {
        while (true) {
            val batch = queueLock.withLock {
                if (queueClosed) return
                if (events.isEmpty()) queueLock.await(25)
                if (queueClosed) return
                List(minOf(64, events.size)) { events.removeFirst() }
            }
            lock.withLock {
                if (closed) return
                for (event in batch) try {
                    when (event) { is Event.Incoming -> receive(event); is Event.Outgoing -> sendIP(event.packet); is Event.Admitted -> completeAdmission(event)
                        // A server back on new ports holds neither our session nor our admission: nothing sent
                        // on the old session can be answered, so rejoin now rather than wait for its silence.
                        is Event.Restarted -> if (event.key == address.serverPublicKey) rejoin() }
                } catch (_: Exception) { }
                tick(monotonicMillis())
            }
        }
    }
    fun awaitConnected(timeoutMillis: Long) = lock.withLock {
        trace?.mark("awaitConnectedStart")
        val end = monotonicMillis() + timeoutMillis
        while (!closed && peers[address.serverPublicKey]?.wg?.isEstablished != true) {
            val remaining = end - monotonicMillis(); if (remaining <= 0) throw TailcatTimeoutException(); lock.await(remaining)
        }
        if (closed) throw TailcatClosedException()
    }
    fun listenTCP(port: Int): TailcatListener = lock.withLock {
        if (closed) throw TailcatClosedException()
        tcpServices.remove(ServiceKey(BytesKey(publicKey.address), port, false))?.close()
        stack.listen(port)
    }
    fun listenUDP(port: Int): TailcatUDPListener = lock.withLock {
        if (closed) throw TailcatClosedException()
        udpServices.remove(ServiceKey(BytesKey(publicKey.address), port, true))?.close()
        stack.listenUDP(port, configuration.udpIdleTimeoutMillis)
    }
    fun dialTCP(endpoint: TailcatEndpoint, timeout: Long): TailcatConnection = stack.connect(endpoint.raw, endpoint.port, timeout)
    fun dialUDP(endpoint: TailcatEndpoint): TailcatUDPConnection = stack.connectUDP(endpoint.raw, endpoint.port)
    fun peerKey(raw: ByteArray): NodePublicKey? = bindingsLock.withLock { bindings[BytesKey(raw)] }
    fun path(key: NodePublicKey): ConnectionPath = network.path(key)
    fun resetNetworkPaths() = network.networkChanged()
    fun retryDirect(key: NodePublicKey?) = network.retryDirect(key)
    fun recheck() {
        network.recheck()
        // An initiation sent before the check may have gone into a dead connection: the next tick sends another.
        // The reset marker the check asked for goes now. An answer due while suspended had no chance to come.
        lock.withLock {
            peers.forEach { (key, peer) ->
                if (!peer.wg.isEstablished) peer.lastHandshake = -100_000
                peer.sentSinceReceived = null
                prepareResetMarker(key, peer)
            }
        }
    }
    fun disconnect(key: NodePublicKey) = lock.withLock { removePeer(key) }
    /** Advertise our endpoints to [key] before it has been admitted, as the Go server does to the clients it knows. */
    internal fun inviteForTesting(key: NodePublicKey, disco: ByteArray) { network.configurePeer(key, disco); network.authenticated(key) }
    private fun removePeer(key: NodePublicKey) {
        peers.remove(key)?.token = nextToken++
        network.removePeer(key); bindingsLock.withLock { bindings.remove(BytesKey(key.address)) }
        stack.disconnect(key.address); targets.values.forEach { it.disconnect(key.address) }
        selected.keys.removeAll { it.source == BytesKey(key.address) }
    }
    fun close() {
        lock.withLock {
            if (closed) return
            closed = true; peers.clear(); stack.close(); targets.values.forEach { it.close() }; targets.clear(); lock.signalAll()
        }
        queueLock.withLock { queueClosed = true; events.clear(); queueLock.signalAll() }
        network.close()
    }
    private fun receive(event: Event.Incoming) {
        val packet = event.packet; val key = event.key
        if (packet.startsWith("meow".encodeToByteArray())) {
            if (!event.relay) return
            if (server) {
                if (packet.size != 69 || packet[4] != 1.toByte() || !packet.copyOfRange(5, 37).contentEquals(key.raw)) return
                val disco = packet.copyOfRange(37, 69); if (disco.all { it == 0.toByte() }) return
                var peer = peers[key]
                if (peer == null) {
                    val unauthenticated = peers.filterValues { !it.authenticated }
                    if (unauthenticated.size >= 128) unauthenticated.minByOrNull { it.value.created }?.key?.let { removePeer(it) }
                    if (peers.size >= 1024) return
                    peer = newPeer(key, disco); peer.acknowledged = true; peers[key] = peer
                    try { network.configurePeer(key, disco) } catch (failure: Exception) { removePeer(key); throw failure }
                } else if (!peer.disco.contentEquals(disco)) return
                network.send(key, "meow\u0002".encodeToByteArray())
            } else if (key == address.serverPublicKey && packet.contentEquals(MEOW_AGAIN)) {
                // The server holds no session for us, as after it restarted, and its old socket,
                // the direct route's end, is gone with it.
                network.invalidate(key); rejoin()
            } else if (key == address.serverPublicKey && packet.contentEquals("meow\u0002".encodeToByteArray())) {
                peers[key]?.acknowledged = true
                trace?.markOnce("meowAck")
            }
            return
        }
        val peer = peers[key] ?: run { if (server && event.relay) askToMeowAgain(key); return }
        val wasAuthenticated = peer.authenticated
        val now = monotonicMillis(); val result = peer.wg.receive(packet, now)
        peer.sentSinceReceived = null
        if (result.plaintext != null && peer.receivedSinceSent == null) peer.receivedSinceSent = now
        val rejoined = result.handshakeCompleted && peer.rejoining
        if (result.handshakeCompleted) { trace?.markOnce("wgEstablished"); peer.rejoining = false }
        result.response?.let { sendPeerPacket(key, peer, it); peer.lastSend = now; peer.receivedSinceSent = null }
        if (result.handshakeCompleted || WireGuard.packetType(packet) == 4) {
            peer.authenticated = true; peer.lastReceived = now
            network.authenticated(key)
            if (server && !peer.admitted && !peer.admissionPending) beginAdmission(key, peer)
        }
        if (result.handshakeCompleted) { flush(key, peer); lock.signalAll() }
        // What went on the old session may be lost with it: resend it now rather than when each
        // flow's backed-off timer comes round.
        if (rejoined) stack.resendOwed()
        if (event.relay && wasAuthenticated && !result.handshakeCompleted && packet.size == 32 && WireGuard.packetType(packet) == 4) {
            // Empty transport is already a valid WireGuard packet. No new message type or crypto.
            // Only markers affect this history: newer direct data may overtake a queued relay marker.
            val index = (0..3).fold(0L) { value, i -> value or (packet[4 + i].u().toLong() shl (8 * i)) }
            val counter = (0..7).fold(0UL) { value, i -> value or (packet[8 + i].u().toULong() shl (8 * i)) }
            val previous = peer.resetCounters[index]
            if (counter > 0UL && (previous == null || counter > previous)) {
                peer.resetCounters.remove(index)
                if (peer.resetCounters.size >= 3) peer.resetCounters.remove(peer.resetCounters.keys.first())
                peer.resetCounters[index] = counter
                network.authenticatedRelayReset(key)
            }
        }
        val ip = result.plaintext ?: return
        if (!peer.admitted || ip.size < 40 || ip[0].u() ushr 4 != 6) return
        if (server) {
            if (!ip.copyOfRange(8, 24).contentEquals(key.address)) return
        } else {
            if (!ip.copyOfRange(24, 40).contentEquals(publicKey.address)) return
        }
        if (server) deliverServerIP(ip) else stack.receive(ip)
    }
    /**
     * A client still sending on a session this server doesn't have, as after it restarted, is told
     * to meow again, at most once a second: otherwise it waits for its own timeouts.
     */
    private fun askToMeowAgain(key: NodePublicKey) {
        val now = monotonicMillis()
        if (askedToMeow[key]?.let { now - it < 1000 } == true) return
        if (askedToMeow.size >= 1024) askedToMeow.clear()
        askedToMeow[key] = now
        val hook = configuration.allowClient
        if (hook == null) { network.send(key, MEOW_AGAIN); return }
        // Only a client it would admit; the hook may be slow, so not on the engine thread.
        if (admissionJobs >= 128) return
        admissionJobs++
        startThread("tailcat-admission") {
            val allowed = try { hook(key) } catch (_: Exception) { false }
            lock.withLock { admissionJobs-- }
            if (allowed) try { network.send(key, MEOW_AGAIN) } catch (_: Exception) { }
        }
    }
    /** Meow and handshake again; the session stays in use until a new one replaces it. */
    private fun rejoin() {
        val peer = peers[address.serverPublicKey] ?: return
        if (server || !peer.acknowledged) return
        peer.acknowledged = false; peer.rejoining = true; peer.lastMeow = -100_000; peer.lastHandshake = -100_000
        peer.sentSinceReceived = null
    }
    private fun beginAdmission(key: NodePublicKey, peer: Peer) {
        val hook = configuration.allowClient
        if (hook == null) { peer.admitted = true; bindingsLock.withLock { bindings[BytesKey(key.address)] = key }; return }
        if (admissionJobs >= 128) return
        admissionJobs++; peer.admissionPending = true; peer.token = nextToken++
        val token = peer.token
        startThread("tailcat-admission") {
            val accepted = try { hook(key) } catch (_: Exception) { false }
            lock.withLock { admissionJobs-- }
            try { offer(Event.Admitted(key, token, accepted)) } catch (_: Exception) { }
        }
    }
    private fun completeAdmission(event: Event.Admitted) {
        val peer = peers[event.key] ?: return
        if (!peer.admissionPending || peer.token != event.token || closed) return
        peer.admissionPending = false
        if (!event.allowed) { removePeer(event.key); return }
        peer.admitted = true; bindingsLock.withLock { bindings[BytesKey(event.key.address)] = event.key }
    }
    /** Only the engine owns WG crypto. Never call back into it from the network/DERP locks. */
    private fun prepareResetMarker(key: NodePublicKey, peer: Peer) {
        val token = network.pendingResetMarker(key) ?: return
        val marker = try {
            if (peer.wg.isEstablished) {
                var encrypted = peer.wg.encrypt(byteArrayOf(), monotonicMillis())
                // A responder may not have sent its first transport packet yet. Reserve counter zero
                // for confirmation semantics; a deliberate reset must be distinguishable from it.
                if ((8..15).all { encrypted[it] == 0.toByte() }) encrypted = peer.wg.encrypt(byteArrayOf(), monotonicMillis())
                encrypted
            } else null
        }
        catch (_: Exception) { null }
        network.completeResetMarker(key, token, marker)
    }
    private fun sendPeerPacket(key: NodePublicKey, peer: Peer, packet: ByteArray) {
        repeat(4) {
            prepareResetMarker(key, peer)
            if (network.trySend(key, packet)) return
        }
        // Continuous host notifications cannot monopolize the engine; TCP retains its retransmission.
        throw TailcatException("Network is changing during send")
    }
    private fun sendIP(packet: ByteArray) {
        if (packet.size < 40) return
        val key = if (server) peerKey(packet.copyOfRange(24, 40)) ?: return else address.serverPublicKey
        val peer = peers[key] ?: return
        if (peer.wg.isEstablished) sendPayload(key, peer, packet)
        else if (peer.pendingBytes + packet.size <= 262144) { peer.pending.addLast(packet); peer.pendingBytes += packet.size }
    }
    private fun flush(key: NodePublicKey, peer: Peer) {
        while (peer.pending.isNotEmpty() && peer.wg.isEstablished) {
            val packet = peer.pending.removeFirst(); peer.pendingBytes -= packet.size
            sendPayload(key, peer, packet)
        }
    }
    /** IP or, empty, a keepalive on the current session. */
    private fun sendPayload(key: NodePublicKey, peer: Peer, packet: ByteArray) {
        val now = monotonicMillis()
        sendPeerPacket(key, peer, peer.wg.encrypt(packet, now))
        peer.lastSend = now; peer.receivedSinceSent = null
        if (packet.isNotEmpty() && peer.sentSinceReceived == null) peer.sentSinceReceived = now
    }
    private fun deliverServerIP(ip: ByteArray) {
        val destination = ip.copyOfRange(24, 40); val source = ip.copyOfRange(8, 24)
        val local = destination.contentEquals(publicKey.address)
        var protocol = ip[6].u(); var offset = 40; var extensions = 0
        while (protocol in listOf(0, 60, 43, 44)) {
            if (++extensions > 8 || offset + 8 > ip.size) return
            val next = ip[offset].u()
            if (protocol == 44) { if (ip.be16(offset + 2) != 0) return; offset += 8 } else offset += (ip[offset + 1].u() + 1) * 8
            protocol = next
        }
        val udp = protocol == 17
        if ((protocol != 6 && !udp) || offset + (if (udp) 8 else 20) > ip.size) return
        val port = ip.be16(offset + 2); val remotePort = ip.be16(offset); if (port == 0 || remotePort == 0) return
        val endpoint = TailcatEndpoint.fromRaw(destination, port)
        val destinationKey = BytesKey(destination)
        val target = if (local) stack else {
            if (configuration.allowProxy?.invoke(endpoint) == false || (if (udp) configuration.onUDPForward == null else configuration.onTCPForward == null)) return
            targets[destinationKey] ?: run {
                if (targets.size >= 128) return
                newStack(destination).also { targets[destinationKey] = it }
            }
        }
        if (!local) targetActivity[destinationKey] = monotonicMillis()
        val serviceKey = ServiceKey(destinationKey, port, udp)
        val automatic = if (udp) udpServices.containsKey(serviceKey) else tcpServices.containsKey(serviceKey)
        val bound = if (udp) target.hasUDPSocket(port) else target.hasTCPListener(port)
        val served = if (udp) configuration.servedUDPPorts else configuration.servedTCPPorts
        if (local && served != null && port !in served && !(bound && !automatic)) return
        if (udp) {
            if (!bound && !target.hasUDPFlow(source, port, remotePort)) {
                if (tcpServices.size + udpServices.size >= 256) return
                val handler = if (local) configuration.onUDP?.invoke(port) else configuration.onUDPForward?.invoke(endpoint)
                if (handler == null) return
                val listener = target.listenUDP(port, configuration.udpIdleTimeoutMillis); udpServices[serviceKey] = listener
                startThread("tailcat-udp-accept") {
                    while (true) {
                        val connection = try { listener.accept() } catch (_: Exception) { return@startThread }
                        val chosen = try { if (local) configuration.onUDP?.invoke(port) else configuration.onUDPForward?.invoke(endpoint) } catch (_: Exception) { null }
                        dispatchUDP(connection, chosen)
                    }
                }
            }
        } else if (ip[offset + 13].u() and 0x17 == 2 && (!bound || automatic) && !target.hasTCPFlow(source, port, remotePort)) {
            val handler = if (local) configuration.onTCP?.invoke(port) else configuration.onTCPForward?.invoke(endpoint)
            if (handler == null || selected.size >= 1024) { target.rejectTCP(source, ip.copyOfRange(offset, ip.size)); return }
            selected[FlowKey(destinationKey, BytesKey(source), port, remotePort)] = Selected(handler, monotonicMillis())
            if (!bound) {
                if (tcpServices.size + udpServices.size >= 256) return
                val listener = target.listen(port); tcpServices[serviceKey] = listener
                startThread("tailcat-tcp-accept") {
                    while (true) {
                        val connection = try { listener.accept() } catch (_: Exception) { return@startThread }
                        val chosen = lock.withLock { selected.remove(FlowKey(BytesKey(connection.localAddress), BytesKey(connection.remoteAddress), connection.localPort, connection.remotePort))?.handler }
                        dispatchTCP(connection, chosen)
                    }
                }
            }
        }
        target.receive(ip)
    }
    private fun dispatchTCP(connection: TailcatConnection, handler: TailcatTCPHandler?) {
        val allowed = lock.withLock { if (handler == null || closed || handlerJobs >= 128) false else { handlerJobs++; true } }
        if (!allowed) { connection.abort(); return }
        startThread("tailcat-tcp-handler") { try { handler!!(connection) } catch (_: Exception) { connection.abort() } finally { lock.withLock { handlerJobs-- } } }
    }
    private fun dispatchUDP(connection: TailcatUDPConnection, handler: TailcatUDPHandler?) {
        val allowed = lock.withLock { if (handler == null || closed || handlerJobs >= 128) false else { handlerJobs++; true } }
        if (!allowed) { connection.close(); return }
        startThread("tailcat-udp-handler") { try { handler!!(connection) } catch (_: Exception) { connection.close() } finally { lock.withLock { handlerJobs-- } } }
    }
    private fun tick(now: Long) {
        stack.tick(now); targets.values.forEach { it.tick(now) }
        selected.entries.removeAll { now - it.value.time > 60_000 }
        for ((key, peer) in peers.toMap()) {
            if ((!peer.authenticated && now - peer.created > 30_000) || (server && peer.authenticated && now - peer.lastReceived > 300_000)) { removePeer(key); continue }
            try {
                peer.wg.maintenance(now)
                prepareResetMarker(key, peer)
                // As in WireGuard, data with nothing authenticated back for its keepalive and rekey timeouts,
                // 15 s, starts a new handshake. A server restarted with the same key holds neither our session
                // nor our admission, so the handshake goes with a meow, as when connecting.
                if (!server && peer.sentSinceReceived?.let { now - it >= 15_000 } == true) rejoin()
                if (!server && !peer.acknowledged && now - peer.lastMeow >= 1000) {
                    peer.lastMeow = now; network.send(key, "meow\u0001".encodeToByteArray() + publicKey.raw + identity.discoPublicKey)
                    trace?.markOnce("meowQueued")
                }
                // Data waiting on a handshake retries it each second, not five: an initiation lost to a
                // relay that died during a suspension otherwise holds that data for five seconds.
                // So does a rejoin, which keeps the old session in use until a new one replaces it.
                val spacing = if ((!peer.wg.isEstablished && peer.pending.isNotEmpty()) || peer.rejoining) 1000 else 5000
                if (peer.acknowledged && (!peer.wg.isEstablished || peer.rejoining || peer.wg.needsRekey(now)) && now - peer.lastHandshake >= spacing && (!server || peer.wg.isEstablished)) {
                    peer.lastHandshake = now; sendPeerPacket(key, peer, peer.wg.initiate(now))
                    trace?.markOnce("wgInitiationQueued")
                } else if (peer.wg.isEstablished && peer.receivedSinceSent?.let { now - it >= 10_000 } == true) {
                    // WireGuard's passive keepalive: data is answered within its keepalive timeout.
                    sendPayload(key, peer, byteArrayOf())
                } else if (peer.wg.isEstablished && now - peer.lastSend >= 25_000) sendPayload(key, peer, byteArrayOf())
            } catch (_: Exception) { network.invalidate(key) }
        }
        for ((key, activity) in targetActivity.toMap()) {
            val target = targets[key] ?: continue
            if (now - activity > maxOf(300_000, configuration.udpIdleTimeoutMillis) && target.connectionCount == 0 && target.udpConnectionCount == 0) {
                tcpServices.keys.filter { it.destination == key }.forEach { tcpServices.remove(it)?.close() }
                udpServices.keys.filter { it.destination == key }.forEach { udpServices.remove(it)?.close() }
                target.close(); targets.remove(key); targetActivity.remove(key)
            }
        }
    }
}

/** A server's answer to a packet on a session it doesn't hold: meow again. */
private val MEOW_AGAIN = "meow\u0003".encodeToByteArray()

/** Copy streams in both directions, propagating each EOF as a FIN. */
fun proxyConnections(first: TailcatConnection, second: TailcatConnection, timeoutMillis: Long = 0) {
    val lock = PlatformLock(); var done = false; var failure: Throwable? = null
    fun copy(source: TailcatConnection, destination: TailcatConnection) {
        val buffer = ByteArray(16384)
        while (true) { val n = source.read(buffer, timeoutMillis = timeoutMillis); if (n < 0) { destination.shutdownOutput(timeoutMillis); return }; destination.write(buffer, length = n, timeoutMillis = timeoutMillis) }
    }
    startThread("tailcat-proxy") {
        try { copy(first, second) } catch (error: Throwable) { lock.withLock { failure = error }; first.close(); second.close() }
        finally { lock.withLock { done = true; lock.signalAll() } }
    }
    try { copy(second, first); lock.withLock { while (!done) lock.await(1000); failure?.let { throw it } } }
    finally { first.close(); second.close() }
}
