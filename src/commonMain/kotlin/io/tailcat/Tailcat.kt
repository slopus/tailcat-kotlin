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
)
data class ClientConfiguration(
    val privateKey: NodePrivateKey? = null,
    val mapProvider: DERPMapProvider = DERPMapProvider(),
    val connectTimeoutMillis: Long = 30_000,
    val testOnlyPlaintextDERP: Boolean = false,
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
            val region = configuration.region ?: configuration.mapProvider.regions(cancelled).let { regions ->
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
    fun path(key: NodePublicKey): ConnectionPath = current().path(key)
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
    fun resetNetworkPaths() = engine.resetNetworkPaths()
    fun close() = engine.close()
    companion object {
        fun connect(text: String, configuration: ClientConfiguration = ClientConfiguration()): TailcatClient = connect(TailcatAddress.parse(text), configuration)
        fun connect(address: TailcatAddress, configuration: ClientConfiguration = ClientConfiguration()): TailcatClient {
            require(configuration.connectTimeoutMillis > 0)
            val deadline = monotonicMillis() + configuration.connectTimeoutMillis
            val disco = address.serverDiscoPublicKey
            require(disco != null && disco.any { it != 0.toByte() }) { "Missing server discovery key" }
            val regions = try {
                configuration.mapProvider.expand(address) { monotonicMillis() >= deadline }
            } catch (failure: Exception) {
                if (monotonicMillis() >= deadline) throw TailcatTimeoutException()
                throw failure
            }
            require(regions.isNotEmpty()) { "No relay region" }
            val expanded = TailcatAddress(address.serverPublicKey, disco, address.presharedKey, regions, address.regionID)
            val prepared = TailcatEngine(configuration.privateKey ?: NodePrivateKey.generate(), expanded, false,
                ServerConfiguration(testOnlyPlaintextDERP = configuration.testOnlyPlaintextDERP))
            try {
                prepared.start((deadline-monotonicMillis()).coerceAtLeast(1))
                prepared.awaitConnected((deadline-monotonicMillis()).coerceAtLeast(1))
                return TailcatClient(prepared)
            } catch (failure: Exception) { prepared.close(); if (monotonicMillis() >= deadline) throw TailcatTimeoutException(); throw failure }
        }
    }
}

internal class TailcatEngine(private val identity: NodePrivateKey, val address: TailcatAddress,
    private val server: Boolean, private val configuration: ServerConfiguration) {
    val publicKey = identity.publicKey
    private class Peer(val wg: WireGuard, val disco: ByteArray, val created: Long) {
        var acknowledged = false; var authenticated = false; var admitted = false; var admissionPending = false
        var token = 0L; var lastReceived = created; var lastSend = created; var lastMeow = -100_000L; var lastHandshake = -100_000L
        val pending = ArrayDeque<ByteArray>(); var pendingBytes = 0
    }
    private sealed class Event {
        class Incoming(val key: NodePublicKey, val packet: ByteArray, val relay: Boolean) : Event()
        class Outgoing(val packet: ByteArray) : Event()
        class Admitted(val key: NodePublicKey, val token: Long, val allowed: Boolean) : Event()
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
    private var closed = false
    private var queueClosed = false
    private var nextToken = 1L
    private var admissionJobs = 0
    private var handlerJobs = 0
    private val network = NetworkTransport(identity, address.regions.first().nodes, configuration.testOnlyPlaintextDERP) { key, packet, relay -> offer(Event.Incoming(key, packet, relay)) }
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
                    when (event) { is Event.Incoming -> receive(event); is Event.Outgoing -> sendIP(event.packet); is Event.Admitted -> completeAdmission(event) }
                } catch (_: Exception) { }
                tick(monotonicMillis())
            }
        }
    }
    fun awaitConnected(timeoutMillis: Long) = lock.withLock {
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
    fun disconnect(key: NodePublicKey) = lock.withLock { removePeer(key) }
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
            } else if (key == address.serverPublicKey && packet.contentEquals("meow\u0002".encodeToByteArray())) peers[key]?.acknowledged = true
            return
        }
        val peer = peers[key] ?: return
        val now = monotonicMillis(); val result = peer.wg.receive(packet, now)
        result.response?.let { network.send(key, it); peer.lastSend = now }
        if (result.handshakeCompleted || WireGuard.packetType(packet) == 4) {
            peer.authenticated = true; peer.lastReceived = now
            if (server && !peer.admitted && !peer.admissionPending) beginAdmission(key, peer)
        }
        if (result.handshakeCompleted) { flush(key, peer); lock.signalAll() }
        val ip = result.plaintext ?: return
        if (!peer.admitted || ip.size < 40 || ip[0].u() ushr 4 != 6) return
        if (server) {
            if (!ip.copyOfRange(8, 24).contentEquals(key.address)) return
            deliverServerIP(ip)
        } else {
            if (!ip.copyOfRange(24, 40).contentEquals(publicKey.address)) return
            stack.receive(ip)
        }
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
    private fun sendIP(packet: ByteArray) {
        if (packet.size < 40) return
        val key = if (server) peerKey(packet.copyOfRange(24, 40)) ?: return else address.serverPublicKey
        val peer = peers[key] ?: return
        if (peer.wg.isEstablished) { network.send(key, peer.wg.encrypt(packet, monotonicMillis())); peer.lastSend = monotonicMillis() }
        else if (peer.pendingBytes + packet.size <= 262144) { peer.pending.addLast(packet); peer.pendingBytes += packet.size }
    }
    private fun flush(key: NodePublicKey, peer: Peer) {
        while (peer.pending.isNotEmpty() && peer.wg.isEstablished) {
            val packet = peer.pending.removeFirst(); peer.pendingBytes -= packet.size
            network.send(key, peer.wg.encrypt(packet, monotonicMillis())); peer.lastSend = monotonicMillis()
        }
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
                if (!server && !peer.acknowledged && now - peer.lastMeow >= 1000) {
                    peer.lastMeow = now; network.send(key, "meow\u0001".encodeToByteArray() + publicKey.raw + identity.discoPublicKey)
                }
                if (peer.acknowledged && (!peer.wg.isEstablished || peer.wg.needsRekey(now)) && now - peer.lastHandshake >= 5000 && (!server || peer.wg.isEstablished)) {
                    peer.lastHandshake = now; network.send(key, peer.wg.initiate(now))
                } else if (peer.wg.isEstablished && now - peer.lastSend >= 25_000) { network.send(key, peer.wg.encrypt(byteArrayOf(), now)); peer.lastSend = now }
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
