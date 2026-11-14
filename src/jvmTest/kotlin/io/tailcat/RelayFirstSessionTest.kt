package io.tailcat

import io.tailcat.crypto.NaClBox
import io.tailcat.platform.secureRandom
import io.tailcat.wireguard.WireGuard
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.*

/** Real local sockets, DERP authentication and WireGuard; no external relay or test environment needed. */
class RelayFirstSessionTest {
    private class LocalRelay : AutoCloseable {
        private class Session(val socket: Socket) {
            /** A black hole: frames are read and dropped, nothing goes out, as on a connection that died silently. */
            @Volatile var silent = false
            fun read(): DerpFrame {
                val header = exact(5)
                val length = header.be32(1)
                require(length <= DerpFrame.MAXIMUM)
                return DerpFrame(header[0].u(), exact(length.toInt()))
            }
            private fun exact(length: Int): ByteArray = socket.getInputStream().readNBytes(length).also { check(it.size == length) }
            @Synchronized fun write(frame: DerpFrame) { socket.getOutputStream().write(frame.encode()) }
        }
        private val key = NodePrivateKey.generate()
        private val listener = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        private val sessions = ConcurrentHashMap<NodePublicKey, Session>()
        private val sockets = CopyOnWriteArrayList<Socket>()
        val packets = CopyOnWriteArrayList<ByteArray>()
        val sourcedPackets = CopyOnWriteArrayList<Pair<NodePublicKey, ByteArray>>()
        val connections = AtomicInteger()
        @Volatile var allowDiscovery = false
        @Volatile var stallAuthentication = false
        @Volatile var blockedDiscoverySource: NodePublicKey? = null
        /** WireGuard transport from this node goes nowhere; handshakes and meows still pass. */
        @Volatile var droppedTransportSource: NodePublicKey? = null
        /** Packets this matches, by source, go nowhere. */
        @Volatile var dropped: ((NodePublicKey, ByteArray) -> Boolean)? = null
        val region = DERPRegion(1, listOf(DERPNode("127.0.0.1", ipv4 = "127.0.0.1", derpPort = listener.localPort, stunPort = -1)))
        val connected: Int get() = sessions.size
        val openConnections: Int get() = sockets.size
        init {
            thread(name = "test-relay-accept", isDaemon = true) {
                while (!listener.isClosed) {
                    val socket = try { listener.accept() } catch (_: Exception) { return@thread }
                    sockets.add(socket)
                    thread(name = "test-relay-peer", isDaemon = true) { serve(socket) }
                }
            }
        }
        private fun serve(socket: Socket) {
            val session = Session(socket)
            var client: NodePublicKey? = null
            try {
                val input = socket.getInputStream()
                val header = StringBuilder()
                while (!header.endsWith("\r\n\r\n")) { val byte = input.read(); check(byte >= 0 && header.length < 16384); header.append(byte.toChar()) }
                socket.getOutputStream().write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".encodeToByteArray())
                session.write(DerpFrame(1, "DERP🔑".encodeToByteArray() + key.publicKey.raw))
                val info = session.read(); check(info.type == 2 && info.payload.size >= 72)
                client = NodePublicKey(info.payload.copyOfRange(0, 32))
                NaClBox.open(info.payload.copyOfRange(56, info.payload.size), info.payload.copyOfRange(32, 56), client.raw, key.raw)
                if (stallAuthentication) {
                    while (input.read() != -1) { /* Hold only this unauthenticated socket until its client cancels. */ }
                    return
                }
                val nonce = secureRandom(24)
                session.write(DerpFrame(3, nonce + NaClBox.seal("{\"version\":2}".encodeToByteArray(), nonce, client.raw, key.raw)))
                sessions[client] = session
                connections.incrementAndGet()
                while (true) {
                    val frame = session.read()
                    if (session.silent) continue
                    when (frame.type) {
                        4 -> {
                            val destination = NodePublicKey(frame.payload.copyOfRange(0, 32))
                            val packet = frame.payload.copyOfRange(32, frame.payload.size)
                            packets.add(packet)
                            sourcedPackets.add(client to packet)
                            if (client == droppedTransportSource && WireGuard.packetType(packet) == 4) continue
                            if (dropped?.invoke(client, packet) == true) continue
                            if (allowDiscovery && client != blockedDiscoverySource || !packet.startsWith(Discovery.magic)) {
                                try { sessions[destination]?.takeUnless { it.silent }?.write(DerpFrame(5, client.raw + packet)) } catch (_: Exception) { }
                            }
                        }
                        0x12 -> session.write(DerpFrame(0x13, frame.payload))
                    }
                }
            } catch (_: Exception) {
                // Disconnects are deliberate fault injection in these tests.
            } finally {
                if (client != null) sessions.remove(client, session)
                socket.close(); sockets.remove(socket)
            }
        }
        fun inject(source: NodePublicKey, destination: NodePublicKey, packet: ByteArray) {
            checkNotNull(sessions[destination]).write(DerpFrame(5, source.raw + packet))
        }
        fun disconnectAll() { for (socket in sockets) socket.close() }
        fun silence(key: NodePublicKey) { checkNotNull(sessions[key]).silent = true }
        override fun close() { listener.close(); disconnectAll() }
    }
    private fun eventually(message: String, predicate: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        while (!predicate()) { check(System.nanoTime() < deadline) { message }; Thread.sleep(20) }
    }
    private val echo: TailcatTCPHandler = { connection ->
        try {
            val buffer = ByteArray(4096)
            while (true) {
                val count = connection.read(buffer, timeoutMillis = 20_000)
                if (count < 0) break
                connection.write(buffer, length = count, timeoutMillis = 10_000)
            }
        } finally { connection.close() }
    }
    private fun exchange(connection: TailcatConnection, text: String) {
        val payload = text.encodeToByteArray()
        connection.write(payload, timeoutMillis = 10_000)
        val received = ArrayList<Byte>()
        while (received.size < payload.size) received.addAll(connection.read(payload.size - received.size, 10_000).toList())
        assertContentEquals(payload, received.toByteArray())
    }

    @Test fun independentClientsHaveSeparateSocketsSessionsAndRecovery() {
        for (mode in listOf(false, true)) LocalRelay().use { relay ->
            val server = TailcatServer(ServerConfiguration(region = relay.region, testOnlyPlaintextDERP = true,
                relayFirst = mode, onTCP = { echo }))
            val address = server.start()
            val firstTrace = StartupTrace(); val secondTrace = StartupTrace()
            val config = ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = mode)
            val first = TailcatClient.connectTraced(address, config, firstTrace)
            val second = TailcatClient.connectTraced(address, config, secondTrace)
            try {
                assertNotEquals(first.publicKey, second.publicKey)
                eventually("All three independent DERP sockets must be active") { relay.connected == 3 }
                fun port(trace: StartupTrace, name: String) = trace.snapshot().firstOrNull { it.name == name }?.value
                assertNotNull(port(firstTrace, "tcpConnected"))
                assertNotEquals(port(firstTrace, "tcpConnected"), port(secondTrace, "tcpConnected"))
                eventually("Each client must bind its own UDP socket") {
                    port(firstTrace, "udp4Bound") != null && port(secondTrace, "udp4Bound") != null
                }
                assertNotEquals(port(firstTrace, "udp4Bound"), port(secondTrace, "udp4Bound"))
                val meows = relay.sourcedPackets.filter { it.second.startsWith("meow\u0001".encodeToByteArray()) }
                val disco1 = meows.first { it.first == first.publicKey }.second.copyOfRange(37, 69)
                val disco2 = meows.first { it.first == second.publicKey }.second.copyOfRange(37, 69)
                assertFalse(disco1.contentEquals(disco2))
                val stream1 = first.dialTCP(80); val stream2 = second.dialTCP(80)
                try {
                    val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>(null)
                    val start = java.util.concurrent.CountDownLatch(1)
                    val worker = thread(isDaemon = true) {
                        try { start.await(); repeat(20) { exchange(stream1, "first independent payload $it") } }
                        catch (error: Throwable) { failure.set(error) }
                    }
                    start.countDown()
                    repeat(20) { exchange(stream2, "second isolated payload $it") }
                    worker.join(15_000); assertFalse(worker.isAlive); failure.get()?.let { throw it }
                    val secondInitiations = relay.sourcedPackets.count { it.first == second.publicKey && WireGuard.packetType(it.second) == 1 }
                    first.resetNetworkPaths()
                    exchange(stream2, "second session unaffected by first network reset")
                    exchange(stream1, "first session recovers on its own connection")
                    assertEquals(secondInitiations, relay.sourcedPackets.count { it.first == second.publicKey && WireGuard.packetType(it.second) == 1 })
                    if (mode) {
                        second.close(); exchange(stream1, "first survives second close")
                    } else {
                        first.close(); exchange(stream2, "second survives first close")
                    }
                } finally { stream1.close(); stream2.close() }
                for (trace in listOf(firstTrace, secondTrace)) {
                    val events = trace.snapshot()
                    fun at(name: String) = events.first { it.name == name }.atMillis
                    assertTrue(at("derpServerInfoAuthenticated") <= at("meowAck"))
                    assertTrue(at("meowAck") <= at("wgEstablished"))
                    assertTrue(at("wgEstablished") <= at("connectReturn"))
                    assertTrue(events.size <= 128)
                }
            } finally { first.close(); second.close(); server.close() }
        }
    }

    @Test fun startupTraceIsBoundedAndSnapshotsDoNotChange() {
        val trace = StartupTrace()
        trace.markOnce("first")
        val snapshot = trace.snapshot()
        repeat(1000) { trace.markOnce("first"); trace.mark("attempt", it.toLong()) }
        assertEquals(1, snapshot.size)
        assertEquals(128, trace.snapshot().size)
        assertEquals(1, trace.snapshot().count { it.name == "first" })
    }

    @Test fun timedOutSecondClientClosesOnlyItsOwnRelaySocket() {
        LocalRelay().use { relay ->
            val server = TailcatServer(ServerConfiguration(region = relay.region, testOnlyPlaintextDERP = true, onTCP = { echo }))
            val address = server.start()
            val first = TailcatClient.connect(address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
            try {
                val stream = first.dialTCP(80)
                try {
                    exchange(stream, "first before second timeout")
                    relay.stallAuthentication = true
                    val trace = StartupTrace()
                    assertFailsWith<TailcatTimeoutException> {
                        TailcatClient.connectTraced(address, ClientConfiguration(testOnlyPlaintextDERP = true,
                            relayFirst = true, connectTimeoutMillis = 500), trace)
                    }
                    eventually("Timed-out client must release its socket without closing the first") { relay.openConnections == 2 && relay.connected == 2 }
                    exchange(stream, "first after second timeout")
                    assertTrue(trace.snapshot().any { it.name == "derpClientInfoWritten" })
                    assertFalse(trace.snapshot().any { it.name == "connectReturn" })
                } finally { stream.close() }
            } finally { first.close(); server.close() }
        }
    }

    @Test fun sameEncryptedStreamSurvivesUpgradeRelayRecoveryAndNetworkChangeWithMixedModes() {
        // Both opt-in and each one-sided pairing must interoperate with the existing default.
        for ((serverRelayFirst, clientRelayFirst) in listOf(true to true, false to true, true to false)) {
            LocalRelay().use { relay ->
                val server = TailcatServer(ServerConfiguration(region = relay.region, testOnlyPlaintextDERP = true,
                    relayFirst = serverRelayFirst, onTCP = { echo }))
                val address = server.start()
                val client = TailcatClient.connect(address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = clientRelayFirst))
                try {
                    val clientIdentity = client.publicKey
                    val serverIdentity = server.publicKey
                    val connection = client.dialTCP(80)
                    try {
                        assertEquals(ConnectionPath.Relay, client.path)
                        assertEquals(ConnectionPath.Relay, server.path(clientIdentity))
                        exchange(connection, "encrypted initial relay stream")
                        assertTrue(relay.packets.any { WireGuard.packetType(it) == 1 })
                        assertTrue(relay.packets.any { WireGuard.packetType(it) == 2 })
                        assertTrue(relay.packets.any { WireGuard.packetType(it) == 4 })
                        assertFalse(relay.packets.any { it.decodeToString().contains("encrypted initial relay stream") })
                        val relayConnections = relay.connections.get()
                        relay.disconnectAll()
                        eventually("Relay-only session should recover") { relay.connections.get() >= relayConnections + 2 && relay.connected == 2 }
                        exchange(connection, "same relay stream after DERP disconnect")

                        relay.allowDiscovery = true
                        client.retryDirect(); server.retryDirect(clientIdentity)
                        eventually("Both peers should upgrade the existing session") {
                            client.path is ConnectionPath.Direct && server.path(clientIdentity) is ConnectionPath.Direct
                        }
                        exchange(connection, "same stream after direct upgrade")
                        client.retryDirect(); server.retryDirect()
                        assertTrue(client.path is ConnectionPath.Direct)
                        val directConnections = relay.connections.get()
                        relay.disconnectAll()
                        exchange(connection, "direct remains usable while DERP reconnects")
                        eventually("DERP reconnects in the background") { relay.connections.get() >= directConnections + 2 && relay.connected == 2 }
                        assertTrue(client.path is ConnectionPath.Direct)

                        relay.allowDiscovery = false
                        client.resetNetworkPaths(); server.resetNetworkPaths()
                        assertEquals(ConnectionPath.Relay, client.path)
                        exchange(connection, "same stream after network reset over recovered relay")
                        relay.allowDiscovery = true
                        client.retryDirect(); server.retryDirect()
                        eventually("New sockets must validate a new direct path") {
                            client.path is ConnectionPath.Direct && server.path(clientIdentity) is ConnectionPath.Direct
                        }
                        exchange(connection, "same stream after second upgrade")
                        assertEquals(clientIdentity, client.publicKey)
                        assertEquals(serverIdentity, server.publicKey)
                        // No route transition re-created the WireGuard session.
                        assertEquals(1, relay.packets.count { WireGuard.packetType(it) == 1 })
                    } finally { connection.close() }
                } finally { client.close(); server.close() }
            }
        }
    }

    @Test fun oneSidedClientRebindKeepsExistingTcpStreamAndRefreshesServerReturnPath() {
        LocalRelay().use { relay ->
            val server = TailcatServer(ServerConfiguration(region = relay.region, testOnlyPlaintextDERP = true,
                relayFirst = true, onTCP = { echo }))
            val client = TailcatClient.connect(server.start(), ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
            try {
                val connection = client.dialTCP(80)
                try {
                    exchange(connection, "initial relay stream")
                    relay.allowDiscovery = true
                    client.retryDirect(); server.retryDirect()
                    eventually("Initial direct paths") { client.path is ConnectionPath.Direct && server.path(client.publicKey) is ConnectionPath.Direct }
                    val oldServerReturnPath = server.path(client.publicKey)
                    relay.inject(client.publicKey, server.publicKey, ByteArray(32).also { it[0] = 4 })
                    exchange(connection, "forged relay traffic cannot change the authenticated route")
                    assertTrue(server.path(client.publicKey) is ConnectionPath.Direct)
                    // Withhold every new endpoint advertisement: no new direct validation can complete.
                    relay.allowDiscovery = false
                    val resetAt = System.nanoTime()
                    // Do not reset the server: it still has the old, recently validated client port.
                    client.resetNetworkPaths()
                    exchange(connection, "same stream after only the client changed network")
                    assertTrue(System.nanoTime() - resetAt < TimeUnit.SECONDS.toNanos(5), "Recovery must not wait for discovery or the ten-second maintenance probe")
                    assertEquals(ConnectionPath.Relay, server.path(client.publicKey))
                    relay.allowDiscovery = true
                    client.retryDirect(); server.retryDirect()
                    val stableBy = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
                    var stableEchoes = 0
                    var previousPaths = ""
                    while (stableEchoes < 60) {
                        exchange(connection, "bidirectional traffic continues while direct paths converge")
                        val paths = "client=${client.path} server=${server.path(client.publicKey)}"
                        if (paths != previousPaths) {
                            println("RECOVERY-TRACE ${(System.nanoTime() - resetAt) / 1_000_000}ms $paths")
                            previousPaths = paths
                        }
                        val direct = client.path is ConnectionPath.Direct && server.path(client.publicKey) is ConnectionPath.Direct &&
                            server.path(client.publicKey) != oldServerReturnPath
                        stableEchoes = if (direct) stableEchoes + 1 else 0
                        check(System.nanoTime() < stableBy) { "Direct paths oscillated during continuous bidirectional traffic" }
                        Thread.sleep(50)
                    }
                    val marker = relay.sourcedPackets.last { it.first == client.publicKey && it.second.size == 32 &&
                        WireGuard.packetType(it.second) == 4 && (8..15).any { index -> it.second[index] != 0.toByte() } }.second
                    relay.inject(client.publicKey, server.publicKey, marker)
                    exchange(connection, "new validated return path")
                    assertTrue(server.path(client.publicKey) is ConnectionPath.Direct, "Replaying an authenticated marker cannot demote a new route")
                    assertEquals(1, relay.packets.count { WireGuard.packetType(it) == 1 })
                } finally { connection.close() }
            } finally { client.close(); server.close() }
        }
    }

    @Test fun repeatedOneSidedResetsRemainBoundedWithAdvertisementsBlocked() {
        LocalRelay().use { relay ->
            val server = TailcatServer(ServerConfiguration(region = relay.region, testOnlyPlaintextDERP = true,
                relayFirst = true, onTCP = { echo }))
            val client = TailcatClient.connect(server.start(), ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
            try {
                val connection = client.dialTCP(80)
                try {
                    exchange(connection, "initial relay stream")
                    relay.allowDiscovery = true
                    client.retryDirect(); server.retryDirect()
                    eventually("Initial direct paths") { client.path is ConnectionPath.Direct && server.path(client.publicKey) is ConnectionPath.Direct }
                    val oldReturn = server.path(client.publicKey)
                    // Only server advertisements pass: the server learns the client's new port from Ping,
                    // not a changed CMM. The encrypted marker must keep the existing stream usable.
                    relay.blockedDiscoverySource = client.publicKey
                    client.resetNetworkPaths(); server.retryDirect()
                    exchange(connection, "first asymmetric reset")
                    eventually("First reset revalidates without the client's changed advertisement") {
                        server.path(client.publicKey) is ConnectionPath.Direct && server.path(client.publicKey) != oldReturn
                    }
                    relay.allowDiscovery = false
                    val secondReset = System.nanoTime()
                    client.resetNetworkPaths()
                    exchange(connection, "second immediate reset, with all discovery withheld")
                    val recoveryMillis = (System.nanoTime() - secondReset) / 1_000_000
                    println("SECOND-RESET-RECOVERY ${recoveryMillis}ms")
                    assertTrue(recoveryMillis < 3000, "Second asymmetric reset did not promptly recover over DERP")
                    assertEquals(ConnectionPath.Relay, server.path(client.publicKey))
                    relay.blockedDiscoverySource = null; relay.allowDiscovery = true
                    client.retryDirect(); server.retryDirect()
                    eventually("Direct restores after discovery is allowed again") { client.path is ConnectionPath.Direct && server.path(client.publicKey) is ConnectionPath.Direct }
                    exchange(connection, "same stream after both resets")
                    assertEquals(1, relay.packets.count { WireGuard.packetType(it) == 1 })
                } finally { connection.close() }
            } finally { client.close(); server.close() }
        }
    }

    @Test fun wakeAndNetworkChangeKeepTheRelayAndRouteThatAnswer() {
        LocalRelay().use { relay ->
            val server = TailcatServer(ServerConfiguration(region = relay.region, testOnlyPlaintextDERP = true,
                relayFirst = true, onTCP = { echo }))
            val client = TailcatClient.connect(server.start(), ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
            try {
                val connection = client.dialTCP(80)
                try {
                    exchange(connection, "initial relay stream")
                    val connections = relay.connections.get()
                    client.wake()
                    Thread.sleep(2500)
                    exchange(connection, "same stream after waking on a live relay")
                    assertEquals(connections, relay.connections.get(), "An answering relay is kept")
                    relay.allowDiscovery = true
                    client.retryDirect(); server.retryDirect()
                    eventually("Direct paths") { client.path is ConnectionPath.Direct && server.path(client.publicKey) is ConnectionPath.Direct }
                    client.notifyNetworkChanged()
                    Thread.sleep(2500)
                    exchange(connection, "same stream after a network change that broke nothing")
                    // Every interface of the server answers; any of them may be selected.
                    assertTrue(client.path is ConnectionPath.Direct, "A direct route that answers is kept")
                    assertEquals(connections, relay.connections.get(), "So is the relay")
                    assertEquals(1, relay.packets.count { WireGuard.packetType(it) == 1 }, "And the session")
                } finally { connection.close() }
            } finally { client.close(); server.close() }
        }
    }

    @Test fun wakeReplacesASilentRelayWithinItsDeadlineAndKeepsTheSession() {
        LocalRelay().use { relay ->
            val server = TailcatServer(ServerConfiguration(region = relay.region, testOnlyPlaintextDERP = true,
                relayFirst = true, onTCP = { echo }))
            val client = TailcatClient.connect(server.start(), ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
            try {
                val connection = client.dialTCP(80)
                try {
                    exchange(connection, "initial relay stream")
                    val connections = relay.connections.get()
                    relay.silence(client.publicKey)
                    val woke = System.nanoTime()
                    client.wake()
                    eventually("The silent relay is replaced") { relay.connections.get() > connections }
                    val millis = (System.nanoTime() - woke) / 1_000_000
                    println("SILENT-RELAY-RECOVERY ${millis}ms")
                    assertTrue(millis in 1400..2500, "Replaced at the 1.5 s deadline before a round trip is measured, not the 120-second one: ${millis}ms")
                    exchange(connection, "same stream once the silent relay is replaced")
                    assertEquals(1, relay.packets.count { WireGuard.packetType(it) == 1 }, "The session is kept")
                } finally { connection.close() }
            } finally { client.close(); server.close() }
        }
    }

    /** A server restarted with the same key: same address, none of its sessions or admissions. */
    private class RestartableServer(private val relay: LocalRelay, private val handler: TailcatTCPHandler,
                                    private val udp: TailcatUDPHandler? = null) : AutoCloseable {
        private val key = NodePrivateKey.generate()
        private val psk = PresharedKey.generate()
        @Volatile var server = make()
        val address = server.start()
        private fun make() = TailcatServer(ServerConfiguration(privateKey = key, presharedKey = psk, region = relay.region,
            testOnlyPlaintextDERP = true, relayFirst = true, onTCP = { handler }, onUDP = { udp }))
        fun restart() { stop(); start() }
        fun stop() = server.close()
        fun start() {
            server = make()
            check(server.start().encode() == address.encode())
        }
        override fun close() = server.close()
    }
    private val meowAgain = "meow\u0003".encodeToByteArray()

    @Test fun aServerRestartedWithTheSameKeyIsRejoinedOnItsMeowAgain() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    client.dialTCP(80).let { try { exchange(it, "before the restart") } finally { it.close() } }
                    restartable.restart()
                    eventually("The restarted server is on the relay") { relay.connected == 2 }
                    val restarted = System.nanoTime()
                    val connection = client.dialTCP(80, 10_000)
                    try { exchange(connection, "after the restart") } finally { connection.close() }
                    val millis = (System.nanoTime() - restarted) / 1_000_000
                    println("RESTART-REJOIN ${millis}ms")
                    assertTrue(relay.sourcedPackets.any { it.first == restartable.server.publicKey && it.second.contentEquals(meowAgain) }, "The server says it has no session")
                    assertTrue(millis < 3000, "Rejoined on the server's answer, not after the flow's timeouts: ${millis}ms")
                    assertTrue(relay.sourcedPackets.count { it.first == client.publicKey && it.second.startsWith("meow\u0001".encodeToByteArray()) } >= 2,
                        "The client meowed again")
                } finally { client.close() }
            }
        }
    }

    @Test fun aRejoinResendsWhatEachFlowOwesAtOnce() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    client.dialTCP(80).let { try { exchange(it, "before the restart") } finally { it.close() } }
                    restartable.stop()
                    // Its SYN goes nowhere and backs off: 0, 0.5, 1.5 and 3.5 s, then not until 7.5 s.
                    val began = System.nanoTime()
                    val owed = java.util.concurrent.atomic.AtomicReference<Any?>(null)
                    val waiting = thread(isDaemon = true) {
                        owed.set(try { client.dialTCP(80, 20_000).also { exchange(it, "owed since the restart"); it.close() } } catch (failure: Throwable) { failure })
                    }
                    Thread.sleep(4000)
                    restartable.start()
                    eventually("The restarted server is on the relay") { relay.connected == 2 }
                    // A new flow meets the server's meow again, and the rejoin it starts makes a new session.
                    client.dialTCP(80, 10_000).let { try { exchange(it, "after the restart") } finally { it.close() } }
                    waiting.join(10_000)
                    val millis = (System.nanoTime() - began) / 1_000_000
                    println("REJOIN-RESEND ${millis}ms")
                    assertTrue(owed.get() is TailcatConnection, "The owed flow got through: ${owed.get()}")
                    assertTrue(millis < 6500, "Its SYN went again with the new session, not at 7.5 s: ${millis}ms")
                } finally { client.close() }
            }
        }
    }

    @Test fun aWakeTellsTheRelayAtOnceAndSoMeetsARestartedServerBeforeTheDirectCheck() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    client.dialTCP(80).let { try { exchange(it, "before the restart") } finally { it.close() } }
                    relay.allowDiscovery = true
                    client.retryDirect(); restartable.server.retryDirect()
                    eventually("Direct paths") { client.path is ConnectionPath.Direct && restartable.server.path(client.publicKey) is ConnectionPath.Direct }
                    // The restarted server's invitation would say so too; this is about the marker alone.
                    relay.allowDiscovery = false
                    restartable.restart()
                    eventually("The restarted server is on the relay") { relay.connected == 2 }
                    fun meows() = relay.sourcedPackets.count { it.first == client.publicKey && it.second.startsWith("meow\u0001".encodeToByteArray()) }
                    val before = meows()
                    val woke = System.nanoTime()
                    client.wake()
                    eventually("The client rejoins") { meows() > before }
                    val millis = (System.nanoTime() - woke) / 1_000_000
                    println("WAKE-MARKER-REJOIN ${millis}ms")
                    assertTrue(millis < 1000, "Rejoined on the marker's answer, not after the 2 s direct check: ${millis}ms")
                    client.dialTCP(80, 10_000).let { try { exchange(it, "after the wake") } finally { it.close() } }
                } finally { client.close() }
            }
        }
    }

    @Test fun aRestartedServersInvitationOnNewPortsIsRejoinedAtOnce() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    client.dialTCP(80).let { try { exchange(it, "before the restart") } finally { it.close() } }
                    relay.allowDiscovery = true
                    client.retryDirect(); restartable.server.retryDirect()
                    eventually("Direct paths") { client.path is ConnectionPath.Direct && restartable.server.path(client.publicKey) is ConnectionPath.Direct }
                    restartable.restart()
                    eventually("The restarted server is on the relay") { relay.connected == 2 }
                    fun meows() = relay.sourcedPackets.count { it.first == client.publicKey && it.second.startsWith("meow\u0001".encodeToByteArray()) }
                    val before = meows()
                    val disco = relay.sourcedPackets.first { it.first == client.publicKey && it.second.startsWith("meow\u0001".encodeToByteArray()) }.second.copyOfRange(37, 69)
                    // The client is idle: nothing it sends could draw a meow again.
                    val invited = System.nanoTime()
                    restartable.server.inviteForTesting(client.publicKey, disco)
                    eventually("The client rejoins") { meows() > before }
                    val millis = (System.nanoTime() - invited) / 1_000_000
                    println("INVITE-REJOIN ${millis}ms")
                    assertTrue(millis < 1000, "Rejoined on the invitation: ${millis}ms")
                    client.dialTCP(80, 10_000).let { try { exchange(it, "after the invitation") } finally { it.close() } }
                } finally { client.close() }
            }
        }
    }

    private fun meows(relay: LocalRelay, client: TailcatClient) =
        relay.sourcedPackets.count { it.first == client.publicKey && it.second.startsWith("meow\u0001".encodeToByteArray()) }

    @Test fun dataUnansweredFor15SecondsMeowsAndHandshakesAgain() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    val before = meows(relay, client)
                    val initiations = relay.sourcedPackets.count { it.first == client.publicKey && WireGuard.packetType(it.second) == 1 }
                    // A server that reads nothing we send and says nothing: no meow again, no TCP to time out.
                    relay.droppedTransportSource = client.publicKey
                    val flow = client.dialUDP(9)
                    val sent = System.nanoTime()
                    flow.send("unanswered".encodeToByteArray())
                    val deadline = sent + TimeUnit.SECONDS.toNanos(20)
                    while (meows(relay, client) == before) { check(System.nanoTime() < deadline) { "No rejoin" }; Thread.sleep(20) }
                    val millis = (System.nanoTime() - sent) / 1_000_000
                    println("UNANSWERED-REJOIN ${millis}ms")
                    assertTrue(millis in 14_900..17_500, "Rejoined 15 s after the unanswered data, give or take a loaded host: ${millis}ms")
                    eventually("And handshook again") {
                        relay.sourcedPackets.count { it.first == client.publicKey && WireGuard.packetType(it.second) == 1 } > initiations
                    }
                    relay.droppedTransportSource = null
                    client.dialTCP(80, 10_000).let { try { exchange(it, "after the rejoin") } finally { it.close() } }
                } finally { client.close() }
            }
        }
    }

    @Test fun dataReceivedIsAnsweredWithAPassiveKeepaliveWithin10Seconds() {
        LocalRelay().use { relay ->
            val reply: TailcatUDPHandler = { flow -> try { flow.send(flow.receive(10_000)); Thread.sleep(20_000) } finally { flow.close() } }
            RestartableServer(relay, echo, reply).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    val flow = client.dialUDP(9)
                    flow.send("ping".encodeToByteArray())
                    assertContentEquals("ping".encodeToByteArray(), flow.receive(10_000))
                    val received = System.nanoTime()
                    val already = relay.sourcedPackets.size
                    fun keepalive() = relay.sourcedPackets.drop(already).any { it.first == client.publicKey && it.second.size == 32 && WireGuard.packetType(it.second) == 4 }
                    val deadline = received + TimeUnit.SECONDS.toNanos(15)
                    while (!keepalive()) { check(System.nanoTime() < deadline) { "No passive keepalive" }; Thread.sleep(20) }
                    val millis = (System.nanoTime() - received) / 1_000_000
                    println("PASSIVE-KEEPALIVE ${millis}ms")
                    assertTrue(millis in 9_900..11_500, "Answered 10 s after the data, not at the 25 s keepalive: ${millis}ms")
                } finally { client.close() }
            }
        }
    }

    @Test fun aFlowUnacknowledgedFor5SecondsHandshakesAgainWhileTheServerStillSends() {
        LocalRelay().use { relay ->
            // Port 81 writes forever: the server keeps sending, so something always comes back.
            val handler: TailcatTCPHandler = { connection ->
                if (connection.localPort == 81) try { while (true) { connection.write("tick".encodeToByteArray(), timeoutMillis = 60_000); Thread.sleep(100) } } catch (_: Exception) { connection.close() }
                else echo(connection)
            }
            RestartableServer(relay, handler).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    val talking = client.dialTCP(81)
                    val reader = thread(isDaemon = true) { try { while (talking.read(4096, 30_000).isNotEmpty()) { } } catch (_: Exception) { } }
                    val connection = client.dialTCP(80)
                    exchange(connection, "before the server stops reading")
                    val before = meows(relay, client)
                    relay.droppedTransportSource = client.publicKey
                    val wrote = System.nanoTime()
                    thread(isDaemon = true) { try { connection.write("unacknowledged".encodeToByteArray(), timeoutMillis = 30_000) } catch (_: Exception) { } }
                    val deadline = wrote + TimeUnit.SECONDS.toNanos(12)
                    while (meows(relay, client) == before) { check(System.nanoTime() < deadline) { "No rejoin" }; Thread.sleep(20) }
                    val millis = (System.nanoTime() - wrote) / 1_000_000
                    println("OWED-REJOIN ${millis}ms")
                    assertTrue(millis in 5_000..7_000, "5 s after its first retransmission: ${millis}ms")
                    relay.droppedTransportSource = null
                    talking.close(); reader.join(5000); connection.close()
                } finally { client.close() }
            }
        }
    }

    @Test fun theTickThatEndsASuspensionDoesNotCountItAsUnanswered() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    val before = meows(relay, client)
                    relay.droppedTransportSource = client.publicKey
                    val sent = relay.sourcedPackets.size
                    client.dialUDP(9).send("sent just before a suspension".encodeToByteArray())
                    eventually("Sent") { relay.sourcedPackets.drop(sent).any { it.first == client.publicKey && WireGuard.packetType(it.second) == 4 } }
                    // The timer's first tick may come before the wake: 20 s away is not 20 s unanswered.
                    client.resumeForTesting(20_000)
                    Thread.sleep(1000)
                    assertEquals(before, meows(relay, client), "No rejoin for the time away")
                } finally { client.close() }
            }
        }
    }

    @Test fun aRejoinUnderWayKeepsItsHandshakeSpacingThroughAnotherMeowAgain() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    client.dialTCP(80).let { try { exchange(it, "before") } finally { it.close() } }
                    val server = restartable.server.publicKey
                    fun initiations() = relay.sourcedPackets.count { it.first == client.publicKey && WireGuard.packetType(it.second) == 1 }
                    val before = initiations()
                    // Hold the server's answer, so the rejoin is still under way when the next meow again comes.
                    relay.dropped = { source, packet -> source == server && WireGuard.packetType(packet) == 2 }
                    relay.inject(server, client.publicKey, meowAgain)
                    eventually("The rejoin initiates") { initiations() > before }
                    // The server answers each packet the client still sends on the old session.
                    relay.inject(server, client.publicKey, meowAgain)
                    Thread.sleep(500)
                    assertEquals(before + 1, initiations(), "No second initiation inside the first one's second")
                    relay.dropped = null
                    eventually("The rejoin's next initiation completes") { initiations() > before + 1 }
                    client.dialTCP(80, 10_000).let { try { exchange(it, "after the rejoin") } finally { it.close() } }
                } finally { client.close() }
            }
        }
    }

    @Test fun aCheckWaitsThreeOfTheRelaysRoundTripsAtLeastASecond() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    // A check on a live relay measures its round trip, a millisecond here.
                    client.wake(); Thread.sleep(500)
                    val connections = relay.connections.get()
                    relay.silence(client.publicKey)
                    val woke = System.nanoTime()
                    client.wake()
                    eventually("The silent relay is replaced") { relay.connections.get() > connections }
                    val millis = (System.nanoTime() - woke) / 1_000_000
                    println("MEASURED-CHECK ${millis}ms")
                    assertTrue(millis in 900..1400, "Replaced after a second: ${millis}ms")
                } finally { client.close() }
            }
        }
    }

    @Test fun aRelayReplacedAfterAFailureGetsWhatEachFlowOwesAtOnce() {
        LocalRelay().use { relay ->
            RestartableServer(relay, echo).use { restartable ->
                val client = TailcatClient.connect(restartable.address, ClientConfiguration(testOnlyPlaintextDERP = true, relayFirst = true))
                try {
                    val connection = client.dialTCP(80)
                    exchange(connection, "before the relay goes silent")
                    // A move nobody is told of: the relay connection goes dead with nothing said.
                    relay.silence(client.publicKey)
                    val began = System.nanoTime()
                    val done = java.util.concurrent.atomic.AtomicReference<Throwable?>(null)
                    val owed = thread(isDaemon = true) { try { exchange(connection, "sent into the dead relay") } catch (failure: Throwable) { done.set(failure) } }
                    // Its segment backs off: 0.5, 1.5 and 3.5 s, then not until 7.5 s.
                    Thread.sleep(4000)
                    client.wake()
                    owed.join(10_000); done.get()?.let { throw it }
                    val millis = (System.nanoTime() - began) / 1_000_000
                    println("RELAY-RECOVERY-RESEND ${millis}ms")
                    assertTrue(millis < 6500, "Resent when the relay was replaced at about 5.5 s, not at 7.5 s: ${millis}ms")
                } finally { client.close() }
            }
        }
    }

    @Test fun realDerpMarkerBarrierPreservesPriorityAndAllowsRekeyControlAndOtherPeers() {
        LocalRelay().use { fixture ->
            val identity = NodePrivateKey.generate()
            val blockedPeer = NodePrivateKey.generate().publicKey
            val otherPeer = NodePrivateKey.generate().publicKey
            val transport = DerpTransport(fixture.region.nodes, identity, true) { }
            try {
                transport.start(5000)
                val data = ByteArray(48).also { it[0] = 4; it[16] = 11 }
                val handshake = ByteArray(148).also { it[0] = 1 }
                val otherData = ByteArray(48).also { it[0] = 4; it[16] = 12 }
                val marker = ByteArray(32).also { it[0] = 4; it[8] = 1 }
                transport.setResetBarrier(blockedPeer, true)
                transport.send(blockedPeer, data)
                transport.send(blockedPeer, handshake)
                transport.send(otherPeer, otherData)
                eventually("Handshake and unrelated peer must bypass missing marker key") {
                    fixture.packets.any { it.contentEquals(handshake) } && fixture.packets.any { it.contentEquals(otherData) }
                }
                assertFalse(fixture.packets.any { it.contentEquals(data) })
                transport.queueResetMarker(blockedPeer, marker)
                eventually("Marker and deferred application data should drain") { fixture.packets.any { it.contentEquals(data) } }
                assertTrue(fixture.packets.indexOfFirst { it.contentEquals(marker) } < fixture.packets.indexOfFirst { it.contentEquals(data) })
                eventually("Completed marker must stop forcing data through DERP") { !transport.hasResetMarker(blockedPeer) }
                transport.setResetBarrier(blockedPeer, true)
                val unavailable = data.copyOf().also { it[17] = 7 }
                transport.send(blockedPeer, unavailable)
                transport.discardResetMarker(blockedPeer)
                eventually("Expired/missing key or removed peer must release barrier") { fixture.packets.any { it.contentEquals(unavailable) } }
            } finally { transport.close() }
        }
    }
}