package io.tailcat

import io.tailcat.platform.*
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.*

class RelayFirstTransportTest {
    private class Gate {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        fun block() { entered.countDown(); check(release.await(10, TimeUnit.SECONDS)) }
        fun await() { assertTrue(entered.await(3, TimeUnit.SECONDS), "Discovery did not enter gate") }
    }
    private class Udp(override val localPort: Int) : NetworkUdp {
        val writes = LinkedBlockingQueue<Pair<Endpoint, ByteArray>>()
        val reads = LinkedBlockingQueue<RawDatagram>()
        val closed = AtomicBoolean()
        var failSend = false
        var failReceive = false
        override fun send(destination: Endpoint, data: ByteArray) {
            check(!closed.get() && !failSend) { "UDP unavailable" }
            writes.add(destination to data)
        }
        override fun receive(): RawDatagram? {
            check(!closed.get() && !failReceive)
            return reads.poll(25, TimeUnit.MILLISECONDS)
        }
        override fun close() { closed.set(true) }
    }
    private class Environment : NetworkEnvironment() {
        val time = AtomicLong(100_000)
        val sockets = CopyOnWriteArrayList<Udp>()
        val addressCalls = AtomicInteger()
        var bindGate: Gate? = null
        var addressGate: Gate? = null
        var resolveGate: Gate? = null
        var failReceive = false
        @Volatile var hosts = listOf("192.0.2.1")
        override fun now(): Long = time.get()
        override fun addresses(): List<String> { addressCalls.incrementAndGet(); addressGate?.block(); return hosts }
        override fun resolve(host: String): List<String> { resolveGate?.block(); return listOf("192.0.2.53") }
        override fun udp(ipv6: Boolean): NetworkUdp {
            if (ipv6) throw TailcatException("IPv6 unavailable in fixture")
            bindGate?.block()
            return Udp(10_000 + sockets.size).also { it.failReceive = failReceive; sockets.add(it) }
        }
    }
    private class Relay(val incoming: (DerpPacket) -> Unit) : NetworkRelay {
        val writes = LinkedBlockingQueue<Pair<NodePublicKey, ByteArray>>()
        @Volatile override var connectionGeneration: Long? = null
        var reconnects = 0
        var checks = 0
        var closed = false
        val resetBarriers = mutableSetOf<NodePublicKey>()
        val markers = mutableMapOf<NodePublicKey, ByteArray>()
        override fun start(timeoutMillis: Long) { connectionGeneration = 1 }
        override fun send(key: NodePublicKey, packet: ByteArray) { check(!closed); writes.add(key to packet) }
        override fun setResetBarrier(key: NodePublicKey, blocked: Boolean) { if (blocked) resetBarriers.add(key) else resetBarriers.remove(key) }
        override fun queueResetMarker(key: NodePublicKey, packet: ByteArray) { markers[key] = packet; writes.add(key to packet); resetBarriers.remove(key) }
        override fun hasResetMarker(key: NodePublicKey) = key in markers
        override fun discardResetMarker(key: NodePublicKey) { markers.remove(key); resetBarriers.remove(key) }
        override fun tick(now: Long) = Unit
        override fun reconnect() { reconnects++; connectionGeneration = null }
        override fun check(deadlineMillis: Long) { checks++ }
        override fun close() { closed = true; connectionGeneration = null; markers.clear(); resetBarriers.clear() }
    }
    private class Fixture(val environment: Environment = Environment(), relayFirst: Boolean = true, stun: Boolean = false) {
        val local = NodePrivateKey.generate()
        val remote = NodePrivateKey.generate()
        val endpoint = Endpoint("198.51.100.2", 4000)
        lateinit var relay: Relay
        val received = LinkedBlockingQueue<ByteArray>()
        val restarted = LinkedBlockingQueue<NodePublicKey>()
        val transport = NetworkTransport(local, listOf(DERPNode("fixture", stunPort = if (stun) 3478 else -1)),
            relayFirst = relayFirst, environment = environment, relayFactory = { Relay(it).also { r -> relay = r } },
            restarted = { restarted.add(it) }) { _, packet, _ -> received.add(packet) }
        init { transport.configurePeer(remote.publicKey, remote.discoPublicKey); transport.start() }
        fun callMeMaybe(endpoints: List<Endpoint> = listOf(endpoint)) = relay.incoming(DerpPacket(remote.publicKey, seal(DiscoveryMessage.CallMeMaybe(endpoints))))
        fun seal(message: DiscoveryMessage): ByteArray = Discovery.seal(message, local.discoPublicKey, remote.discoPrivateKey, remote.discoPublicKey)
        fun ping(socket: Udp): DiscoveryMessage.Ping {
            val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (System.nanoTime() < end) {
                val packet = socket.writes.poll(50, TimeUnit.MILLISECONDS)?.second
                if (packet == null) { advance(); continue }
                if (Discovery.sourceKey(packet) != null) {
                    val message = Discovery.open(packet, remote.discoPrivateKey).second
                    if (message is DiscoveryMessage.Ping) return message
                }
            }
            error("No direct probe")
        }
        fun pong(socket: Udp, ping: DiscoveryMessage.Ping, source: Endpoint = endpoint) {
            socket.reads.add(RawDatagram(source, seal(DiscoveryMessage.Pong(ping.transaction, Endpoint("192.0.2.1", socket.localPort)))))
        }
        fun advance(millis: Long = 1000) { environment.time.addAndGet(millis) }
        fun close() { transport.close(); environment.bindGate?.release?.countDown(); environment.addressGate?.release?.countDown(); environment.resolveGate?.release?.countDown() }
    }
    private fun eventually(message: String = "Condition did not become true", predicate: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
        while (!predicate()) { check(System.nanoTime() < end) { message }; Thread.sleep(10) }
    }
    private fun validated(f: Fixture): Udp {
        eventually { f.environment.sockets.isNotEmpty() }
        val udp = f.environment.sockets.last()
        f.transport.authenticated(f.remote.publicKey)
        f.advance(); f.callMeMaybe(); f.pong(udp, f.ping(udp))
        eventually { f.transport.path(f.remote.publicKey) is ConnectionPath.Direct }
        return udp
    }
    private fun barrier(f: Fixture) {
        f.relay.incoming(DerpPacket(f.remote.publicKey, byteArrayOf(99)))
        assertContentEquals(byteArrayOf(99), f.received.poll(1, TimeUnit.SECONDS))
    }
    private fun pingTo(f: Fixture, udp: Udp, endpoint: Endpoint): DiscoveryMessage.Ping? = udp.writes
        .filter { it.first == endpoint && Discovery.sourceKey(it.second) != null }
        .map { Discovery.open(it.second, f.remote.discoPrivateKey).second }
        .filterIsInstance<DiscoveryMessage.Ping>().firstOrNull()

    @Test fun anInvitationThatMovesEveryPortSaysThePeerRestarted() {
        val f = Fixture()
        try {
            eventually { f.environment.sockets.isNotEmpty() }
            f.transport.authenticated(f.remote.publicKey)
            f.callMeMaybe(listOf(Endpoint("198.51.100.2", 4000), Endpoint("203.0.113.9", 4000))); barrier(f)
            f.callMeMaybe(listOf(Endpoint("198.51.100.2", 4000), Endpoint("198.51.100.3", 4000))); barrier(f)
            assertTrue(f.restarted.isEmpty(), "The first invitation, and one that keeps a port, are no restart")
            f.callMeMaybe(listOf(Endpoint("198.51.100.2", 4001), Endpoint("198.51.100.3", 4001))); barrier(f)
            assertEquals(f.remote.publicKey, f.restarted.poll(1, TimeUnit.SECONDS))
            f.callMeMaybe(listOf(Endpoint("198.51.100.2", 4001), Endpoint("198.51.100.2", 4002))); barrier(f)
            assertTrue(f.restarted.isEmpty(), "One that keeps a port is not another")
            // Forged by anyone but the peer: never opened.
            f.relay.incoming(DerpPacket(NodePrivateKey.generate().publicKey, f.seal(DiscoveryMessage.CallMeMaybe(listOf(Endpoint("198.51.100.2", 4009)))))); barrier(f)
            assertTrue(f.restarted.isEmpty())
        } finally { f.close() }
    }

    @Test fun aRelayResetMarkerReprobesAtOnceAndOnceMore() {
        val f = Fixture()
        try {
            val udp = validated(f)
            f.advance(); f.transport.recheck(); barrier(f) // A wake probes the route.
            assertNotNull(pingTo(f, udp, f.endpoint))
            udp.writes.clear()
            // The peer's marker comes just after, and cancels that probe with the route.
            f.transport.authenticatedRelayReset(f.remote.publicKey)
            assertNotNull(pingTo(f, udp, f.endpoint), "Probed again at once, not after the one-second spacing")
            udp.writes.clear()
            f.advance(1000)
            eventually("And once more after the spacing") { pingTo(f, udp, f.endpoint) != null }
        } finally { f.close() }
    }

    @Test fun aSendThatFindsTheDirectRouteExpiredReprobesAtOnce() {
        val f = Fixture()
        try {
            val udp = validated(f)
            f.advance(31_000)
            eventually("The maintenance probe") { pingTo(f, udp, f.endpoint) != null }
            udp.writes.clear()
            assertTrue(f.transport.trySend(f.remote.publicKey, ByteArray(148).also { it[0] = 1 }))
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            assertNotNull(pingTo(f, udp, f.endpoint), "The send that expired the route probes it again at once")
        } finally { f.close() }
    }

    @Test fun defaultsRemainOptIn() {
        assertFalse(ClientConfiguration().relayFirst)
        assertFalse(ServerConfiguration().relayFirst)
    }

    @Test fun emptyProbeDoesNotDelayFirstAuthenticatedCandidate() {
        for (mode in listOf(false, true)) {
            val f = Fixture(relayFirst = mode)
            try {
                eventually { f.environment.sockets.isNotEmpty() }
                val udp = f.environment.sockets.single()
                f.transport.authenticated(f.remote.publicKey)
                barrier(f) // Process the empty pending round, without advancing the fake clock.
                assertTrue(udp.writes.isEmpty())
                f.advance(100)
                f.callMeMaybe(); barrier(f)
                eventually("Empty probes must not impose a one-second wait on the first real challenge") {
                    pingTo(f, udp, f.endpoint) != null
                }
                assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey), "A candidate is not a validated path")
                val count = udp.writes.size
                repeat(50) { f.transport.authenticated(f.remote.publicKey); f.callMeMaybe() }
                barrier(f)
                assertEquals(count, udp.writes.size, "Real probes must still obey the per-peer limiter")
                f.pong(udp, checkNotNull(pingTo(f, udp, f.endpoint)))
                eventually { f.transport.path(f.remote.publicKey) is ConnectionPath.Direct }
            } finally { f.close() }
        }
    }

    @Test fun openingAuthenticationGateImmediatelyInvitesAndProbesOnlyOnce() {
        val f = Fixture()
        try {
            eventually { f.environment.sockets.isNotEmpty() }
            val udp = f.environment.sockets.single()
            f.callMeMaybe(); barrier(f)
            assertTrue(udp.writes.isEmpty(), "Relay-first must not probe before authentication")
            assertTrue(f.relay.writes.none { Discovery.sourceKey(it.second) != null })
            f.transport.authenticated(f.remote.publicKey)
            assertNotNull(pingTo(f, udp, f.endpoint), "Opening the gate must immediately challenge known candidates")
            val invitations = f.relay.writes.count { Discovery.sourceKey(it.second) != null }
            assertEquals(1, invitations, "Opening the gate must advertise without waiting for maintenance")
            val probes = udp.writes.size
            repeat(100) { f.transport.authenticated(f.remote.publicKey) }
            assertEquals(probes, udp.writes.size)
            assertEquals(invitations, f.relay.writes.count { Discovery.sourceKey(it.second) != null })
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
        } finally { f.close() }
    }

    @Test fun relayTrafficDoesNotWaitForUdpBindingInterfacesOrStun() {
        for (phase in 0..2) {
            val gate = Gate()
            val environment = Environment().apply {
                when (phase) { 0 -> bindGate = gate; 1 -> addressGate = gate; else -> resolveGate = gate }
            }
            val f = Fixture(environment, stun = true)
            try {
                gate.await()
                val packet = byteArrayOf(4, 3, 2, 1)
                f.transport.send(f.remote.publicKey, packet)
                assertTrue(f.relay.writes.any { it.second.contentEquals(packet) })
                f.relay.incoming(DerpPacket(f.remote.publicKey, packet))
                assertContentEquals(packet, f.received.poll(1, TimeUnit.SECONDS))
                assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
                repeat(100) { f.transport.retryDirect() }
                assertTrue(environment.addressCalls.get() <= 1, "Requests must share one discovery worker")
            } finally { f.close() }
        }
    }

    @Test fun onlyMatchingPongUpgradesAndRelayFirstWaitsForEncryption() {
        val f = Fixture()
        try {
            eventually { f.environment.sockets.isNotEmpty() }
            val udp = f.environment.sockets.last()
            f.callMeMaybe()
            f.transport.send(f.remote.publicKey, byteArrayOf(1))
            assertTrue(f.relay.writes.any { it.second.contentEquals(byteArrayOf(1)) })
            assertTrue(udp.writes.isEmpty(), "No direct discovery before encrypted session establishment")
            f.transport.authenticated(f.remote.publicKey)
            f.advance(); f.callMeMaybe(); val ping = f.ping(udp)
            f.pong(udp, ping, Endpoint("198.51.100.3", 4000))
            f.relay.incoming(DerpPacket(f.remote.publicKey, byteArrayOf(9)))
            assertNotNull(f.received.poll(1, TimeUnit.SECONDS))
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            f.pong(udp, ping)
            // A subsequent UDP event confirms the matching Pong was processed.
            udp.reads.add(RawDatagram(f.endpoint, byteArrayOf(7)))
            assertContentEquals(byteArrayOf(7), f.received.poll(1, TimeUnit.SECONDS))
            eventually { f.transport.path(f.remote.publicKey) is ConnectionPath.Direct }
            f.transport.send(f.remote.publicKey, byteArrayOf(2))
            assertTrue(udp.writes.any { it.second.contentEquals(byteArrayOf(2)) })
        } finally { f.close() }
    }

    @Test fun retryIsNonDisruptiveAndRelayRecoveryKeepsDirectAndRelayIngress() {
        val f = Fixture()
        try {
            val udp = validated(f)
            f.relay.connectionGeneration = null
            f.advance(); f.transport.retryDirect()
            assertTrue(f.transport.path(f.remote.publicKey) is ConnectionPath.Direct)
            f.transport.send(f.remote.publicKey, byteArrayOf(5))
            assertTrue(udp.writes.any { it.second.contentEquals(byteArrayOf(5)) })
            f.relay.connectionGeneration = 2
            f.advance()
            f.relay.incoming(DerpPacket(f.remote.publicKey, byteArrayOf(8)))
            assertContentEquals(byteArrayOf(8), f.received.poll(1, TimeUnit.SECONDS))
            assertTrue(f.transport.path(f.remote.publicKey) is ConnectionPath.Direct)
        } finally { f.close() }
    }

    @Test fun directSendFailureAndSilentExpiryFallBackToRelay() {
        for (sendFailure in listOf(true, false)) {
            val f = Fixture()
            try {
                val udp = validated(f)
                if (sendFailure) udp.failSend = true else f.advance(30_001)
                f.transport.send(f.remote.publicKey, byteArrayOf(42))
                assertTrue(f.relay.writes.any { it.second.contentEquals(byteArrayOf(42)) })
                assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            } finally { f.close() }
        }
    }

    @Test fun networkChangeRebindsAndRejectsOldProbeOnOldAndNewSockets() {
        val f = Fixture()
        try {
            val old = validated(f)
            f.advance(); f.transport.retryDirect(); val pending = f.ping(old)
            f.transport.networkChanged()
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            eventually { f.environment.sockets.size == 2 }
            val fresh = f.environment.sockets.last()
            assertTrue(old.closed.get()); assertNotEquals(old.localPort, fresh.localPort)
            f.pong(old, pending); f.pong(fresh, pending)
            Thread.sleep(100)
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            f.advance(); f.callMeMaybe(); f.pong(fresh, f.ping(fresh))
            eventually { f.transport.path(f.remote.publicKey) is ConnectionPath.Direct }
            assertEquals(1, f.relay.reconnects)
        } finally { f.close() }
    }

    @Test fun recheckKeepsTheDirectRouteThatAnswersAndDropsOneThatDoesNot() {
        for (answers in listOf(true, false)) {
            val f = Fixture()
            try {
                val udp = validated(f)
                f.advance(); udp.writes.clear()
                f.transport.recheck(2000)
                assertEquals(1, f.relay.checks)
                val ping = assertNotNull(pingTo(f, udp, f.endpoint), "The direct route is probed at once")
                assertTrue(f.relay.writes.any { Discovery.sourceKey(it.second) != null }, "Addresses are advertised again at once")
                if (answers) {
                    f.pong(udp, ping)
                    udp.reads.add(RawDatagram(f.endpoint, byteArrayOf(91)))
                    assertContentEquals(byteArrayOf(91), f.received.poll(1, TimeUnit.SECONDS))
                }
                f.advance(2001); barrier(f)
                if (answers) assertEquals(ConnectionPath.Direct(f.endpoint.toString()), f.transport.path(f.remote.publicKey))
                else {
                    eventually { f.transport.path(f.remote.publicKey) == ConnectionPath.Relay }
                    assertNotNull(f.transport.pendingResetMarker(f.remote.publicKey), "The peer is told to leave the dead route too")
                }
                assertEquals(0, f.relay.reconnects)
                assertEquals(1, f.environment.sockets.size); assertFalse(udp.closed.get())
            } finally { f.close() }
        }
    }

    @Test fun automaticAddressChangeChecksWithoutRebindingAndCloseRejectsInFlightDiscovery() {
        val f = Fixture()
        try {
            val old = validated(f)
            f.environment.hosts = listOf("192.0.2.2")
            f.advance(); f.transport.retryDirect()
            eventually { f.relay.checks == 1 }
            f.pong(old, checkNotNull(pingTo(f, old, f.endpoint)))
            old.reads.add(RawDatagram(f.endpoint, byteArrayOf(92)))
            assertContentEquals(byteArrayOf(92), f.received.poll(1, TimeUnit.SECONDS))
            f.advance(2001); barrier(f)
            assertEquals(ConnectionPath.Direct(f.endpoint.toString()), f.transport.path(f.remote.publicKey))
            assertFalse(old.closed.get()); assertEquals(1, f.environment.sockets.size)
            assertEquals(0, f.relay.reconnects)
        } finally { f.close() }
        val gate = Gate()
        val blocked = Fixture(Environment().apply { bindGate = gate })
        gate.await()
        blocked.transport.close()
        assertFailsWith<TailcatClosedException> { blocked.transport.retryDirect() }
        assertFailsWith<TailcatClosedException> { blocked.transport.networkChanged() }
        assertFailsWith<TailcatClosedException> { blocked.transport.recheck() }
        assertFailsWith<TailcatClosedException> { blocked.transport.send(blocked.remote.publicKey, byteArrayOf()) }
        gate.release.countDown()
        eventually { blocked.environment.sockets.singleOrNull()?.closed?.get() == true }
        assertTrue(blocked.relay.closed)
    }

    @Test fun staleDiscoveryCompletionAndRemovedPeerCannotResurrectRoutes() {
        val gate = Gate()
        val f = Fixture(Environment().apply { addressGate = gate })
        try {
            gate.await()
            val old = f.environment.sockets.single()
            f.transport.authenticated(f.remote.publicKey)
            f.advance(); f.callMeMaybe(); val pending = f.ping(old)
            repeat(100) { f.transport.networkChanged() }
            assertEquals(100, f.relay.reconnects)
            f.environment.addressGate = null; gate.release.countDown()
            eventually { f.environment.sockets.size == 2 }
            val fresh = f.environment.sockets.last()
            f.transport.removePeer(f.remote.publicKey)
            f.transport.configurePeer(f.remote.publicKey, f.remote.discoPublicKey)
            f.transport.authenticated(f.remote.publicKey)
            f.pong(fresh, pending)
            Thread.sleep(100)
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            assertTrue(old.closed.get())
        } finally { f.close() }
    }

    @Test fun unansweredProbesBackOffAndExplicitRetryDoesNotCreateWorkers() {
        val f = Fixture()
        try {
            eventually { f.environment.sockets.isNotEmpty() }
            val udp = f.environment.sockets.last()
            f.transport.authenticated(f.remote.publicKey)
            f.advance(); f.callMeMaybe(); f.ping(udp)
            repeat(60) { f.advance(); Thread.sleep(60) }
            val automatic = udp.writes.count { Discovery.sourceKey(it.second) != null }
            assertTrue(automatic in 2..8, "Expected bounded exponential backoff, got $automatic probes in a minute")
            udp.writes.clear()
            repeat(100) { f.transport.retryDirect() }
            f.advance(); f.ping(udp)
            assertEquals(1, f.environment.sockets.size)
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
        } finally { f.close() }
    }

    @Test fun persistentUdpReadFailureBacksOffWithoutRestartingHealthyRelay() {
        val f = Fixture(Environment().apply { failReceive = true })
        try {
            eventually { f.environment.sockets.singleOrNull()?.closed?.get() == true }
            repeat(100) { f.transport.retryDirect() }
            Thread.sleep(100)
            assertEquals(1, f.environment.sockets.size, "No hot-loop rebinding on persistent UDP errors")
            assertEquals(0, f.relay.reconnects)
            f.transport.send(f.remote.publicKey, byteArrayOf(44))
            assertTrue(f.relay.writes.any { it.second.contentEquals(byteArrayOf(44)) })
            f.advance(1000); f.transport.retryDirect()
            eventually { f.environment.sockets.size == 2 && f.environment.sockets.last().closed.get() }
            f.advance(1000); f.transport.retryDirect(); Thread.sleep(100)
            assertEquals(2, f.environment.sockets.size, "Second retry must wait for the doubled backoff")
        } finally { f.close() }
    }

    @Test fun freshEndpointInsideLimiterSurvivesLateOldPongAndIsProbedWithinOneSecond() {
        for (viaPing in listOf(false, true)) {
            val f = Fixture()
            try {
                val udp = validated(f)
                f.advance(); f.transport.retryDirect(); val oldPending = f.ping(udp)
                val fresh = f.endpoint.copy(port = f.endpoint.port + 1)
                f.advance(100)
                if (viaPing) {
                    udp.reads.add(RawDatagram(fresh, f.seal(DiscoveryMessage.Ping(secureRandom(12), f.remote.publicKey.raw))))
                    udp.reads.add(RawDatagram(fresh, byteArrayOf(98)))
                    assertContentEquals(byteArrayOf(98), f.received.poll(1, TimeUnit.SECONDS))
                } else {
                    f.relay.incoming(DerpPacket(f.remote.publicKey, f.seal(DiscoveryMessage.CallMeMaybe(listOf(f.endpoint, fresh)))))
                    barrier(f)
                }
                // This old-round success used to overwrite the new request with a ten-second delay.
                f.pong(udp, oldPending)
                udp.reads.add(RawDatagram(f.endpoint, byteArrayOf(97)))
                assertContentEquals(byteArrayOf(97), f.received.poll(1, TimeUnit.SECONDS))
                assertEquals(ConnectionPath.Direct(f.endpoint.toString()), f.transport.path(f.remote.publicKey))
                assertNull(pingTo(f, udp, fresh), "The one-second rate limit must still apply")
                f.advance(899); barrier(f)
                assertNull(pingTo(f, udp, fresh))
                f.advance(1)
                eventually("Fresh candidate request was dropped inside the limiter") { pingTo(f, udp, fresh) != null }
                f.pong(udp, checkNotNull(pingTo(f, udp, fresh)), fresh)
                eventually { f.transport.path(f.remote.publicKey) == ConnectionPath.Direct(fresh.toString()) }
            } finally { f.close() }
        }
    }

    @Test fun freshCandidateTakesPriorityOverFullStaleEndpointCache() {
        val f = Fixture()
        try {
            val udp = validated(f)
            val stale = (0 until 127).map { Endpoint("198.51.100.10", 5000 + it) }
            f.relay.incoming(DerpPacket(f.remote.publicKey, f.seal(DiscoveryMessage.CallMeMaybe(listOf(f.endpoint) + stale))))
            barrier(f)
            f.advance()
            eventually { udp.writes.count { it.first in stale } >= 8 }
            val fresh = Endpoint("198.51.100.2", 9000)
            f.advance(100)
            f.relay.incoming(DerpPacket(f.remote.publicKey, f.seal(DiscoveryMessage.CallMeMaybe(listOf(f.endpoint, fresh)))))
            barrier(f)
            assertEquals(ConnectionPath.Direct(f.endpoint.toString()), f.transport.path(f.remote.publicKey))
            f.advance(900)
            eventually("New remote ports must precede stale candidate rounds") { pingTo(f, udp, fresh) != null }
            f.pong(udp, checkNotNull(pingTo(f, udp, fresh)), fresh)
            eventually { f.transport.path(f.remote.publicKey) == ConnectionPath.Direct(fresh.toString()) }
        } finally { f.close() }
    }

    @Test fun globalBudgetExhaustionDefersRatherThanDropsFreshCandidate() {
        val f = Fixture()
        try {
            val udp = validated(f)
            val beforeWindow = udp.writes.size
            f.advance(); barrier(f)
            // Include any maintenance probe at this window's opening, rather than clearing a
            // packet that already consumed part of the same shared budget.
            // Freeze the clock while forty authenticated peers share the 32-packet budget.
            repeat(40) { index ->
                val remote = NodePrivateKey.generate()
                f.transport.configurePeer(remote.publicKey, remote.discoPublicKey)
                f.transport.authenticated(remote.publicKey)
                val packet = Discovery.seal(DiscoveryMessage.CallMeMaybe(listOf(Endpoint("198.51.100.20", 6000 + index))),
                    f.local.discoPublicKey, remote.discoPrivateKey, remote.discoPublicKey)
                f.relay.incoming(DerpPacket(remote.publicKey, packet))
                barrier(f)
            }
            assertEquals(32, udp.writes.size - beforeWindow, "Probe budget must remain globally bounded")
            val fresh = Endpoint("198.51.100.2", 9100)
            f.relay.incoming(DerpPacket(f.remote.publicKey, f.seal(DiscoveryMessage.CallMeMaybe(listOf(f.endpoint, fresh)))))
            barrier(f)
            assertNull(pingTo(f, udp, fresh))
            f.advance()
            eventually("Budget exhaustion must retain the requested probe") { pingTo(f, udp, fresh) != null }
            assertTrue(udp.writes.size - beforeWindow <= 64)
        } finally { f.close() }
    }

    @Test fun withdrawnSelectedEndpointFallsBackUntilFreshPongAndOldPongCannotRestoreIt() {
        val f = Fixture()
        try {
            val udp = validated(f)
            f.advance(); f.transport.retryDirect(); val oldPending = f.ping(udp)
            f.advance(100)
            // Empty/unchanged advertisements and a voluntary retry preserve the validated route.
            f.relay.incoming(DerpPacket(f.remote.publicKey, f.seal(DiscoveryMessage.CallMeMaybe(listOf(f.endpoint)))))
            f.relay.incoming(DerpPacket(f.remote.publicKey, f.seal(DiscoveryMessage.CallMeMaybe(emptyList()))))
            barrier(f)
            assertEquals(ConnectionPath.Direct(f.endpoint.toString()), f.transport.path(f.remote.publicKey))
            val fresh = f.endpoint.copy(port = 9200)
            f.relay.incoming(DerpPacket(f.remote.publicKey, f.seal(DiscoveryMessage.CallMeMaybe(listOf(fresh)))))
            barrier(f)
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            f.pong(udp, oldPending)
            udp.reads.add(RawDatagram(f.endpoint, byteArrayOf(96)))
            assertContentEquals(byteArrayOf(96), f.received.poll(1, TimeUnit.SECONDS))
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            f.transport.send(f.remote.publicKey, byteArrayOf(45))
            assertTrue(f.relay.writes.any { it.second.contentEquals(byteArrayOf(45)) })
            f.advance(900)
            eventually { pingTo(f, udp, fresh) != null }
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey), "A probe request is not validation")
            f.pong(udp, checkNotNull(pingTo(f, udp, fresh)), fresh)
            eventually { f.transport.path(f.remote.publicKey) == ConnectionPath.Direct(fresh.toString()) }
        } finally { f.close() }
    }

    @Test fun remoteResetInvalidatesOldProbeWithoutReflexiveMarker() {
        val f = Fixture()
        try {
            val udp = validated(f)
            f.advance(); f.transport.retryDirect(); val oldPending = f.ping(udp)
            f.advance(100)
            f.transport.authenticatedRelayReset(f.remote.publicKey)
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            assertNull(f.transport.pendingResetMarker(f.remote.publicKey))
            f.pong(udp, oldPending)
            udp.reads.add(RawDatagram(f.endpoint, byteArrayOf(95)))
            assertContentEquals(byteArrayOf(95), f.received.poll(1, TimeUnit.SECONDS))
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            f.advance(900)
            val fresh = f.ping(udp)
            repeat(10) { f.relay.incoming(DerpPacket(f.remote.publicKey, byteArrayOf(4, 1, 2, 3))) }
            f.pong(udp, fresh)
            eventually { f.transport.path(f.remote.publicKey) is ConnectionPath.Direct }
        } finally { f.close() }
    }

    @Test fun resetMarkersAreGenerationScopedBoundedAndPrecedeDataWithoutBlockingControl() {
        val f = Fixture()
        try {
            validated(f)
            val data = ByteArray(48).also { it[0] = 4 }
            val marker = ByteArray(32).also { it[0] = 4 }
            f.transport.networkChanged()
            val obsolete = checkNotNull(f.transport.pendingResetMarker(f.remote.publicKey))
            repeat(100) { f.transport.networkChanged() }
            val latest = checkNotNull(f.transport.pendingResetMarker(f.remote.publicKey))
            assertFalse(f.transport.completeResetMarker(f.remote.publicKey, obsolete, marker))
            assertFalse(f.transport.trySend(f.remote.publicKey, data))
            assertTrue(f.transport.trySend(f.remote.publicKey, byteArrayOf(1, 0, 0, 0)), "Rekey handshakes bypass marker preparation")
            assertEquals(1, f.relay.resetBarriers.size)
            assertTrue(f.transport.completeResetMarker(f.remote.publicKey, latest, marker))
            assertTrue(f.transport.trySend(f.remote.publicKey, data))
            val writes = f.relay.writes.toList()
            assertTrue(writes.indexOfFirst { it.second === marker } < writes.indexOfFirst { it.second === data })
            assertEquals(1, f.relay.markers.size)
            f.transport.networkChanged()
            val noKey = checkNotNull(f.transport.pendingResetMarker(f.remote.publicKey))
            assertTrue(f.transport.completeResetMarker(f.remote.publicKey, noKey, null), "Missing/expired key releases the barrier for rekey")
            assertTrue(f.relay.resetBarriers.isEmpty()); assertTrue(f.relay.markers.isEmpty())
            f.transport.networkChanged()
            val removed = checkNotNull(f.transport.pendingResetMarker(f.remote.publicKey))
            f.transport.removePeer(f.remote.publicKey)
            assertFalse(f.transport.completeResetMarker(f.remote.publicKey, removed, marker))
            assertTrue(f.relay.resetBarriers.isEmpty())
        } finally { f.close() }
    }

    @Test fun changedHintRetiresOldProbeEvenAfterRelayFallbackClearedDirect() {
        val f = Fixture()
        try {
            val udp = validated(f)
            f.advance()
            f.transport.authenticatedRelayReset(f.remote.publicKey)
            val oldPortProof = f.ping(udp)
            val fresh = f.endpoint.copy(port = 9300)
            f.relay.incoming(DerpPacket(f.remote.publicKey, f.seal(DiscoveryMessage.CallMeMaybe(listOf(fresh)))))
            barrier(f)
            f.pong(udp, oldPortProof)
            udp.reads.add(RawDatagram(f.endpoint, byteArrayOf(93)))
            assertContentEquals(byteArrayOf(93), f.received.poll(1, TimeUnit.SECONDS))
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey))
            f.advance()
            eventually { pingTo(f, udp, fresh) != null }
            f.pong(udp, checkNotNull(pingTo(f, udp, fresh)), fresh)
            eventually { f.transport.path(f.remote.publicKey) == ConnectionPath.Direct(fresh.toString()) }
            f.transport.authenticatedRelayReset(f.remote.publicKey)
            assertEquals(ConnectionPath.Relay, f.transport.path(f.remote.publicKey), "A second discrete reset is immediate")
        } finally { f.close() }
    }
}