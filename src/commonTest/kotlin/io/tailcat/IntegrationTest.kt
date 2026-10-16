package io.tailcat

import io.tailcat.platform.*
import kotlin.test.*

class IntegrationTest {
    private class Job<T>(body: () -> T) {
        private val lock = PlatformLock(); private var done = false; private var result: T? = null; private var failure: Throwable? = null
        init { startThread("integration-job") { try { val value = body(); lock.withLock { result = value } } catch (error: Throwable) { lock.withLock { failure = error } } finally { lock.withLock { done = true; lock.signalAll() } } } }
        fun await(): T = lock.withLock { val end = monotonicMillis()+30000; while (!done) { val left = end-monotonicMillis(); check(left > 0); lock.await(left) }; failure?.let { throw it }; @Suppress("UNCHECKED_CAST") (result as T) }
    }
    private fun region(): DERPRegion? = platformTestEnv("TAILCAT_LOCAL_RELAY_PORT")?.toInt()?.let { DERPRegion(1,listOf(DERPNode("127.0.0.1",ipv4="127.0.0.1",derpPort=it,stunPort=-1))) }
    private val echo: TailcatTCPHandler = { connection ->
        try { val bytes = ByteArray(8192); while (true) { val n = connection.read(bytes,timeoutMillis=10000); if (n < 0) break; connection.write(bytes,length=n,timeoutMillis=10000) }; connection.shutdownOutput(10000) }
        finally { connection.close() }
    }
    private fun config(region: DERPRegion) = ServerConfiguration(region=region,testOnlyPlaintextDERP=true)
    private fun connect(address: TailcatAddress, identity: NodePrivateKey? = null) = TailcatClient.connect(address,ClientConfiguration(privateKey=identity,testOnlyPlaintextDERP=true))
    private fun roundtrip(connection: TailcatConnection) {
        val bytes = "a real encrypted socket".encodeToByteArray(); connection.write(bytes,timeoutMillis=10000); assertContentEquals(bytes,connection.read(bytes.size,10000)); connection.shutdownOutput(10000); assertTrue(connection.read(1,10000).isEmpty()); connection.close()
    }
    @Test fun callbacksForwardingAndFreshPolicy() {
        val region = region() ?: return
        val policy = PlatformLock(); var allowed = true
        val server = TailcatServer(config(region).copy(onTCP={ policy.withLock { if (allowed) echo else null } },onTCPForward={ echo },
            onUDPForward={ { connection -> try { connection.send(connection.receive(10000)) } finally { connection.close() } } }))
        val address = server.start(); val client = connect(address)
        try {
            roundtrip(client.dialTCP(80)); policy.withLock { allowed = false }; assertFails { client.dialTCP(80,3000) }; policy.withLock { allowed = true }; roundtrip(client.dialTCP(80))
            for (ip in listOf("198.51.100.7","2001:db8::7")) {
                val endpoint = TailcatEndpoint(ip,8080); roundtrip(client.dialTCP(endpoint))
                val udp = client.dialUDP(endpoint); udp.send(byteArrayOf()); assertTrue(udp.receive(10000).isEmpty()); udp.close()
            }
        } finally { client.close(); server.close() }
    }
    @Test fun peerAttributionEphemeralListenersAndRevoke() {
        val region = region() ?: return
        val keys = KeySet(); val identity = NodePrivateKey.generate(); keys.add(identity.publicKey)
        val server = TailcatServer(config(region).copy(allowClient={ it in keys },servedTCPPorts=emptySet(),servedUDPPorts=emptySet()))
        val address = server.start(); val tcp = server.listenTCP(); val udp = server.listenUDP(); val client = connect(address,identity)
        try {
            val dialing = Job { client.dialTCP(tcp.port) }; val accepted = tcp.accept(10000); val connection = dialing.await()
            assertEquals(identity.publicKey,accepted.peer); assertEquals(identity.publicKey,server.peerKey(accepted))
            val datagrams = client.dialUDP(udp.port); datagrams.send(byteArrayOf()); val flow = udp.accept(10000)
            assertEquals(identity.publicKey,flow.peer); assertEquals(identity.publicKey,server.peerKey(flow)); assertTrue(flow.receive(10000).isEmpty())
            keys.remove(identity.publicKey); connection.write(byteArrayOf(9),timeoutMillis=10000); assertContentEquals(byteArrayOf(9),accepted.read(1,10000))
            val blocked = Job { assertFails { connection.read(1,10000) } }; server.disconnectClient(identity.publicKey); blocked.await()
            flow.close(); datagrams.close()
        } finally { client.close(); server.close() }
    }
    @Test fun slowAdmissionDoesNotBlockOtherPeersAndCannotReturnAfterRevoke() {
        val region = region() ?: return
        val slow = NodePrivateKey.generate(); val gate = PlatformLock(); var entered = false; var release = false
        val server = TailcatServer(config(region).copy(allowClient={ key ->
            if (key == slow.publicKey) gate.withLock { entered = true; gate.signalAll(); while (!release) gate.await(1000) }
            true
        },onTCP={ echo }))
        val address = server.start(); val pending = connect(address,slow)
        var healthy: TailcatClient? = null
        try {
            gate.withLock { val end = monotonicMillis()+10000; while (!entered) { val left=end-monotonicMillis(); check(left > 0); gate.await(left) } }
            healthy = connect(address); roundtrip(healthy.dialTCP(80)); server.disconnectClient(slow.publicKey)
            gate.withLock { release = true; gate.signalAll() }; platformSleep(50)
            assertFails { pending.dialTCP(80,500) }; roundtrip(healthy.dialTCP(80))
        } finally { gate.withLock { release = true; gate.signalAll() }; pending.close(); healthy?.close(); server.close() }
    }
    @Test fun closePendingPublicStartup() {
        val listener = TestListener(); val server = TailcatServer(ServerConfiguration(region=DERPRegion(1,listOf(DERPNode("127.0.0.1",derpPort=listener.port,stunPort=-1)))))
        val starting = Job { assertFails { server.start() } }
        try { assertTrue(listener.awaitAccepted(10000)); server.close(); starting.await() }
        finally { server.close(); listener.close() }
    }
    @Test fun relayNodeFailoverAndRepeatedPathReset() {
        val available = region() ?: return
        val failover = available.copy(nodes=listOf(available.nodes.first().copy(derpPort=1))+available.nodes)
        val server = TailcatServer(config(failover).copy(onTCP={ echo },onUDP={ { flow ->
            try { flow.send(flow.receive(10000)) } finally { flow.close() }
        } }))
        val address = server.start(); val client = connect(address)
        try {
            repeat(3) {
                roundtrip(client.dialTCP(80))
                val udp = client.dialUDP(53)
                try { udp.send(byteArrayOf()); assertTrue(udp.receive(10000).isEmpty()) } finally { udp.close() }
                client.resetNetworkPaths(); server.resetNetworkPaths()
            }
        } finally { client.close(); server.close() }
    }
}
