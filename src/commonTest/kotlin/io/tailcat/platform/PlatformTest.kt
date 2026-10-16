package io.tailcat.platform

import kotlin.test.*

internal expect fun platformTestEnv(name: String): String?
internal expect class TestListener() { val port: Int; fun awaitAccepted(timeoutMillis: Long): Boolean; fun close() }
private class Completion {
    private val lock = PlatformLock(); private var done = false
    var failure: Throwable? = null
        private set
    fun finish(error: Throwable? = null) = lock.withLock { failure = error; done = true; lock.signalAll() }
    fun await(timeoutMillis: Long): Boolean = lock.withLock {
        val deadline = monotonicMillis()+timeoutMillis
        while (!done) { val left = deadline-monotonicMillis(); if (left <= 0) return false; lock.await(left) }; true
    }
}
class PlatformTest {
    @Test fun clocksEntropyThreads() {
        val first = secureRandom(32); assertFalse(first.contentEquals(secureRandom(32))); assertTrue(first.any { it != 0.toByte() }); assertFails { secureRandom(-1) }
        val start = monotonicMillis(); platformSleep(3); assertTrue(monotonicMillis() >= start+1); assertTrue(wallClockMillis() > 1600000000000)
        val lock = PlatformLock(); var count = 0; val workers = List(4) { startThread("counter") { repeat(1000) { lock.withLock { count++ } } } }
        workers.forEach { it.join(2000) }; assertEquals(4000,lock.withLock { count }); assertTrue(resolveHost("localhost").any { it == "127.0.0.1" || it == "::1" })
    }
    private fun udp(ipv6: Boolean) {
        val receiver = PlatformUdp(0,ipv6); val sender = PlatformUdp(0,ipv6)
        try {
            val target = Endpoint(if (ipv6) "::1" else "127.0.0.1",receiver.localPort); val payload = secureRandom(2048)
            sender.send(target,payload); val packet = assertNotNull(receiver.receive(1000)); assertContentEquals(payload,packet.data); assertEquals(sender.localPort,packet.source.port); assertEquals(target.host,packet.source.host)
            sender.send(target,byteArrayOf()); assertEquals(0,assertNotNull(receiver.receive(1000)).data.size)
            val start = monotonicMillis(); assertNull(receiver.receive(30)); assertTrue(monotonicMillis()-start >= 20)
        } finally { receiver.close(); sender.close() }
    }
    @Test fun udp4() = udp(false)
    @Test fun udp6() = udp(true)
    @Test fun closeBlockedUdp() {
        val socket = PlatformUdp(); val entered = Completion(); val finished = Completion()
        val worker = startThread("blocked-udp") { entered.finish(); try { socket.receive(0); finished.finish() } catch (failure: Throwable) { finished.finish(failure) } }
        assertTrue(entered.await(1000)); platformSleep(20); socket.close(); assertTrue(finished.await(1000)); assertNotNull(finished.failure); worker.join(1000)
    }
    @Test fun closeHandshakeAndRead() {
        for (tls in listOf(false,true)) {
            val listener = TestListener(); val stream = PlatformStream(); val connected = Completion(); val finished = Completion()
            val worker = startThread("stalled-stream") {
                try { stream.connect("127.0.0.1",listener.port,tls,"test.invalid",timeoutMillis=10000); connected.finish(); stream.read(ByteArray(32)); finished.finish() }
                catch (failure: Throwable) { finished.finish(failure) }
            }
            try {
                assertTrue(listener.awaitAccepted(3000), "TCP accept tls=$tls")
                if (!tls) assertTrue(connected.await(1000), "plain connect")
                platformSleep(20); stream.close()
                assertTrue(finished.await(1000), "close did not interrupt tls=$tls")
                assertNotNull(finished.failure)
            }
            finally { stream.close(); listener.close(); worker.join(1000) }
        }
    }
    private fun exchange(host: String, port: Int, insecure: Boolean) {
        val stream = PlatformStream()
        try {
            stream.connect(host,port,true,host,host,10000,insecure)
            val received = Completion(); val written = Completion(); var reply = byteArrayOf()
            val reader = startThread("tls-read") { try { val buffer = ByteArray(4096); val count = stream.read(buffer); check(count > 0); reply = buffer.copyOf(count); received.finish() } catch (failure: Throwable) { received.finish(failure) } }
            platformSleep(30)
            val writer = startThread("tls-write") { try { stream.write("GET /derp HTTP/1.1\r\nHost: $host\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n".encodeToByteArray()); written.finish() } catch (failure: Throwable) { written.finish(failure) } }
            try { assertTrue(written.await(5000)); assertNull(written.failure); assertTrue(received.await(5000)); assertNull(received.failure); assertTrue(reply.decodeToString().startsWith("HTTP/1.1 101")) }
            finally { stream.close(); reader.join(1000); writer.join(1000) }
        } finally { stream.close() }
    }
    @Test fun verifiedTlsAndWrongName() {
        val host = platformTestEnv("TAILCAT_PLATFORM_TLS_HOST") ?: return
        val port = platformTestEnv("TAILCAT_PLATFORM_TLS_PORT")?.toInt() ?: 443
        exchange(host,port,false)
        val stream = PlatformStream(); try { assertFails { stream.connect(host,port,true,host,"wrong.invalid",10000) } } finally { stream.close() }
    }
    @Test fun selfSignedTlsRequiresExplicitFlag() {
        val port = platformTestEnv("TAILCAT_PLATFORM_SELF_TLS_PORT")?.toInt() ?: return
        val host = platformTestEnv("TAILCAT_PLATFORM_SELF_TLS_HOST") ?: "127.0.0.1"
        val stream = PlatformStream(); try { assertFails { stream.connect(host,port,true,host,host,3000,false) } } finally { stream.close() }
        exchange(host,port,true)
    }
    @Test fun closeBackpressuredWrite() {
        val listener = TestListener(); val stream = PlatformStream(); val entered = Completion(); val finished = Completion()
        var worker: PlatformThread? = null
        try {
            stream.connect("127.0.0.1",listener.port,false); assertTrue(listener.awaitAccepted(1000))
            worker = startThread("blocked-write") { entered.finish(); try { stream.write(ByteArray(16*1024*1024)); finished.finish() } catch (error: Throwable) { finished.finish(error) } }
            assertTrue(entered.await(1000)); platformSleep(100); stream.close(); assertTrue(finished.await(1000)); assertNotNull(finished.failure)
        } finally { stream.close(); listener.close(); worker?.join(1000) }
    }
    @Test fun closeBlockedTlsRead() {
        val port = platformTestEnv("TAILCAT_PLATFORM_SELF_TLS_PORT")?.toInt() ?: return
        val host = platformTestEnv("TAILCAT_PLATFORM_SELF_TLS_HOST") ?: "127.0.0.1"
        val stream = PlatformStream(); val entered = Completion(); val finished = Completion(); var worker: PlatformThread? = null
        try {
            stream.connect(host,port,true,host,host,3000,true)
            worker = startThread("blocked-tls-read") { entered.finish(); try { stream.read(ByteArray(32)); finished.finish() } catch (error: Throwable) { finished.finish(error) } }
            assertTrue(entered.await(1000)); platformSleep(20); stream.close(); assertTrue(finished.await(1000)); assertNotNull(finished.failure)
        } finally { stream.close(); worker?.join(1000) }
    }
}
