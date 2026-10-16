package io.tailcat.platform

import java.net.ServerSocket
import java.net.Socket

internal actual fun platformTestEnv(name: String): String? = System.getenv(name)
internal actual class TestListener actual constructor() {
    private val server = ServerSocket(0,4,java.net.InetAddress.getByName("127.0.0.1"))
    private val lock = PlatformLock(); private var client: Socket? = null; private var closed = false
    actual val port: Int get() = server.localPort
    private val worker = startThread("test-listener") { try { val accepted = server.accept(); lock.withLock { if (closed) accepted.close() else client = accepted; lock.signalAll() } } catch (_: Exception) { } }
    actual fun awaitAccepted(timeoutMillis: Long): Boolean = lock.withLock {
        val deadline = monotonicMillis()+timeoutMillis
        while (client == null && !closed) { val remaining = deadline-monotonicMillis(); if (remaining <= 0) return false; lock.await(remaining) }; client != null
    }
    actual fun close() { lock.withLock { closed = true; client?.close(); lock.signalAll() }; server.close(); worker.join(1000) }
}
