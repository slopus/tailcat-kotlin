package io.tailcat.platform

/** System facilities only. The protocol and packet stack live in common Kotlin. */
internal expect class PlatformLock() {
    fun lock()
    fun unlock()
    /** Atomically release this held lock, wait, then reacquire it. */
    fun await(timeoutMillis: Long)
    fun signalAll()
}

internal inline fun <T> PlatformLock.withLock(block: () -> T): T {
    lock()
    try { return block() } finally { unlock() }
}

internal expect class PlatformThread {
    fun join(timeoutMillis: Long = 5000)
}
internal expect fun startThread(name: String, block: () -> Unit): PlatformThread
internal expect fun monotonicMillis(): Long
internal expect fun wallClockMillis(): Long
internal expect fun secureRandom(count: Int): ByteArray
internal expect fun platformSleep(millis: Long)

internal data class Endpoint(val host: String, val port: Int) {
    init { require(port in 0..65535) }
    override fun toString(): String = if (':' in host) "[$host]:$port" else "$host:$port"
}
internal data class RawDatagram(val source: Endpoint, val data: ByteArray)

internal expect class PlatformUdp(bindPort: Int = 0, ipv6: Boolean = false) {
    val localPort: Int
    fun send(destination: Endpoint, data: ByteArray)
    /** Timeout returns null; a zero length datagram is a valid result. */
    fun receive(timeoutMillis: Int = 1000): RawDatagram?
    fun close()
}

internal expect class PlatformStream() {
    fun connect(host: String, port: Int, tls: Boolean, serverName: String = host, certificateName: String = serverName, timeoutMillis: Int = 10000, insecureForTests: Boolean = false)
    fun read(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size - offset): Int
    fun write(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size - offset)
    fun close()
}

internal expect fun resolveHost(host: String): List<String>
internal expect fun localAddresses(): List<String>
