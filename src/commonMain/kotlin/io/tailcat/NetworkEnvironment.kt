package io.tailcat

import io.tailcat.platform.*

/** Internal seams for deterministic path/lifecycle tests; not part of the public transport API. */
internal interface NetworkUdp {
    val localPort: Int
    fun send(destination: Endpoint, data: ByteArray)
    fun receive(): RawDatagram?
    fun close()
}

internal interface NetworkRelay {
    /** A new value for each authenticated connection; null while disconnected. */
    val connectionGeneration: Long?
    fun start(timeoutMillis: Long)
    fun send(key: NodePublicKey, packet: ByteArray)
    fun setResetBarrier(key: NodePublicKey, blocked: Boolean)
    fun queueResetMarker(key: NodePublicKey, packet: ByteArray)
    fun hasResetMarker(key: NodePublicKey): Boolean
    fun discardResetMarker(key: NodePublicKey)
    fun tick(now: Long)
    fun reconnect()
    fun close()
}

internal open class NetworkEnvironment {
    open fun now(): Long = monotonicMillis()
    open fun addresses(): List<String> = localAddresses()
    open fun resolve(host: String): List<String> = resolveHost(host)
    open fun udp(ipv6: Boolean): NetworkUdp = object : NetworkUdp {
        private val socket = PlatformUdp(ipv6 = ipv6)
        override val localPort: Int get() = socket.localPort
        override fun send(destination: Endpoint, data: ByteArray) = socket.send(destination, data)
        override fun receive(): RawDatagram? = socket.receive()
        override fun close() = socket.close()
    }
}