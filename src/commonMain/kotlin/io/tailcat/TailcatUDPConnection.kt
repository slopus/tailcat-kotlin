package io.tailcat

import io.tailcat.stack.IPStack

/** One connected UDP flow. Empty datagrams are valid messages. */
class TailcatUDPConnection internal constructor(private val stack: IPStack, internal val id: Long,
    localAddress: ByteArray, remoteAddress: ByteArray, val localPort: Int, val remotePort: Int, val peer: NodePublicKey?) {
    private val local = localAddress.copyOf(); private val remote = remoteAddress.copyOf()
    val localAddress: ByteArray get() = local.copyOf()
    val remoteAddress: ByteArray get() = remote.copyOf()
    fun receive(timeoutMillis: Long = 0): ByteArray = stack.receiveUDPFlow(id, timeoutMillis)
    fun send(data: ByteArray) = stack.sendUDPFlow(id, data)
    fun write(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
        require(offset >= 0 && length >= 0 && offset <= data.size && length <= data.size - offset)
        send(data.copyOfRange(offset, offset + length))
    }
    fun read(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size - offset, timeoutMillis: Long = 0): Int {
        require(offset >= 0 && length >= 0 && offset <= buffer.size && length <= buffer.size - offset)
        val data = receive(timeoutMillis); val count = minOf(length, data.size); data.copyInto(buffer, offset, 0, count); return count
    }
    fun close() = stack.closeUDPFlow(id)
}
class TailcatUDPListener internal constructor(private val stack: IPStack, internal val id: Long, val port: Int, localAddress: ByteArray) {
    private val address = localAddress.copyOf()
    val localAddress: ByteArray get() = address.copyOf()
    fun accept(timeoutMillis: Long = 0): TailcatUDPConnection = stack.acceptUDP(id, timeoutMillis)
    fun close() = stack.closeUDPListener(id)
}
