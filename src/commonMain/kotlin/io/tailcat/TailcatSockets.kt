// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package io.tailcat

import io.tailcat.stack.IPStack

/** A TCP byte stream carried directly over the encrypted IPv6 tunnel. */
class TailcatConnection internal constructor(
    private val stack: IPStack,
    internal val id: Long,
    localAddress: ByteArray,
    remoteAddress: ByteArray,
    val localPort: Int,
    val remotePort: Int,
    val peer: NodePublicKey?,
) {
    private val local = localAddress.copyOf()
    private val remote = remoteAddress.copyOf()
    val localAddress: ByteArray get() = local.copyOf()
    val remoteAddress: ByteArray get() = remote.copyOf()
    fun read(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size - offset,
             timeoutMillis: Long = 0): Int = stack.read(id, buffer, offset, length, timeoutMillis)
    fun read(maximumBytes: Int = 65536, timeoutMillis: Long = 0): ByteArray {
        require(maximumBytes > 0)
        val buffer = ByteArray(maximumBytes)
        val count = read(buffer, timeoutMillis = timeoutMillis)
        return if (count < 0) ByteArray(0) else buffer.copyOf(count)
    }
    /** Returns only after all supplied bytes have been acknowledged. */
    fun write(data: ByteArray, offset: Int = 0, length: Int = data.size - offset,
              timeoutMillis: Long = 0) = stack.write(id, data, offset, length, timeoutMillis)
    fun drain(timeoutMillis: Long = 0) = stack.drain(id, timeoutMillis)
    fun shutdownOutput(timeoutMillis: Long = 0) = stack.closeWrite(id, timeoutMillis)
    fun closeWrite(timeoutMillis: Long = 0) = shutdownOutput(timeoutMillis)
    fun close() = stack.closeConnection(id)
    internal fun abort() = stack.abortConnection(id)
}

class TailcatListener internal constructor(
    private val stack: IPStack,
    internal val id: Long,
    val port: Int,
    localAddress: ByteArray,
) {
    private val address = localAddress.copyOf()
    val localAddress: ByteArray get() = address.copyOf()
    fun accept(timeoutMillis: Long = 0): TailcatConnection = stack.accept(id, timeoutMillis)
    fun close() = stack.closeListener(id)
}

class TailcatDatagram(data: ByteArray, peer: ByteArray, val port: Int) {
    private val payload = data.copyOf()
    private val address = peer.copyOf()
    val data: ByteArray get() = payload.copyOf()
    val peer: ByteArray get() = address.copyOf()
}

class TailcatUDPSocket internal constructor(
    private val stack: IPStack,
    internal val id: Long,
    val port: Int,
) {
    fun send(data: ByteArray, to: ByteArray, port: Int) = stack.sendUDP(id, data, to, port)
    fun receive(timeoutMillis: Long = 0): TailcatDatagram = stack.receiveUDP(id, timeoutMillis)
    fun close() = stack.closeUDP(id)
}
