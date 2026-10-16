package io.tailcat

import io.tailcat.crypto.NaClBox
import io.tailcat.crypto.TailcatCrypto
import io.tailcat.platform.Endpoint
import io.tailcat.platform.secureRandom

internal fun Endpoint.wireBytes(): ByteArray {
    val ip = IpAddress.parse4(host)?.let { IpAddress.mappedPrefix + it } ?: IpAddress.parse6(host) ?: error("Expected numeric endpoint")
    return ip + be16(port)
}
internal fun endpointFromWire(bytes: ByteArray): Endpoint {
    require(bytes.size == 18)
    return Endpoint(if (bytes.startsWith(IpAddress.mappedPrefix)) IpAddress.format4(bytes.copyOfRange(12, 16)) else IpAddress.format6(bytes.copyOfRange(0, 16)), bytes.be16(16))
}

internal sealed class DiscoveryMessage {
    class Ping(val transaction: ByteArray, val nodeKey: ByteArray?) : DiscoveryMessage()
    class Pong(val transaction: ByteArray, val observed: Endpoint) : DiscoveryMessage()
    class CallMeMaybe(val endpoints: List<Endpoint>) : DiscoveryMessage()
    fun encode(): ByteArray = when (this) {
        is Ping -> { require(transaction.size == 12 && (nodeKey == null || nodeKey.size == 32)); byteArrayOf(1, 0) + transaction + (nodeKey ?: byteArrayOf()) }
        is Pong -> { require(transaction.size == 12); byteArrayOf(2, 0) + transaction + observed.wireBytes() }
        is CallMeMaybe -> { require(endpoints.size <= 128); endpoints.fold(byteArrayOf(3, 0)) { b, endpoint -> b + endpoint.wireBytes() } }
    }
    companion object {
        fun decode(bytes: ByteArray): DiscoveryMessage {
            require(bytes.size >= 2 && bytes[1] == 0.toByte())
            return when (bytes[0].u()) {
                1 -> { require(bytes.size == 14 || bytes.size >= 46); Ping(bytes.copyOfRange(2, 14), if (bytes.size >= 46) bytes.copyOfRange(14, 46) else null) }
                2 -> { require(bytes.size >= 32); Pong(bytes.copyOfRange(2, 14), endpointFromWire(bytes.copyOfRange(14, 32))) }
                3 -> { require((bytes.size - 2) % 18 == 0 && bytes.size <= 2 + 128 * 18); CallMeMaybe((2 until bytes.size step 18).map { endpointFromWire(bytes.copyOfRange(it, it + 18)) }) }
                else -> error("Unknown discovery message")
            }
        }
    }
}
internal object Discovery {
    val magic = "TS💬".encodeToByteArray()
    fun sourceKey(packet: ByteArray): ByteArray? = if (packet.size >= 78 && packet.startsWith(magic)) packet.copyOfRange(6, 38) else null
    fun seal(message: DiscoveryMessage, to: ByteArray, privateKey: ByteArray, publicKey: ByteArray = TailcatCrypto.publicKey(privateKey)): ByteArray {
        val nonce = secureRandom(24)
        return magic + publicKey + nonce + NaClBox.seal(message.encode(), nonce, to, privateKey)
    }
    fun open(packet: ByteArray, privateKey: ByteArray): Pair<ByteArray, DiscoveryMessage> {
        val source = sourceKey(packet) ?: error("Malformed discovery packet")
        return source to DiscoveryMessage.decode(NaClBox.open(packet.copyOfRange(62, packet.size), packet.copyOfRange(38, 62), source, privateKey))
    }
}

internal object Stun {
    val cookie = byteArrayOf(0x21, 0x12, 0xa4.toByte(), 0x42)
    fun request(transaction: ByteArray): ByteArray { require(transaction.size == 12); return byteArrayOf(0, 1, 0, 0) + cookie + transaction }
    fun response(packet: ByteArray, transaction: ByteArray): Endpoint {
        require(packet.size >= 20 && packet[0] == 1.toByte() && packet[1] == 1.toByte() && packet.copyOfRange(4, 8).contentEquals(cookie))
        require(transaction.size == 12 && packet.copyOfRange(8, 20).contentEquals(transaction) && packet.size == 20 + packet.be16(2))
        var offset = 20
        while (offset + 4 <= packet.size) {
            val type = packet.be16(offset); val length = packet.be16(offset + 2); offset += 4
            require(length <= packet.size - offset)
            if (type == 0x20 || type == 1) {
                require(length >= 4)
                val family = packet[offset + 1].u(); require(family == 1 || family == 2)
                val size = if (family == 1) 4 else 16; require(length == 4 + size)
                val xor = type == 0x20; val mask = cookie + transaction
                val port = packet.be16(offset + 2) xor (if (xor) 0x2112 else 0)
                val address = ByteArray(size) { (packet[offset + 4 + it].u() xor if (xor) mask[it].u() else 0).toByte() }
                return Endpoint(if (family == 1) IpAddress.format4(address) else IpAddress.format6(address), port)
            }
            offset += (length + 3) and -4
        }
        error("STUN response has no mapped address")
    }
}
