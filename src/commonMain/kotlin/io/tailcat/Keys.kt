package io.tailcat

import io.tailcat.crypto.TailcatCrypto
import io.tailcat.platform.PlatformLock
import io.tailcat.platform.secureRandom
import io.tailcat.platform.withLock

open class TailcatException(message: String, cause: Throwable? = null) : Exception(message, cause)
class TailcatClosedException : TailcatException("Tailcat is closed")
class TailcatTimeoutException : TailcatException("Tailcat operation timed out")
class TailcatRejectedException : TailcatException("Peer rejected")

/** Immutable WireGuard identity; its tunnel IP derives from its first ten bytes. */
class NodePublicKey(rawValue: ByteArray) {
    internal val raw = rawValue.copyOf()
    val rawValue: ByteArray get() = raw.copyOf()
    val address: ByteArray get() = byteArrayOf(0xfd.toByte(), 0x7a, 0x11, 0x5c, 0xa1.toByte(), 0xe0.toByte()) + raw.copyOfRange(0, 10)
    init { require(raw.size == 32) { "A node key must contain 32 bytes" } }
    constructor(text: String) : this(hexBytes(text.removePrefix("nodekey:").also { require(text.startsWith("nodekey:")) }))
    override fun equals(other: Any?): Boolean = other is NodePublicKey && raw.contentEquals(other.raw)
    override fun hashCode(): Int = raw.contentHashCode()
    override fun toString(): String = "nodekey:" + raw.hex()
}

/** Persist [rawValue] to retain identity. Private material is never printed by toString. */
class NodePrivateKey(rawValue: ByteArray) {
    internal val raw = rawValue.copyOf()
    val rawValue: ByteArray get() = raw.copyOf()
    init {
        require(raw.size == 32)
        raw[0] = (raw[0].u() and 248).toByte()
        raw[31] = ((raw[31].u() and 127) or 64).toByte()
    }
    val publicKey: NodePublicKey by lazy { NodePublicKey(TailcatCrypto.publicKey(raw)) }
    private val derivedDiscoPrivate: ByteArray by lazy { TailcatCrypto.hmacSHA256(raw, "github.com/tailscale/tailcat disco key v1".encodeToByteArray()).also {
        it[0] = (it[0].u() and 248).toByte(); it[31] = ((it[31].u() and 127) or 64).toByte()
    } }
    private val derivedDiscoPublic: ByteArray by lazy { TailcatCrypto.publicKey(derivedDiscoPrivate) }
    internal val discoPrivateKey: ByteArray get() = derivedDiscoPrivate.copyOf()
    val discoPublicKey: ByteArray get() = derivedDiscoPublic.copyOf()
    override fun toString(): String = "NodePrivateKey(<redacted>)"
    companion object { fun generate(): NodePrivateKey = NodePrivateKey(secureRandom(32)) }
}

class PresharedKey(rawValue: ByteArray) {
    internal val raw = rawValue.copyOf()
    val rawValue: ByteArray get() = raw.copyOf()
    val isZero: Boolean get() = raw.all { it == 0.toByte() }
    init { require(raw.size == 32) }
    override fun equals(other: Any?): Boolean = other is PresharedKey && raw.constantEquals(other.raw)
    override fun hashCode(): Int = raw.contentHashCode()
    override fun toString(): String = "PresharedKey(<redacted>)"
    companion object { fun generate(): PresharedKey = PresharedKey(secureRandom(32)) }
}

/** A synchronized allow-list suitable for ServerConfiguration.allowClient. */
class KeySet {
    private val lock = PlatformLock()
    private val keys = mutableSetOf<NodePublicKey>()
    fun add(key: NodePublicKey) { lock.withLock { keys.add(key) } }
    fun remove(key: NodePublicKey) { lock.withLock { keys.remove(key) } }
    operator fun contains(key: NodePublicKey): Boolean = lock.withLock { key in keys }
}
