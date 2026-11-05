package io.tailcat

import io.tailcat.crypto.NaClBox
import io.tailcat.platform.secureRandom

/** Capability and relay public key from the current verified TLS 1.3 certificate message. */
internal data class DerpTlsMetadata(val publicKey: NodePublicKey, val protocolVersion: Int)
internal data class DerpServerInfo(val rate: Double, val burst: Double)

/** Only registration framing: callers keep all queued traffic gated on authenticated ServerInfo. */
internal class DerpHandshake(
    private val identity: NodePrivateKey,
    private val hostName: String,
    private val metadata: DerpTlsMetadata?,
    private val trace: StartupTrace?,
    private val read: (ByteArray, Int, Int) -> Int,
    private val write: (ByteArray) -> Unit,
) {
    fun authenticate(): DerpServerInfo {
        require(hostName.none { it == '\r' || it == '\n' })
        val fast = metadata != null
        val request = ("GET /derp HTTP/1.1\r\nHost: $hostName\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n" +
            (if (fast) "Derp-Fast-Start: 1\r\n" else "") + "\r\n").encodeToByteArray()
        trace?.mark("httpUpgradeStart")
        if (metadata != null) {
            // One write pipelines fresh authenticated ClientInfo with the HTTP request. The key is
            // from this TLS handshake, never cached across connections or taken from an unverified TLS session.
            write(request + clientInfo(metadata.publicKey.raw))
            trace?.mark("derpFastStart", metadata.protocolVersion.toLong())
            trace?.mark("derpClientInfoWritten")
        } else {
            write(request)
            readUpgrade()
            trace?.mark("httpUpgradeDone")
        }
        // Upstream still sends its greeting in fast-start mode; it must match the TLS metadata.
        val greeting = frame()
        require(greeting.type == 1 && greeting.payload.size in 40..1024 && greeting.payload.startsWith("DERP🔑".encodeToByteArray()))
        val serverKey = greeting.payload.copyOfRange(8, 40)
        require(metadata == null || metadata.publicKey.raw.contentEquals(serverKey)) { "DERP TLS metadata key mismatch" }
        trace?.mark("derpGreeting")
        if (!fast) {
            write(clientInfo(serverKey))
            trace?.mark("derpClientInfoWritten")
        }
        val info = frame()
        require(info.type == 3 && info.payload.size in 40..65536)
        val plaintext = NaClBox.open(info.payload.copyOfRange(24, info.payload.size), info.payload.copyOfRange(0, 24), serverKey, identity.raw)
        val json = Json.parse(plaintext.decodeToString(throwOnInvalidSequence = true)) as? Map<*, *> ?: error("Expected DERP server info")
        require(((json["version"] as? Number)?.toInt() ?: 0) >= 2)
        trace?.mark("derpServerInfoAuthenticated")
        return DerpServerInfo(
            ((json["TokenBucketBytesPerSecond"] as? Number)?.toDouble() ?: 0.0).coerceAtLeast(0.0),
            ((json["TokenBucketBytesBurst"] as? Number)?.toDouble() ?: 0.0).coerceAtLeast(0.0),
        )
    }

    private fun clientInfo(serverKey: ByteArray): ByteArray {
        val nonce = secureRandom(24)
        val info = "{\"version\":2,\"CanAckPings\":true}".encodeToByteArray()
        return DerpFrame(2, identity.publicKey.raw + nonce + NaClBox.seal(info, nonce, serverKey, identity.raw)).encode()
    }

    private fun readUpgrade() {
        val header = ArrayList<Byte>()
        val one = ByteArray(1)
        while (true) {
            require(header.size < 16384)
            if (read(one, 0, 1) != 1) throw TailcatClosedException()
            header.add(one[0])
            if (header.size >= 4 && header.takeLast(4) == listOf<Byte>(13, 10, 13, 10)) break
        }
        val lines = header.toByteArray().decodeToString(throwOnInvalidSequence = true).split("\r\n")
        require(lines.first().startsWith("HTTP/1.1 101 ") || lines.first() == "HTTP/1.1 101")
        val headers = lines.drop(1).filter { it.isNotEmpty() }.associate { line ->
            val colon = line.indexOf(':'); require(colon > 0)
            line.substring(0, colon).lowercase() to line.substring(colon + 1).trim().lowercase()
        }
        require(headers["upgrade"] == "derp" && headers["connection"]?.split(',')?.any { it.trim() == "upgrade" } == true)
    }

    private fun exact(count: Int): ByteArray {
        val bytes = ByteArray(count); var offset = 0
        while (offset < count) {
            val received = read(bytes, offset, count - offset)
            if (received <= 0) throw TailcatClosedException()
            offset += received
        }
        return bytes
    }

    private fun frame(): DerpFrame {
        val header = exact(5)
        val size = header.be32(1)
        require(size <= DerpFrame.MAXIMUM)
        return DerpFrame(header[0].u(), exact(size.toInt()))
    }
}