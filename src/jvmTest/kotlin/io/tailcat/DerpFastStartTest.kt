package io.tailcat

import io.tailcat.crypto.NaClBox
import io.tailcat.platform.parseDerpTlsMetadata
import io.tailcat.platform.secureRandom
import java.io.ByteArrayInputStream
import java.math.BigInteger
import kotlin.test.*

class DerpFastStartTest {
    private val upgrade = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".encodeToByteArray()
    private class Wire(bytes: ByteArray) {
        val input = ByteArrayInputStream(bytes)
        val writes = mutableListOf<ByteArray>()
        var closed = false
        fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            check(writes.isNotEmpty()) { "Client must write before reading" }
            if (closed) throw TailcatClosedException()
            return input.read(bytes, offset, minOf(length, 3))
        }
        fun write(bytes: ByteArray) { if (closed) throw TailcatClosedException(); writes.add(bytes.copyOf()) }
    }
    private fun greeting(server: NodePrivateKey) = DerpFrame(1, "DERP🔑".encodeToByteArray() + server.publicKey.raw).encode()
    private fun serverInfo(client: NodePrivateKey, server: NodePrivateKey): ByteArray {
        val nonce = secureRandom(24)
        val json = "{\"version\":2,\"TokenBucketBytesPerSecond\":500,\"TokenBucketBytesBurst\":1000}".encodeToByteArray()
        return DerpFrame(3, nonce + NaClBox.seal(json, nonce, client.publicKey.raw, server.raw)).encode()
    }
    private fun clientInfo(bytes: ByteArray): ByteArray {
        assertEquals(2, bytes[0].u())
        assertEquals(bytes.size - 5, bytes.be32(1).toInt())
        return bytes.copyOfRange(5, bytes.size)
    }
    private fun checkClientInfo(payload: ByteArray, client: NodePrivateKey, server: NodePrivateKey) {
        assertContentEquals(client.publicKey.raw, payload.copyOfRange(0, 32))
        val plaintext = NaClBox.open(payload.copyOfRange(56, payload.size), payload.copyOfRange(32, 56), client.publicKey.raw, server.raw)
        assertEquals("{\"version\":2,\"CanAckPings\":true}", plaintext.decodeToString())
    }
    private fun headerEnd(bytes: ByteArray): Int = (3 until bytes.size).first {
        bytes[it - 3] == 13.toByte() && bytes[it - 2] == 10.toByte() && bytes[it - 1] == 13.toByte() && bytes[it] == 10.toByte()
    } + 1

    @Test fun normalAndFastStartAuthenticateWithChunkedAndCoalescedFrames() {
        for (fast in listOf(false, true)) {
            val client = NodePrivateKey.generate(); val server = NodePrivateKey.generate()
            val marker = byteArrayOf(77, 88, 99)
            val wire = Wire((if (fast) byteArrayOf() else upgrade) + greeting(server) + serverInfo(client, server) + marker)
            val trace = StartupTrace()
            val result = DerpHandshake(client, "relay.example", if (fast) DerpTlsMetadata(server.publicKey, 2) else null,
                trace, wire::read, wire::write).authenticate()
            assertEquals(DerpServerInfo(500.0, 1000.0), result)
            assertContentEquals(marker, wire.input.readAllBytes(), "Handshake must preserve subsequent DERP frames")
            val first = wire.writes.first()
            val end = headerEnd(first)
            val header = first.copyOfRange(0, end).decodeToString()
            if (fast) {
                assertTrue(header.contains("Derp-Fast-Start: 1\r\n"))
                assertEquals(1, wire.writes.size, "HTTP request and ClientInfo must share one write")
                checkClientInfo(clientInfo(first.copyOfRange(end, first.size)), client, server)
                val phases = trace.snapshot().map { it.name }
                assertTrue(phases.indexOf("derpClientInfoWritten") < phases.indexOf("derpGreeting"))
            } else {
                assertFalse(header.contains("Derp-Fast-Start"))
                assertEquals(first.size, end)
                assertEquals(2, wire.writes.size)
                checkClientInfo(clientInfo(wire.writes[1]), client, server)
            }
            assertEquals("derpServerInfoAuthenticated", trace.snapshot().last().name)
        }
    }

    @Test fun metadataRequiresVerifiedTLS13ExactSubjectAndBoundedVersion() {
        val key = NodePrivateKey.generate().publicKey
        val subject = "CN=derpkey" + key.raw.hex()
        val valid = listOf(subject to BigInteger.TWO)
        assertEquals(DerpTlsMetadata(key, 2), parseDerpTlsMetadata("TLSv1.3", true, valid))
        assertNull(parseDerpTlsMetadata("TLSv1.2", true, valid))
        assertNull(parseDerpTlsMetadata("TLSv1.3", false, valid))
        assertNull(parseDerpTlsMetadata("TLSv1.3", true, emptyList()))
        for (serial in listOf(BigInteger.ZERO, BigInteger.valueOf(-1), BigInteger.valueOf(256))) {
            assertNull(parseDerpTlsMetadata("TLSv1.3", true, listOf(subject to serial)))
        }
        for (invalid in listOf("CN=derpkeyinvalid", "CN=other\\,$subject", "$subject,O=unexpected", "CN=derpkey" + "0".repeat(64))) {
            assertNull(parseDerpTlsMetadata("TLSv1.3", true, listOf(invalid to BigInteger.TWO)))
        }
    }

    @Test fun wrongMagicKeyAndUnauthenticatedServerInfoNeverComplete() {
        val client = NodePrivateKey.generate(); val server = NodePrivateKey.generate()
        val wrong = NodePrivateKey.generate()
        val malformed = DerpFrame(1, ByteArray(40)).encode()
        for (reply in listOf(malformed + serverInfo(client, server), greeting(wrong) + serverInfo(client, wrong),
            greeting(server) + DerpFrame(3, ByteArray(64)).encode())) {
            val wire = Wire(reply); val trace = StartupTrace()
            assertFails {
                DerpHandshake(client, "relay.example", DerpTlsMetadata(server.publicKey, 2), trace, wire::read, wire::write).authenticate()
            }
            assertFalse(trace.snapshot().any { it.name == "derpServerInfoAuthenticated" })
            assertEquals(1, wire.writes.size, "Failure must not release any application or reset packets")
        }
    }

    @Test fun rotationAndCancelledFastStartDoNotShareIdentityNonceOrConnectionState() {
        val first = NodePrivateKey.generate(); val second = NodePrivateKey.generate(); val server = NodePrivateKey.generate()
        val firstWire = Wire(greeting(server) + serverInfo(first, server))
        DerpHandshake(first, "relay.example", DerpTlsMetadata(server.publicKey, 2), null, firstWire::read, firstWire::write).authenticate()
        val cancelled = Wire(byteArrayOf())
        assertFailsWith<TailcatClosedException> {
            DerpHandshake(second, "relay.example", DerpTlsMetadata(server.publicKey, 2), null, cancelled::read, {
                cancelled.write(it); cancelled.closed = true
            }).authenticate()
        }
        val rotated = NodePrivateKey.generate()
        val stale = Wire(greeting(rotated) + serverInfo(second, rotated))
        assertFails {
            DerpHandshake(second, "relay.example", DerpTlsMetadata(server.publicKey, 2), null, stale::read, stale::write).authenticate()
        }
        val fresh = Wire(greeting(rotated) + serverInfo(second, rotated))
        DerpHandshake(second, "relay.example", DerpTlsMetadata(rotated.publicKey, 2), null, fresh::read, fresh::write).authenticate()
        val firstInfo = clientInfo(firstWire.writes.single().let { it.copyOfRange(headerEnd(it), it.size) })
        val freshInfo = clientInfo(fresh.writes.single().let { it.copyOfRange(headerEnd(it), it.size) })
        assertFalse(firstInfo.copyOfRange(0, 32).contentEquals(freshInfo.copyOfRange(0, 32)))
        assertFalse(firstInfo.copyOfRange(32, 56).contentEquals(freshInfo.copyOfRange(32, 56)))
        firstWire.write(byteArrayOf(1)) // A separate failed/cancelled handshake did not close this connection.
        assertEquals(2, firstWire.writes.size)
    }

    @Test fun unexpectedHttpAndOversizedFramesFailBeforeReadingPayload() {
        val client = NodePrivateKey.generate(); val server = NodePrivateKey.generate()
        for (reply in listOf(upgrade, byteArrayOf(1) + be32(DerpFrame.MAXIMUM.toLong() + 1) + byteArrayOf(99))) {
            val wire = Wire(reply); val trace = StartupTrace()
            assertFails {
                DerpHandshake(client, "relay.example", DerpTlsMetadata(server.publicKey, 2), trace, wire::read, wire::write).authenticate()
            }
            assertEquals(reply.size - 5, wire.input.available(), "Reject the five-byte header before allocating or waiting for a large payload")
            assertFalse(trace.snapshot().any { it.name == "derpServerInfoAuthenticated" })
        }
    }
}