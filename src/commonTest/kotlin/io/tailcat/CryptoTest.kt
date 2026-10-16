package io.tailcat

import io.tailcat.crypto.TailcatCrypto as C
import io.tailcat.crypto.NaClBox
import io.tailcat.wireguard.WireGuard as WG
import kotlin.test.*

class CryptoTest {
    private fun h(s: String) = hexBytes(s.filterNot { it.isWhitespace() })
    private fun eq(a: ByteArray, b: ByteArray) = assertContentEquals(a, b)
    private val mono = 1000L
    private val wall = 1700000000000L
    private fun peers(a: ByteArray = ByteArray(32), b: ByteArray = ByteArray(32)): Pair<WG, WG> {
        val ka = ByteArray(32) { it.toByte() }; val kb = ByteArray(32) { (it + 32).toByte() }
        return WG(ka, C.publicKey(kb), a) to WG(kb, C.publicKey(ka), b)
    }
    private fun ip(value: Int = 42) = ByteArray(43).also { it[0] = 0x60; it[5] = 3; it[40] = value.toByte() }
    private fun establish(a: WG, b: WG) {
        val init = a.initiate(mono, wall); assertEquals(148, init.size)
        val response = b.receive(init, mono).response!!; assertEquals(92, response.size)
        val result = a.receive(response, mono); assertTrue(result.handshakeCompleted)
        assertTrue(b.receive(result.response!!, mono).handshakeCompleted)
    }
    @Test fun hashes() {
        eq(C.sha256("abc".encodeToByteArray()), h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
        eq(C.sha256(byteArrayOf()), h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        eq(C.hmacSHA256(ByteArray(20) { 11 }, "Hi There".encodeToByteArray()), h("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))
        eq(C.hmacSHA256(ByteArray(131) { 0xaa.toByte() }, "Test Using Larger Than Block-Size Key - Hash Key First".encodeToByteArray()), h("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"))
        eq(C.blake2s(byteArrayOf()), h("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"))
        eq(C.blake2s("abc".encodeToByteArray()), h("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"))
        eq(C.blake2s(byteArrayOf(0,1,2), ByteArray(32) { it.toByte() }), h("1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b"))
        eq(C.blake2s("abc".encodeToByteArray(), ByteArray(32) { it.toByte() },16), h("61ba5f165c194692e09d12520cc4c74a"))
    }
    @Test fun x25519() {
        val a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val ap = h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bp = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        eq(C.publicKey(a), ap); eq(C.publicKey(b), bp)
        eq(C.sharedSecret(a,bp), h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
        eq(C.sharedSecret(a,bp), C.sharedSecret(b,ap))
        assertFails { C.sharedSecret(a, ByteArray(32)) }; assertFails { C.sharedSecret(a, ByteArray(32).also { it[0] = 1 }) }
    }
    @Test fun chachaAndXchacha() {
        val text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".encodeToByteArray()
        val key = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val aad = h("50515253c0c1c2c3c4c5c6c7"); val nonce = h("070000004041424344454647")
        val expected = h("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
        eq(C.seal(text,key,nonce,aad),expected); eq(C.open(expected,key,nonce,aad),text)
        assertFails { C.open(expected,key,nonce) }
        val xn = h("404142434445464748494a4b4c4d4e4f5051525354555657")
        val xe = h("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49")
        eq(C.xSeal(text,key,xn,aad),xe); eq(C.xOpen(xe,key,xn,aad),text)
    }
    @Test fun goNaClAndAddressGolden() {
        val a = h("0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f60")
        val b = h("2022232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
        val nonce = h("000102030405060708090a0b0c0d0e0f1011121314151617")
        val text = "{\"version\":2,\"CanAckPings\":true}".encodeToByteArray()
        val encrypted = h("176bdffac6239dc06abd2678210731e169d7ad3c284e14bd97d07b31d36052dc1b4b776d33dac1529db871ecd021683e")
        eq(NaClBox.seal(text,nonce,C.publicKey(b),a),encrypted); eq(NaClBox.open(encrypted,nonce,C.publicKey(a),b),text)
        for (size in listOf(0,1,15,16,17,31,32,33,63,64,65,1024,65536)) {
            val bytes = ByteArray(size) { it.toByte() }; eq(NaClBox.open(NaClBox.seal(bytes,nonce,C.publicKey(b),a),nonce,C.publicKey(a),b),bytes)
        }
        for (index in listOf(0,15,16,encrypted.lastIndex)) assertFails { NaClBox.open(encrypted.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() },nonce,C.publicKey(a),b) }
        val identity = NodePrivateKey(a)
        assertEquals("nodekey:07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c", identity.publicKey.toString())
        eq(identity.discoPublicKey,h("0b625209067cf41fd90fedfc16dfd17c5b02cbd02aa5a8597b5e7faea9035063"))
        val address = TailcatAddress(identity.publicKey, identity.discoPublicKey, PresharedKey(ByteArray(32) { (255-it).toByte() }), regionID = 302)
        assertEquals("tcpGFwWCAHo3y8FCCTyLdV3BsQ6Gy0JjdK0WqoU-0L38CyuG0cfGFrWCALYlIJBnz0H9kP7fwW39F8WwLL0CqlqFl7Xn-uqQNQY2FxWCD__v38-_r5-Pf29fTz8vHw7-7t7Ovq6ejn5uXk4-Lh4GFpGQEu",address.encode())
        assertEquals(address.encode(),TailcatAddress.parse(address.encode()).encode())
    }
    @Test fun transportReplayRekeyAndOverlap() {
        val (a,b) = peers(); establish(a,b)
        val oldA = a.encrypt(ip(3),mono); val oldB = b.encrypt(ip(4),mono)
        val corrupt = oldA.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }; assertFails { b.receive(corrupt,mono) }
        val now = mono+121000
        assertTrue(a.needsRekey(now))
        val response = b.receive(a.initiate(now,wall+121000),now).response!!
        eq(a.receive(b.encrypt(ip(5),now),now).plaintext!!,ip(5))
        val confirmation = a.receive(response,now).response!!; eq(a.receive(oldB,now).plaintext!!,ip(4))
        b.receive(confirmation,now); eq(b.receive(oldA,now).plaintext!!,ip(3))
        assertFails { a.receive(oldB,now) }; assertFails { a.encrypt(ip(),now+180000) }
        a.maintenance(now+180000); assertFalse(a.isEstablished)
    }
    @Test fun wrongPskAndCrossedHandshakes() {
        val (a,b) = peers(ByteArray(32) { 7 }); val response = b.receive(a.initiate(mono,wall),mono).response!!
        assertFails { a.receive(response,mono) }; assertFalse(a.isEstablished); assertFalse(b.isEstablished)
        val (c,d) = peers(ByteArray(32) { 7 },ByteArray(32) { 7 }); establish(c,d)
        val (e,f) = peers(); val ei = e.initiate(mono,wall); val fi = f.initiate(mono,wall)
        val fr = f.receive(ei,mono).response!!; val er = e.receive(fi,mono).response!!
        val ec = e.receive(fr,mono).response!!; val fc = f.receive(er,mono).response!!
        e.receive(fc,mono); f.receive(ec,mono)
        eq(e.receive(f.encrypt(ip(8),mono),mono).plaintext!!,ip(8)); eq(f.receive(e.encrypt(ip(9),mono),mono).plaintext!!,ip(9))
    }
    @Test fun cookiesAndWindow() {
        val (a,b) = peers(); val source = byteArrayOf(100,64,0,1,0x12,0x34)
        val challenge = b.receive(a.initiate(mono,wall),mono,source,true).response!!; assertEquals(3,WG.packetType(challenge))
        val retry = a.receive(challenge,mono).response!!
        assertEquals(3,WG.packetType(b.receive(retry,mono,byteArrayOf(9),true).response!!))
        val response = b.receive(retry,mono,source,true).response!!
        assertTrue(b.receive(a.receive(response,mono).response!!,mono).handshakeCompleted)
        val w = WG.ReplayWindow()
        for (n in listOf(0UL,1UL,63UL,8192UL)) assertTrue(w.accept(n))
        for (n in listOf(0UL,1UL,63UL)) assertFalse(w.accept(n))
        assertTrue(w.accept(2UL)); assertFalse(w.accept(2UL)); assertTrue(w.accept(16384UL)); assertFalse(w.accept(8192UL)); assertTrue(w.accept(8193UL))
        assertFalse(w.accept(ULong.MAX_VALUE-8192UL)); assertFalse(w.accept(ULong.MAX_VALUE))
    }
    @Test fun independentlyGeneratedNoise() {
        val packet = h("01000000efbeadde79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51af0225eb421886af8f54fb31289d49dcd82b0f6f3279d40d7cff913fece0c64ad226eef3320755b393b72f16842c8d7ee78a74e937e3f2a828ff4ecc11547a9c7d1ee1b22fedf3178ecbaddb30932c6694d28366d80c9b4730611031e00000000000000000000000000000000")
        val (_,b) = peers(); assertEquals(2,WG.packetType(b.receive(packet,mono).response!!))
    }
}
