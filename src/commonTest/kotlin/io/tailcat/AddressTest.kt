package io.tailcat

import kotlin.test.*

class AddressTest {
    @Test fun numericAddressesAndNat64() {
        for (value in listOf("::", "::1", "2001:db8::7", "fd7a:115c:a1e0:abcd::ef", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) {
            val bytes = IpAddress.parse6(value)!!; assertContentEquals(bytes,IpAddress.parse6(IpAddress.format6(bytes)))
        }
        val endpoint = TailcatEndpoint("198.51.100.7",8080)
        assertEquals("0064ff9b0000000000000000c6336407",endpoint.tunnelAddress.hex())
        assertEquals(endpoint,TailcatEndpoint.fromRaw(endpoint.tunnelAddress,8080))
        for (value in listOf("1::2::3", ":::1", "1:2:3:4:5:6:7", "gggg::1")) assertNull(IpAddress.parse6(value))
    }
    @Test fun malformedAddressIsolation() {
        for (bytes in listOf(byteArrayOf(),byteArrayOf(0xbf.toByte()),hexBytes("a2617001617002"),hexBytes("a1617082582000"))) assertFails { Cbor.decode(bytes) }
        assertFails { TailcatAddress.parse("tc=") }; assertFails { Base64Url.decode("_x") }
        val root = Cbor.Map(mapOf("unknown" to Cbor.Array(listOf(Cbor.Null)),"p" to Cbor.Bytes(ByteArray(32) { 7 })))
        assertEquals(NodePublicKey(ByteArray(32) { 7 }),TailcatAddress.parse("tc"+Base64Url.encode(root.encode())).serverPublicKey)
    }
}
