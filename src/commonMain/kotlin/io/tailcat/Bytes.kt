package io.tailcat

internal fun Byte.u(): Int = toInt() and 255
internal fun ByteArray.hex(): String = joinToString("") { it.u().toString(16).padStart(2, '0') }
internal fun hexBytes(text: String): ByteArray {
    require(text.length % 2 == 0) { "Odd hexadecimal length" }
    return ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
internal fun ByteArray.be16(at: Int): Int = (this[at].u() shl 8) or this[at + 1].u()
internal fun ByteArray.be32(at: Int): Long = (0..3).fold(0L) { n, i -> (n shl 8) or this[at + i].u().toLong() }
internal fun be16(n: Int): ByteArray = byteArrayOf((n ushr 8).toByte(), n.toByte())
internal fun be32(n: Long): ByteArray = ByteArray(4) { (n ushr (24 - it * 8)).toByte() }
internal fun ByteArray.startsWith(prefix: ByteArray): Boolean = size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
internal fun ByteArray.constantEquals(other: ByteArray): Boolean {
    if (size != other.size) return false
    var diff = 0
    for (i in indices) diff = diff or (this[i].u() xor other[i].u())
    return diff == 0
}

internal class BytesKey(bytes: ByteArray) {
    val bytes = bytes.copyOf()
    override fun equals(other: Any?): Boolean = other is BytesKey && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = bytes.contentHashCode()
}

internal object Base64Url {
    private const val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    fun encode(bytes: ByteArray): String = buildString {
        var i = 0
        while (i < bytes.size) {
            val a = bytes[i++].u()
            val b = if (i < bytes.size) bytes[i++].u() else -1
            val c = if (i < bytes.size) bytes[i++].u() else -1
            append(alphabet[a ushr 2]); append(alphabet[((a and 3) shl 4) or (if (b < 0) 0 else b ushr 4)])
            if (b >= 0) append(alphabet[((b and 15) shl 2) or (if (c < 0) 0 else c ushr 6)])
            if (c >= 0) append(alphabet[c and 63])
        }
    }
    fun decode(text: String): ByteArray {
        require(text.length % 4 != 1 && text.length <= 90_000) { "Invalid base64url length" }
        val result = ByteArray(text.length * 6 / 8)
        var bits = 0; var accumulator = 0; var offset = 0
        for (c in text) {
            val n = alphabet.indexOf(c)
            require(n >= 0) { "Invalid base64url character" }
            accumulator = (accumulator shl 6) or n; bits += 6
            if (bits >= 8) { bits -= 8; result[offset++] = (accumulator ushr bits).toByte() }
        }
        require(bits == 0 || accumulator and ((1 shl bits) - 1) == 0) { "Noncanonical base64url" }
        return result
    }
}
