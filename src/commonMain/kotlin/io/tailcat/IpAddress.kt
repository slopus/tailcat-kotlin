package io.tailcat

/** Numeric IP parsing without DNS or platform dependencies. */
internal object IpAddress {
    val nat64Prefix = byteArrayOf(0, 0x64, 0xff.toByte(), 0x9b.toByte(), 0, 0, 0, 0, 0, 0, 0, 0)
    val mappedPrefix = ByteArray(10) + byteArrayOf(-1, -1)
    fun parse4(text: String): ByteArray? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        return ByteArray(4) { index ->
            val part = parts[index]
            if (part.isEmpty() || part.any { it !in '0'..'9' } || part.length > 3) return null
            val n = part.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            n.toByte()
        }
    }
    fun parse6(text: String): ByteArray? {
        if (text.isEmpty() || '%' in text || text.count { it == ':' } < 2) return null
        val compression = text.indexOf("::")
        if (compression >= 0 && text.indexOf("::", compression + 2) >= 0) return null
        fun words(part: String): List<Int>? {
            if (part.isEmpty()) return emptyList()
            val result = mutableListOf<Int>()
            val pieces = part.split(':')
            for ((i, piece) in pieces.withIndex()) {
                if ('.' in piece) {
                    if (i != pieces.lastIndex) return null
                    val v4 = parse4(piece) ?: return null
                    result.add(v4.be16(0)); result.add(v4.be16(2))
                } else {
                    if (piece.isEmpty() || piece.length > 4 || piece.any { it.digitToIntOrNull(16) == null }) return null
                    result.add(piece.toInt(16))
                }
            }
            return result
        }
        val left = words(if (compression >= 0) text.substring(0, compression) else text) ?: return null
        val right = if (compression >= 0) words(text.substring(compression + 2)) ?: return null else emptyList()
        val missing = 8 - left.size - right.size
        if ((compression < 0 && missing != 0) || (compression >= 0 && missing < 1)) return null
        val all = left + List(missing) { 0 } + right
        return ByteArray(16) { i -> (all[i / 2] ushr (if (i % 2 == 0) 8 else 0)).toByte() }
    }
    fun format4(bytes: ByteArray): String = bytes.joinToString(".") { it.u().toString() }
    fun format6(bytes: ByteArray): String {
        require(bytes.size == 16)
        val words = List(8) { bytes.be16(it * 2) }
        var bestStart = -1; var bestLength = 1; var i = 0
        while (i < 8) {
            if (words[i] != 0) { i++; continue }
            val start = i
            while (i < 8 && words[i] == 0) i++
            if (i - start > bestLength) { bestStart = start; bestLength = i - start }
        }
        if (bestStart < 0) return words.joinToString(":") { it.toString(16) }
        return words.take(bestStart).joinToString(":") { it.toString(16) } + "::" +
            words.drop(bestStart + bestLength).joinToString(":") { it.toString(16) }
    }
}

/** An explicit numeric destination. IPv4 is encoded using the upstream NAT64 prefix. */
class TailcatEndpoint(val ipAddress: String, val port: Int) {
    val tunnelAddress: ByteArray
        get() = raw.copyOf()
    internal val raw: ByteArray = IpAddress.parse4(ipAddress)?.let { IpAddress.nat64Prefix + it }
        ?: IpAddress.parse6(ipAddress) ?: throw IllegalArgumentException("Expected numeric IP address")
    init { require(port in 1..65535) }
    override fun toString(): String = if (':' in ipAddress) "[$ipAddress]:$port" else "$ipAddress:$port"
    override fun equals(other: Any?): Boolean = other is TailcatEndpoint && port == other.port && raw.contentEquals(other.raw)
    override fun hashCode(): Int = 31 * raw.contentHashCode() + port
    internal companion object {
        fun fromRaw(raw: ByteArray, port: Int): TailcatEndpoint = TailcatEndpoint(
            if (raw.startsWith(IpAddress.nat64Prefix)) IpAddress.format4(raw.copyOfRange(12, 16)) else IpAddress.format6(raw), port)
    }
}
