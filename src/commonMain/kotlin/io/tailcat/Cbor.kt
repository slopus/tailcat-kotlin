package io.tailcat

internal sealed class Cbor {
    class Integer(val value: Long) : Cbor()
    class Bytes(val value: ByteArray) : Cbor()
    class Text(val value: String) : Cbor()
    class Array(val value: List<Cbor>) : Cbor()
    class Map(val value: kotlin.collections.Map<String, Cbor>) : Cbor()
    class Bool(val value: Boolean) : Cbor()
    data object Null : Cbor()

    fun encode(): ByteArray {
        fun head(major: Int, count: Long): ByteArray {
            val prefix = major shl 5
            if (count < 24) return byteArrayOf((prefix or count.toInt()).toByte())
            val size = when { count <= 255 -> 1; count <= 65535 -> 2; count <= 0xffffffffL -> 4; else -> 8 }
            val extra = when (size) { 1 -> 24; 2 -> 25; 4 -> 26; else -> 27 }
            return byteArrayOf((prefix or extra).toByte()) + ByteArray(size) { (count ushr ((size - 1 - it) * 8)).toByte() }
        }
        return when (this) {
            is Integer -> if (value >= 0) head(0, value) else head(1, -(value + 1))
            is Bytes -> head(2, value.size.toLong()) + value
            is Text -> value.encodeToByteArray().let { head(3, it.size.toLong()) + it }
            is Array -> value.fold(head(4, value.size.toLong())) { bytes, item -> bytes + item.encode() }
            is Map -> value.entries.fold(head(5, value.size.toLong())) { bytes, entry -> bytes + Text(entry.key).encode() + entry.value.encode() }
            is Bool -> byteArrayOf(if (value) 0xf5.toByte() else 0xf4.toByte())
            Null -> byteArrayOf(0xf6.toByte())
        }
    }
    companion object {
        fun decode(bytes: ByteArray): Cbor {
            require(bytes.size <= 65536) { "CBOR size limit" }
            var cursor = 0
            fun parse(depth: Int): Cbor {
                require(depth <= 24 && cursor < bytes.size) { "Truncated or nested CBOR" }
                val first = bytes[cursor++].u(); val major = first ushr 5; val extra = first and 31
                if (major == 7) return when (extra) { 20 -> Bool(false); 21 -> Bool(true); 22 -> Null; else -> error("Unsupported CBOR value") }
                var count = extra.toLong()
                if (extra >= 24) {
                    require(extra <= 27) { "Indefinite CBOR" }
                    val size = 1 shl (extra - 24)
                    require(size <= bytes.size - cursor) { "Truncated CBOR length" }
                    count = 0
                    repeat(size) { require(count >= 0 && count <= Long.MAX_VALUE ushr 8); count = (count shl 8) or bytes[cursor++].u().toLong() }
                }
                require(count >= 0)
                if (major <= 1) return Integer(if (major == 0) count else -1 - count)
                require(count <= 65536) { "CBOR collection limit" }
                val n = count.toInt()
                return when (major) {
                    2, 3 -> {
                        require(n <= bytes.size - cursor) { "Truncated CBOR string" }
                        val value = bytes.copyOfRange(cursor, cursor + n); cursor += n
                        if (major == 2) Bytes(value) else Text(value.decodeToString(throwOnInvalidSequence = true))
                    }
                    4 -> { require(n <= bytes.size - cursor); Array(List(n) { parse(depth + 1) }) }
                    5 -> {
                        require(n <= (bytes.size - cursor) / 2)
                        val map = linkedMapOf<String, Cbor>()
                        repeat(n) {
                            val key = (parse(depth + 1) as? Text)?.value ?: error("Nontext CBOR map key")
                            require(!map.containsKey(key)) { "Duplicate CBOR map key" }
                            map[key] = parse(depth + 1)
                        }
                        Map(map)
                    }
                    else -> error("Unsupported CBOR type")
                }
            }
            return parse(0).also { require(cursor == bytes.size) { "Trailing CBOR data" } }
        }
    }
}
