package io.tailcat

/** A bounded JSON reader for relay metadata; no reflective serialization runtime. */
internal object Json {
    fun parse(text: String): Any? {
        require(text.length <= 2_097_152)
        var at = 0
        fun ws() { while (at < text.length && text[at] in " \r\n\t") at++ }
        fun string(): String {
            require(at < text.length && text[at++] == '"')
            return buildString {
                var ended = false
                while (at < text.length) {
                    val c = text[at++]
                    if (c == '"') { ended = true; break }
                    require(c >= ' ')
                    if (c != '\\') { append(c); continue }
                    require(at < text.length)
                    when (val escape = text[at++]) {
                        '"', '\\', '/' -> append(escape)
                        'b' -> append('\b'); 'f' -> append('\u000c'); 'n' -> append('\n'); 'r' -> append('\r'); 't' -> append('\t')
                        'u' -> { require(at + 4 <= text.length); append(text.substring(at, at + 4).toInt(16).toChar()); at += 4 }
                        else -> error("Invalid JSON escape")
                    }
                }
                require(ended) { "Unterminated JSON string" }
            }
        }
        fun value(depth: Int): Any? {
            require(depth < 32); ws(); require(at < text.length)
            return when (text[at]) {
                '"' -> string()
                '{' -> {
                    at++; ws(); val map = linkedMapOf<String, Any?>()
                    if (at < text.length && text[at] == '}') { at++; map } else {
                        while (true) {
                            ws(); val key = string(); require(!map.containsKey(key)); ws(); require(at < text.length && text[at++] == ':')
                            map[key] = value(depth + 1); require(map.size <= 16384); ws(); require(at < text.length)
                            val separator = text[at++]; if (separator == '}') break; require(separator == ',')
                        }
                        map
                    }
                }
                '[' -> {
                    at++; ws(); val list = mutableListOf<Any?>()
                    if (at < text.length && text[at] == ']') { at++; list } else {
                        while (true) {
                            list.add(value(depth + 1)); require(list.size <= 16384); ws(); require(at < text.length)
                            val separator = text[at++]; if (separator == ']') break; require(separator == ',')
                        }
                        list
                    }
                }
                't' -> { require(text.startsWith("true", at)); at += 4; true }
                'f' -> { require(text.startsWith("false", at)); at += 5; false }
                'n' -> { require(text.startsWith("null", at)); at += 4; null }
                else -> {
                    val start = at
                    while (at < text.length && text[at] in "-+0123456789.eE") at++
                    require(at > start)
                    val token = text.substring(start, at)
                    token.toLongOrNull() ?: token.toDoubleOrNull()?.also { require(it.isFinite()) } ?: error("Invalid JSON number")
                }
            }
        }
        return value(0).also { ws(); require(at == text.length) }
    }
}
