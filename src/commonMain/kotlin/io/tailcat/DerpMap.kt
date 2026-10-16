package io.tailcat

import io.tailcat.platform.PlatformLock
import io.tailcat.platform.PlatformStream
import io.tailcat.platform.monotonicMillis
import io.tailcat.platform.withLock

/** Cache storage may be persisted by the embedding application. */
data class DERPMapCacheEntry(val json: String, val etag: String, val fetchedAtMillis: Long)
interface DERPMapCache {
    fun load(): DERPMapCacheEntry?
    fun store(entry: DERPMapCacheEntry)
}
class MemoryDERPMapCache : DERPMapCache {
    private val lock = PlatformLock()
    private var entry: DERPMapCacheEntry? = null
    override fun load(): DERPMapCacheEntry? = lock.withLock { entry }
    override fun store(entry: DERPMapCacheEntry) { lock.withLock { this.entry = entry } }
}

/** DERP map loading and expansion, with a one-hour cache and stale fallback. */
class DERPMapProvider(
    private val url: String = "https://controlplane.tailscale.com/derpmap/default",
    private val cache: DERPMapCache = MemoryDERPMapCache(),
) {
    fun regions(cancelled: () -> Boolean = { false }): List<DERPRegion> {
        if (cancelled()) throw TailcatClosedException()
        val previous = cache.load()
        val now = io.tailcat.platform.wallClockMillis()
        if (previous != null && now >= previous.fetchedAtMillis && now - previous.fetchedAtMillis < 3_600_000) {
            try { return parse(previous.json) } catch (_: Exception) { }
        }
        return try {
            val response = httpsGet(url, previous?.etag,cancelled)
            val entry = if (response.status == 304 && previous != null) previous.copy(fetchedAtMillis = now)
                else { require(response.status == 200); DERPMapCacheEntry(response.body.decodeToString(throwOnInvalidSequence = true), response.headers["etag"] ?: "", now) }
            val parsed = parse(entry.json)
            require(parsed.isNotEmpty())
            cache.store(entry); parsed
        } catch (_: Exception) {
            if (cancelled()) throw TailcatClosedException()
            previous?.let { try { parse(it.json) } catch (_: Exception) { null } } ?: builtInRegions
        }
    }
    fun expand(address: TailcatAddress, cancelled: () -> Boolean = { false }): List<DERPRegion> = if (address.regions.isNotEmpty()) address.regions
        else regions(cancelled).let { map -> if (address.regionID == 0) map else map.filter { it.regionID == address.regionID } }

    /** Probe HTTPS latency for candidate regions; fall back to the first usable node. */
    fun select(regions: List<DERPRegion>, cancelled: () -> Boolean = { false }): DERPRegion {
        val candidates = regions.filter { it.nodes.any { n -> !n.stunOnly } }
        require(candidates.isNotEmpty()) { "No usable DERP regions" }
        var best = candidates.first(); var bestTime = Long.MAX_VALUE
        // Probe a bounded representative set to avoid large maps delaying startup indefinitely.
        for (region in candidates.take(8)) {
            if (cancelled()) throw TailcatClosedException()
            val node = region.nodes.first { !it.stunOnly }
            val stream = PlatformStream()
            try {
                val start = monotonicMillis()
                val host = node.ipv4.takeIf { it.isNotEmpty() && it != "none" } ?: node.hostName
                if (node.insecureForTests) {
                    require(host in listOf("127.0.0.1", "::1", "localhost"))
                    return region
                }
                streamDeadline(stream,1500,cancelled) {
                    stream.connect(host, node.derpPort.takeIf { it > 0 } ?: 443, true, node.hostName, node.certName.ifEmpty { node.hostName }, 1500)
                }
                val elapsed = monotonicMillis() - start
                if (elapsed < bestTime) { best = region; bestTime = elapsed }
            } catch (_: Exception) { } finally { stream.close() }
        }
        if (cancelled()) throw TailcatClosedException()
        return best
    }

    companion object {
        val builtInRegions: List<DERPRegion> = listOf(
            DERPRegion(1, listOf(DERPNode("derp1.tailscale.com", regionID = 1)), "nyc", "New York"),
            DERPRegion(2, listOf(DERPNode("derp2.tailscale.com", regionID = 2)), "sfo", "San Francisco"),
            DERPRegion(4, listOf(DERPNode("derp4.tailscale.com", regionID = 4)), "fra", "Frankfurt"),
        )
        fun parse(json: String): List<DERPRegion> {
            val root = Json.parse(json) as? Map<*, *> ?: error("Invalid DERP map")
            val regions = root["Regions"] as? Map<*, *> ?: error("Missing DERP regions")
            require(regions.size <= 1024)
            fun Map<*, *>.str(key: String): String = this[key] as? String ?: ""
            fun Map<*, *>.int(key: String): Int = (this[key] as? Number)?.toInt() ?: 0
            return regions.values.map { entry ->
                val r = entry as? Map<*, *> ?: error("Invalid DERP region")
                val id = r.int("RegionID"); require(id > 0)
                val nodes = (r["Nodes"] as? List<*>) ?: emptyList<Any?>(); require(nodes.size <= 128)
                DERPRegion(id, nodes.map { raw ->
                    val n = raw as? Map<*, *> ?: error("Invalid DERP node")
                    DERPNode(n.str("HostName"), n.str("Name"), n.int("RegionID").takeIf { it > 0 } ?: id,
                        n.str("CertName"), n.str("IPv4"), n.str("IPv6"), n.int("STUNPort"), n.int("DERPPort"),
                        n["InsecureForTests"] == true, n["STUNOnly"] == true)
                }, r.str("RegionCode"), r.str("RegionName"))
            }.sortedBy { it.regionID }
        }
    }
}

private data class HttpResponse(val status: Int, val headers: Map<String, String>, val body: ByteArray)
private fun httpsGet(url: String, etag: String?, cancelled: () -> Boolean): HttpResponse {
    require(url.startsWith("https://")) { "DERP map URL requires HTTPS" }
    val remainder = url.substring(8)
    val authority = remainder.substringBefore('/'); val path = "/" + remainder.substringAfter('/', "")
    require(authority.isNotEmpty() && authority.none { it in "\r\n@" } && path.none { it in "\r\n" })
    val host = authority.substringBefore(':'); val port = authority.substringAfter(':', "443").toInt()
    val stream = PlatformStream()
    return streamDeadline(stream,15000,cancelled) { try {
        stream.connect(host, port, true)
        val conditional = if (!etag.isNullOrEmpty() && etag.none { it == '\r' || it == '\n' }) "If-None-Match: $etag\r\n" else ""
        stream.write("GET $path HTTP/1.1\r\nHost: $authority\r\nAccept: application/json\r\nConnection: close\r\n$conditional\r\n".encodeToByteArray())
        fun line(): String {
            val output = ArrayList<Byte>(); val one = ByteArray(1)
            while (true) {
                require(output.size < 16384)
                if (stream.read(one) <= 0) throw TailcatClosedException()
                output.add(one[0])
                if (output.size >= 2 && output[output.size - 2] == 13.toByte() && output.last() == 10.toByte()) break
            }
            return output.dropLast(2).toByteArray().decodeToString(throwOnInvalidSequence = true)
        }
        val status = line().split(' ').getOrNull(1)?.toIntOrNull() ?: error("Invalid HTTP response")
        val headers = mutableMapOf<String, String>(); var headerSize = 0
        while (true) {
            val line = line(); headerSize += line.length; require(headerSize <= 65536)
            if (line.isEmpty()) break
            val colon = line.indexOf(':'); require(colon > 0)
            headers[line.substring(0, colon).lowercase()] = line.substring(colon + 1).trim()
        }
        fun exact(count: Int): ByteArray {
            require(count in 0..2_097_152)
            val result = ByteArray(count); var offset = 0
            while (offset < count) { val n = stream.read(result, offset, count - offset); if (n <= 0) throw TailcatClosedException(); offset += n }
            return result
        }
        val body = if (status == 304) byteArrayOf() else if (headers["transfer-encoding"]?.lowercase() == "chunked") {
            var all = byteArrayOf()
            while (true) {
                val count = line().substringBefore(';').toInt(16)
                require(count >= 0 && count <= 2_097_152 - all.size)
                if (count == 0) { while (line().isNotEmpty()) { }; break }
                all += exact(count); require(line().isEmpty())
            }
            all
        } else if (headers.containsKey("content-length")) exact(headers.getValue("content-length").toInt()) else {
            var all = byteArrayOf(); val buffer = ByteArray(8192)
            while (true) { val n = stream.read(buffer); if (n <= 0) break; require(n <= 2_097_152 - all.size); all += buffer.copyOf(n) }
            all
        }
        HttpResponse(status, headers, body)
    } finally { stream.close() } }
}

private fun <T> streamDeadline(stream: PlatformStream, timeoutMillis: Long, cancelled: () -> Boolean, block: () -> T): T {
    val lock = PlatformLock(); var done = false; val end = monotonicMillis()+timeoutMillis
    io.tailcat.platform.startThread("tailcat-http-deadline") {
        while (true) {
            if (lock.withLock { if (done) true else { lock.await(100); done } }) return@startThread
            if (cancelled() || monotonicMillis() >= end) { stream.close(); return@startThread }
        }
    }
    try { return block() } finally { lock.withLock { done = true; lock.signalAll() } }
}
