package io.tailcat

import io.tailcat.platform.*
import kotlin.test.*

class DerpMapTest {
    private val tailcatMap = """{"Regions":{"302":{"RegionID":302,"RegionCode":"tc302","RegionName":"Tailcat 302",
        "Nodes":[{"Name":"302a","RegionID":302,"HostName":"tc302a.ipn.dev"}]}}}"""
    private fun cached(fetchedAtMillis: Long) = MemoryDERPMapCache().apply { store(DERPMapCacheEntry(tailcatMap, "\"v1\"", fetchedAtMillis)) }
    // Connection refused locally, so fetches fail without touching the network.
    private val unreachable = "https://127.0.0.1:1/derpmap.json"

    @Test fun defaultsToTailcatMap() {
        assertEquals("https://tailcat.dev/derpmap.json", DERPMapProvider.defaultURL)
        assertEquals(DERPMapProvider.defaultURL, DERPMapProvider().url)
        assertEquals(DERPMapProvider.defaultURL, ClientConfiguration().mapProvider.url)
        assertEquals(DERPMapProvider.defaultURL, ServerConfiguration().mapProvider.url)
    }
    @Test fun expandsTailcatRegionFromCachedMap() {
        val provider = DERPMapProvider(cache = cached(wallClockMillis()))
        val address = TailcatAddress(NodePrivateKey.generate().publicKey, regionID = 302)
        val region = provider.expand(address).single()
        assertEquals(302, region.regionID)
        assertEquals("tc302a.ipn.dev", region.nodes.single().hostName)
        assertEquals(listOf(302), provider.regions(forServer = true).map { it.regionID })
    }
    @Test fun failedFetchUsesStaleMapAndHasNoBuiltInFallback() {
        val stale = DERPMapProvider(unreachable, cached(wallClockMillis() - 7_200_000))
        assertEquals(listOf(302), stale.regions().map { it.regionID })
        assertFails { DERPMapProvider(unreachable).regions() }
    }
    @Test fun aRegionMissingFromTheSavedMapIsFetched() {
        var requests = 0
        val current = """{"Regions":{"9":{"RegionID":9,"Nodes":[{"Name":"9a","RegionID":9,"HostName":"nine.example"}]}}}"""
        val provider = DERPMapProvider(unreachable, cached(wallClockMillis())) { _, _, _, _ -> requests++; HttpResponse(200, emptyMap(), current.encodeToByteArray()) }
        val region = provider.expand(TailcatAddress(NodePrivateKey.generate().publicKey, regionID = 9)).single()
        assertEquals("nine.example", region.nodes.single().hostName)
        assertEquals(1, requests)
    }
    /** Opt-in: TAILCAT_LIVE_DERP_MAP=1 fetches the default map over the network. */
    @Test fun liveDefaultMap() {
        if (platformTestEnv("TAILCAT_LIVE_DERP_MAP") != "1") return
        val regions = DERPMapProvider().regions()
        assertTrue(regions.isNotEmpty())
        assertTrue(regions.none { region -> region.nodes.any { it.hostName.endsWith(".tailscale.com") } })
        println("Live DERP map regions: ${regions.map { it.regionID }}")
    }
}
