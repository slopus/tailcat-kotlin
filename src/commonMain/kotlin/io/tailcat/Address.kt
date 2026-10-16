package io.tailcat

data class DERPNode(
    val hostName: String,
    val name: String = "",
    val regionID: Int = 0,
    val certName: String = "",
    val ipv4: String = "",
    val ipv6: String = "",
    val stunPort: Int = 0,
    val derpPort: Int = 0,
    val insecureForTests: Boolean = false,
    val stunOnly: Boolean = false,
)

data class DERPRegion(
    val regionID: Int,
    val nodes: List<DERPNode>,
    val regionCode: String = "",
    val regionName: String = "",
)

/** A shareable secret containing the server identity, PSK and relay information. */
class TailcatAddress(
    val serverPublicKey: NodePublicKey,
    serverDiscoPublicKey: ByteArray? = null,
    val presharedKey: PresharedKey? = null,
    regions: List<DERPRegion> = emptyList(),
    val regionID: Int = 0,
) {
    private val disco = serverDiscoPublicKey?.copyOf()
    val serverDiscoPublicKey: ByteArray? get() = disco?.copyOf()
    val regions: List<DERPRegion> = regions.map { it.copy(nodes = it.nodes.toList()) }
    init { require(disco == null || disco.size == 32) }

    fun encode(): String {
        val fields = linkedMapOf<String, Cbor>("p" to Cbor.Bytes(serverPublicKey.raw))
        if (disco != null && disco.any { it != 0.toByte() }) fields["k"] = Cbor.Bytes(disco)
        if (presharedKey != null && !presharedKey.isZero) fields["q"] = Cbor.Bytes(presharedKey.raw)
        if (regions.isNotEmpty()) fields["r"] = Cbor.Array(regions.map { region ->
            val nodes = region.nodes.filter { !it.stunOnly }.map { node ->
                val n = linkedMapOf<String, Cbor>()
                fun text(key: String, value: String) { if (value.isNotEmpty()) n[key] = Cbor.Text(value) }
                fun integer(key: String, value: Int) { if (value != 0) n[key] = Cbor.Integer(value.toLong()) }
                if (node.hostName.isEmpty()) text("n", node.name)
                text("h", node.hostName); text("t", node.certName); text("4", node.ipv4); text("6", node.ipv6)
                integer("s", node.stunPort); integer("d", node.derpPort)
                if (node.insecureForTests) n["x"] = Cbor.Bool(true)
                Cbor.Map(n)
            }
            Cbor.Map(if (nodes.isEmpty()) emptyMap() else mapOf("N" to Cbor.Array(nodes)))
        })
        if (regionID != 0) fields["i"] = Cbor.Integer(regionID.toLong())
        return "tc" + Base64Url.encode(Cbor.Map(fields).encode())
    }
    override fun toString(): String = encode()

    companion object {
        fun parse(text: String): TailcatAddress {
            require(text.startsWith("tc") && text.length <= 90_000) { "Expected tc address" }
            val root = (Cbor.decode(Base64Url.decode(text.substring(2))) as? Cbor.Map)?.value ?: error("Expected address map")
            fun Map<String, Cbor>.bytes(key: String): ByteArray? = if (containsKey(key)) (get(key) as? Cbor.Bytes)?.value ?: error("Expected bytes: $key") else null
            fun Map<String, Cbor>.int(key: String, default: Int = 0): Int {
                val n = (get(key) as? Cbor.Integer)?.value ?: if (containsKey(key)) error("Expected integer: $key") else return default
                require(n in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()); return n.toInt()
            }
            fun Map<String, Cbor>.string(key: String): String = (get(key) as? Cbor.Text)?.value ?: if (containsKey(key)) error("Expected text: $key") else ""
            val regions = if (!root.containsKey("r")) emptyList() else {
                val entries = (root["r"] as? Cbor.Array)?.value ?: error("Expected regions")
                require(entries.size <= 1024)
                entries.mapIndexed { index, entry ->
                    val r = (entry as? Cbor.Map)?.value ?: error("Expected region")
                    val id = r.int("i").let { if (it == 0) index + 1 else it }
                    val nodeEntries = if (r.containsKey("N")) (r["N"] as? Cbor.Array)?.value ?: error("Expected nodes") else emptyList()
                    require(nodeEntries.size <= 128)
                    val nodes = nodeEntries.map { node ->
                        val n = (node as? Cbor.Map)?.value ?: error("Expected node")
                        val host = n.string("h")
                        val port = n.int("d"); val stunPort = n.int("s")
                        require(port in 0..65535 && stunPort in -1..65535)
                        DERPNode(hostName = host, name = n.string("n").ifEmpty { host }, regionID = n.int("i").let { if (it == 0) id else it },
                            certName = n.string("t"), ipv4 = n.string("4"), ipv6 = n.string("6"), stunPort = stunPort, derpPort = port,
                            insecureForTests = (n["x"] as? Cbor.Bool)?.value ?: false)
                    }
                    DERPRegion(id, nodes, r.string("c").ifEmpty { id.toString() }, r.string("m"))
                }
            }
            return TailcatAddress(NodePublicKey(root.bytes("p") ?: error("Missing public key")), root.bytes("k"),
                root.bytes("q")?.let(::PresharedKey), regions, root.int("i"))
        }
    }
}
