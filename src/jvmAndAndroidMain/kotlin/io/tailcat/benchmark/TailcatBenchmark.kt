package io.tailcat.benchmark

import io.tailcat.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** Opt-in, raw-TCP-echo benchmark runner shared by the JVM CLI and Android debug example. */
class TailcatBenchmark(private val output: (String) -> Unit = ::println) : AutoCloseable {
    private val closed = AtomicBoolean()
    @Volatile private var server: TailcatServer? = null
    @Volatile private var client: TailcatClient? = null
    @Volatile private var independentFirst: TailcatClient? = null
    @Volatile private var independentSecond: TailcatClient? = null
    private fun now() = System.nanoTime()
    private fun elapsed(start: Long) = (now() - start) / 1_000_000.0
    private fun route(client: TailcatClient): String = when (val path = client.path) {
        ConnectionPath.Relay -> "relay"
        is ConnectionPath.Direct -> "direct:${path.endpoint}"
    }
    private fun emit(values: Map<String, Any?>) = output(json(values))

    fun run(arguments: Array<String>) {
        val options = arguments.drop(1).associate { it.substringBefore('=') to it.substringAfter('=', "") }
        val mode = options["relayFirst"]?.toBooleanStrict() ?: false
        val source = options["source"] ?: "unknown"
        val android = System.getProperty("java.vm.name") == "Dalvik"
        val common = linkedMapOf<String, Any?>("schema" to "tailcat-benchmark-v1", "runtime" to if (android) "kotlin-android" else "kotlin-jvm",
            "source" to source, "target" to options["target"], "runId" to options["runId"], "relayFirst" to mode,
            "vmName" to System.getProperty("java.vm.name"), "javaVersion" to System.getProperty("java.version"),
            "buildVariant" to if (android) "debug" else "jvm", "os" to System.getProperty("os.name"),
            "osVersion" to System.getProperty("os.version"), "pid" to processId(), "wallTimeMillis" to System.currentTimeMillis())
        try {
            when (arguments.firstOrNull()) {
                "server" -> runServer(options, mode, common)
                "client" -> runClient(options, mode, common)
                else -> error("server|client source=linux target=mac relayFirst=false region=301 address=tc... trials=1 bytes=262144 recovery=true")
            }
        } catch (failure: Throwable) {
            emit(common + mapOf("type" to "error", "event" to "error", "status" to "error", "error" to failure.toString()))
            throw failure
        }
    }

    private fun runServer(options: Map<String, String>, mode: Boolean, common: Map<String, Any?>) {
        val regionID = options["region"]?.toInt() ?: 301
        val region = DERPMapProvider().regions().first { it.regionID == regionID }
        val echo: TailcatTCPHandler = { stream ->
            try {
                val buffer = ByteArray(16_384)
                while (!closed.get()) {
                    val count = stream.read(buffer, timeoutMillis = 120_000)
                    if (count < 0) break
                    stream.write(buffer, length = count, timeoutMillis = 60_000)
                }
            } finally { stream.close() }
        }
        val instance = TailcatServer(ServerConfiguration(region = region, relayFirst = mode,
            onTCP = { port -> if (port == 8080) echo else null }))
        server = instance
        if (closed.get()) { instance.close(); return }
        val start = now()
        val address = instance.start()
        emit(common + mapOf("type" to "ready", "event" to "serverReady", "address" to address.encode(), "port" to 8080,
            "regionId" to region.regionID, "regionCode" to region.regionCode,
            "relay" to region.nodes.first().hostName,
            "relayHosts" to region.nodes.map { it.hostName }, "relayIPv4" to region.nodes.map { it.ipv4 },
            "serverStartMs" to elapsed(start)))
        while (!closed.get()) Thread.sleep(200)
    }

    private fun runClient(options: Map<String, String>, mode: Boolean, common: Map<String, Any?>) {
        if (options["secondIndependent"]?.toBooleanStrict() == true) {
            runIndependentClients(options, mode, common)
            return
        }
        val address = options["address"] ?: error("address required")
        val trials = options["trials"]?.toInt() ?: 1
        val firstTrial = options["trial"]?.toInt() ?: 1
        val payloadBytes = options["bytes"]?.toInt() ?: 262_144
        require(trials in 1..20 && payloadBytes in 32..4_194_304)
        val mapProvider = DERPMapProvider()
        repeat(trials) { index ->
            check(!closed.get())
            val start = now()
            val instance = TailcatClient.connect(address, ClientConfiguration(mapProvider = mapProvider,
                connectTimeoutMillis = 30_000, relayFirst = mode))
            client = instance
            if (closed.get()) { instance.close(); return }
            val connectMs = elapsed(start)
            val trial = common + mapOf("trial" to firstTrial + index, "coldProcess" to (index == 0),
                "regionId" to instance.serverAddress.regions.firstOrNull()?.regionID,
                "relayHosts" to instance.serverAddress.regions.flatMap { it.nodes }.map { it.hostName })
            try {
                measure(instance, start, connectMs, "cold_new_client", false, payloadBytes,
                    options["recovery"]?.toBooleanStrict() ?: true, trial)
                if (options["warm"]?.toBooleanStrict() != false) {
                    measure(instance, now(), 0.0, "warm_reused_client_second_stream", true, payloadBytes, false, trial)
                }
            } finally { instance.close(); client = null }
        }
    }

    /** A separate experiment: no second stream is mistaken for a second independent client. */
    private fun runIndependentClients(options: Map<String, String>, mode: Boolean, common: Map<String, Any?>) {
        val address = TailcatAddress.parse(options["address"] ?: error("address required"))
        val trials = options["trials"]?.toInt() ?: 1
        val firstTrial = options["trial"]?.toInt() ?: 1
        require(trials in 1..20)
        repeat(trials) { index ->
            val trial = common + mapOf("schema" to "tailcat-independent-startup-v1", "trial" to firstTrial + index,
                "sessionReused" to false, "firstRetained" to true,
                "relayHosts" to address.regions.flatMap { it.nodes }.map { it.hostName })
            val firstTrace = StartupTrace()
            var secondTrace: StartupTrace? = null
            var firstStream: TailcatConnection? = null
            var secondStream: TailcatConnection? = null
            var heartbeat: Thread? = null
            val running = AtomicBoolean(true)
            val heartbeatFailure = AtomicReference<Throwable?>(null)
            val heartbeatCount = AtomicInteger()
            val heartbeatReady = CountDownLatch(1)
            var firstResult: MutableMap<String, Any?>? = null
            var secondResult: MutableMap<String, Any?>? = null
            fun exchange(stream: TailcatConnection, sequence: Int) {
                val bytes = packet(sequence)
                stream.write(bytes, timeoutMillis = 30_000)
                check(readExact(stream, bytes.size).contentEquals(bytes)) { "Independent stream payload mismatch" }
            }
            fun connect(trace: StartupTrace, phase: String, cold: Boolean): Triple<TailcatClient, TailcatConnection, MutableMap<String, Any?>> {
                check(!closed.get())
                val result = (trial + mapOf("type" to "sample", "event" to "sample", "phase" to phase,
                    "coldProcess" to cold, "status" to "error")).toMutableMap()
                if (phase == "first_independent_client") firstResult = result else secondResult = result
                val start = now()
                val identity = NodePrivateKey.generate()
                val instance = TailcatClient.connectTraced(address, ClientConfiguration(privateKey = identity,
                    connectTimeoutMillis = 30_000, relayFirst = mode), trace)
                if (phase == "first_independent_client") independentFirst = instance else independentSecond = instance
                if (closed.get()) { instance.close(); throw TailcatClosedException() }
                val connected = elapsed(start)
                val stream = instance.dialTCP(8080, 30_000)
                try {
                    trace.mark("tcpDialDone")
                    val bytes = packet(if (cold) 101 else 202)
                    stream.write(bytes, timeoutMillis = 30_000)
                    val firstByte = readExact(stream, 1)
                    val firstAppByte = elapsed(start)
                    trace.mark("firstAppByte")
                    check((firstByte + readExact(stream, bytes.size - 1)).contentEquals(bytes))
                    val echoTime = elapsed(start)
                    trace.mark("firstEcho")
                    result.putAll(mapOf("connectMs" to connected, "firstAppByteMs" to firstAppByte,
                        "firstEchoMs" to echoTime, "pathAtFirstEcho" to route(instance),
                        "nodePublicKey" to instance.publicKey.toString(),
                        "discoPublicKey" to identity.discoPublicKey.hex(), "status" to "ok"))
                    return Triple(instance, stream, result)
                } catch (failure: Throwable) { stream.close(); throw failure }
            }
            try {
                val (first, stream1, result1) = connect(firstTrace, "first_independent_client", index == 0)
                firstStream = stream1; firstResult = result1
                heartbeat = thread(name = "benchmark-independent-first", isDaemon = true) {
                    try {
                        while (running.get() && !closed.get()) {
                            exchange(stream1, 10_000 + heartbeatCount.get())
                            heartbeatCount.incrementAndGet(); heartbeatReady.countDown()
                            Thread.sleep(25)
                        }
                    } catch (failure: Throwable) { heartbeatFailure.set(failure); heartbeatReady.countDown() }
                }
                check(heartbeatReady.await(30, TimeUnit.SECONDS)) { "First client heartbeat did not start" }
                heartbeatFailure.get()?.let { throw it }
                val beforeConnect = heartbeatCount.get()
                val trace2 = StartupTrace()
                secondTrace = trace2
                val (second, stream2, result2) = connect(trace2, "second_independent_client", false)
                secondStream = stream2; secondResult = result2
                val afterConnect = heartbeatCount.get()
                check(first.publicKey != second.publicKey) { "Independent clients reused a node identity" }
                val beforeTraffic = heartbeatCount.get()
                repeat(16) { exchange(stream2, 20_000 + it) }
                // This observation wait is outside both startup measurements.
                val progressDeadline = now() + TimeUnit.SECONDS.toNanos(30)
                while (heartbeatCount.get() == beforeTraffic && heartbeatFailure.get() == null && now() < progressDeadline && !closed.get()) Thread.sleep(5)
                heartbeatFailure.get()?.let { throw it }
                check(heartbeatCount.get() > beforeTraffic) { "First client stopped making independent progress" }
                running.set(false); heartbeat.join(31_000)
                check(!heartbeat.isAlive) { "First client heartbeat did not stop" }
                heartbeatFailure.get()?.let { throw it }
                second.close(); independentSecond = null
                exchange(stream1, 30_000)
                val firstTCP = firstTrace.snapshot().firstOrNull { it.name == "tcpConnected" }?.value
                val secondTCP = trace2.snapshot().firstOrNull { it.name == "tcpConnected" }?.value
                check(firstTCP != null && secondTCP != null && firstTCP != secondTCP) { "Expected separate relay TCP sockets" }
                val firstUDP = firstTrace.snapshot().filter { it.name == "udp4Bound" || it.name == "udp6Bound" }.mapNotNull { it.value }.toSet()
                val secondUDP = trace2.snapshot().filter { it.name == "udp4Bound" || it.name == "udp6Bound" }.mapNotNull { it.value }.toSet()
                check(firstUDP.intersect(secondUDP).isEmpty()) { "Independent clients reused a UDP port" }
                emit(trial + mapOf("type" to "independenceCheck", "event" to "independenceCheck", "status" to "ok",
                    "firstEchoesDuringSecondConnect" to afterConnect - beforeConnect,
                    "firstConcurrentEchoes" to heartbeatCount.get(), "secondConcurrentEchoes" to 16,
                    "distinctNodeKeys" to true, "distinctRelayTCPPorts" to true,
                    "firstUDPPorts" to firstUDP.toList(), "secondUDPPorts" to secondUDP.toList(),
                    "udpPortsObservedForBoth" to (firstUDP.isNotEmpty() && secondUDP.isNotEmpty()),
                    "firstSurvivesSecondClose" to true))
            } catch (failure: Throwable) {
                firstResult?.set("status", "error"); secondResult?.set("status", "error")
                emit(trial + mapOf("type" to "independenceCheck", "event" to "independenceCheck", "status" to "error", "error" to failure.toString()))
                throw failure
            } finally {
                running.set(false)
                firstStream?.close(); secondStream?.close()
                independentSecond?.close(); independentFirst?.close()
                independentSecond = null; independentFirst = null
                heartbeat?.join(1000)
                fun finish(result: MutableMap<String, Any?>?, trace: StartupTrace) {
                    if (result == null) return
                    val events = trace.snapshot()
                    result["startupTrace"] = events.map { mapOf("phase" to it.name, "atMs" to it.atMillis, "value" to it.value) }
                    result["wgEstablishedMs"] = events.firstOrNull { it.name == "wgEstablished" }?.atMillis
                    result["connectReturnMs"] = events.firstOrNull { it.name == "connectReturn" }?.atMillis
                    val established = events.firstOrNull { it.name == "wgEstablished" }?.atMillis
                    val returned = events.firstOrNull { it.name == "connectReturn" }?.atMillis
                    result["handshakeToConnectReturnMs"] = if (established != null && returned != null) returned - established else null
                    emit(result)
                }
                finish(firstResult, firstTrace); secondTrace?.let { finish(secondResult, it) }
            }
        }
    }

    private fun measure(instance: TailcatClient, start: Long, connectMs: Double, phase: String,
                        reused: Boolean, payloadBytes: Int, recover: Boolean, common: Map<String, Any?>) {
        val result = linkedMapOf<String, Any?>()
        result.putAll(common)
        result.putAll(mapOf("type" to "sample", "event" to "sample", "phase" to phase, "sessionReused" to reused,
            "connectMs" to connectMs, "initialPath" to route(instance), "directObservationWindowMs" to 15_000))
        val sampling = AtomicBoolean(true)
        val firstDirect = AtomicReference<Double?>(null)
        val transitions = mutableListOf<Map<String, Any?>>()
        val sampler = thread(name = "benchmark-path", isDaemon = true) {
            var previous = ""
            while (sampling.get() && !closed.get()) {
                val path = route(instance)
                val at = elapsed(start)
                if (path.startsWith("direct:") && firstDirect.get() == null) firstDirect.set(at)
                if (path != previous) synchronized(transitions) { transitions.add(mapOf("atMs" to at, "path" to path)); previous = path }
                Thread.sleep(20)
            }
        }
        var stream: TailcatConnection? = null
        var stage = "dial"
        var recoveryObserver: Thread? = null
        var recoveryDeadline = 0L
        val recoverySampling = AtomicBoolean(true)
        val recoveryDirect = AtomicReference<Double?>(null)
        try {
            stream = instance.dialTCP(8080, 30_000)
            result["dialCompleteMs"] = elapsed(start)
            stage = "firstEcho"
            val initial = packet(0)
            stream.write(initial, timeoutMillis = 30_000)
            val first = readExact(stream, 1)
            result["firstAppByteMs"] = elapsed(start)
            check((first + readExact(stream, 31)).contentEquals(initial))
            result["firstEchoMs"] = elapsed(start)
            result["pathAtFirstEcho"] = route(instance)
            stage = "directObservation"
            val deadline = start + ((connectMs + 15_000) * 1_000_000).toLong()
            while (firstDirect.get() == null && now() < deadline && !closed.get()) Thread.sleep(20)
            val observedDirect = firstDirect.get()
            result["directObservedMs"] = observedDirect
            result["directCensored"] = observedDirect == null
            result["steadyPath"] = route(instance)
            stage = "rtt"
            result["rttMs"] = (1..20).map { sequence ->
                val ping = packet(sequence)
                val pingStart = now()
                stream.write(ping, timeoutMillis = 30_000)
                check(readExact(stream, ping.size).contentEquals(ping))
                elapsed(pingStart)
            }
            stage = "throughput"
            val payload = ByteArray(payloadBytes) { (it * 31 + 7).toByte() }
            val writerDone = CountDownLatch(1)
            val writerFailure = AtomicReference<Throwable?>(null)
            val transferStart = now()
            val active = stream
            val writer = thread(name = "benchmark-write", isDaemon = true) {
                try { active.write(payload, timeoutMillis = 60_000) }
                catch (failure: Throwable) { writerFailure.set(failure); active.close() }
                finally { writerDone.countDown() }
            }
            try {
                check(readExact(stream, payload.size).contentEquals(payload))
                check(writerDone.await(60, TimeUnit.SECONDS)) { "Writer completion timed out" }
                writerFailure.get()?.let { throw it }
            } finally { if (writer.isAlive) { active.close(); writer.join(1000) } }
            val transferMs = elapsed(transferStart)
            result["payloadBytes"] = payloadBytes
            result["throughputEchoMs"] = transferMs
            result["throughputPayloadMbps"] = payloadBytes * 8.0 / (transferMs * 1000)
            result["throughputIntegrity"] = true
            if (recover) {
                stage = "recovery"
                result["pathBeforeRecovery"] = route(instance)
                val recoveryStart = now()
                instance.resetNetworkPaths()
                result["pathAfterNotification"] = route(instance)
                // Observe independently of TCP retransmission/echo completion, after the old route is cleared.
                recoveryDeadline = now() + TimeUnit.SECONDS.toNanos(15)
                recoveryObserver = thread(name = "benchmark-recovery-path", isDaemon = true) {
                    while (recoverySampling.get() && !closed.get() && now() < recoveryDeadline) {
                        val direct = instance.path is ConnectionPath.Direct
                        if (direct && now() < recoveryDeadline) { recoveryDirect.set(elapsed(recoveryStart)); break }
                        Thread.sleep(20)
                    }
                }
                val echo = packet(1001)
                stream.write(echo, timeoutMillis = 30_000)
                check(readExact(stream, echo.size).contentEquals(echo))
                result["recoveryEchoMs"] = elapsed(recoveryStart)
                result["pathAtRecoveryEcho"] = route(instance)
            }
            result["status"] = "ok"
        } catch (failure: Throwable) {
            result["status"] = "error"; result["errorStage"] = stage; result["error"] = failure.toString()
        } finally {
            recoveryObserver?.let { observer ->
                observer.join(((recoveryDeadline - now()) / 1_000_000).coerceAtLeast(0) + 1000)
                recoverySampling.set(false)
                result["recoveryDirectMs"] = recoveryDirect.get()
                result["recoveryDirectCensored"] = recoveryDirect.get() == null
                result["recoveryDirectObservationWindowMs"] = 15_000
                result["recoveryPath"] = route(instance)
            }
            stream?.close(); sampling.set(false); sampler.join(1000)
            result["pathTransitions"] = synchronized(transitions) { transitions.toList() }
            result["totalMs"] = elapsed(start)
            emit(result)
        }
    }

    private fun packet(sequence: Int) = ByteArray(32) { index -> if (index < 4) (sequence ushr (index * 8)).toByte() else (index * 17 + sequence).toByte() }
    private fun readExact(stream: TailcatConnection, size: Int): ByteArray {
        val bytes = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val count = stream.read(bytes, offset, size - offset, 30_000)
            check(count > 0) { "Unexpected EOF at $offset/$size" }; offset += count
        }
        return bytes
    }
    override fun close() { closed.set(true); client?.close(); independentFirst?.close(); independentSecond?.close(); server?.close() }

    companion object {
        @JvmStatic fun main(args: Array<String>) {
            TailcatBenchmark().use { runner ->
                Runtime.getRuntime().addShutdownHook(Thread({ runner.close() }, "benchmark-shutdown"))
                runner.run(args)
            }
        }
        private fun processId(): Long? = try {
            val process = Class.forName("android.os.Process")
            (process.getMethod("myPid").invoke(null) as Number).toLong()
        } catch (_: Exception) {
            try {
                val handle = Class.forName("java.lang.ProcessHandle")
                (handle.getMethod("pid").invoke(handle.getMethod("current").invoke(null)) as Number).toLong()
            } catch (_: Exception) { null }
        }
        internal fun json(value: Any?): String = when (value) {
            null -> "null"
            is String -> "\"" + value.flatMap { char -> when (char) {
                '\\' -> "\\\\"; '"' -> "\\\""; '\n' -> "\\n"; '\r' -> "\\r"; '\t' -> "\\t"
                else -> if (char < ' ') "\\u" + char.code.toString(16).padStart(4, '0') else char.toString()
            }.toList() }.joinToString("") + "\""
            is Number, is Boolean -> value.toString()
            is Map<*, *> -> value.entries.joinToString(",", "{", "}") { json(it.key.toString()) + ":" + json(it.value) }
            is Iterable<*> -> value.joinToString(",", "[", "]") { json(it) }
            else -> json(value.toString())
        }
    }
}
