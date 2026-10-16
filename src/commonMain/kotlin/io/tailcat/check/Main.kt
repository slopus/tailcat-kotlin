package io.tailcat.check

import io.tailcat.*
import io.tailcat.platform.*

/** Executable embedding example and independent upstream transfer check. */
fun main(args: Array<String>) {
    val tcpEcho: TailcatTCPHandler = { connection ->
        val buffer = ByteArray(16384)
        while (true) { val n = connection.read(buffer, timeoutMillis = 120000); if (n < 0) break; connection.write(buffer, length = n, timeoutMillis = 120000) }
        connection.shutdownOutput(30000); connection.close()
    }
    val udpEcho: TailcatUDPHandler = { connection ->
        try { while (true) connection.send(connection.receive(120000)) } finally { connection.close() }
    }
    when (args.firstOrNull()) {
        "client" -> {
            require(args.size >= 2) { "client tc-address [bytes] [plain]" }
            val count = args.getOrNull(2)?.toInt() ?: 262144
            val timeout = args.firstOrNull { it.startsWith("timeout=") }?.substringAfter('=')?.toLong() ?: 30_000
            val client = TailcatClient.connect(args[1], ClientConfiguration(connectTimeoutMillis = timeout, testOnlyPlaintextDERP = "plain" in args))
            println("Tunnel connected; opening sockets")
            try {
                val target = args.firstOrNull { it.startsWith("target=") }?.substring(7)?.let { value ->
                    if (value.startsWith('[')) TailcatEndpoint(value.substringAfter('[').substringBefore(']'),value.substringAfter("]:").toInt())
                    else TailcatEndpoint(value.substringBeforeLast(':'),value.substringAfterLast(':').toInt())
                }
                val stream = if (target == null) client.dialTCP(80) else client.dialTCP(target)
                val expected = ByteArray(count) { (it * 31).toByte() }
                val lock = PlatformLock(); var done = false; var failure: Throwable? = null
                startThread("check-write") {
                    try { stream.write(expected, timeoutMillis = 120000); stream.shutdownOutput(30000) }
                    catch (error: Throwable) { lock.withLock { failure = error }; stream.close() }
                    finally { lock.withLock { done = true; lock.signalAll() } }
                }
                val buffer = ByteArray(16384); var received = 0
                while (true) {
                    val n = stream.read(buffer, timeoutMillis = 120000); if (n < 0) break
                    check(received + n <= count)
                    repeat(n) { check(buffer[it] == expected[received + it]) }
                    received += n
                }
                check(received == count)
                lock.withLock { while (!done) lock.await(1000); failure?.let { throw it } }
                stream.close()
                val udp = if (target == null) client.dialUDP(53) else client.dialUDP(target)
                for (size in listOf(0, 1, 31, 1232)) {
                    val bytes = ByteArray(size) { it.toByte() }; udp.send(bytes); check(udp.receive(10000).contentEquals(bytes))
                }
                udp.close()
                println("PASS TCP $count bytes FIN/EOF; UDP 0/1/31/1232; ${client.path}")
            } finally { client.close() }
        }
        "server" -> {
            require(args.size >= 3) { "server relay-host relay-port [plain]" }
            val node = DERPNode(args[1], ipv4 = args[1], stunPort = -1, derpPort = args[2].toInt())
            val server = TailcatServer(ServerConfiguration(region = DERPRegion(1, listOf(node)), testOnlyPlaintextDERP = "plain" in args,
                onTCP = { port -> if (port == 80) tcpEcho else null },
                onUDP = { port -> if (port == 53) udpEcho else null },
                onTCPForward = { tcpEcho }, onUDPForward = { udpEcho }))
            println(server.start().encode())
            while (true) platformSleep(1000)
        }
        else -> println("tailcat-check client tc-address [bytes] [plain] | server relay-host relay-port [plain]")
    }
}
