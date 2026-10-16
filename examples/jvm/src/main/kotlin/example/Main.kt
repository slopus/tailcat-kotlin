package example

import io.tailcat.*

fun main(args: Array<String>) {
    if (args.isEmpty()) { println("Identity: ${NodePrivateKey.generate().publicKey}"); return }
    val client = TailcatClient.connect(args[0])
    try {
        val stream = client.dialTCP(args.getOrNull(1)?.toInt() ?: 8080)
        stream.write("hello from the JVM".encodeToByteArray())
        stream.shutdownOutput()
        while (true) { val bytes = stream.read(); if (bytes.isEmpty()) break; print(bytes.decodeToString()) }
        stream.close()
    } finally { client.close() }
}
