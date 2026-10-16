# tailcat-kotlin

Embed private TCP streams and UDP datagrams in JVM servers, Android apps and
Linux Kotlin/Native programs.

A Kotlin Multiplatform port of [tailscale/tailcat](https://github.com/tailscale/tailcat).
One app starts a server and shares its `tc` address; another connects and reads
and writes bytes through a blocking socket API. WireGuard encrypts the tunnel,
with direct peer connections and DERP relay fallback.

The protocol stack is common Kotlin. The Kotlin standard library is its only
runtime package dependency; platform SDKs provide sockets and TLS. There is no
Go runtime, Swift bridge, TUN device, daemon or Tailscale account to configure.

## Platforms

| Target | Runtime requirements | Verified here |
| --- | --- | --- |
| JVM | Java 17+; SDK sockets and TLS | Tests and Go interoperability on JDK 21 |
| Android | API 24+; SDK sockets and TLS | API 36 ART client/server transfers and verified TLS |
| Linux x64 | POSIX, OpenSSL 3 and a system CA store | Native tests, client/server transfers and a standalone consumer |
| Linux arm64 | POSIX, OpenSSL 3 and a system CA store | Compiled and published; runtime not executed |

## Install

Publish a checkout to your local Maven repository before adding the dependency.
Building this repository uses JDK 21, Android SDK 36 and Build Tools 36.0.0.
Publish the Linux variants from a Linux checkout.

```sh
git clone https://github.com/slopus/tailcat-kotlin.git
cd tailcat-kotlin
./gradlew publishToMavenLocal
```

In your JVM or Android module's `build.gradle.kts`:

```kotlin
repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("io.tailcat:tailcat-kotlin:0.1.0")
}
```

For a Multiplatform module, put the same dependency in
`kotlin.sourceSets.commonMain.dependencies`. Gradle selects the platform variant.
The standalone [JVM](examples/jvm), [Android](examples/android) and
[Native](examples/native) examples consume these published coordinates.

## Start a TCP server

This echo server listens on tunnel port 8080 and accepts connections in sequence.
Run it from a `main` function or an application worker thread:

```kotlin
import io.tailcat.*

fun main() {
    val server = TailcatServer()
    try {
        val address = server.start()
        val listener = server.listenTCP(8080)
        println(address.encode()) // Share this tc address privately.

        while (true) {
            val stream = listener.accept()
            try {
                val buffer = ByteArray(8192)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    stream.write(buffer, length = count)
                }
                stream.shutdownOutput()
            } finally {
                stream.close()
            }
        }
    } finally {
        server.close()
    }
}
```

The address includes the server identity, relay details and a random preshared
key. Treat it as a bearer secret. For concurrent services, dispatch accepted
connections to your application's executor or configure an `onTCP` handler in
`ServerConfiguration`; handlers run on library workers.

## Connect from another app

Pass the server's printed address as the first argument to this client. One
client can open multiple independent TCP streams and UDP flows.

```kotlin
import io.tailcat.*

fun main(args: Array<String>) {
    require(args.size == 1) { "Pass the server's tc address" }
    val client = TailcatClient.connect(args[0])
    try {
        val stream = client.dialTCP(8080)
        try {
            stream.write("hello from Kotlin".encodeToByteArray(), timeoutMillis = 10_000)
            stream.shutdownOutput(timeoutMillis = 10_000)

            while (true) {
                val bytes = stream.read(timeoutMillis = 10_000)
                if (bytes.isEmpty()) break // TCP EOF
                print(bytes.decodeToString())
            }
        } finally {
            stream.close()
        }
    } finally {
        client.close()
    }
}
```

`read(buffer)` returns available bytes, blocks when none are ready and returns
`-1` at EOF. The byte-array overload returns an empty array at EOF. `write` waits
for acknowledgement; `drain` waits for outstanding writes without sending FIN.
`shutdownOutput` waits for FIN acknowledgement and keeps reads open. For larger
transfers, read and write concurrently so neither side fills the other's buffer.

Close servers, clients, listeners and streams when their owning feature ends.
Closing an owner interrupts its pending operations and closes its sockets. A
timeout of zero waits indefinitely on reads, writes and accepts; client startup
has a configurable positive `connectTimeoutMillis`.

## Send UDP datagrams

Configure this separate echo server for UDP port 5353. The selector runs for
each new flow; the handler echoes one datagram and closes that flow.

```kotlin
val udpServer = TailcatServer(
    ServerConfiguration(onUDP = { port ->
        if (port != 5353) null else { flow ->
            try {
                flow.send(flow.receive(timeoutMillis = 10_000))
            } finally {
                flow.close()
            }
        }
    })
)

try {
    println(udpServer.start().encode())
    readln() // Keep this console example running until Enter is pressed.
} finally {
    udpServer.close()
}
```

Connect to that server's address and send an empty datagram:

```kotlin
val client = TailcatClient.connect(udpServerAddress)
try {
    val flow = client.dialUDP(5353)
    try {
        flow.send(byteArrayOf())
        val reply = flow.receive(timeoutMillis = 10_000)
        check(reply.isEmpty()) // A valid empty datagram, not EOF.
    } finally {
        flow.close()
    }
} finally {
    client.close()
}
```

Datagrams preserve message boundaries and support payloads up to 1,232 bytes.
For explicit listeners, use `server.listenUDP(5353)` and `listener.accept()`;
each accepted connection identifies one source IP and port. Idle flows expire
after two minutes by default, configurable with `udpIdleTimeoutMillis`.

## Identity, admission and forwarding

Supply a `NodePrivateKey` through `ServerConfiguration` or `ClientConfiguration`
to retain an identity across launches. Persist its `rawValue` in your app's
secure storage and restore it with `NodePrivateKey(savedBytes)`. Servers also
need a persistent `PresharedKey` to keep the same address secret. Keys expose
defensive byte copies; the library leaves storage to the app.

`KeySet` supplies a synchronized allow-list for `allowClient`. Removing a key
affects future admissions; call `server.disconnectClient(key)` to revoke an
existing peer. `server.peerKey(connection)` attributes both TCP and UDP flows
to an authenticated node. Explicit listeners take precedence over `onTCP` and
`onUDP` selectors.

Clients can dial a `TailcatEndpoint` to request a destination through the server.
Configure `onTCPForward` or `onUDPForward` to supply the service or proxy handler,
and `allowProxy` to restrict targets. Endpoints accept numeric IP addresses;
IPv4 uses upstream's `64:ff9b::/96` mapping. `proxyConnections` copies two Tailcat
streams with half-close propagation.

DERP provides the initial route and stays available when direct UDP cannot
connect. `client.path` and `server.path(key)` report the current route. Local
interface changes refresh discovery; call `resetNetworkPaths()` after a known
network change. Custom regions and cached DERP maps are configurable before
startup. Production TLS verifies the certificate chain and hostname by default.

## Android and Native integration

On Android, keep blocking calls off the UI thread and close the client/server
with the owning component. Use a worker thread, your application's executor or
its coroutine I/O dispatcher; the library adds no coroutine dependency.
Coroutine callers must arrange owner closure or library timeouts for cancellation.
Include the Internet permission in the host manifest:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

The [example Activity](examples/android/src/main/kotlin/io/tailcat/example/MainActivity.kt)
shows worker-thread connection and lifecycle cleanup.

Linux Native needs target-architecture OpenSSL 3 (`libssl.so.3` and
`libcrypto.so.3`) and a system CA store. Executables inherit the libraries'
glibc requirements; [Native linking](Documentation/Architecture.md#native-linking)
covers library paths and sysroot details.

## Build and verification

Run shared tests and Android release checks:

```sh
./gradlew jvmTest linuxX64Test assembleRelease lintRelease
```

After publishing locally, build the standalone consumers:

```sh
./gradlew -p examples/jvm run
./gradlew -p examples/android assembleDebug
./gradlew -p examples/native linkDebugExecutableLinuxX64
```

The JVM and Linux x64 Native suites each passed 32 tests, including loss,
reordering, concurrent streams, shutdown and configured TLS/relay fixtures.
Independent Go peers exercised both client and server roles on JVM, Native and
Android API 36. Android also completed transfers through public DERP with normal
SDK certificate validation. Device checks used ADB TCP forwarding to reach the
relay; direct Android UDP, NAT traversal and older API levels remain untested.

See [Verification](Documentation/Verification.md) for the executed matrix and
[Architecture](Documentation/Architecture.md) for protocol ownership, resource
limits and shutdown behavior. The tunnel MTU is 1,280 bytes. IP fragment
reassembly, TCP SACK/window scaling, router port mapping and upstream CLI
applications such as SSH/SFTP belong outside this library's current scope.

## Upstream and license

The protocol reference is [tailscale/tailcat](https://github.com/tailscale/tailcat)
at `52fbad323e9d352f1febb623e0975368e9a8cbdd`, with behavior cross-checked against
the [Swift port](https://github.com/slopus/tailcat-swift) at `b40c9b4`. Upstream
Go fixtures are test tools and are excluded from runtime artifacts.

BSD 3-Clause, the same license as upstream. See [LICENSE](LICENSE).
