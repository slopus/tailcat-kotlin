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

For a known peer, connect once during your feature's startup or foreground work
and retain that `TailcatClient`. Its authenticated DERP connection stays open,
including while traffic uses a direct path, and reconnects after relay failures.
Later `client.dialTCP(...)` calls reuse the same client, relay transport and
WireGuard session; they create only another TCP stream inside the tunnel. Reuse
an existing stream when you want to avoid even that stream handshake. Close the
client when the owning feature no longer needs it. Mobile suspension and network
loss can interrupt connectivity; retaining an object is not an OS background
execution guarantee.

This known-peer prewarming needs no separate API: call `TailcatClient.connect`
before the first application request. Each new client instance still establishes
its own peer-specific relay transport and encrypted session; this library does
not provide a peer-independent preconnected node or a shared client relay pool.

## Optional relay-first connections

Separate calls to `TailcatClient.connect` still create independent clients and
their own DERP connections, WireGuard sessions, and UDP sockets. JVM/Android can
use DERP's standard fast-start capability advertised inside a verified TLS 1.3
handshake; unsupported relays and Linux Native use normal registration. Across
platforms, authenticated discovery starts immediately when its gate opens, and
empty probe rounds do not delay the first real candidate. These optimizations
are automatic: no new public API, connection pooling, or standby prewarming. The
[independent-client benchmark](Documentation/Benchmark.md#second-independent-client-startup)
measures a second fresh client while the first stays connected, separately from
the reused-client warm-stream measurement.

Set `relayFirst = true` independently on either end. The default remains `false`.

```kotlin
val server = TailcatServer(ServerConfiguration(relayFirst = true))
val address = server.start()
val client = TailcatClient.connect(address, ClientConfiguration(relayFirst = true))

client.retryDirect()                  // Background retry; keeps a healthy current path.
server.retryDirect(client.publicKey)  // One peer, or omit the key for every peer.

client.notifyNetworkChanged()         // Invalidate old paths, rebind UDP, reconnect DERP.
server.notifyNetworkChanged()
```

In this mode, UDP binding, interface enumeration and STUN do not block DERP
startup or relay traffic. `connect` still waits for the authenticated WireGuard
session, including its encrypted confirmation sent through DERP; it does not
mean merely "relay socket open." DERP map loading, region selection, relay DNS,
TLS and peer authentication can still delay or fail startup. `server.start()`
means the server is listening through its relay, not that a client is connected.
Relay-first therefore does not mean zero cold-start setup. In the benchmarks,
"cold" starts with a fresh client process; "warm" opens another TCP stream on an
already-connected client. Message RTT on an existing stream is a separate metric
from the warm stream's handshake and first response.

After authentication, background discovery upgrades the same session only after
an encrypted discovery Pong matches the peer, endpoint and outstanding probe.
Existing TCP streams and UDP flows stay attached to that session; keys, identity,
address encoding and the wire protocol are unchanged. A relay-first endpoint
interoperates with a default-mode endpoint. `client.path` and `server.path(key)`
report the selected outbound route; `Relay` is not a relay-health guarantee.

`retryDirect()` is non-blocking and coalesced: it does not tear down a working
direct path, reconnect DERP or create a new session. `notifyNetworkChanged()`
invalidates old endpoint/probe generations, closes and rebinds UDP sockets,
reconnects DERP, and rediscovers in the background. `resetNetworkPaths()` remains
an alias for this network-change operation. Requests after close fail with
`TailcatClosedException`; closing cancels retries and prevents late discovery
results from restoring a route.

The discovery worker polls local addresses roughly every five seconds on JVM,
Android and Linux Native; there is no platform connectivity callback subscription.
Hosts should call `notifyNetworkChanged()` for Wi-Fi/cellular/VPN/default-route
changes, especially when the local address list stays the same. Blocking platform
discovery calls run outside the transport lock and cannot stall relay traffic or
close. They cannot always be interrupted: one old call can delay fresh direct
discovery until it returns, but its stale result is discarded and repeated
notifications do not accumulate discovery workers.

Failed direct probes back off from one to at most 30 seconds, with a global
32-probe/second budget and at most eight endpoints per peer per round. Validated
paths are reprobed about every ten seconds. New authenticated endpoint advertisements inside the probe rate limit are queued
for the next allowed probe, including when only the remote peer changes networks.
If an authenticated, nonempty advertisement withdraws the selected endpoint from
the peer's previous nonempty advertisement, traffic falls back to DERP until a
replacement is validated. Empty or unchanged advertisements do not discard a
working path, and older outstanding Pongs cannot restore a withdrawn route.
Local path resets queue an authenticated empty WireGuard transport packet through
DERP before application data, using the existing keepalive wire format. A peer
recognizes a fresh relay-carried empty packet on an established session as a
discrete reset hint and revalidates its return path. Initial key confirmations,
forged packets and replayed markers cannot trigger it; ordinary application data
never demotes a path. Marker counters are tracked separately from data because
direct data can overtake the relay hint. Peer-induced fallback does not send a
reflexive marker. Older implementations still accept the unchanged WireGuard
packet, but may rely on discovery/lease expiry for prompt return-path recovery.
Fast marker-assisted one-sided recovery requires the receiving peer to run the
updated library. Mixing `relayFirst = true` and `false` on updated peers is not
the same as testing an older library binary; the mixed-mode tests cover the former.
A local UDP send error immediately
retries that ciphertext through DERP; a silent blackhole falls back when the last
valid Pong is 30 seconds old. Application sends do not extend this lease. Relay
disconnects reconnect with bounded backoff while a healthy direct path remains
usable, and relay receive stays active even after a direct upgrade.

Route changes are not lossless delivery guarantees: datagrams may be lost or
reordered, TCP uses its existing retransmission/timeouts, and long outages can
exhaust bounded queues or expire sessions (including the server's five-minute
peer inactivity limit). Neither mode guarantees direct NAT traversal or indefinite
offline session survival.

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
interface changes refresh discovery; call `notifyNetworkChanged()` after a known
network change. Relay regions come from Tailcat's DERP map,
`https://tailcat.dev/derpmap.json`, cached for an hour and revalidated with its
ETag; a failed refresh uses the cached map. Pass a `DERPMapProvider` with another
URL or cache, or a fixed `region`, to override it. Production TLS verifies the
certificate chain and hostname by default.

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
