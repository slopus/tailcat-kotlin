# tailcat-kotlin

An embedded tailcat socket library written in Kotlin Multiplatform. Common Kotlin
implements addresses, NaCl, WireGuard, discovery, relay protocols and a userspace
IPv6 TCP/UDP stack. The runtime has no third-party package dependencies and ships
no Go binaries, Go runtime, Swift bridge, TUN device or daemon.

Targets are JVM servers (Java 17+), Android (API 24+) and Kotlin/Native Linux.
JVM and Android use SDK sockets and SSLSocket. Linux Native uses POSIX sockets
and the system OpenSSL 3 libraries (`libssl.so.3`, `libcrypto.so.3`) and CA store.
TLS verifies the certificate chain and hostname by default. Custom DERP maps
preserve distinct HostName/SNI and CertName verification. The explicit upstream
`InsecureForTests` node flag skips TLS certificate checks; TLS stays enabled.
`testOnlyPlaintextDERP` separately enables local HTTP fixtures and is restricted
to loopback and the Android emulator host alias.

Use it as a Gradle project dependency, or publish the KMP module locally with
`./gradlew publishToMavenLocal`. Coordinates are `io.tailcat:tailcat-kotlin:0.1.0`;
Gradle selects the platform variant. Build tools are Gradle 8.14.3, Kotlin 2.2.21,
AGP 8.10.1 and JDK 21, with JVM bytecode targeting Java 17. Android builds require
SDK 36 and Build Tools 36.0.0.

Standalone consumers are in [`examples/jvm`](examples/jvm),
[`examples/android`](examples/android) and [`examples/native`](examples/native).
After publishing, run `./gradlew -p examples/jvm run` or
`./gradlew -p examples/native linkDebugExecutableLinuxX64`. The Android example
builds with `./gradlew -p examples/android assembleDebug`. Each resolves the
published module rather than including the library source. Set
`-PtailcatRepository=/path/to/repository` to use a separate local Maven repository.

Linux Native consumers link against OpenSSL 3 installed for their target. Set
`-Ptailcat.opensslLibDir=/path/to/libraries` for the executable examples when it
differs from `/usr/lib/x86_64-linux-gnu`. The checked Linux executable uses the
host OpenSSL and inherits its glibc requirement; it is not a portable static
binary. `--allow-shlib-undefined` accommodates the Kotlin compiler's older
link-time sysroot while the host loader resolves the system libraries. Choose
OpenSSL and a matching sysroot for the oldest distribution you support.

```kotlin
val server = TailcatServer()
val address = server.start()
val listener = server.listenTCP(8080)
println(address.encode()) // Contains a PSK: share as a secret.
val connection = listener.accept()
val buffer = ByteArray(8192)
val count = connection.read(buffer)
if (count >= 0) connection.write(buffer, length = count)
connection.shutdownOutput()
connection.close()
server.close()
```

```kotlin
val client = TailcatClient.connect("tc…")
val tcp = client.dialTCP(8080)
tcp.write("hello".encodeToByteArray())
tcp.shutdownOutput()
val reply = tcp.read()
tcp.close()
val udp = client.dialUDP(5353)
udp.send(byteArrayOf()) // Empty UDP datagrams are valid messages.
val datagram = udp.receive(timeoutMillis = 10_000)
udp.close()
client.close()
```

These are blocking operations. On Android, call them from a worker thread; on a
coroutine-based application use its I/O dispatcher. There is no coroutine runtime
dependency. A timeout of zero waits indefinitely. TCP `read(buffer)` returns -1
at EOF; the byte-array convenience overload returns an empty array. `write` waits
for acknowledgement, `drain` waits for outstanding writes, and `shutdownOutput`
sends FIN. Read and write concurrently when streaming in both directions. Closing
an owner interrupts pending operations. Client connect uses a fresh identity by
default; supply `NodePrivateKey` in the configuration to retain it across launches.
Private keys and PSKs expose defensive raw byte copies for application persistence.

Servers support explicit TCP/UDP listeners, ephemeral ports, per-flow `onTCP` and
`onUDP` handlers, peer attribution, synchronized `KeySet` admission and
`disconnectClient`. Admission hooks run independently with bounded concurrency.
`onTCPForward` and `onUDPForward` select handlers for explicit `TailcatEndpoint`
destinations; IPv4 uses upstream's `64:ff9b::/96` NAT64 mapping. `allowProxy` and
served-port sets filter services. `proxyConnections` copies two tunnel streams
with half-close propagation. Resolve application hostnames before constructing
`TailcatEndpoint`; the tunnel API accepts numeric IP addresses.

DERP maps support custom regions, cached HTTPS fetches, ETags, stale fallback and
latency selection. DERP reconnects and tries alternate region nodes. Discovery
uses authenticated NaCl boxes, STUN and direct IPv4/IPv6 probes with relay fallback.
Call `resetNetworkPaths` after a known network change; local interface changes are
also polled. WireGuard supports PSKs, MACs, cookie replies, replay protection,
overlapping rekeys and keepalives.

Queue limits include 256 raw network packets, 512 engine events, 256 DERP sends,
128 pending accepts and 128 datagrams per UDP flow. Servers admit at most 1,024
identities, 128 pending tunnel authentications and 128 concurrent admission hooks.
Pending identities expire after 30 seconds and rotate when full; authenticated
inactive peers expire after five minutes. TCP has at most 1,024 states per stack,
a 64 KiB receive window and a 4 MiB write queue per connection. Forwarding has
at most 128 destination stacks and 256 automatic service listeners.

The tunnel MTU is 1,280 bytes; UDP payloads are at most 1,232 bytes. TCP negotiates
MSS without SACK, timestamps or window scaling. Non-atomic IP fragments are not
reassembled. NAT port-mapping protocols are outside this implementation; DERP
remains available when UDP paths cannot be established. SSH, SFTP and command
execution applications belong to the embedding project.

Run `./gradlew jvmTest linuxX64Test assembleRelease lintRelease` for shared tests
and Android checks. `runJvmCheck -PcheckArgs='client tc-address 262144'` exercises
an independent echo peer on TCP 80/UDP 53. Linux Native's `tailcat-check` executable
accepts the same arguments. The Android instrumentation runner executes the real
library with supplied relay/echo arguments. See [Architecture](Documentation/Architecture.md)
and [Verification](Documentation/Verification.md) for exact executed targets and results.

Protocol reference: [tailscale/tailcat](https://github.com/tailscale/tailcat) commit
`52fbad323e9d352f1febb623e0975368e9a8cbdd`, with behavior cross-checked against the
native Swift port at `b40c9b4`. Protocol fixtures and upstream Go peers are test
tools only and are excluded from published artifacts. BSD-3-Clause.
