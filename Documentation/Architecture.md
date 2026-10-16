# Implementation contract

The embedded library is a Kotlin Multiplatform module. All address, CBOR, discovery,
NaCl, WireGuard, IPv6, TCP, UDP, admission and relay state machines are common Kotlin.
Platform actuals provide threads, condition locks, clocks, entropy and system sockets.
JVM and Android share Java sockets and verified SSLSocket TLS. Linux Native uses POSIX
sockets and verified system OpenSSL TLS. No Go executable or runtime is shipped.

Public operations are ordinary blocking socket operations. Applications may call them
from their own executors or coroutine dispatchers without a coroutine dependency.
`TailcatServer.start()` returns the shareable `tc` address. `listenTCP`/`listenUDP`
return listeners, `accept` returns a peer-attributed connection, and clients expose
`dialTCP`/`dialUDP`. Read returns -1 for TCP EOF; UDP receives return an object even
for an empty payload. TCP supports `shutdownOutput`, `drain` and `close`. Closing
any owner wakes pending operations. Deadlines are relative milliseconds, zero means
unlimited. Callbacks run away from the shared packet reader.

Common components and ownership:

* `crypto` and `wireguard`: pure Kotlin cryptography, Noise handshake, keypair overlap,
  timestamp/counter replay, cookies, PSK and maintenance.
* `stack`: packet parsing and checksums, reliable IPv6 TCP byte streams, bounded UDP
  flows, socket lifetimes and peer metadata.
* `platform`: OS facilities and TLS, no protocol policy.
* Core: addresses/keys, DERP map and client, STUN/discovery, peer admission, authenticated
  path management, forwarding and the public server/client façade.

The packet stack receives complete authenticated IPv6 packets with their peer key;
its outbound callback emits a complete IPv6 packet and peer destination. It is driven
by bounded ingress and a maintenance tick, without one thread per packet. Inbound
path authentication is independent of the selected outgoing path. Server source IPs
must match the authenticated node key. Client initiated forwarding flows accept
responses from their configured target through the authenticated server.

Tests must distinguish compilation from execution. Runtime evidence includes JVM
tests, an Android ART device runner (instrumentation or `app_process`), and a real
compiled Linux Native binary. Upstream Go fixtures are test tools only.

## Concurrency and shutdown

Each transport has a bounded packet queue and one consumer. UDP receivers and the
DERP reader enqueue complete packets; they never create a task for an individual
packet. The engine serializes WireGuard and peer state and hands complete packets
to the stack. Stack output enqueues engine events, so it cannot re-enter the engine
while holding the stack lock. A separate peer-address binding lock supplies socket
attribution without taking the engine lock. Native locks are non-recursive.

Admission and application handlers run on separate workers with concurrency caps.
Admission results carry a generation token so a delayed approval cannot restore a
revoked peer. Pending authentication state, probes, endpoint bindings, forwarded
destinations, listeners and TCP/UDP queues all have independent bounds. The engine
expires inactive peers; stack maintenance retries segments and expires datagrams.

Platform streams exist before DNS and TLS startup. Closing them cancels pending
startup or interrupts reads and writes. DNS uses two workers and a bounded queue;
an OS resolver call already in progress may finish after its caller has left.
DERP-map HTTP reads have a watchdog deadline, and map loading observes server
shutdown or the client's overall connection deadline. STUN resolution runs after
relay startup and cannot hold the public startup operation.

The Native stream serializes individual OpenSSL calls while polling outside that
lock, permitting simultaneous read and write. Active-operation counts defer file
descriptor and SSL object release until operations have observed shutdown. SIGPIPE
is handled per calling thread rather than changing process-wide signal policy.
The JVM implementation uses independent read and write locks and closes the SDK
socket to interrupt blocking operations.

## Publication boundary

The Maven module publishes common metadata, JVM bytecode, the Android release AAR
and Linux x64/arm64 klibs with their OpenSSL cinterop metadata. Kotlin's standard
library is the only runtime package dependency. OpenSSL, POSIX and Java/Android SDK
facilities are platform dependencies. Test libraries, Gradle plugins, upstream Go
fixtures and build tools are excluded from runtime artifacts. Standalone examples
resolve the published coordinates to check that boundary.
