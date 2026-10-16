# Verification record

Executed on 2026-10-16. Build outputs and fixture logs are local verification
materials, excluded from Git and runtime publications.

The protocol reference is tailscale/tailcat
`52fbad323e9d352f1febb623e0975368e9a8cbdd`. Independent Go fixture programs were
built from that source outside this module. They are test tools, not runtime or
publication dependencies. Local fixtures used an explicit plaintext relay option;
public DERP tests used verified TLS without that option.

## Protocol and socket tests

Common tests execute on both JVM and Linux x64 Native. They include SHA-256,
HMAC, Blake2s, RFC X25519 and ChaCha20-Poly1305 vectors, XChaCha and NaCl fixtures,
Go key/address goldens, independently generated Noise packets, wrong PSKs,
tampering, replay, cookies, crossed handshakes and overlapping keypairs.

The packet stack tests transfer four concurrent 2 MiB TCP streams. Fault injection
drops SYN, SYN-ACK, data, ACK, window-update, FIN and FIN-ACK packets and introduces
reordering and duplicates. They check half-close, graceful drain, timeouts,
refusal, checksums, listener closure, empty UDP datagrams, UDP size limits,
listener replacement and idle expiry.

A focused regression also completes both TCP FIN exchanges, removes the peer's
closed state and provokes a late reset while 3,072 response bytes remain unread.
It failed with `CONNECTION_RESET` before the TIME-WAIT fix and now preserves both
the remaining response and orderly EOF. Active connections still reject resets.

With a local relay, facade tests cover per-flow policy changes, IPv4 NAT64 and
IPv6 forwarding, peer attribution, ephemeral listeners, explicit-listener
precedence, admission revocation, isolation of slow admission callbacks and
shutdown during an incomplete TLS startup.
They also try an unavailable relay node before a working node and repeat TCP/UDP
exchanges across three explicit network-path resets.

Platform tests cover entropy, clocks, concurrent locks, IPv4/IPv6 UDP, empty
datagrams, socket cancellation, backpressured writes, simultaneous verified TLS
reads and writes, rejection of a wrong certificate name, rejection of a self-signed
certificate and explicit test-only acceptance of that certificate. Set the
following environment variables to enable external fixture cases:

```sh
TAILCAT_LOCAL_RELAY_PORT=39871
TAILCAT_PLATFORM_TLS_HOST=tc302a.ipn.dev
TAILCAT_PLATFORM_TLS_PORT=443
TAILCAT_PLATFORM_SELF_TLS_HOST=127.0.0.1
TAILCAT_PLATFORM_SELF_TLS_PORT=40623
```

Run the suite with `./gradlew jvmTest linuxX64Test`. Each target executes 32 test
methods when built with this record's fixtures. Fixtures are optional so the
ordinary suite can run offline; a return from an unconfigured fixture case is not
evidence that its network path executed.

## Independent Go interoperability

| Runtime and direction | Executed result |
| --- | --- |
| Kotlin JVM client to Go server | 256 KiB exact TCP echo, FIN/EOF; UDP 0, 1, 31 and 1,232 bytes passed |
| Go client to Kotlin JVM server | 2 MiB TCP echo and UDP cases passed |
| Kotlin Linux x64 Native executable to Go | 2 MiB TCP echo and UDP cases passed |
| Go client to Kotlin Linux x64 Native server | 2 MiB TCP echo and UDP cases passed |
| JVM and Native clients through public DERP TLS | 16 KiB TCP echo and UDP cases passed with normal certificate verification |
| Native client to Go forwarding server | Both IPv4 `198.51.100.7:8080` via NAT64 and IPv6 `[2001:db8::7]:8080`: 64 KiB TCP, FIN/EOF and UDP cases passed |
| Go client to Native forwarding server | Both destination families: 64 KiB TCP, FIN/EOF and UDP cases passed |
| Android API 36 ART client to Go | 16 KiB TCP echo, FIN/EOF and UDP 0, 1, 31 and 1,232 bytes passed through DERP |
| Go client to Android API 36 ART server | 16 KiB exact TCP echo, FIN/EOF and UDP 0, 1, 31 and 1,232 bytes passed through DERP |
| Android API 36 ART client through public verified DERP TLS | 1 KiB TCP echo, FIN/EOF and UDP 0, 1, 31 and 1,232 bytes passed with normal SDK certificate validation |

Go also exercised four concurrent 256 KiB TCP connections and eight concurrent
1,232-byte UDP exchanges against the JVM and Linux x64 Native servers. Malformed meow
advertisements with a forged node key or zero discovery key were rejected;
legitimate probes before and after the malformed traffic and a fresh subsequent
peer still succeeded. Local peers established authenticated direct UDP paths.
Public relay tests exercised the relay transport and verified platform TLS.

## Build and runtime scope

Builds use Gradle 8.14.3, Kotlin 2.2.21, JDK 21, AGP 8.10.1 and Android SDK/Build
Tools 36. JVM output targets Java 17. Linux execution uses x86-64 Linux, system
OpenSSL 3 and the host CA store. Linux arm64 is a separate compilation target;
x64 execution does not establish arm64 runtime behavior.

| Build or consumer | Executed result |
| --- | --- |
| `jvmTest` and `linuxX64Test` | Both passed, including all configured relay/TLS fixtures |
| `compileKotlinLinuxArm64` | Passed; arm64 klib and OpenSSL cinterop published; no arm64 runtime execution |
| `assembleRelease lintRelease` | Android release AAR passed; lint: zero errors, one AGP update notice |
| `publishToMavenLocal` | Root KMP metadata plus JVM, Android, Linux x64 and Linux arm64 variants present |
| Standalone JVM consumer | Published variant resolved and compiled; five exact small TCP echoes with orderly EOF passed through public verified DERP TLS |
| Standalone Linux x64 Native consumer | Published klib/cinterop resolved; executable linked and ran, including a real TCP echo through public verified DERP TLS |
| Standalone Android consumer | Published Android AAR resolved; APK assembled and lint passed with zero errors |

Native execution used glibc 2.39 and OpenSSL 3.0.13. The executable example's
system-library linker settings inherit the host's glibc requirement; published
klibs still require a compatible OpenSSL installation when a consumer links.

The Android library, device runner and standalone consumer use SDK sockets and
TLS through the same JVM/Android platform implementation. Device execution is
recorded separately from AAR and APK assembly. The Android example keeps blocking
library calls on a worker thread.

The Android runtime check executed `io.tailcat.AndroidCheck` with `app_process`
on a Google APIs x86-64 API 36 software emulator. Its system services had not
finished enabling ordinary guest networking, so standard ADB TCP forwarding made
the host relay reachable on emulator loopback. A separate SDK socket probe first
confirmed the DERP HTTP upgrade. The full Kotlin client then passed against the
independent Go peer using `plain timeout=180000`. The final Android server runner,
including cached immutable key derivation, also passed the independent Go client:
16 KiB exact TCP echo with FIN/EOF and all four UDP payload sizes. Both directions
used standard, non-root ADB TCP forwarding to the relay. This establishes actual
Android ART client and server execution and encrypted tunnel TCP/UDP over DERP.

The final Android Kotlin client also passed against the independent Go peer
through public DERP `tc302a.ipn.dev`: 1 KiB exact TCP echo with FIN/EOF and UDP
payloads of 0, 1, 31 and 1,232 bytes. Both TLS certificate chain and hostname
validation remained enabled, with `InsecureForTests` false and the plaintext
fixture option disabled. The node's explicit dial address was `127.0.0.1:44543`;
standard ADB reverse forwarding reached a host TCP passthrough to the public
DERP's port 443. HostName, SNI and certificate identity remained
`tc302a.ipn.dev`, and TLS terminated at the public DERP. A separate SDK-only
probe independently completed verified TLS 1.3 and the HTTP 101 DERP upgrade
over this route. The full Kotlin runner reported `PASS` after all TCP and UDP
assertions, with connection path `Relay`.

These device checks establish Android relay interoperability and verified SDK
TLS. Android direct UDP, NAT traversal and older API levels remain outside the
executed coverage. The instrumentation APK was assembled; PackageManager
instrumentation was not used.

No iOS, macOS or Windows target is claimed by this port. Linux OpenSSL and glibc
requirements apply to Native consumers. This is a userspace IPv6 stack with a
1,280-byte MTU; it does not implement IP fragment reassembly, SACK, TCP window
scaling or router port-mapping protocols.
