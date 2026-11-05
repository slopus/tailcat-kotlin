# Relay-first benchmark harness

The optional JVM/Android runner uses TCP port 8080 as a raw echo service, compatible
with the Swift benchmark. It changes no tunnel framing or cryptography.

Build the host jar with `./gradlew benchmarkJar`. Run with the same JVM options on
both Linux hosts and for both modes:

```sh
java -Xms64m -Xmx256m -jar build/libs/tailcat-benchmark.jar \
  server source=linux relayFirst=false region=301 runId=linux-off

java -Xms64m -Xmx256m -jar build/libs/tailcat-benchmark.jar \
  client source=linux target=mac relayFirst=false address=tc-address \
  runId=linux-mac-off-1 trial=1 trials=1 bytes=262144 warm=true recovery=true
```

Use the emitted `serverReady.address` as the destination. Servers explicitly select
region 301 (NYC, `tc301a.ipn.dev`) by default, rather than using adaptive region
selection. Both ends should use the same `relayFirst` setting for each comparison.
The test server accepts only echo traffic, with no forwarding/proxy handlers.

Run five independent processes for five cold trials, alternating mode order.
`trials=N` instead creates fresh clients in one process and labels only the first
`coldProcess=true`; it is not a substitute for process-cold repetitions. A warm
sample uses a second TCP stream on the **same** client, WireGuard session and relay
transport, so it must not be reported as a fresh-connection startup comparison.
JVM JIT warmup, Android debug builds, and host load must be retained in the report.

### Second independent client startup

Pass `secondIndependent=true` to run a separate startup experiment. It creates
two fresh clients in one process against the same peer, retaining the first
client and its echo stream while the second connects. Both have fresh node and
discovery identities, WireGuard sessions, UDP sockets, and DERP TCP connections.
This is neither the existing reused-client warm stream nor a shared relay pool.
The normal `warm`, `bytes`, and `recovery` options are not used by this experiment.

The runner emits `tailcat-independent-startup-v1` JSONL: two `sample` rows with
phases `first_independent_client` and `second_independent_client`, plus an
`independenceCheck` row. Only the first client of the first trial is labeled
`coldProcess=true`; repeat whole processes for independent cold trials.
Address parsing happens before timing. Fresh identity generation is included in
`connectMs`; the internal `connectStart` event follows generation.

Each sample reports `connectMs`, `firstAppByteMs`, `firstEchoMs`, and a bounded
`startupTrace` array of `{phase, atMs, value}`. Timestamps are integer monotonic
milliseconds relative to that client's trace creation. Phases separate map
expansion, engine creation, UDP binding, TLS factory setup, resolution, TCP,
TLS, HTTP upgrade, DERP authentication, meow, WireGuard establishment, connect
return, virtual TCP dial, and first echo. `tcpConnected` and UDP binding values
are local ports; `derpAttempt`/`derpReady` values are per-client generations.
`handshakeToConnectReturnMs` distinguishes handshake completion from caller wakeup.
The trace is internal and disabled for normal public API calls.

The first client sends distinct numbered payloads during second-client startup
and concurrent echo checks. The runner checks distinct node identities and TCP
ports, records UDP ports (explicitly unavailable if binding has not completed),
and verifies an echo through the first client after closing the second.
Public node/discovery keys identify the independent clients; private keys,
session keys, nonces, relay keys, and the bearer address are not included in these
sample rows. Errors are emitted and fail the run rather than becoming successful
independence assertions. Preserve baseline binaries and results before comparing
any startup optimization.

Each JSONL sample contains:

- `connectMs`, measured from immediately before `connect` through authenticated
  tunnel establishment; zero for the reused-client warm phase.
- `firstAppByteMs` and `firstEchoMs`, from the same start through the first received
  byte and complete verified 32-byte echo. Warm timing starts before `dialTCP`.
- `directObservedMs`, polling the selected route every 20 ms, and `directCensored`
  when no direct path is observed within 15 seconds after connect completes.
- Twenty sequential, exact-size 32-byte echo RTTs in `rttMs`, after direct
  observation completes or times out. Report median/range across cold trials;
  do not call a five-sample percentile a reliable p95.
- A concurrent writer/reader 256 KiB echo, checked byte-for-byte. The payload rate
  is `payloadBytes * 8 / elapsedSeconds`, **not** a doubled aggregate duplex rate.
- An optional `notifyNetworkChanged()` followed by a numbered echo on the same
  stream, plus an independent post-notification observer for the new direct path,
  censored after 15 seconds even when the echo takes longer. This is a package API
  recovery exercise, not physical link loss or a DERP-server outage injection.
- Route transition timestamps, endpoint strings, runtime/build metadata and
  stage-specific failures. Failed/censored samples must be retained, not replaced
  with success-only averages.

The direct poll starts when `connect` returns; an immediately direct initial path
is therefore an upper-bound observation, not an exact internal validation time.
Direct endpoints on Tailscale's overlay demonstrate an overlay UDP path, not
successful Internet NAT traversal. Keep shared host networking/VPNs unchanged.

The embedded `tc` address can normalize its region ID to a synthetic value when
decoded. Use the server-ready region ID and the recorded relay hostname to group
results; a client-side synthetic ID does not mean a different relay was selected.

## Android debug runner

Build on the authorized Mac from this source checkout (the composite build avoids
publishing or replacing another project's Maven artifacts):

```sh
./gradlew -p examples/android --include-build /absolute/path/to/tailcat-kotlin assembleDebug
```

Install `examples/android/build/outputs/apk/debug/tailcat-android-example-debug.apk`
on a dedicated emulator. The actual filename may vary with Gradle's project name;
inspect the output directory. Launch the explicit benchmark Activity:

```sh
adb -s emulator-SERIAL shell am start -n io.tailcat.example/.BenchmarkActivity \
  --es mode server --es source android-emulator --es relayFirst true \
  --es region 301 --es runId android-on

adb -s emulator-SERIAL shell am start -n io.tailcat.example/.BenchmarkActivity \
  --es mode client --es source android-emulator --es target linux \
  --es address tc-address --es relayFirst true --es trial 1 --es trials 1 \
  --es runId android-linux-on-1 --es warm true --es recovery true
```

All extras are strings. Force-stop only `io.tailcat.example` on the dedicated
emulator between cold trials. JSONL is logged under the `TailcatBenchmark` tag and
appended to `files/<runId>.jsonl`; retrieve it with
`adb shell run-as io.tailcat.example cat files/<runId>.jsonl`. Use a unique run ID
per process to avoid accidentally appending a repeat to an earlier result.

Keep the Activity foreground. Destroying it closes the benchmark client/server.
Never stop, reuse or reconfigure unrelated emulators to make a result faster.