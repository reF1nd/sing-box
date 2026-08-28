# Local transparent inbound benchmarking

This guide covers repeatable local runs outside GitHub Actions. Standard Linux
can use the automated namespace topology. Rooted Android uses the same traffic
generator but requires a physical remote endpoint and device-specific routing.

## Standard Linux

### Requirements

Use a disposable test host or VM with root access, cgroup v2, and a kernel that
supports the selected inbound. Install Go, `iproute2`, `iptables`/`ip6tables`,
`nftables`, `jq`, `curl`, `ethtool`, `iputils-ping`, `procps`, and `util-linux`.
The automated script creates only names prefixed with `sb-bench-` and a cgroup
prefixed with `sing-box-benchmark-`, then removes them on exit.

Build the release binary, diagnostic binary, and traffic generator. CGO and an
Android NDK are not required for this Linux harness:

```sh
mkdir -p build/inbound-benchmark
CGO_ENABLED=0 go build -trimpath -tags with_ebpf,with_gvisor \
  -o build/inbound-benchmark/sing-box ./cmd/sing-box
CGO_ENABLED=0 go build -trimpath -tags with_ebpf,with_gvisor,ebpf_debug \
  -o build/inbound-benchmark/sing-box-ebpf-debug ./cmd/sing-box
CGO_ENABLED=0 go build -trimpath \
  -o build/inbound-benchmark/interception-bench \
  ./cmd/internal/interception_bench
```

Run a short functional smoke test first:

```sh
sudo .github/benchmark/run-inbound-benchmark.sh \
  --sing-box "$PWD/build/inbound-benchmark/sing-box" \
  --debug-sing-box "$PWD/build/inbound-benchmark/sing-box-ebpf-debug" \
  --benchmark "$PWD/build/inbound-benchmark/interception-bench" \
  --output "$PWD/build/inbound-benchmark/smoke-ipv4" \
  --family ipv4 \
  --duration 200ms \
  --warmup 50ms \
  --repetitions 1 \
  --concurrency 2 \
  --profile-seconds 0
```

Repeat with a new output directory and `--family ipv6`. A normal comparison
should use longer sampling and at least five randomized repetitions:

```sh
sudo .github/benchmark/run-inbound-benchmark.sh \
  --sing-box "$PWD/build/inbound-benchmark/sing-box" \
  --debug-sing-box "$PWD/build/inbound-benchmark/sing-box-ebpf-debug" \
  --benchmark "$PWD/build/inbound-benchmark/interception-bench" \
  --output "$PWD/build/inbound-benchmark/results-ipv4" \
  --family ipv4 \
  --duration 30s \
  --warmup 5s \
  --repetitions 5 \
  --concurrency 16 \
  --tcp-payload-size 32768 \
  --udp-payload-size 1200 \
  --profile-seconds 15
python3 .github/benchmark/summarize.py \
  build/inbound-benchmark/results-ipv4
```

Limit an A/B run with `--variants` and `--scenarios`, for example:

```sh
--variants direct,ebpf-local,tun-mixed,tun-mixed-auto-redirect \
--scenarios tcp-short,udp-pps,udp-churn
```

Use `--ebpf-policy-prefixes 4096` in a separate run to measure a large
non-matching bypass policy. Never compare that result against an eBPF run with
zero prefixes without labeling the policy difference.

After an interrupted run, verify that no test resources remain:

```sh
ip netns list | grep '^sb-bench-' || true
find /sys/fs/cgroup -maxdepth 1 -type d \
  -name 'sing-box-benchmark-*' -print
```

### Measurement hygiene

Prefer a bare-metal host with a fixed performance governor and stable cooling.
Stop unrelated workloads, keep offloads unchanged across variants, and retain
the complete output directory. Monitor temperature and frequency separately;
discard a run that throttles. Do not run two benchmark jobs concurrently.

For short-connection pressure, increase `--concurrency` and select `tcp-short`.
For UDP state pressure, select `udp-churn` and test several concurrency levels.
For datagram behavior, run separate 64, 512, 1200, and 1400 byte experiments.
A 10-30 minute soak is useful for lifecycle stability, but should not be merged
with short steady-state throughput samples.

## Rooted Android

Android results must be collected on a physical device. The supplied harness
creates application, router, and server network namespaces on that device:

```text
application (10.89.0.2) -> router (10.89.0.1 / 10.89.1.1) -> server (10.89.1.2)
```

This is the same logical topology as the Linux and GitHub Actions harness. It
does not use Wi-Fi, mobile data, an external server, or `adb reverse`, so ADB
transport throughput and Android's main namespace policy routing do not affect
the data path. Absolute in-memory veth throughput is not a physical-network
claim; use the randomized same-device relative results to compare inbounds.
The Android harness covers the same TCP and UDP workloads as the Linux harness.
Redirect remains TCP-only by design. Shared eBPF is measured at the router-side
veth ingress, which represents a downstream device rather than local traffic.

### Build and deploy

Build a release sing-box binary for the device. `with_gvisor` is mandatory for
the `tun-mixed` variants and `with_ebpf` is mandatory for eBPF:

```sh
TAGS=with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,badlinkname,tfogo_checklinkname0 \
CGO_ENABLED=1 \
CC="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
GOARCH=arm64 GOOS=android make build
```

The traffic generator is pure Go:

```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
  -o build/inbound-benchmark/interception-bench-android-arm64 \
  ./cmd/internal/interception_bench
```

Verify that ADB shell is root and that the required kernel and Android tools are
available. The script uses PID-backed namespaces because Android Toybox does
not provide the same named-netns behavior as util-linux:

```sh
adb shell 'id; mount | grep cgroup2'
adb shell 'for command in ip iptables nsenter su unshare; do command -v $command; done'
```

Stop the installed sing-box service before the benchmark. The exact service
command is installation-specific; for the KernelSU layout used during
development it is:

```sh
adb shell /data/adb/ksu/bin/box stop
```

Deploy the two binaries and the harness into its dedicated temporary directory:

```sh
BENCHMARK_ROOT=/data/local/tmp/sing-box-inbound-benchmark
adb shell "mkdir -p $BENCHMARK_ROOT"
adb push build/sing-box "$BENCHMARK_ROOT/sing-box"
adb push build/inbound-benchmark/interception-bench-android-arm64 \
  "$BENCHMARK_ROOT/interception-bench"
adb push .github/benchmark/android-inbound-benchmark.sh \
  "$BENCHMARK_ROOT/android-inbound-benchmark.sh"
adb shell "chmod 0755 $BENCHMARK_ROOT/sing-box \
  $BENCHMARK_ROOT/interception-bench \
  $BENCHMARK_ROOT/android-inbound-benchmark.sh"
```

### Run the comparison

Create the topology, then run five interleaved repetitions. Defaults are 5
seconds measurement, 3 seconds warm-up, concurrency 8, 32768-byte TCP frames,
and 1200-byte UDP datagrams. The suite covers direct, local and shared eBPF,
Redirect, TProxy, mixed-stack TUN, and mixed-stack TUN with auto redirect. All
variants except Redirect run TCP short/upload/download plus connected,
unconnected, and churn UDP workloads:

```sh
adb shell "$BENCHMARK_ROOT/android-inbound-benchmark.sh setup"
adb shell "$BENCHMARK_ROOT/android-inbound-benchmark.sh suite"
```

After the performance rounds, the suite performs direct-leak checks. It rejects
the benchmark UID's original OUTPUT for local eBPF and rejects app-to-server
forwarding for shared eBPF, Redirect, and TProxy. Intercepted traffic still
passes because sing-box creates the replacement connection outside the rejected
path. Failed validation is written to `failures.tsv` and is never evidence of a
valid transparent benchmark.

Override sampling parameters through environment variables when needed:

```sh
adb shell "BENCHMARK_DURATION=15s BENCHMARK_WARMUP=3s \
  BENCHMARK_CONCURRENCY=16 BENCHMARK_REPETITIONS=5 \
  BENCHMARK_UDP_PAYLOAD_SIZE=1200 \
  $BENCHMARK_ROOT/android-inbound-benchmark.sh suite"
```

Follow progress from another terminal. A failure does not stop later variants:

```sh
adb shell "tail -f $BENCHMARK_ROOT/progress.log"
adb shell "cat $BENCHMARK_ROOT/failures.tsv"
```

Run or repeat one variant without rerunning the matrix:

```sh
adb shell "$BENCHMARK_ROOT/android-inbound-benchmark.sh run ebpf-local 6"
```

For local eBPF, the harness starts the client through Android `su 2000`, pauses
it, then moves the resulting UID 2000 process back into
`/sys/fs/cgroup/sing-box-inbound-benchmark` before execution. This is necessary
because Android `su` applies a UID task profile and migrates its child away from
the requested cgroup, unlike Linux `setpriv`. The sing-box process remains
outside the benchmark cgroup, so its direct outbound is not recursively
intercepted. Other variants also run the client as UID 2000.

Android Toybox `nsenter` also continues parsing command options in cases where
util-linux stops. The harness always enters a namespace through this script and
only then starts binaries, avoiding errors such as `Unknown option 'mode'`.

### Collect and summarize

Pull the complete directory before cleanup and run the same summarizer used by
GitHub Actions:

```sh
RESULT=build/inbound-benchmark/android-$(date +%Y%m%d-%H%M%S)
adb pull "$BENCHMARK_ROOT" "$RESULT"
python3 .github/benchmark/summarize.py "$RESULT" > "$RESULT/summary.md"
sed -n '1,120p' "$RESULT/summary.md"
(cd "$(dirname "$RESULT")" && zip -qr "$(basename "$RESULT").zip" "$(basename "$RESULT")")
```

Reject or repeat a result when `failures.tsv` is non-empty, a result has a
non-zero `errors` count, the number of valid JSON reports is not the requested
repetition count, or thermal throttling differs materially between variants.
The suite interleaves variant order between repetitions to reduce systematic
temperature and background-load bias.

The generated configurations explicitly set `default_interface` because the
Android interface monitor may not classify a veth-only namespace as the system
default network. For additional diagnosis, an eBPF run can temporarily use
`info` log level; successful interception produces an outbound log entry for
every benchmark connection. A direct-like result with failed leak validation or
no sing-box connection logs is not an eBPF measurement.

### Cleanup

Remove the namespace processes and cgroup after pulling results, then restart
the installed service:

```sh
adb shell "$BENCHMARK_ROOT/android-inbound-benchmark.sh cleanup"
adb shell /data/adb/ksu/bin/box start
```

`cleanup` intentionally leaves `$BENCHMARK_ROOT` and its evidence intact. After
confirming the pull, that exact temporary directory may be removed manually.

The namespace shared-eBPF result measures its forwarding data plane and is
comparable with the automated Linux topology. A real hotspot validation still
requires a second downstream device because Android tethering, OEM offloads,
and the physical downstream interface are outside this synthetic topology.

### Android evidence to retain

For every run, keep:

- sing-box commit, build tags, config, complete debug log, and raw JSON;
- `uname -a`, relevant `getprop` output, device model, and Android security patch;
- `id`, cgroup path, namespace addresses, routes, rules, and firewall state;
- `/proc/PID/status`, thermal and battery state before and after the run;
- eBPF startup/shutdown snapshots and pprof captures from
  `experimental.debug.listen` when diagnostics are enabled.

Run normal throughput with a non-`ebpf_debug` binary. Use the debug build only
for a separate reproduction or diagnostic phase; its startup/shutdown map scans
and kernel BPF runtime statistics intentionally add observation overhead. It
does not enable a periodic reporter or hot-path diagnostic counters.
