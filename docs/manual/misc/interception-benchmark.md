# Transparent inbound benchmark protocol

This protocol compares the eBPF, Redirect, TProxy, and TUN transparent
inbounds with the same traffic generator and remote endpoint. It is intended
for repeatable engineering measurements, not as a universal ranking: kernel,
NIC, offload, CPU frequency, routing rules, and the direct/proxy traffic ratio
can change the result.

## Workloads

| Scenario | Measurement | Purpose |
|---|---|---|
| `tcp-short` | Completed TCP request/response connections per second | Connection setup, interception, map/conntrack, and user-space dispatch overhead |
| `tcp-upload` | Server-confirmed bits per second over persistent TCP connections | Client-to-server long-connection throughput |
| `tcp-download` | Client-received bits per second over persistent TCP connections | Server-to-client long-connection throughput |
| `udp-pps` | Echoed datagrams per second from connected UDP sockets | Connected UDP interception and NAT/session processing cost |
| `udp-unconnected-pps` | Echoed datagrams per second from unconnected UDP sockets | Per-destination sendmsg interception and flow-cache cost |

Redirect supports TCP only in sing-box, so its UDP results are reported as not
applicable. Do not substitute a different UDP implementation under the Redirect
label.

## Build the traffic generator

```sh
go build -o interception-bench ./cmd/internal/interception_bench
```

Run the server on a separate, otherwise idle machine reachable from the device
under test. TCP and UDP use the same port:

```sh
./interception-bench -mode server -listen :5201
```

Run a direct baseline before enabling a transparent inbound, then run the same
command for each inbound:

```sh
./interception-bench -mode client \
  -target 192.0.2.2:5201 \
  -scenario all \
  -duration 30s \
  -warmup 5s \
  -concurrency 16 \
  -payload-size 1200 > result.json
```

The client prints one JSON report. Long uploads use length-prefixed data frames
and an explicit end frame; the server returns the received payload byte count,
instead of counting bytes accepted only by the local socket buffer or relying
on TCP half-close behavior through the interception path. UDP uses one request
followed by one echo response per flow, so the result is processed round-trip
PPS rather than unconfirmed send PPS.

## Comparable setup

Use the same sing-box binary, server address, route, outbound, logging level,
CPU affinity, concurrency, duration, and payload size for every run. Disable
sniffing, protocol multiplexing, DNS rules, and unrelated rule-sets. Use a
`direct` outbound and exclude the sing-box process from any external
Redirect/TProxy firewall rule to prevent loops.

Recommended inbound profiles are:

| Variant | Required setup |
|---|---|
| eBPF | Local cgroup interception, `dns_mode: off`, no `bypass_rule_set`, and no `shared_network` |
| Redirect | TCP listener plus an nftables/iptables Redirect rule matching only the benchmark server and port |
| TProxy | TCP/UDP listener plus matching TProxy rules, a dedicated mark, policy rule, and local route |
| TUN | `auto_route: true`, `auto_redirect: true`, `stack: system`, and `route_address` limited to the benchmark server prefix |

Limit interception to the benchmark destination. A full-device catch-all adds
uncontrolled background traffic and makes CPU samples incomparable. Keep
hardware and kernel offloads unchanged; record their state instead of changing
them for only one variant.

For eBPF, run the benchmark client inside the configured `cgroup_path`. For
Redirect and TProxy, use a dedicated benchmark UID or cgroup in the firewall
match and explicitly bypass the sing-box service UID. For TUN, use matching
include/exclude UID settings. This keeps the captured process set identical.

## Repetition and system metrics

Run each profile at least five times in randomized order. Keep the median and
the full raw JSON output. Before every measured run, restart sing-box, allow
the configured warm-up to complete, and verify that the server has no other
clients.

Record sing-box CPU time and peak resident memory with the platform's normal
process monitor. On standard Linux, one reproducible option is:

```sh
/usr/bin/time -v ./sing-box run -c benchmark.json 2> sing-box-resource.txt
```

Also record:

- sing-box commit and build tags;
- kernel version and architecture;
- device model, CPU governor, and thermal state;
- NIC, MTU, link speed, and offload state;
- inbound configuration and firewall/policy-routing rules;
- direct baseline and every raw JSON report;
- packet loss or non-zero `errors` in the report.

Discard a run with errors, thermal throttling, link renegotiation, or unrelated
traffic. Compare both absolute results and overhead relative to the direct
baseline. In particular, test eBPF once without a bypass rule and separately
with a representative CIDR bypass; those are different data paths and should
not be merged into one number.

## Reference Android measurement

The following result is a reference measurement from 2026-08-03, not a
performance guarantee or a universal inbound ranking. It is included to make
the expected artifact, interpretation, and rooted-device reproduction process
concrete.

The tested source tree was recorded as `55095cf9` before the eBPF development
history was squashed. Its data-path implementation is contained in the current
`Implement eBPF inbound` commit. The later Android lookup-and-delete change is
a compatibility fallback and does not alter the fast path on a kernel that
accepts the combined syscall.

| Item | Value |
|------|-------|
| Device | OPPO PKX110 |
| System | Android 16 (SDK 36), arm64 |
| Kernel | 6.6.89 Android common-kernel derivative |
| Build tags | `with_ebpf,with_gvisor` |
| Topology | Private mount, cgroup, and network namespaces with two in-kernel veth pairs |
| Measurement | 5 seconds after a 1 second warm-up |
| Repetitions | 5, with a rotating inbound order |
| Concurrency and payload | 16 flows, 1200 bytes |
| TUN variant | `stack: system`, `auto_redirect: true` |
| Reported errors | 0 in every measured run |

The medians were:

| Variant | TCP short | TCP upload | TCP download | Connected UDP | Unconnected UDP |
|---------|----------:|-----------:|-------------:|--------------:|----------------:|
| Direct | 9.648k op/s | 6.725 Gbit/s | 83.952 Gbit/s | 53.161k PPS | 51.815k PPS |
| eBPF | 8.704k (90.2%) | 6.536 Gbit/s (97.2%) | 65.632 Gbit/s (78.2%) | 21.877k (41.2%) | 22.621k (43.7%) |
| Redirect | 8.749k (90.7%) | 6.398 Gbit/s (95.1%) | 65.872 Gbit/s (78.5%) | N/A | N/A |
| TProxy | 9.162k (95.0%) | 5.493 Gbit/s (81.7%) | 68.198 Gbit/s (81.2%) | 22.558k (42.4%) | 22.326k (43.1%) |
| TUN | 3.924k (40.7%) | 524.809 Mbit/s (7.8%) | 280.913 Mbit/s (0.3%) | 22.573k (42.5%) | 22.291k (43.0%) |

The published medians and environment are also available as a
[machine-readable JSON summary](interception-benchmark-android-20260803.json).

In this topology, eBPF and Redirect were effectively tied for TCP; their small
differences were below the observed run-to-run variation. TProxy had the
highest intercepted short-connection median but lower upload throughput.
Connected and unconnected eBPF UDP were close to TProxy and TUN. Redirect is
TCP-only and therefore has no UDP result.

The unusually high Direct download result comes from moving traffic through
local in-kernel veth links, without a physical NIC. It makes the percentage of
copy-heavy paths, especially TUN, look much smaller than it would on a real
network whose line rate is the bottleneck. The useful result is relative
interception overhead on this device, not the displayed absolute Gbit/s.

CPU-related thermal sensors ranged from approximately 36.4 C to 73.4 C over
the full matrix. Android background services remained enabled, CPU frequency
was not pinned, and the device was not placed in airplane mode. Medians reduce
but do not remove that noise. This test covers local cgroup interception only;
it does not measure `shared_network`, Wi-Fi tethering, cellular throughput, or
hardware tethering offload.

### Reproduce on a rooted Android device

The procedure needs a disposable directory such as `/data/local/tmp/sing`,
root, cgroup v2, network namespaces, veth, iptables, and an `ip` implementation
with `netns` support. A production phone should not be used unless the operator
understands the temporary namespace, cgroup, route, and firewall changes. Keep
all names and paths under a unique benchmark prefix and install cleanup traps.

Build an Android sing-box binary and the traffic generator from the same source
tree:

```sh
CGO_ENABLED=1 \
GOOS=android \
GOARCH=arm64 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang" \
TAGS="with_ebpf,with_gvisor" \
make build

CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
  go build -o build/interception-bench ./cmd/internal/interception_bench

adb shell su -c 'mkdir -p /data/local/tmp/sing'
adb push sing-box build/interception-bench /data/local/tmp/sing/
adb shell su -c 'chmod 700 /data/local/tmp/sing/sing-box /data/local/tmp/sing/interception-bench'
```

Create three network namespaces and two veth pairs with this fixed topology:

| Namespace | Interface and address | Peer |
|-----------|-----------------------|------|
| Application | `sba0`, `10.89.0.2/24` | Router `sbr0`, `10.89.0.1/24` |
| Router | `srr0`, `10.89.1.1/24` | Server `sbs0`, `10.89.1.2/24` |

Android commonly has no writable `/run/netns`. One compatible method is to
keep three `unshare -n` holder processes alive and enter them with
`nsenter -t PID -n`; record those PIDs with the result. A Termux or pushed
static iproute2/util-linux toolset may be needed because Toybox variants differ
between vendors.

Enable IPv4 forwarding only inside the router namespace, allow forwarding in
its private firewall, add an application default route through `10.89.0.1`,
and add the return route on the server. Use a private mount namespace and mount
cgroup v2 below `/data/local/tmp/sing/cgroup`; create a `client` child cgroup
and move only the benchmark client into it.

The Direct run uses the namespace route without sing-box. Run eBPF in the
application namespace with `cgroup_path` set to the `client` cgroup,
`dns_mode: off`, no rule-set bypass, and a direct outbound bound to `sba0`.
Run Redirect, TProxy, and TUN in the router namespace. Match only
`10.89.1.2:5201` in Redirect/TProxy rules; use dedicated ports and remove each
variant's rules before starting the next. Limit TUN `route_address` to
`10.89.1.2/32` and record its stack and `auto_redirect` setting.

Start the server in the server namespace:

```sh
/data/local/tmp/sing/interception-bench \
  -mode server -listen :5201
```

For each variant, move the client shell into the benchmark cgroup and run:

```sh
echo $$ > /data/local/tmp/sing/cgroup/client/cgroup.procs
exec /data/local/tmp/sing/interception-bench \
  -mode client \
  -target 10.89.1.2:5201 \
  -scenario all \
  -duration 5s \
  -warmup 1s \
  -concurrency 16 \
  -payload-size 1200
```

Repeat every variant five times and rotate the starting variant on each pass.
Restart sing-box and clear only that variant's firewall/policy-routing state
between measurements. Save every JSON result, generated config, sing-box log,
kernel/device record, namespace topology, and thermal sample. Verify zero
errors before calculating medians. Finally remove the benchmark processes,
rules, routes, cgroup, namespaces, and `/data/local/tmp/sing` contents created
by the test.

The namespace and inbound setup should follow the corresponding functions in
`.github/benchmark/run-inbound-benchmark.sh`; that runner is also a useful
reference for cleanup ordering. It targets a GNU/Linux userland and is not
intended to be executed unchanged by Android Toybox.

## GitHub Actions

The manually triggered `Inbound benchmark` workflow automates an IPv4 Linux
test topology with separate application, router, and server network
namespaces. It runs the direct baseline and the eBPF, Redirect, TProxy, and TUN
variants in randomized order, uploads every raw JSON report and environment
record, and writes median rates relative to the direct baseline to the job
summary. Redirect omits both UDP scenarios because the inbound is TCP-only.

An additional eBPF validation run executes the TCP short-connection and both
UDP workloads as an unprivileged UID while an owner firewall rule rejects that
UID's direct access to the server. The validation succeeds only when the cgroup
program redirects every tested socket through sing-box; its JSON result is
stored under `results/validation` and is not included in performance medians.

The workflow also performs one dedicated connected eBPF UDP profiling run when
`profile_seconds` is greater than zero. It uses a separate sing-box binary so
mutex and blocking profile collection cannot affect the normal benchmark. The
artifact contains raw CPU, allocation, mutex, and blocking profiles under
`results/profiles`, together with `go tool pprof -top` text reports. Set
`profile_seconds` to zero when profiles are not needed.

The workflow can use either `ubuntu-24.04` or a Linux self-hosted runner with
the custom `inbound-benchmark` label. Dependencies are installed automatically
only on the hosted runner; prepare the fixed runner with the commands checked
by the workflow. GitHub hosted runners are useful for checking that every data
path works and for finding large regressions within one job. Their virtual CPU
model, neighboring load, and frequency behavior are not stable enough for
publishable absolute performance figures or small differences between
inbounds.

Prefer comparisons within one job against that job's Direct baseline. Do not
compare absolute rates from unrelated hosted-runner jobs as if they used the
same machine. CPU steal time, host scheduling, turbo state, runner image
changes, and noisy neighbors can move individual results. The short default
duration is appropriate for CI regression detection but magnifies startup and
frequency-transition effects; use longer runs and a fixed self-hosted machine
for publishable numbers. The namespace/veth topology also favors in-kernel
paths and cannot represent Android policy routing, a physical NIC, radio power
management, hotspot TC hooks, or hardware offload.

The workflow inputs also select the TUN `stack` (`system`, `gvisor`, or
`mixed`) and whether `auto_redirect` is enabled. Both values are written to the
result environment record. Treat each combination as a separate variant and
do not merge their measurements into one TUN result.

When running the shell runner directly, `--variants` and `--scenarios` can
limit an engineering A/B run to a specific data path. The workflow intentionally
keeps the complete default matrix so its published artifacts remain comparable.

For a data table intended for documentation or promotion, select a fixed
bare-metal `self-hosted` Linux runner, run at least five repetitions, repeat
the entire workflow on different days, and publish the raw artifact together
with the median. Keep the runner kernel, firmware, CPU governor, NIC/offload
state, and sing-box build unchanged. Android cgroup eBPF behavior must still be
measured on a physical Android device; the Linux workflow cannot represent its
kernel, tethering path, or thermal limits.
