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
