# eBPF inbound troubleshooting guide

This is a temporary collection guide for testing the eBPF inbound. Attach the
smallest complete report that reproduces the problem. A startup-only log is
usually insufficient for intermittent interception, resource growth, or a
kernel restart.

## Minimum report

Include all of the following:

1. The exact sing-box commit or full `sing-box version` output and the build
   tags used.
2. The eBPF inbound configuration and relevant route rules. Remove passwords,
   private keys, tokens, and unrelated server credentials, but do not remove
   eBPF mode, interfaces, UID ranges, DNS mode, IPv6 flags, or
   bypass policy.
3. Device model, operating system release, and complete kernel release. On
   Android also include the build fingerprint; on OpenWrt include
   `/etc/openwrt_release`.
4. A Debug-level log from process startup, through one reproduction, to a
   graceful shutdown when possible. Record the wall-clock time of the failure.
   For a long-running local UDP failure, preserve the startup line containing
   `udp_state_cleanup`. When using an `ebpf_debug` build, also preserve all
   `eBPF debug snapshot` lines and the nearby detailed Debug logs.
5. Exact reproduction steps, expected result, actual result, affected protocol,
   whether local or downstream traffic is affected, and whether restarting
   sing-box temporarily fixes it.
6. The matching kernel capability report:

```sh
sing-box tools ebpf status --mode local --network tcp,udp --json
sing-box tools ebpf status --mode shared-network --interface br-lan --json
```

Use the command that matches the configured path. For hybrid mode, run both or
use `--mode all` with the downstream interface.

Useful platform information:

```sh
uname -a
cat /proc/version
cat /proc/meminfo
cat /proc/self/mountinfo
```

Android:

```sh
getprop ro.product.model
getprop ro.build.fingerprint
getprop ro.build.version.release
logcat -b all -d > logcat-all.txt
```

OpenWrt:

```sh
cat /etc/openwrt_release
ubus call system board
ip -details link show
tc -details qdisc show
tc -details filter show
```

## Kernel panic or device restart

After the device restarts, copy every file from `/sys/fs/pstore` before another
crash overwrites it. In particular, provide `console-ramoops-*`,
`dmesg-ramoops-*`, and `pmsg-ramoops-*` when present:

```sh
ls -la /sys/fs/pstore
cp -a /sys/fs/pstore ./pstore-copy
dmesg -T > dmesg-after-reboot.txt
```

Also state whether local mode, shared mode, or only hotspot activation triggers
the restart. A userspace log may end before the kernel records the fault, so
pstore is the primary artifact for this class of failure.

## Diagnostic build

Add `ebpf_debug` to the normal build tags. For Android arm64 with NDK r29:

```sh
TAGS=with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0,with_provider,with_ebpf,ebpf_debug \
CGO_ENABLED=1 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
GOARCH=arm64 GOOS=android make build
```

Set the sing-box log level to `debug`. The diagnostic build emits an `eBPF
debug snapshot` JSON object after startup, immediately before shutdown, and
when a valid local or shared TCP token has lost its redirect state. It contains
map type, key/value sizes, capacity, current entry count, kernel memlock,
map/program IDs, and per-program run count, cumulative kernel runtime, average
nanoseconds per run, and recursion misses. It also logs detailed startup
configuration, bypass-policy changes, and successful janitor removals.
Collection is event driven; there is no periodic reporter and no diagnostic
counter in the forwarding hot path. A normal `with_ebpf` build does not walk
maps or enable program runtime statistics even when Debug logging is active.

An `ebpf_debug` build temporarily enables the kernel's
`BPF_STATS_RUN_TIME` facility while at least one eBPF inbound is active. This
is the most direct measurement of BPF data-plane cost, but it is a system-wide
kernel statistic with measurable overhead. Use it for diagnosis rather than a
normal release build. Kernels older than 5.8 and vendor kernels that reject the
facility continue without program runtime statistics. The snapshot's program
`error` field records the read failure when available.

For local UDP, compare `cgroup_udp_redirect`, `cgroup_udp_token`,
`cgroup_udp_peer`, and `cgroup_udp_flow` entry counts with their capacities.
The startup log's `udp_state_cleanup=socket_release` means an exact
`cgroup/sock_release` cleanup program is active; `lru_fallback` uses bounded LRU
state instead. For shared pressure, inspect `shared_flow_by_original` and
`shared_flow_by_token`; both directions should remain close in occupancy.

## CPU and memory profiles

Go pprof is provided by sing-box itself and does not require `ebpf_debug`.
Enable the shared debug HTTP endpoint in the configuration:

```json
{
  "experimental": {
    "debug": {
      "listen": "127.0.0.1:6060"
    }
  }
}
```

Keep this listener on loopback. On Android, forward it to the host:

```sh
adb forward tcp:6060 tcp:6060
```

Capture CPU while reproducing the issue, then capture heap and goroutines:

```sh
curl -o cpu.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
curl -o heap.pprof 'http://127.0.0.1:6060/debug/pprof/heap?gc=1'
curl -o goroutine.txt 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=2'
go tool pprof -top cpu.pprof
go tool pprof -top heap.pprof
```

For memory growth, capture heap once after startup and again after the growth
is visible. Include both profiles, the eBPF debug snapshots, and
`/proc/<pid>/status`. Stop the diagnostic build after collection.

pprof measures Go userspace CPU and heap. It does not measure time executing
inside kernel BPF programs or kernel map memory. Use the debug snapshot's
`memlock_bytes`, program IDs, startup attachment mode, and kernel logs for the latter.
On a kernel with suitable perf/BPF permissions, a maintainer may request a
separate `bpftool prog profile id <id>` capture; do not enable global kernel
BPF statistics unless specifically requested because they affect the whole
system.

## Runtime maintenance

Shared flow cleanup, attachment reconciliation, and local TCP cleanup are
correctness work and remain enabled in normal builds. Most
work is event or deadline driven, with low-frequency watchdogs for kernel state
that has no reliable userspace event. If CPU usage appears periodic, include an
`ebpf_debug` snapshot and a CPU profile instead of disabling these
tasks; doing so can cause map exhaustion, stale redirects, or detached
interfaces.

## Privacy and packaging

Logs and profiles can contain destination addresses, domains, interface names,
package names, file paths, and configuration fragments. Remove credentials and
unrelated personal data before publishing, but preserve timestamps, errno
values, program/map IDs, UID ranges, kernel stack traces, and the sequence
around the failure. Package the configuration, logs, capability JSON, profiles,
and pstore files together with a short timeline.
