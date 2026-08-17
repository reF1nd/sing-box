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
   eBPF mode, interfaces, UID ranges, DNS mode, IPv6 mode, capacities, or
   bypass policy.
3. Device model, operating system release, and complete kernel release. On
   Android also include the build fingerprint; on OpenWrt include
   `/etc/openwrt_release`.
4. A Debug-level log from process startup, through one reproduction, to a
   graceful shutdown when possible. Record the wall-clock time of the failure.
   For a long-running local UDP failure, preserve the last `eBPF runtime
   status` JSON before restarting and the startup line containing
   `udp_state_cleanup`.
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

Set the sing-box log level to `debug`. The diagnostic build adds a `debug`
object to the eBPF runtime-status JSON every minute. It contains:

- Go heap, stack, total runtime allocation, RSS, goroutine, GC, and GC pause
  counters;
- run count, error count, total, maximum, and last duration for local TCP
  cleanup, shared pressure polling, shared flow cleanup, attachment
  reconciliation, IPv6 route probes, and status collection;
- normal map entries, capacity, key/value sizes, kernel memlock, program IDs,
  link IDs, and queried attachment health.

The normal `with_ebpf` build keeps the correctness counters and ten-minute
runtime status when Debug logging is active. At Info level it does not start
the periodic status reporter. The extra Go runtime and task-duration sampling
exists only in an `ebpf_debug` build.

For local UDP, inspect `local.backend.udp_cleanup_mode`,
`udp_redirect_reservation_failures`, and the `cgroup_udp_redirect` and
`cgroup_udp_token` map entries/capacities. `socket_release` should have a loaded
and attached `sb_ebpf_rel` program. `lru_fallback` intentionally has no release
program and both state maps must be `LRUHash`. Any other combination is invalid.
A growing reservation-failure counter or a rate-limited 90% map-pressure
warning identifies state exhaustion rather than program detachment.
`diagnostics.local.udp_connected_recovery` counts redirect entries rebuilt from
the surviving connected-socket token and peer state in `lru_fallback` mode. A
non-zero value confirms that the exceptional self-recovery path prevented a
connected UDP packet from being dropped; steady-state traffic does not run this
scan.

## CPU and memory profiles

Go pprof is opt-in in an `ebpf_debug` build. Select a free port when starting
sing-box:

```sh
SING_BOX_EBPF_PPROF_PORT=6060 sing-box run -c config.json
```

The server listens only on `127.0.0.1`. On Android, forward it to the host:

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
is visible. Include both profiles, the Debug runtime-status records between
them, and `/proc/<pid>/status`. Stop the diagnostic build after collection.

pprof measures Go userspace CPU and heap. It does not measure time executing
inside kernel BPF programs or kernel map memory. Use the runtime-status
`memlock_bytes`, program IDs, attachment health, and kernel logs for the latter.
On a kernel with suitable perf/BPF permissions, a maintainer may request a
separate `bpftool prog profile id <id>` capture; do not enable global kernel
BPF statistics unless specifically requested because they affect the whole
system.

## Periodic maintenance is not debug code

The following work keeps interception correct over time and remains enabled in
normal builds:

| Task | Trigger | Purpose |
|------|---------|---------|
| Shared pressure poll | Every 5 seconds | Detect token allocation failures and map pressure early. |
| Shared flow sweep | Normally every 30 seconds, faster under pressure | Release orphaned token, reply, and listener state without removing active flows. |
| Shared attachment reconciliation | Network change or every 30 seconds | Attach new interfaces and repair removed TCX/clsact state and `route_localnet`. |
| Local TCP redirect sweep | Every minute | Remove stale connect state left by failed or abandoned accepts. |
| Local IPv6 route probe | Debounced network-change event | Keep `local.ipv6_mode: auto` synchronized with usable native IPv6. |

Disabling these tasks can cause the exact long-running failures they diagnose:
full maps, stale redirects, or silently detached interfaces. The
`ebpf_debug` timing counters and pprof should first establish which task is
expensive. Change an interval only after a profile and runtime-status sample
show a measurable problem on the affected kernel.

## Privacy and packaging

Logs and profiles can contain destination addresses, domains, interface names,
package names, file paths, and configuration fragments. Remove credentials and
unrelated personal data before publishing, but preserve timestamps, errno
values, program/map IDs, UID ranges, kernel stack traces, and the sequence
around the failure. Package the configuration, logs, capability JSON, profiles,
and pstore files together with a short timeline.
