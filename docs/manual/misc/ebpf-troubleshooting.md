---
icon: material/stethoscope
---

# eBPF inbound troubleshooting

Provide a complete report from startup through one reproduction and shutdown.
Startup-only logs rarely explain intermittent packet loss, attachment changes,
or resource growth.

## Triage by symptom

| Symptom | First evidence | Common distinction |
| --- | --- | --- |
| Startup fails at object load | `tools ebpf status --json`, verifier log, full error | Missing helper/program/map support or security policy denial |
| Startup fails at attach | startup log, target cgroup/interface, SELinux/LSM log | Object support exists, but the real hook is denied or already occupied |
| Inbound starts but traffic bypasses | `api ebpf`, attachment list, filter counters, pass/fragment counters | Wrong path/interface or intentional policy/fragment bypass |
| UDP intermittently fails | first warning, UDP NAT counters, map occupancy, network-change timestamps | Queue/map pressure, stale assignment, release notification loss, or upstream loss |
| Traffic changes after Wi-Fi/mobile/hotspot switch | before/after runtime report, routes, links and TC filters | Waiting for a new interface, recovering managed state, or lost OS tethering state |
| CPU or memory grows | pprof, active UDP sessions, reply-socket pool, map occupancy | Go heap/goroutines, userspace session churn, or kernel map allocation |
| Device reboots or kernel panics | `/sys/fs/pstore`, kernel release, enabled policy | Kernel verifier/map/driver defect; userspace logs alone are insufficient |

Do not infer the responsible data plane from the word “eBPF” alone. Local
`cgroup`, local `tc`, shared `socket_assign`, and shared `packet_rewrite` use
different hooks, maps, delivery paths, and cleanup mechanisms.

## Minimum report

Include:

1. The exact sing-box commit or full `sing-box version` output and build tags.
2. The eBPF inbound configuration and relevant route rules. Remove credentials,
   but retain enabled/data-plane settings, interfaces, UID or source policy, DNS and IPv6 settings, TC
   priority, and bypass policy.
3. Device model, operating-system release, complete kernel release, and, on
   Android, the build fingerprint.
4. Debug-level logs from startup through reproduction and graceful shutdown.
5. Reproduction steps, expected and actual behavior, affected protocol, local
   or downstream scope, and whether restarting sing-box changes the result.
6. A capability report matching the intended path:

```sh
sing-box tools ebpf status --local-data-plane cgroup --network tcp,udp --json
sing-box tools ebpf status --shared-data-plane packet_rewrite --interface br-lan --json
```

Add `--ipv6=false` when the inbound configuration disables IPv6. The command
exits non-zero when a required capability is missing or cannot be verified.

For a configuration that enables both paths, pass both data-plane flags in one
command. Run probes with the same privileges as the service.

7. If the sing-box API service is configured, the running-instance report from
   `sing-box api ebpf` (see [eBPF configuration](/configuration/inbound/ebpf/#diagnostics)):

```sh
sing-box api ebpf --url http://127.0.0.1:9090 --secret "$SECRET"
```

This is distinct from item 6's capability probe: it reports what the running
inbound is actually doing (attachments, active programs, map occupancy,
pending recovery, recent errors and counters), not what the kernel could
theoretically support. Include it whenever the report concerns whether
interception is actually happening, rather than whether the kernel supports it.

Useful platform information:

```sh
uname -a
cat /proc/version
cat /proc/meminfo
ip -details link show
tc -details qdisc show
tc -statistics -details filter show
```

Android reports should also include `getprop ro.build.fingerprint` and a full
`logcat -b all -d`. OpenWrt reports should include `/etc/openwrt_release` and
`ubus call system board`.

## Kernel panic or device restart

After restart, copy `/sys/fs/pstore` before another crash overwrites it:

```sh
ls -la /sys/fs/pstore
cp -a /sys/fs/pstore ./pstore-copy
dmesg -T > dmesg-after-reboot.txt
```

Include `console-ramoops-*`, `dmesg-ramoops-*`, and `pmsg-ramoops-*` files when
present. State whether local mode, shared mode, or only a network-interface
change triggers the restart. The kernel record is more useful than a userspace
log that stops before the fault.

## Logs and runtime state

A successful startup emits a brief `eBPF inbound started` summary at Debug
level: enabled paths, each attachment's actual interface and mechanism, any
path still waiting for an interface, and what `fakeip_icmp` actually covers.
Debug logging also includes an `eBPF cgroup active` or `eBPF TC active` summary containing the
selected data planes and their effective runtime paths. TC summaries also include the default interface, attachments,
internal listeners, routing state, and delivery interface when applicable. Each
attachment includes its local/shared role and framing. A network event emits a
Debug entry only when attachments or managed network state are changed; repair
failures produce rate-limited warnings. Userspace handoff failures produce
rate-limited Warn or Error entries. BPF packet return paths do not emit
per-packet logs. Interface lifecycle handling is event-driven with a
low-frequency drift check for silent kernel-state changes. Shared
`packet_rewrite` runs bounded maintenance when flow events, release deadlines,
or map pressure require it. These tasks do not emit periodic status records.

If the log reports an assignment or UDP original-destination failure, retain
the complete log around the first error and collect the TC attachment state
described below.

### Interpreting `sing-box api ebpf`

The top-level state is an operational summary:

| State | Meaning | Action |
| --- | --- | --- |
| `normal` | Every configured path is attached and no recovery is pending. | Compare counters before and after one controlled flow. |
| `waiting_for_interface` | A configured TC path has no eligible interface. | Check default/downstream interface selection; this is not itself a failed recovery. |
| `recovering` | A retry is scheduled after a recoverable topology or policy failure. | Preserve `last_error`, `next_retry_at`, and a later snapshot. |
| `needs_attention` | Reconciliation or policy rollback cannot safely continue. | Preserve diagnostics, then restart the inbound to rebuild state. |

Read attachment entries as the source of truth for the mechanism actually in
use. A configured path without a corresponding attachment may legitimately be
waiting for an interface; a cgroup attachment has no network-interface filter.

For local cgroup, also record the effective runtime fields returned by the API:
`local_cgroup_attach_mode` (`link_create`, `legacy_multi`,
`legacy_exclusive`, or `mixed`), `local_udp_cleanup_mode`,
`local_udp_userspace_cleanup_mode`, `local_udp_storage_mode`, and
`local_udp_time_mode`. These describe the path actually selected after vendor
kernel and security-policy fallbacks; they are not capability guesses.

When local TC or shared `socket_assign` is enabled, the API also reports `tc_*`
runtime fields: the effective `tcx`/`clsact`/`mixed` attachment mechanism,
`sockmap`/`direct` TCP listener lookup, delivery interface and ifindex, policy
routing mark/table/priority, active and retired resource counts, health state,
the last health-check/reconcile times, and the network generation. These are
live resource snapshots rather than kernel-version guesses. The network
generation increments at the managed network-change boundary so before/after
captures can separate handover effects. Reading these fields does not add
per-packet counters, full map scans, or a new background timer.

Counter values are cumulative for the current process or cache lifetime. Take a
snapshot immediately before and after a small controlled test instead of
interpreting a single large number:

- rising assignment, socket-lookup, `sk_assign`, token-reservation, or rewrite
  failures indicates a kernel handoff/drop point and should be accompanied by
  the first warning and attachment state;
- fragment-pass counters mean fragmented IPv4 or non-atomic IPv6 was
  intentionally allowed through, not that the parser silently lost it;
- shared ingress/egress pass counters cover all explicit pass exits and help
  reveal asymmetric bypass or reply-path behavior;
- UDP `capacity_evictions`, `queue_drops`, pending-release rejection, and
  release-notification drops are distinct pressure signals. They do not all
  mean that the BPF assignment map is missing;
- map occupancy is collected only on an explicit diagnostic request. `UNKNOWN`
  means the map type cannot be safely iterated or inspection was denied; it is
  not zero occupancy.

Program/map enumeration uses the `sb_` naming convention and can see another
visible sing-ebpf process in the same kernel. Per-inbound attachments, policy
state, userspace sessions, and counters remain the correct instance-specific
evidence.

## Startup and attachment failures

Run the non-attaching probe with the same UID, capabilities, namespace, cgroup
view, and SELinux/LSM domain as the service. Root in an interactive shell can
produce a different result from the service manager.

- `operation not permitted` while loading an object usually points to BPF
  syscall, verifier, capability, lockdown, or LSM policy. Preserve the verifier
  log when present.
- `operation not permitted` while attaching a successfully loaded cgroup
  program points to the selected hierarchy, delegation, multi/exclusive attach
  support, or an existing hook such as Android netd. The cgroup fallback mode
  selected at startup matters.
- TC attach failure after a successful probe requires the actual link type,
  qdisc/filter inventory, interface lock result, and netlink error. The probe
  intentionally does not modify qdiscs.
- A SOCKMAP failure may legitimately select the legacy TC object. Report it as
  a startup failure only when the selected fallback also fails or the inbound
  does not become active.
- Denial of the optional cgroup socket-release observer may legitimately select
  bounded LRU cleanup. Confirm the effective program/attachment instead of
  assuming local cgroup is unavailable.

## CPU and memory profiles

Enable the standard debug endpoint on loopback to use Go pprof:

```json
{
  "experimental": {
    "debug": {
      "listen": "127.0.0.1:6060"
    }
  }
}
```

Then collect CPU, heap, and goroutine profiles around the reproduction:

```sh
curl -o cpu.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
curl -o heap.pprof 'http://127.0.0.1:6060/debug/pprof/heap?gc=1'
curl -o goroutine.txt 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=2'
go tool pprof -top cpu.pprof
go tool pprof -top heap.pprof
```

pprof measures Go userspace CPU and memory, not BPF execution or kernel map
memory. Use TC state, `dmesg`, and BPF inspection tools available on the target
system for the kernel side.

## Attachment and interface checks

Local `cgroup` mode follows the selected cgroup v2 hierarchy and has no network
interface attachment. Local `tc` follows the current default interface. Shared
mode follows the configured downstream interfaces and retries interfaces that
were absent at startup. A configured shared interface is detached while it is
the current default upstream and restored when it becomes downstream again. Network events also
validate the managed TC filters, policy routing, and delivery link. When
interception changes after an interface event, capture before and after output
from:

```sh
ip -details link show
ip route show table all
ip -6 route show table all
tc -details qdisc show
tc -statistics -details filter show
```

Also retain the startup `eBPF TC active` summary. Do not manually remove the
internal veth or managed TC filters while sing-box is running.

For local `tc` interception, compare the packet counts on the default-interface
egress filter and the logged delivery-interface ingress filter:

```sh
tc -statistics filter show dev wlan0 egress
tc -statistics filter show dev sbdXXXXXXXX ingress
```

Replace both interface names with those from the startup log. If the local
filter count increases while the delivery filter does not, retain both filter
outputs and the corresponding `ip -details link show` output.

## Traffic bypass, drops, and fragments

Test one TCP and one UDP flow whose destination is known not to match a bypass
rule. Record the destination, source UID or downstream source, DNS mode, and
before/after diagnostics. Then check in this order:

1. the intended role and interface appear in `attachments`;
2. the relevant TC filter packet count or cgroup program is active;
3. the flow is not excluded by address family, protocol, service traffic,
   self-bypass, UID/source, port, private-address, or rule-set policy;
4. fragment-pass and general pass counters do not explain the result;
5. assignment/rewrite failure counters stay unchanged;
6. the sing-box listener and router receive the flow.

IPv4 fragments and non-atomic IPv6 fragments intentionally bypass because they
do not carry a complete transport tuple at every hook. A five-tuple proxy cannot
safely redirect later fragments independently. If fragmentation is unexpected,
capture both sides of the affected interface and determine whether MTU, PMTU
discovery, an upstream tunnel, or the sender created it.

For checksum or hardware-offload suspicion, use the dedicated
[checksum/offload verification](/manual/misc/ebpf-checksum-offload-verification/)
procedure. A sending-side capture can show incomplete checksums before the NIC
finishes offload; the receiving payload and remote capture are authoritative.

## Network changes and recovery

Capture `sing-box api ebpf` immediately before the switch, during the failure,
and after the expected recovery. Correlate `last_error_at`, `last_recovery_at`,
`next_retry_at`, attachment ifindex changes, and route/link events.

Local TC follows the current default interface. Shared interfaces are eligible
only while downstream; an interface temporarily acting as the default upstream
is deliberately detached. The last local attachment can remain until a new
default interface is ready, avoiding an unnecessary gap. This does not recreate
Android hotspot IPv6 prefixes, default routes, DHCP, NAT, or forwarding removed
by the operating system.

If state stays `recovering`, wait through the reported next retry and capture a
second report. If it becomes `needs_attention`, do not manually splice together
routes or filters from different generations; preserve evidence and restart.

## Shutdown and stale state

Prefer a graceful stop and retain the shutdown log. After the process exits,
verify that its internal delivery link, owned filter handles, policy rules,
routes, interface locks, and modified sysctls were removed or restored. Do not
delete unrelated `clsact` qdiscs or filters merely because they share an
interface.

If cleanup reports an error, preserve the exact object/interface identifiers
and retry by starting then gracefully stopping the same build before manual
removal. Manual cleanup should be the last step and must target only positively
identified sing-box-owned state.

## Privacy

Logs and profiles can contain destination addresses, domains, interface and
package names, file paths, and configuration fragments. Remove credentials and
unrelated personal data, while preserving timestamps, error numbers, program
and map IDs, UID ranges, kernel stack traces, and event order.
