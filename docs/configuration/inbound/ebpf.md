---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

The eBPF inbound transparently intercepts local or downstream TCP and UDP
traffic. The `local` data path uses cgroup socket-address programs. The
`shared` data path uses TC to intercept forwarded traffic from hotspot, router,
or other downstream interfaces.

It is available on Android and Linux builds compiled with `with_ebpf`. The
runtime does not require cgo, but requires root or equivalent BPF, cgroup, and
network administration privileges.

!!! warning "Linux 6.6 LPM trie compatibility"

    Linux 6.6.0 through 6.6.46 can panic under UBSAN while updating a BPF LPM
    trie. The default `shared_network` host-address policy uses exact-match
    hash maps and is unaffected. Local UID/package filters, `bypass_rule_set`,
    and shared source CIDR filters populate LPM tries and require Linux 6.6.47
    or a vendor kernel containing upstream fix
    `896880ff30866f386ebed14ab81ce1ad3710cfc4`. sing-box rejects those policies
    on a known-unfixed kernel instead of risking a kernel panic.

### Structure

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "mode": "local",
  "network": ["tcp", "udp"],
  "udp_timeout": "5m",
  "dns_mode": "hijack",
  "bypass_rule_set": ["geoip-cn"],
  "local": {
    "cgroup_path": "",
    "ipv6_mode": "auto",
    "bypass_private_address": true,
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": [],
    "state_capacity": 0
  },
  "shared": {
    "interface": [],
    "ipv6_mode": "always",
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "state_capacity": 0,
    "advanced": {
      "tc_priority": 1
    }
  }
}
```

The eBPF inbound does not use [listen fields](/configuration/shared/listen/).
sing-box allocates internal listener ports and non-conflicting redirect prefixes.

### mode

| Value | Data path |
|-------|-----------|
| `local` | Intercept local cgroup traffic only. |
| `shared` | Intercept forwarded traffic on selected downstream interfaces only. |
| `hybrid` | Enable both data paths. Rule-set bypass is shared; private-address bypass is configured independently. |

Default is `local`. `local` fields require local or hybrid mode; `shared`
fields require shared or hybrid mode.

### network

Enabled protocols, `tcp` and/or `udp`. Both are enabled by default.

### udp_timeout

UDP session timeout. Default is `5m`.

### dns_mode

Controls how destination port 53 interacts with bypass policy:

| Value | Behavior |
|-------|----------|
| `hijack` | Intercept DNS before private-address and rule-set bypass checks. |
| `respect_bypass` | Apply bypass checks before deciding whether to intercept DNS. |
| `off` | Do not intercept destination port 53. |

Default is `hijack`. UID, protocol, self-loop, DHCP, and shared client filters
still run before this policy. This captures TCP/UDP port 53 and is not the same
as the `hijack-dns` routing action. UDP must be enabled when shared DNS
interception is active.

### bypass_rule_set

Rule sets whose destination IP CIDRs bypass this inbound. Only CIDRs are
extracted; domains, ports, processes, and other conditions are not evaluated in
the kernel. Map contents are refreshed after rule-set updates. Existing flows
keep their decision until they expire.

When a FakeIP DNS server is configured, its IPv4 and IPv6 allocation ranges
are force-intercepted before private-address and rule-set bypass checks. This
also lets FakeIP IPv6 work while `local.ipv6_mode` is `auto` and no usable
native IPv6 route is present. UID, package, shared source, protocol, self-loop,
and exact local-host address filters still take precedence. A rule-set overlap
is reported at startup; an unsafe FakeIP range overlapping unspecified,
loopback, multicast, or an internal redirect range is rejected.

### local

#### local.cgroup_path

Absolute cgroup v2 path to intercept. Empty uses the detected cgroup v2 root.
Only one eBPF inbound can own a cgroup path at a time.

#### local.ipv6_mode

| Value | Behavior |
|-------|----------|
| `auto` | Intercept new native IPv6 flows only while a usable IPv6 route exists. |
| `always` | Always enable native IPv6 interception. |
| `off` | Do not intercept native IPv6. |

Default is `auto`. IPv4-mapped IPv6 sockets are still handled as IPv4. This
field does not control shared-path IPv6; use `shared.ipv6_mode` separately.
Ordinary native IPv6 follows the route-availability probe; configured FakeIP
IPv6 ranges are intercepted without that route gate so DNS synthesis cannot
produce an unreachable bypass path.

#### local.bypass_private_address

Bypass built-in private, carrier-grade NAT, and link-local destinations on the
local data path. Default is `true`. Setting it to `false` does not disable
protocol, self-loop, DHCP, unspecified-address, loopback, multicast, or exact
local-host address safety bypasses. In `dns_mode: "hijack"`, destination port
53 is handled before destination-address bypasses.

#### local.include_uid

UIDs to intercept. Once any include UID, range, or package is configured,
other UIDs bypass by default.

#### local.include_uid_range

UID ranges to intercept, in `start:end` format.

#### local.exclude_uid

UIDs to bypass. Exclude takes precedence over include.

#### local.exclude_uid_range

UID ranges to bypass, in `start:end` format.

#### local.include_android_user

Android user IDs to intercept. Android only.

#### local.include_package

Android package names to intercept. Names are resolved to UIDs at startup.

#### local.exclude_package

Android package names to bypass. Packages sharing a UID cannot be distinguished.

Package policy only covers sockets directly created by the resolved UID.
System DNS, `DownloadManager`, isolated processes, SDK sandboxes, and similar
delegated traffic may use another UID. Startup logs show the final include and
exclude UID ranges written to the kernel.

#### local.state_capacity

Capacity for local redirect, UDP flow, and socket-cookie fallback state. `0`
uses the implementation default (currently 65536). Valid range is 0 through
1048576. Larger values consume more locked kernel memory.

### shared

Shared mode does not create a hotspot, DHCP, NAT, IPv6 RA, or IP forwarding.
Those remain the responsibility of Android, Linux, or OpenWrt.

#### shared.interface

==Required in shared or hybrid mode==

Downstream interfaces where client packets enter TC ingress. Interfaces may
appear or disappear after startup; sing-box attaches and detaches automatically.
Do not select `lo`, an upstream interface, or a layer-3-only interface. When a
hotspot and Wi-Fi upstream share an interface name, restrict clients with
source CIDR or MAC policy.

#### shared.ipv6_mode

| Value | Behavior |
|-------|----------|
| `always` | Always intercept IPv6 traffic on selected downstream interfaces. |
| `off` | Do not intercept shared-path IPv6 traffic. |

Default is `always`, which preserves the behavior of earlier versions. `off`
does not block IPv6: when the system can forward IPv6, that traffic bypasses
sing-box. Shared mode does not use local native-route probing because downstream
IPv6 availability and proxy reachability cannot be inferred from the host's
default IPv6 route.

#### shared.bypass_private_address

Bypass built-in private, carrier-grade NAT, and link-local destinations on the
shared data path. Default is `true` and is independent from
`local.bypass_private_address`. Setting it to `false` still preserves safety
bypass for IPv4 unspecified (`0.0.0.0/8`), the complete IPv4 loopback range
(`127.0.0.0/8`), IPv6 unspecified and loopback, and IPv4/IPv6 multicast
destinations. Exact addresses assigned to the host also remain bypassed. In
`dns_mode: "hijack"`, destination port 53 keeps its documented compatibility
priority.

#### shared.include_source_cidr

Client source CIDRs allowed into the proxy path. Non-matching traffic bypasses
when the list is non-empty.

#### shared.exclude_source_cidr

Client source CIDRs to bypass. Exclude takes precedence over include.

#### shared.include_mac_address

48-bit client source MAC addresses allowed into the proxy path.

#### shared.exclude_mac_address

Client source MAC addresses to bypass. Exclude takes precedence over include.

#### shared.state_capacity

Capacity for shared proxy, bypass, and fragment state. `0` uses the
implementation defaults: 65536 proxy entries, 8192 fragment entries, and
65536 bypass entries when bypass rule-set or source policies are configured.
The unused bypass cache is reduced to one entry otherwise, including when an
explicit capacity is set. An explicit value applies to the active maps. Valid
range is 0 through 1048576.
When proxy state reaches sustained pressure or token reservation starts to
fail, sing-box temporarily shortens orphan cleanup to recover capacity while
retaining flows referenced by active TCP or UDP sessions.

#### shared.advanced.tc_priority

TC filter priority in the range 1 through 65535. Default is `1`. Change it only
to coordinate with OpenWrt, Android tethering, or existing TC programs. An
interface can be managed by only one eBPF inbound, regardless of priority.
With the default priority, sing-box uses TCX when the kernel supports it and
falls back to clsact automatically. A non-default priority selects clsact so
that the requested ordering remains meaningful.

### Kernel compatibility

Linux 4.19 is the minimum compatibility target for shared mode and TCP-only
local mode. Local UDP also requires the cgroup UDP4/UDP6 recvmsg hooks added by
upstream Linux 5.2, so the default TCP+UDP local or hybrid configuration needs
Linux 5.2 or a vendor backport. Android GKI 5.10+ remains the primary Android
validation target.

The generated programs use the BPF v1 instruction set, contain no verifier
backward jumps, and stay within the Linux 4.19 limit of 4096 instructions per
program. They do not require kernel BTF, CO-RE, bounded-loop verification,
BPF timers, dynptrs, or kfuncs. Local mode requires cgroup v2 and the selected
socket-address hooks. Shared mode requires `sched_cls`, writable-packet and
checksum helpers. TCX is used as an optional modern attachment path with
automatic clsact fallback. Vendor kernels may backport, disable, or alter
individual features, so direct capability probes are more reliable than the
release string.

For local UDP, startup performs an inert attach/detach test against the target
cgroup before choosing the state-map layout. A successful `cgroup/sock_release`
test selects ordinary hash maps with exact cleanup when each UDP socket closes.
If that hook is unavailable, sing-box selects bounded LRU maps instead, so an
older or vendor kernel cannot permanently exhaust UDP redirect state. The
startup log reports the selected path as `udp_state_cleanup=socket_release` or
`udp_state_cleanup=lru_fallback`.

Run the non-disruptive pure-Go probe as root with the same mode and protocols:

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
sing-box tools ebpf status --mode all --interface br-lan --json
```

The command uses `cilium/ebpf` directly and does not require a shell, `bpftool`,
or `tc`. It creates and closes transient probe objects but never attaches a
program or changes cgroups, qdiscs, routes, sysctls, or traffic.
Use `--json` for a machine-readable report suitable for issue attachments.
Traffic-path warnings are rate-limited. When any local or shared lookup,
packet-info, binding, or cleanup error occurred, shutdown logs contain one
aggregate diagnostic summary with the unsuppressed totals.

When Debug logging is enabled, the inbound also emits one JSON runtime-status
record after startup, every 10 minutes, and immediately before shutdown. The
record contains:

- map names, types, IDs, key/value sizes, kernel memlock, current entry counts,
  and capacities;
- loaded program names, sections, IDs, and queried attachment state;
- the local UDP cleanup mode plus TCP and UDP redirect-reservation failure
  counters;
- each shared interface's index and active `tcx` or `clsact` attachment mode;
- TCX link IDs, attachment health, lifecycle repair counters, and traffic
  diagnostic counters.

`entries_known: false` or an `error` field means the kernel rejected that
individual query; interception continues unchanged. Array maps report their
fixed number of slots. LRU maps are counted with key-only iteration so status
collection does not refresh their eviction order. Hash and LPM maps use batch
lookup where supported and automatically fall back on older kernels. Map and
attachment queries and the periodic reporter are skipped unless Debug logging
is active, so the default Info level pays no scanning or timer cost.

A non-zero `udp_redirect_reservation_failures` value means that the kernel
could not reserve a redirect token. Hash-based UDP redirect/token maps also
produce a rate-limited warning after reaching 90% capacity. Either signal is
actionable evidence of UDP state pressure; include the complete runtime-status
record from before restarting sing-box.

`sing-box tools ebpf status` is a non-attaching preflight capability estimate.
The inbound's startup attach/detach test remains authoritative for
`cgroup/sock_release`. The command also cannot report
the live maps or attachments owned by another running sing-box process because
the inbound deliberately does not pin those objects in bpffs. Use the Debug
runtime-status record when reporting a live interception failure.
For Go CPU, heap, RSS, GC, and maintenance-task timing collection, use the
temporary [`ebpf_debug` troubleshooting workflow](/manual/misc/ebpf-troubleshooting/).
