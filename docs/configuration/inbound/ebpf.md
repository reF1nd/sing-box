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
  "bypass_rule_set": ["geoip-cn"],
  "local": {
    "dns_mode": "respect_policy",
    "cgroup_path": "",
    "ipv6": true,
    "bypass_private_address": true,
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": []
  },
  "shared": {
    "dns_mode": "respect_policy",
    "interface": [],
    "ipv6": true,
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
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


### bypass_rule_set

Rule sets whose destination IP CIDRs bypass this inbound. Only CIDRs are
extracted; domains, ports, processes, and other conditions are not evaluated in
the kernel. Map contents are refreshed after rule-set updates. Existing flows
keep their decision until they expire.

When a FakeIP DNS server is configured, its IPv4 and IPv6 allocation ranges
are force-intercepted before private-address and rule-set bypass checks. UID,
package, shared source, protocol, self-loop, and exact local-host address
filters still take precedence. A rule-set overlap
is reported at startup; an unsafe FakeIP range overlapping unspecified,
loopback, multicast, or an internal redirect range is rejected.

### local

#### local.dns_mode

Controls interception of destination port 53 on the local data path:

| Value | Behavior |
|-------|----------|
| `hijack` | Intercept before local UID/package and destination bypass policy. |
| `respect_policy` | Honor local UID/package selection, then intercept selected DNS without destination bypass. |
| `off` | Bypass destination port 53 before local user policy. |

Default is `respect_policy`. It honors UID/package selection, but host, private-address, and
`bypass_rule_set` destination bypass do not apply to selected DNS.
Explicit `hijack` additionally ignores UID/package selection, exact host addresses,
private-address bypass, and `bypass_rule_set` for port 53. Self-loop protection,
internal redirect protection, protocol selection, DHCP safety, packet validity,
and `local.ipv6: false` remain higher-priority correctness gates in every
mode. Only TCP and/or UDP enabled by `network` are considered, so TCP-only and
UDP-only configurations are valid. This setting does not identify DoH or DoT
and is not the same as the `hijack-dns` routing action.

#### local.cgroup_path

Absolute cgroup v2 path to intercept. Empty uses the detected cgroup v2 root.
Only one `local` or `hybrid` eBPF inbound is supported in one sing-box process.
The owning Box registers the socket cookies of sing-box-created sockets in the
local bypass map. Protection is scoped to that Box rather than a process-global
callback, but a second local backend in the same Box is still rejected.

#### local.ipv6

Enable native IPv6 interception on the local cgroup path. Default is `true`.
Set it to `false` when the host must leave native IPv6 outside this inbound.
The value is static for the lifetime of the inbound; sing-box does not infer it
from the current default route. IPv4-mapped IPv6 sockets are still handled as
IPv4. This field does not control shared-path IPv6; use `shared.ipv6`
separately.

#### local.bypass_private_address

Bypass built-in private, carrier-grade NAT, and link-local destinations on the
local data path. Default is `true`. Setting it to `false` does not disable the
safety bypasses for ordinary non-DNS traffic, including unspecified, loopback,
multicast, and exact local-host destinations. As documented under
`local.dns_mode`, `hijack` handles port 53 before all destination bypasses.

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

### shared

Shared mode does not create a hotspot, DHCP, NAT, IPv6 RA, or IP forwarding.
Those remain the responsibility of Android, Linux, or OpenWrt.

#### shared.dns_mode

Controls interception of destination port 53 on the shared data path:

| Value | Behavior |
|-------|----------|
| `hijack` | Intercept before shared client and destination bypass policy. |
| `respect_policy` | Honor shared source CIDR/MAC selection, then intercept selected DNS without destination bypass. |
| `off` | Bypass destination port 53 before shared user policy. |

Default is `respect_policy`. It honors source CIDR/MAC selection, but host, private-address,
and `bypass_rule_set` destination bypass do not apply to selected DNS.
Explicit `hijack` additionally ignores source CIDR/MAC selection, exact host addresses,
private-address bypass, and `bypass_rule_set` for port 53. Protocol selection,
DHCP safety, packet validity, and `shared.ipv6: false` remain
higher-priority correctness gates in every mode. Only TCP and/or UDP enabled by
`network` are considered; shared DNS interception no longer requires UDP when
only TCP is enabled. This setting does not identify DoH or DoT and is not the
same as the `hijack-dns` routing action.

#### shared.interface

==Required in shared or hybrid mode==

Downstream interfaces where client packets enter TC ingress. Interfaces may
appear or disappear after startup; sing-box attaches and detaches automatically.
Shared-network eBPF programs and maps are loaded only when a configured
interface first becomes available, then kept loaded across temporary interface
loss to avoid repeated verifier and map setup work.
Do not select `lo`, an upstream interface, or a layer-3-only interface. When a
hotspot and Wi-Fi upstream share an interface name, restrict clients with
source CIDR or MAC policy.

#### shared.ipv6

Enable IPv6 interception on selected downstream interfaces. Default is `true`.
`false` does not block IPv6: when the system can forward IPv6, that traffic
bypasses sing-box. The value is static for the lifetime of the inbound. Shared
mode does not infer downstream IPv6 availability or proxy reachability from the
host's default IPv6 route.

Shared interception is best effort for fragmented traffic. On ingress, every
real IPv4 fragment, including a first fragment with the More Fragments bit, and
every non-atomic IPv6 fragment bypasses unchanged so one datagram cannot be
split between proxy and direct paths. On egress, a real fragment whose source
is in sing-box's internal token prefix is dropped instead of leaking that token
address onto the downstream network. An IPv6 atomic fragment is not a
fragmented datagram and is parsed normally.

#### shared.bypass_private_address

Bypass built-in private, carrier-grade NAT, and link-local destinations on the
shared data path. Default is `true` and is independent from
`local.bypass_private_address`. Setting it to `false` still preserves safety
bypass for ordinary non-DNS traffic to IPv4 unspecified (`0.0.0.0/8`), the
complete IPv4 loopback range (`127.0.0.0/8`), IPv6 unspecified and loopback,
IPv4/IPv6 multicast destinations, and exact host addresses. As documented
under `shared.dns_mode`, `hijack` handles port 53 before all destination
bypasses.

#### shared.include_source_cidr

Client source CIDRs allowed into the proxy path. Non-matching traffic bypasses
when the list is non-empty.

#### shared.exclude_source_cidr

Client source CIDRs to bypass. Exclude takes precedence over include.

#### shared.include_mac_address

48-bit client source MAC addresses allowed into the proxy path.

#### shared.exclude_mac_address

Client source MAC addresses to bypass. Exclude takes precedence over include.

#### shared.advanced.tc_priority

TC filter priority in the range 1 through 65535. Default is `1`. Change it only
to coordinate with OpenWrt, Android tethering, or existing TC programs. An
interface can be managed by only one eBPF inbound, regardless of priority.
With the default priority, sing-box uses TCX when the kernel supports it and
falls back to clsact automatically. A non-default priority selects clsact so
that the requested ordering remains meaningful.

### Kernel compatibility

See the [eBPF inbound kernel requirements](/manual/misc/ebpf-kernel-requirements/)
for the complete Kconfig, runtime, and Linux/OpenWrt package checklist.

Linux 4.19 is the minimum compatibility target for shared mode and TCP-only
local mode. Local UDP also requires the cgroup UDP4/UDP6 recvmsg hooks added by
upstream Linux 5.2, so the default TCP+UDP local or hybrid configuration needs
Linux 5.2 or a vendor backport. Android GKI 5.10+ remains the primary Android
validation target.

The programs use BPF ISA v1 and do not require BTF or CO-RE. sing-box probes
the required map, program, helper, and attachment capabilities instead of
selecting paths only by kernel version. Newer attachment and batch-operation
paths fall back automatically when unavailable. The startup log reports the
selected local UDP cleanup path as `udp_state_cleanup=socket_release` or
`udp_state_cleanup=lru_fallback`. Shared mode always uses TC destination-token
rewrite on ingress and source restoration on egress.

The Linux 6.6 LPM-trie warning at the top of this page still applies even when
the capability probe succeeds.

### Diagnostics

Run the non-disruptive pure-Go probe as root with the same mode and protocols:

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
sing-box tools ebpf status --mode all --interface br-lan --json
```

The command creates and closes transient probe objects. It does not attach
programs or change cgroups, qdiscs, routes, sysctls, or traffic. `--json`
produces a report suitable for an issue attachment.

Normal builds report the selected cleanup and attachment modes in startup
logs, without walking maps or enabling global kernel statistics. Temporary
builds with the `ebpf_debug` tag emit detailed startup, policy, and cleanup
logs, plus event-driven snapshots containing map occupancy and per-program
kernel runtime statistics when supported. Use the
[eBPF troubleshooting guide](/manual/misc/ebpf-troubleshooting/) when collecting
a report; `ebpf_debug` is not intended for normal release builds.
