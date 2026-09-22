---
icon: material/memory
---

# eBPF

!!! quote "Changes in sing-box 1.15.0"

    The eBPF inbound is experimental. It is available only in Linux and Android
    builds compiled with `with_ebpf`.

The eBPF inbound transparently sends selected local or downstream TCP/UDP
traffic into the normal sing-box routing pipeline. It creates and removes its
own kernel network state and does not use [Listen Fields](/configuration/shared/listen/).

## Example

Local interception with the default cgroup data plane:

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "network": ["tcp", "udp"],
  "local": {
    "enabled": true,
    "data_plane": "cgroup",
    "dns_mode": "respect_policy",
    "bypass_private_address": true
  }
}
```

To intercept downstream clients as well, add a shared path and replace the
interface name:

```json
{
  "shared": {
    "enabled": true,
    "data_plane": "packet_rewrite",
    "interface": ["wlan1"],
    "dns_mode": "respect_policy",
    "bypass_private_address": true
  }
}
```

## Data planes

| Path | Data plane | Use |
| --- | --- | --- |
| local | `cgroup` (default) | Intercepts this host's sockets in a cgroup v2 hierarchy without following an interface. |
| local | `tc` | Intercepts this host's packets on the current default interface. |
| shared | `packet_rewrite` (default) | Rewrites packets on Ethernet-framed downstream interfaces and restores replies. |
| shared | `socket_assign` | Assigns packets to transparent listeners; also supports raw-IP, PPP and tunnel links. |

Use the defaults unless the target kernel or link type requires another path.
See [eBPF kernel requirements](/manual/misc/ebpf-kernel-requirements/) for the
exact capability and interface differences.

## Fields

### network

Enabled transport protocols: `tcp`, `udp`, or both. Both are enabled by default.

### udp_timeout

UDP session timeout. Default is `5m`.

### tc_priority

TC filter priority from 1 through 65535. Default is `1`. Change it only when
coordinating with other filters. The default permits TCX when supported; a
custom priority uses `clsact` so numeric ordering remains meaningful.

### bypass_rule_set

Compatibility shorthand for applying the same destination IP rule sets to both
enabled paths. `local.bypass_rule_set` and `shared.bypass_rule_set` are still
independent and are added to this common list for their respective path.
Duplicate rule-set tags are ignored.

### fakeip_icmp

| Value | Behavior |
| --- | --- |
| `off` | Do not answer ICMP Echo Requests to FakeIP addresses. Default. |
| `reply` | Synthesize a local Echo Reply for safe, unfragmented requests to a configured FakeIP prefix. |

The reply only proves that this host answered; it does not measure the mapped
destination. Local `cgroup` has no packet hook and cannot answer local ICMP.
Local `tc` and either shared data plane can answer traffic on their own paths.

## local

### local.enabled

Enables interception of traffic generated on this host. If neither local nor
shared has an explicit `enabled` field, local is enabled and shared is disabled.
Once either field is explicit, omitted paths are disabled.

### local.data_plane

`cgroup` (default) or `tc`. The TC path follows the current default interface;
the cgroup path follows the selected cgroup v2 subtree.

### local.cgroup_path

Absolute cgroup v2 subtree used by the `cgroup` data plane. When omitted, the
visible cgroup v2 root and its descendants are intercepted.

On Android, a vendor netd cgroup hook can conflict with attachment. sing-box
prefers multi-program attachment and falls back to legacy exclusive attachment
only for compatible errors. Use local `tc` if the device cannot safely share
the root cgroup hook.

### local.dns_mode

| Value | Behavior for destination port 53 |
| --- | --- |
| `hijack` | Intercept before UID/package selection. |
| `respect_policy` | Apply UID/package selection first, then intercept. Default. |
| `off` | Bypass. |

This option applies only to enabled TCP/UDP traffic; it does not detect DoH or DoT.

### local.ipv6

Enables local IPv6 interception. Default is `true`.

### local.bypass_private_address

Bypasses private and special-use destinations. Default is `true`.

### local.bypass_rule_set

Rule sets whose destination IP CIDRs bypass the local data plane. Non-IP rules
are ignored. This policy is independent from `shared.bypass_rule_set` and is
updated transactionally across the active local backends.

### local.include_uid

UIDs to intercept. Any include UID, range, or package makes unmatched UIDs
bypass by default.

### local.include_uid_range

UID ranges to intercept, in inclusive `start:end` form.

### local.exclude_uid

UIDs to bypass. Exclude policy takes precedence over include policy.

### local.exclude_uid_range

UID ranges to bypass, in inclusive `start:end` form.

### local.include_android_user

Android user IDs to intercept. Android only.

### local.include_package

Android packages whose resolved UIDs are intercepted. Android only.

### local.exclude_package

Android packages whose resolved UIDs bypass interception. Android only. Shared
UID packages and work delegated to another system UID cannot be distinguished
by the originating package name.

### local.bypass_port

Destination ports to bypass. FakeIP force interception and DNS mode take
precedence; configuring port 53 therefore emits a warning.

### local.bypass_port_range

Destination port ranges to bypass, in inclusive `start:end` form.

## shared

### shared.enabled

Enables interception of traffic arriving from configured downstream interfaces.

### shared.data_plane

`packet_rewrite` (default) or `socket_assign`. `packet_rewrite` requires
Ethernet framing; use `socket_assign` for raw-IP, PPP/PPPoE and supported tunnel
links. Local and shared data planes are selected independently.

### shared.dns_mode

Uses the same values as `local.dns_mode`. `respect_policy` applies source CIDR
and MAC selection before intercepting port 53.

### shared.interface

==Required when shared interception is enabled==

Downstream interfaces where client traffic enters. Multiple names are allowed.
Missing interfaces are retried; an interface is excluded while it is the current
default upstream and restored when it becomes downstream again. Loopback is not
accepted.

### shared.ipv6

Enables shared IPv6 interception. Default is `true`. This does not configure
client addresses, router advertisements, forwarding or upstream IPv6 routing.

### shared.bypass_private_address

Bypasses private and special-use destinations. Default is `true`.

### shared.bypass_rule_set

Rule sets whose destination IP CIDRs bypass the shared data plane. Non-IP rules
are ignored. This policy is independent from `local.bypass_rule_set` and is
updated transactionally across the active shared backends.

### shared.include_source_cidr

Client source CIDRs to intercept. When source CIDR and/or MAC include lists are
configured, a source matching either include list is selected; unmatched
sources bypass.

### shared.exclude_source_cidr

Client source CIDRs to bypass. Exclude policy takes precedence.

### shared.include_mac_address

48-bit source MAC addresses to intercept. Ethernet-framed interfaces only. MAC
and CIDR includes are alternatives (OR), not a combined requirement.

### shared.exclude_mac_address

48-bit source MAC addresses to bypass. Ethernet-framed interfaces only. A
matching CIDR or MAC exclude always wins over every include selector.

### shared.bypass_port

Destination ports to bypass. FakeIP and DNS precedence is the same as local.

### shared.bypass_port_range

Destination port ranges to bypass, in inclusive `start:end` form.

!!! note

    Shared mode does not provide forwarding, NAT, DHCP, IPv6 router
    advertisements, or hotspot management. Configure them in the operating
    system.

## Policy order

Safety and service-traffic bypasses run first. FakeIP prefixes then force
interception. DNS mode and local UID/shared source selection run before port,
private-address, and the path-specific rule-set bypass. The compatibility
top-level rule set is applied to both enabled paths, while path-specific
rule-set policies remain independent. Shared CIDR and MAC includes are OR'ed;
any matching exclude selector takes precedence.

## Diagnostics

- `sing-box tools ebpf status` performs a non-attaching kernel and object-load
  preflight for the selected data planes.
- `sing-box api ebpf` reads attachments, recovery state, active programs, map
  occupancy, resource use, UDP/session statistics, fragment/pass counters, and
  failures from a running instance. For local cgroup it also reports the
  effective attach, UDP cleanup, socket-storage, and time-source modes after
  fallback. It requires the
  [sing-box API service](/configuration/service/api/).

For local TC and shared `socket_assign`, the response also reports the effective
TCX/clsact attachment mode, SOCKMAP/direct listener lookup, delivery interface,
policy-routing values, active/retired resource counts, health/reconcile times,
and a network generation that increments at managed handover boundaries.

The diagnostics response carries a response-level `schemaVersion`, including
when no eBPF inbound is running. Clients should use that value to version the
whole response; the per-inbound copy is retained for older clients.

See [eBPF troubleshooting](/manual/misc/ebpf-troubleshooting/) for commands and
counter interpretation.

## Limitations

- Only one eBPF inbound per sing-box instance may enable local interception;
  additional eBPF inbounds must be shared-only.
- Fragmented IPv4 and non-atomic IPv6 datagrams bypass interception because a
  complete transport tuple is unavailable. IPv6 atomic fragments are processed.
- Network changes trigger attachment and managed-state reconciliation, but the
  operating system remains responsible for upstream connectivity and tethering.
