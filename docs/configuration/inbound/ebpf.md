---
icon: material/lan-connect
---

# eBPF

!!! quote "Changes in sing-box 1.14.0"

    eBPF inbound is experimental and only available in Linux and Android builds
    with the `with_ebpf` build tag.

The eBPF inbound transparently intercepts selected local or downstream TCP and
UDP traffic. Intercepted connections enter the normal sing-box routing pipeline.
Required system network state is installed and removed automatically.

The eBPF inbound does not use [Listen Fields](/configuration/shared/listen/).

### Structure

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "mode": "hybrid",
  "network": ["tcp", "udp"],
  "udp_timeout": "5m",
  "tc_priority": 1,
  "bypass_rule_set": [],
  "local": {
    "dns_mode": "respect_policy",
    "ipv6": true,
    "bypass_private_address": true,
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": [],
    "bypass_port": [],
    "bypass_port_range": []
  },
  "shared": {
    "dns_mode": "respect_policy",
    "interface": ["wlan1"],
    "ipv6": true,
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "bypass_port": [],
    "bypass_port_range": []
  }
}
```

### Fields

#### mode

| Value | Behavior |
| --- | --- |
| `local` | Intercept traffic generated on this host. |
| `shared` | Intercept traffic arriving on configured downstream interfaces. |
| `hybrid` | Enable both paths. |

Default is `local`. `local` fields require local or hybrid mode; `shared` fields
require shared or hybrid mode.

#### network

Enabled transport protocols, `tcp` and/or `udp`. Both are enabled by default.

#### udp_timeout

UDP session timeout. Default is `5m`.

#### tc_priority

TC filter priority in the range 1 through 65535. Default is `1`. Change it only
when coordinating with other TC filters on the same interfaces.
When left at the default, TCX links are used when supported; a custom priority
keeps the traditional `clsact` attachment so its numeric ordering remains effective.

#### bypass_rule_set

Traffic to destination IP CIDRs contained in these rule sets bypasses this
inbound. Non-IP rules are ignored.

### local

Local interception follows the current system default network interface. It
automatically moves when the default network changes. During a short handoff,
the previous attachment remains active until the replacement is ready.

#### local.dns_mode

| Value | Behavior |
| --- | --- |
| `hijack` | Intercept enabled TCP/UDP traffic to destination port 53. |
| `respect_policy` | Apply local UID and package selection before intercepting destination port 53. |
| `off` | Do not intercept destination port 53. |

Default is `respect_policy`. This setting applies only to enabled TCP/UDP
protocols and does not identify DoH or DoT traffic.

#### local.ipv6

Enable local IPv6 interception. Default is `true`. When disabled, local IPv6
traffic bypasses this inbound.

#### local.bypass_private_address

Bypass private and special-use destinations. Default is `true`.

#### local.include_uid

UIDs to intercept. Once an include UID, range, or package is configured, other
UIDs bypass by default.

#### local.include_uid_range

UID ranges to intercept, in `start:end` format.

#### local.exclude_uid

UIDs to bypass. Exclude policy takes precedence over include policy.

#### local.exclude_uid_range

UID ranges to bypass, in `start:end` format.

#### local.include_android_user

Android user IDs to intercept. Android only.

#### local.include_package

Android package names to intercept. Android only.

#### local.exclude_package

Android package names to bypass. Android only. Packages sharing one UID cannot
be distinguished.

#### local.bypass_port

Destination ports to bypass local interception. TCP and UDP are covered when
enabled by `network`. FakeIP and DNS interception take precedence.

#### local.bypass_port_range

Destination port ranges to bypass, in `start:end` format. The range is
inclusive.

### shared

#### shared.dns_mode

Uses the same values as `local.dns_mode`. In `respect_policy` mode, source CIDR
and MAC selection is applied before destination port 53 is intercepted.

#### shared.interface

==Required in shared or hybrid mode==

Downstream interfaces where client traffic enters the host. Ethernet/IPoE,
raw-IP (including Android rmnet), and PPP/PPPoE interfaces are supported.
Multiple interfaces may be specified; interfaces that are temporarily absent
are retried after network updates. An interface is temporarily excluded from
shared interception while it is the current default upstream, then restored
when it becomes downstream again. Loopback is not accepted.

#### shared.ipv6

Enable shared IPv6 interception. Default is `true`. When disabled, IPv6 traffic
on shared interfaces bypasses this inbound.

#### shared.bypass_private_address

Bypass private and special-use destinations. Default is `true`.

#### shared.include_source_cidr

Client source CIDRs to intercept. When non-empty, non-matching sources bypass.

#### shared.exclude_source_cidr

Client source CIDRs to bypass. Exclude policy takes precedence over include
policy.

#### shared.include_mac_address

48-bit client source MAC addresses to intercept.

This option is available only on Ethernet-framed shared interfaces.

#### shared.exclude_mac_address

48-bit client source MAC addresses to bypass. Exclude policy takes precedence
over include policy.

This option is available only on Ethernet-framed shared interfaces.

#### shared.bypass_port

Destination ports to bypass shared interception. TCP and UDP are covered when
enabled by `network`. FakeIP and DNS interception take precedence.

#### shared.bypass_port_range

Destination port ranges to bypass, in `start:end` format. The range is
inclusive.

!!! note

    Shared mode does not enable IP forwarding or provide NAT, DHCP, IPv6 router
    advertisements, or hotspot management. Configure these functions in Android,
    Linux, or the router operating system. Multiple downstream interfaces may be
    configured for Wi-Fi, USB tethering, and similar links.

### Limitations

- Fragmented IPv4 and IPv6 datagrams bypass interception. IPv6 atomic fragments
  are processed as ordinary IPv6 packets.
- Interception state is restored automatically after network changes.

See [eBPF kernel requirements](/manual/misc/ebpf-kernel-requirements/) before
enabling this inbound on vendor or Android kernels.
