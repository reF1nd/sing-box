---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

The eBPF inbound transparently intercepts local TCP and UDP traffic through
cgroup programs. The optional `shared_network` mode intercepts forwarded
traffic from a hotspot or another downstream network through TC.

It is available on Android and Linux builds compiled with cgo and the
`with_ebpf` build tag. Root or equivalent BPF and network-administration
permissions are required.

### Structure

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",

  "network": "",
  "udp_timeout": "5m",
  "dns_mode": "hijack",
  "cgroup_enabled": true,
  "cgroup_path": "",
  "cgroup_ipv6_mode": "always",
  "redirect_address": [
    "127.128.0.0/9",
    "fd53:696e:672d:626f::/64"
  ],
  "bypass_private_address": true,
  "bypass_rule_set": [
    "geoip-cn"
  ],
  "include_uid": [],
  "include_uid_range": [],
  "exclude_uid": [],
  "exclude_uid_range": [],
  "include_android_user": [],
  "include_package": [],
  "exclude_package": [],
  "map_capacity": {
    "tcp_redirect": 65536,
    "udp_redirect": 65536,
    "socket_bypass": 65536
  },
  "shared_network": {
    "enabled": false,
    "include_interface": [],
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "tc_priority": 1,
    "map_capacity": {
      "proxy": 65536,
      "bypass": 65536,
      "fragment": 65536
    }
  }
}
```

The eBPF inbound does not use [Listen Fields](/configuration/shared/listen/).
Its internal redirect listeners use system-selected ports and are not public
proxy listeners.

### Fields

#### network

Enabled network protocols, one of `tcp` `udp`.

Both are enabled if empty. Disabled protocols bypass this inbound.

#### udp_timeout

UDP NAT session timeout.

Default is `5m`.

#### dns_mode

DNS interception mode. One of:

| Value | Behavior |
|-------|----------|
| `hijack` | Intercept TCP and UDP destination port 53 before destination CIDR bypass. |
| `off` | Leave TCP and UDP destination port 53 on the normal kernel path. |

Default is `hijack`.

The mode applies to both local cgroup traffic and `shared_network`. Keep
`hijack` for a hotspot unless the host provides an independent DNS service.
It captures port 53 traffic but does not replace the `hijack-dns` route action.

DHCP, self-protection, protocol selection, UID policy, and shared-network
client selection are evaluated before DNS interception.

#### cgroup_enabled

Enable interception of locally generated traffic.

Default is `true`.

When disabled, `shared_network.enabled` must be enabled. The cgroup-specific
fields are then unavailable. This permits a Linux or OpenWrt gateway to run
only the TC shared-network path.

#### cgroup_path

Absolute cgroup v2 path to intercept.

If empty, sing-box uses the root of the detected cgroup v2 hierarchy.

#### cgroup_ipv6_mode

Local native IPv6 interception mode. One of:

| Value | Behavior |
|-------|----------|
| `always` | Intercept IPv6 when an IPv6 `redirect_address` is configured. |
| `auto` | Intercept new IPv6 flows only while the current network has a usable IPv6 route. |
| `off` | Do not intercept native IPv6. |

Default is `always`.

IPv4 and IPv4-mapped IPv6 sockets are unaffected. This field does not control
`shared_network` IPv6.

#### redirect_address

Internal token prefixes used by the redirect listeners.

At most one prefix per address family may be configured. IPv4 prefixes must
be within `127.0.0.0/8` with a prefix length from `/8` to `/10`. IPv6 prefixes
must be a ULA `/64`.

Default is `127.128.0.0/9`, which enables IPv4 only. Configure an IPv6 prefix
to enable IPv6 interception. These prefixes are internal token pools, not
addresses for a TUN interface.

sing-box creates the required local routes and removes only routes created by
this inbound.

#### bypass_private_address

Bypass built-in private and special-use destination ranges before sing-box
routing.

Default is `true`. Set to `false` when traffic to private, carrier-grade NAT,
link-local, loopback, multicast, or other non-public addresses should enter
sing-box routing. This applies to both local cgroup traffic and
`shared_network` traffic.

#### bypass_rule_set

List of rule-sets whose destination IP CIDRs bypass the eBPF inbound.

Only destination IP CIDR data is extracted. Domains, ports, processes,
logical conditions, and other rule conditions are ignored. Use CIDR-only
rule-sets for this field.

Matching traffic stays in the kernel and does not enter sing-box routing. The
maps are refreshed when a referenced rule-set is updated. Existing flows keep
their current proxy or bypass decision until they expire.

#### include_uid

List of process UIDs to intercept.

If an include UID or UID range is configured, unmatched UIDs bypass the
inbound.

#### include_uid_range

List of process UID ranges to intercept, in `start:end` format.

#### exclude_uid

List of process UIDs to bypass.

Exclude rules take priority over include rules. On Android, UID `1052`
(`dns_tether`) is always excluded to protect the platform tethering DNS path.

#### exclude_uid_range

List of process UID ranges to bypass, in `start:end` format.

#### include_android_user

List of Android user IDs whose application traffic may be intercepted.

Only available on Android with `cgroup_enabled` enabled.

#### include_package

List of Android package names to intercept.

Package UIDs are merged with `include_uid` and `include_uid_range`.

#### exclude_package

List of Android package names to bypass.

Package UIDs are merged with `exclude_uid` and `exclude_uid_range`. Exclude
rules take priority.

Package names are resolved once at startup. A missing package is reported as a
warning; an unavailable package manager prevents startup. Restart sing-box
after installing, removing, or reinstalling a configured package. Packages
that share an Android UID cannot be distinguished by eBPF.

#### map_capacity

Kernel map capacities for the local cgroup path.

| Field | Purpose |
|-------|---------|
| `tcp_redirect` | TCP original-destination state. |
| `udp_redirect` | UDP redirect and flow state. |
| `socket_bypass` | Self-protection state used by the socket-cookie fallback. |

Each field defaults to `65536` and accepts values from `1` through `1048576`.
Larger values support more concurrent state but consume more locked kernel
memory.

On supported kernels, sing-box uses a TGID self-bypass fast path and does not
create the socket-cookie map. If the kernel rejects that path, sing-box
automatically loads the socket-cookie fallback. The selected mode is shown as
`self_bypass=tgid` or `self_bypass=socket_cookie` in the startup log.

### Shared network fields

#### shared_network.enabled

Enable interception of forwarded traffic from selected downstream interfaces.

Default is `false`. When disabled, all other `shared_network` fields are
ignored.

This option does not create a hotspot, bridge, DHCP server, NAT, IPv6 router
advertisements, or IP forwarding. Those services remain the responsibility of
Android, Linux, or OpenWrt.

#### shared_network.include_interface

==Required if `shared_network.enabled`==

List of downstream interfaces where client frames enter TC ingress.

Interfaces may be absent when sing-box starts. They are attached when they
appear and detached when they disappear. Do not select `lo`, an upstream
interface, or a layer-3-only interface.

On devices that use the same interface name for Wi-Fi client and hotspot
traffic, use `include_source_cidr` to select the hotspot client subnet.

#### shared_network.include_source_cidr

List of client source CIDRs allowed to enter the shared-network proxy path.

When non-empty, unmatched clients bypass the inbound. If only one address
family is listed, the other address family is not intercepted.

#### shared_network.exclude_source_cidr

List of client source CIDRs to bypass.

Exclude rules take priority over include rules.

#### shared_network.include_mac_address

List of client source MAC addresses allowed to enter the shared-network proxy
path. When non-empty, unmatched clients bypass the inbound.

The address is read from the TC Ethernet header and is passed to
`source_mac_address` route and DNS rules.

#### shared_network.exclude_mac_address

List of client source MAC addresses to bypass.

Exclude rules take priority over include rules. MAC addresses can be
randomized or spoofed and must not be used as authentication.

#### shared_network.tc_priority

TC filter priority used on ingress and egress.

Default is `1`. Keep the default on Android so sing-box runs before Android
tethering offload filters. Linux and OpenWrt may choose another value from `1`
through `65535` to fit existing TC filters.

#### shared_network.map_capacity

Kernel map capacities for the shared-network path.

| Field | Purpose |
|-------|---------|
| `proxy` | Proxied-flow token, listener, and reply state. |
| `bypass` | Cached bypass-flow decisions. |
| `fragment` | IPv4 and IPv6 fragment association state. |

Each field defaults to `65536` and accepts values from `1` through `1048576`.

### Shared network behavior

The shared-network policy for a new flow is evaluated in this order:

1. Source MAC exclude/include policy.
2. Source CIDR exclude/include policy.
3. DHCP bypass.
4. `dns_mode`.
5. Addresses assigned to the host.
6. Built-in private and special-use destination ranges, when `bypass_private_address` is enabled.
7. `bypass_rule_set` destination CIDRs.

DHCP ports 67, 68, 546, and 547 always bypass interception. Selected TCP and
UDP traffic is rewritten to an internal token address, and replies are restored
by TC egress. The downstream source IP and source MAC are preserved in route
metadata.

IPv4 shared-network mode temporarily enables `route_localnet` on attached
interfaces. IPv6 requires an IPv6 `/64` in `redirect_address`.

IPv4 and IPv6 fragments for selected TCP and UDP flows are associated with the
first fragment and transparently rewritten in both directions. Later fragments
that arrive before the first fragment, or after the 30-second fragment state
expires, are dropped to prevent a direct-path policy bypass.

The selected interface must expose Ethernet-like frames to TC. XDP, hardware
flow offload, or vendor tethering offload that bypasses TC cannot be
intercepted.

### Kernel requirements

Use the included capability probe before deployment:

```sh
sing-box tools ebpf status --mode local
sing-box tools ebpf status --mode shared-network --interface br-lan
```

The standalone script is also available at `common/ebpf/check-kernel.sh`.

| Data path | Required capabilities |
|-----------|-----------------------|
| All | BPF syscall, required map types, sufficient locked memory, and BPF/network-administration privileges. |
| Local cgroup | cgroup v2, `CONFIG_CGROUP_BPF`, and the enabled connect/sendmsg/recvmsg attach types. |
| `shared_network` | `sched_cls`, `clsact`, writable packet and checksum helpers, and TC administration. |

`BPF_CGROUP_INET_SOCK_RELEASE` is optional. Older kernels use a bounded LRU
compatibility mode for UDP state. TGID self-bypass and map lookup-and-delete
are optional performance optimizations. Batch map operations accelerate large
UID and CIDR policy updates when supported; older kernels use individual map
operations. `CONFIG_BPF_JIT` is strongly recommended.

There is no reliable kernel-version-only check because Android and vendor
kernels frequently backport individual eBPF features. A successful program
load on the target kernel is the final compatibility test.

### OpenWrt

OpenWrt can run both data paths, or only `shared_network` with
`cgroup_enabled: false`.

The shared-network path commonly requires `kmod-sched-core` and
`kmod-sched-bpf`, although package names vary by release. Hardware flow
offload may need to be disabled if it bypasses the selected TC hook. Use an
OpenWrt SDK/toolchain matching the target architecture and libc.

The target does not require Clang, `tc`, `bpftool`, libbpf, or libelf at
runtime. `tc` and `bpftool` are useful only for diagnostics.

### Build

Enable cgo and append `with_ebpf` to the normal build tags:

```sh
CGO_ENABLED=1 \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

For Android, set `GOOS`, `GOARCH`, and an Android NDK compiler. The build host
must provide a Clang with the BPF target and Linux UAPI headers. The generated
BPF objects are embedded in the binary and are not committed to Git.

### Credits

Thanks to [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
for the original eBPF interception implementation on which this inbound is
based.
