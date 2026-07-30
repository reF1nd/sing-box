---
icon: material/lan-connect
---

# eBPF

The eBPF inbound intercepts locally generated TCP and UDP traffic with cgroup
socket-address programs. The optional `shared_network` mode uses TC token
rewrites for forwarded traffic from selected downstream interfaces. It does
not use a TUN device, TProxy, iptables, skb marks, policy routing, loopback TC,
socket assignment, or a SOCKS bridge.

This inbound is intended for a rooted Android or Linux native sing-box binary.
It is included only in builds made with the `with_ebpf` build tag and cgo.

## Structure

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",

  ... // Listen Fields

  "network": "",
  "dns_mode": "hijack",
  "cgroup_path": "",
  "redirect_address": [
    "127.128.0.0/9",
    "fd53:696e:672d:626f::/64"
  ],
  "bypass_rule_set": [
    "geoip-cn"
  ],
  "include_uid": [],
  "include_uid_range": [],
  "exclude_uid": [],
  "exclude_uid_range": [],
  "shared_network": {
    "enabled": false,
    "include_interface": []
  }
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for available fields.

The eBPF inbound uses addresses selected from `redirect_address` internally.
Therefore, `listen` may be omitted or set to an unspecified address (`0.0.0.0`
or `::`). The inbound creates an IPv4 and/or IPv6 wildcard listener according
to the address families enabled by `redirect_address`.

`listen_port` defaults to `65532`. A value of `0` also selects this default;
random listener ports are not supported because the redirect port is embedded
in the eBPF programs when they are loaded.

`proxy_protocol` and `proxy_protocol_accept_no_header` are not supported. The
intercepted application connections do not contain Proxy Protocol headers.

`netns` is not supported. The cgroup hooks and redirect routes operate in the
current network namespace and cannot be scoped to a listener network namespace.

`bind_interface` may be omitted or set to `lo`. Other interfaces are not
supported because redirected connections are delivered through the loopback
interface.

The configured `udp_timeout` and `detour` apply to intercepted UDP sessions as
they do for other UDP inbounds.

### Fields

#### network

Listen network, one of `tcp` `udp`.

Both if empty.

Protocols not selected by `network` bypass the eBPF inbound.

`shared_network` with `dns_mode` set to `hijack` requires UDP because hotspot
DNS is proxied when the mode is enabled.

#### dns_mode

DNS handling mode. One of:

| Mode | Behavior |
|------|----------|
| `hijack` | Intercept TCP and UDP destination port 53 before destination-address and `bypass_rule_set` checks. |
| `off` | Always bypass TCP and UDP destination port 53. |

Defaults to `hijack`.

The mode applies only to protocols selected by `network`. Socket protection,
UID include/exclude policy, the Android `dns_tether` exclusion, and DHCP safety
bypasses are evaluated before DNS handling. In `hijack` mode, destination port
53 then takes priority over unspecified, local, private, multicast, and
`bypass_rule_set` destination checks, preventing a DNS server address contained
in a bypass CIDR from leaking queries outside sing-box.

The same mode applies to `shared_network`. Keep the default `hijack` mode for a
hotspot unless the host provides a working DNS service and intentionally sends
hotspot DNS outside sing-box. With `off`, hotspot DNS is not proxied and may
leak or fail if no independent DNS path exists.

#### cgroup_path

Absolute path to the cgroup v2 hierarchy whose locally generated traffic is
intercepted. If empty, sing-box discovers the cgroup2 mount and uses its root.
On standard Linux, place selected services in a dedicated cgroup and configure
that path when system-wide local interception is not desired. This field does
not restrict forwarded traffic selected by `shared_network`.

#### include_uid

List of process UIDs to intercept.

When `include_uid` or `include_uid_range` is non-empty, traffic from UIDs not
matched by either field bypasses the eBPF inbound.

#### include_uid_range

List of process UID ranges to intercept, in `start:end` format.

#### exclude_uid

List of process UIDs to bypass.

Exclude rules take priority over include rules.

On Android, UID `1052` (`dns_tether`) is always excluded so the platform
tethering DNS service and hotspot clients are not redirected by the local
cgroup programs. This exclusion is independent of `shared_network`.

#### exclude_uid_range

List of process UID ranges to bypass, in `start:end` format.

UID rules match the effective UID of the process performing the socket
operation. Ranges are compiled into compressed eBPF LPM trie entries instead
of being expanded into individual UIDs.

#### bypass_rule_set

List of rule-sets whose destination IP CIDR entries bypass the eBPF inbound.

At startup, sing-box calls the existing rule-set CIDR extractor and merges the
result into IPv4 and IPv6 eBPF LPM trie maps. When a destination matches either
map, the cgroup program leaves the original destination unchanged. The
application socket then uses the kernel network stack directly and does not
enter the eBPF listener, sniffing, normal route rules, or an outbound.

This field performs CIDR extraction, not complete rule-set matching. Only
destination `ip_cidr` and binary IP set entries are extracted. Domain, port,
network, process, source, logical grouping, and invert conditions are not
evaluated by the eBPF program. In particular, an `ip_cidr` combined with
another condition is still extracted without that condition. Use CIDR-only
rule-sets for this field.

Multiple referenced rule-sets and all extracted CIDRs are merged as a union.
Normal route rules that select a `direct` outbound are not automatically
offloaded; only rule-sets explicitly listed here enable kernel direct bypass.

When a referenced local or remote rule-set is reloaded, sing-box extracts the
CIDRs again and updates the maps in place without reloading or reattaching the
eBPF programs. If an update cannot be applied, the error is logged and the
previous successfully applied policy is retained.

This bypass applies only to locally generated traffic that reaches the cgroup
socket-address hooks. Forwarded Android hotspot traffic does not pass through
these hooks.

#### redirect_address

Internal address prefixes used to redirect intercepted connections to the
sing-box listener.

One prefix may be configured for each address family. An IPv4 prefix enables
IPv4 interception, an IPv6 prefix enables native IPv6 interception, and
configuring both enables dual-stack interception. IPv4-mapped IPv6 sockets are
treated as IPv4.

If omitted, `127.128.0.0/9` is used and only IPv4 interception is enabled. IPv4
prefixes must be within `127.0.0.0/8` and use a prefix between `/8` and `/10`.
IPv6 prefixes must be within the ULA range `fc00::/7` and use `/64`.

These prefixes are flow-token pools, not interface subnets like the addresses
used by a TUN inbound. Unconnected UDP derives a stable host token from the
original address, port, and protocol, so repeated packets to the same
destination reuse an existing map entry. TCP and connected UDP additionally
mix the socket `SO_COOKIE` into the token, preventing concurrent sockets to the
same destination from sharing lifecycle state.

TCP and UDP use separate redirect maps with 65536 entries each. The maps do not
evict or overwrite entries. A token collision uses up to eight deterministic
probes, and a full map rejects the new flow instead of routing it to another
destination. Large prefixes keep this lookup path close to one probe. The
default uses the less commonly used upper half of the IPv4 loopback range while
retaining 23 bits of token space. The IPv6 example is a sing-box specific ULA
prefix. Before installing the local route, sing-box rejects a prefix that
overlaps a non-loopback interface address or a non-default route in the main
routing table.

Redirect entries are reclaimed according to their actual owners. A TCP entry
is removed immediately after the listener consumes its original destination.
Unconnected UDP entries are reference-counted across sing-box UDP NAT sessions
and removed when the last session closes. Connected UDP stores its redirect
token by socket cookie and removes the redirect, token, and peer-cache entries
from a cgroup socket-release program when the application socket closes. A UDP
socket reconnect also removes the previous connected mapping before installing
the replacement.

sing-box logs eBPF runtime metrics every five minutes when they change and once
when the inbound stops. The metrics include separate TCP and UDP map occupancy, token
collisions, map update failures, rejected redirects, and userspace original
destination lookup misses. Occupancy at or above 75 percent, rejected redirects,
and lookup misses are logged as warnings.

sing-box automatically installs an `RTN_LOCAL` route for each configured
prefix through the loopback interface in the current network namespace. An
existing local route that covers the prefix is reused. On shutdown, sing-box
removes only routes created by this inbound.

Except for destination port 53 in `dns_mode: hijack`, the local cgroup path
always bypasses unspecified, loopback, multicast, and current local-interface
networks. The interface prefixes are refreshed after network changes. UDP ports
67, 68, 546, and 547 also bypass interception. As a result, enabling the eBPF
inbound without `shared_network` does not attach TC, change `route_localnet`,
proxy hotspot clients, or disturb hotspot DHCP/DNS.

Only one eBPF inbound may own a cgroup hierarchy at a time. sing-box holds an
exclusive lock on the configured cgroup directory for the inbound lifetime. Stale
sing-box eBPF programs left by an unclean exit are removed only after this lock
has been acquired, so starting another instance cannot detach a running one.

sing-box registers the `SO_COOKIE` value of each socket it creates in an eBPF
LRU map. The cgroup programs consult this map before redirecting traffic, which
prevents sing-box outbound connections and UDP listeners from being captured
again.

For locally redirected connections, sing-box preserves the socket's source
port and replaces the listener-observed loopback IP with the preferred source
from the route to the original destination using the originating UID. This
keeps `source_ip_cidr` route rules and Clash API metadata meaningful, including
Android UID-based policy routing.
If the route lookup fails, traffic continues with the listener-observed
loopback source instead of rejecting the connection. Explicitly bound
non-loopback source addresses are preserved.

#### shared_network

Optional forwarding proxy for a hotspot or another shared downstream network.
When disabled or omitted, no shared listener, `clsact` qdisc, TC filter, or
sysctl change is created.

This mode is supported on standard Linux as well as Android. On standard
Linux, it acts as a TC transparent proxy for clients behind an existing routed
LAN, access point, or gateway. It does not create the downstream network or
turn the host into a router by itself.

When enabled, `include_interface` must list one or more downstream
Ethernet-like interfaces. Do not select `lo`, an upstream interface, or a
layer-3-only device such as TUN, WireGuard, PPP, or IPIP. An interface may be
configured before it exists. In that state the eBPF inbound starts normally
and waits without enabling the shared data plane. If an attached interface
disappears, sing-box detaches its state and keeps the local eBPF inbound
running; the same interface name is attached again when it reappears. The list
is reconciled after network changes and every three seconds.

Select the interface where client frames actually enter TC ingress. For a
Linux bridge this is commonly each client-facing bridge port, not necessarily
the bridge master; the exact hook path depends on the bridge and driver. This
mode is intended for a routed downstream whose clients use this host as their
gateway, not for an arbitrary transparent layer-2 bridge.

For every present interface, sing-box attaches an egress filter first and an
ingress filter second, then enables the data plane. Ingress replaces the
destination address and port of selected TCP/UDP packets with a per-flow token
and a random sing-box listener port. Egress restores the original source on
replies. The original-destination key includes the client address and port, so
different hotspot clients cannot alias each other's flow state.

DHCP ports 67, 68, 546, and 547 always bypass TC. In `dns_mode: hijack`,
destination port 53 is captured before host, private-network, or
`bypass_rule_set` checks, including DNS queries sent to the hotspot gateway. In
`dns_mode: off`, destination port 53 always keeps its normal forwarding path.
Other host, private, link-local, multicast, and configured bypass CIDRs also
keep their normal forwarding path.

For IPv4, token addresses use the configured loopback redirect prefix.
sing-box temporarily enables `net.ipv4.conf.<interface>.route_localnet` only
when it was disabled, and restores it after both TC filters are detached. An
existing enabled value is left unchanged. IPv6 uses the configured ULA token
prefix and the local route already managed by this inbound. IPv6 interception
is disabled unless `redirect_address` explicitly includes an IPv6 `/64`; the
default redirect configuration is IPv4-only.

The implementation creates or reuses `clsact` but does not remove it on close,
so unrelated filters remain intact. It uses TC priority `1`, ingress handle
`0x5342`, and egress handle `0x5343`. Bypassed traffic returns `TC_ACT_PIPE`,
allowing later filters to run; captured traffic returns `TC_ACT_OK`. A filter
with a numerically lower priority can still act first. sing-box refuses to
replace a different filter using one of its handles.

Priority `1` places sing-box before Android's AOSP tethering TC offload
(IPv6 priority `2`, IPv4 priority `3`). This is required because Android can
install IPv6 `/128` forwarding entries before the first connection and redirect
public IPv6 traffic before a later filter sees it. DNS sent to the hotspot
gateway is not such forwarded traffic, so observing only IPv6 DNS in sing-box
usually indicates that an earlier tethering offload path is taking the public
IPv6 packets.

The host remains responsible for hotspot or bridge creation, IP forwarding,
IPv4 NAT, IPv6 router advertisements and neighbor discovery, DHCP, and the DNS
service used while `shared_network` is disabled. XDP or hardware tethering
offload that bypasses Linux TC cannot be proxied; verify the actual downstream
interface and both directions on each Android kernel. On standard Linux, also
verify the chosen bridge-port hook and any pre-existing priority `1` TC filter.

## Build

Use the existing `make build` target with cgo enabled and append `with_ebpf` to
the build tags you normally use. For example, to retain the standard sing-box
build tags on Linux:

```sh
CGO_ENABLED=1 \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

For Android, provide the target architecture and an Android NDK compiler while
using the same `make build` target:

```sh
CGO_ENABLED=1 \
GOOS=android \
GOARCH=arm64 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang" \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

When `TAGS` contains `with_ebpf`, `make build` first compiles the TC program
with `-target bpfel`. This requires a BPF-capable Clang and Linux UAPI headers;
the generated object is ignored by Git and is not part of the source tree.

The device kernel must provide cgroup2 and the cgroup attach types required by
the configured address families and `network`: connect4/connect6 and, for UDP,
UDP4/UDP6 sendmsg and recvmsg plus `BPF_CGROUP_INET_SOCK_RELEASE`. The process
needs permission to create and attach BPF maps/programs and to manage local
routes. `shared_network` additionally requires sched_cls TC, `clsact`, writable
per-interface `route_localnet` for IPv4, and `CAP_NET_ADMIN`.

## Credits

Thanks to [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
for the original eBPF interception implementation on which this inbound is
based.
