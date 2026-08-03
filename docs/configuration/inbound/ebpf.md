---
icon: material/lan-connect
---

The eBPF inbound intercepts locally generated TCP and UDP traffic with cgroup
socket-address programs. The optional `shared_network` mode uses TC token
rewrites for forwarded traffic from selected downstream interfaces. It does
not use a TUN device, TProxy, iptables, skb marks, policy routing, loopback TC,
socket assignment, or a SOCKS bridge.

This inbound is intended for a native sing-box binary running as root on
Android or Linux. The build must enable cgo and the `with_ebpf` build tag.

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
  "map_capacity": {
    "tcp_redirect": 65536,
    "udp_redirect": 65536,
    "socket_bypass": 65536
  },
  "shared_network": {
    "enabled": false,
    "include_interface": [],
    "map_capacity": 65536
  }
}
```

The eBPF inbound does not expose [Listen Fields](/configuration/shared/listen/).
It opens separate internal wildcard listeners for the local cgroup and
`shared_network` data paths, each on a system-selected random port. These
listeners are redirect endpoints rather than public proxy servers; their ports
are reported in the startup log and cannot be configured.

### Fields

#### network

Listen network, one of `tcp` `udp`.

Both if empty.

Protocols not selected by `network` bypass the eBPF inbound.

`shared_network` with `dns_mode` set to `hijack` requires UDP because hotspot
DNS is proxied when the mode is enabled.

#### udp_timeout

UDP NAT session timeout for intercepted local and `shared_network` traffic.

Default is `5m`.

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
in a bypass CIDR from bypassing sing-box.

The same mode applies to `shared_network`. Keep the default `hijack` mode for a
hotspot unless the host provides a working DNS service and intentionally sends
hotspot DNS outside sing-box. With `off`, hotspot DNS is not proxied and may
leak or fail if no independent DNS path exists.

For data-path details, performance boundaries, and comparisons with dae, TUN,
Redirect, and TProxy, see the
[eBPF inbound comparison](/manual/misc/ebpf-inbound-comparison/).

#### cgroup_enabled

Enable interception of locally generated traffic through cgroup programs.

Defaults to `true`. When disabled, `shared_network.enabled` must be enabled and
sing-box does not discover cgroup2, load or attach cgroup programs, open the
local redirect listeners, or register a socket protector. This allows a Linux
gateway without cgroup support to run only the TC shared-network data path.

`cgroup_path`, UID policy fields, and the top-level `map_capacity` are rejected
when this option is disabled. `bypass_rule_set` remains available and is loaded
into bypass maps owned by the standalone shared-network backend.

#### cgroup_path

Absolute path to the cgroup v2 hierarchy whose locally generated traffic is
intercepted. If empty, sing-box discovers the cgroup2 mount and uses its root.
On standard Linux, place selected services in a dedicated cgroup and configure
that path when system-wide local interception is not desired. This field does
not restrict forwarded traffic selected by `shared_network`.

#### map_capacity

Kernel map capacities for locally generated traffic. `tcp_redirect` controls
TCP redirect state. `udp_redirect` controls the UDP redirect, connected-token,
peer, and optional unconnected-flow maps together. `socket_bypass` controls
protected outbound socket cookies.

Each field defaults to `65536` and accepts `1` through `1048576`. Larger maps
support more concurrent state but consume more locked kernel memory. Changes
take effect when the inbound is restarted. Setting redirect maps too small can
reject new flows; an undersized `socket_bypass` map can evict protected sockets
and cause self-interception.

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

The same extracted CIDRs are used by `shared_network`. With cgroup interception
enabled, TC programs reuse the cgroup bypass maps; with `cgroup_enabled: false`,
the standalone shared-network backend creates and maintains equivalent maps.
A matching forwarded packet keeps its normal kernel forwarding path instead of
entering the shared redirect listener.

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
destination reuse an existing map entry. TCP, connected UDP, and unconnected
UDP on kernels that support the flow cache additionally mix the socket
`SO_COOKIE` into the token, preventing concurrent sockets to the same
destination from sharing lifecycle state.

TCP and UDP use separate redirect maps whose capacities are configured by
`map_capacity`. On kernels with cgroup socket-release support, the maps do not
evict or overwrite entries. A token collision uses up to four deterministic
probes, and a full map rejects the new flow instead of routing it to another
destination. Large prefixes keep this lookup path close to one probe. The
default uses the less commonly used upper half of the IPv4 loopback range
while retaining 23 bits of token space. The IPv6 example is a sing-box-specific
ULA prefix. Before installing the local route, sing-box rejects a prefix that
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

On kernels with cgroup socket-release support, unconnected UDP also uses an
LRU `(socket cookie, destination)` flow cache. A hit reuses the established
token before evaluating the CIDR bypass policy, so an active proxied flow keeps
its decision across a rule-set reload. The cache and redirect entry are removed
together when the sing-box UDP NAT session reaches `udp_timeout`; the next
packet then evaluates the current policy.

On an older kernel without cgroup socket-release support, sing-box detects and
skips that optional program at startup. The UDP redirect and socket-token maps
then use an LRU compatibility mode so stale connected-UDP entries cannot
permanently exhaust the maps. This mode emits one warning; under heavy map
pressure it may evict an active UDP entry early. A TCP-only configuration does
not probe or require socket-release. The unconnected UDP flow cache is disabled
in compatibility mode because independent LRU eviction could leave a cached
token without its redirect entry.

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
exclusive lock on the configured cgroup directory for the inbound lifetime.
Stale sing-box eBPF programs left by an unclean exit are removed only after
this lock has been acquired, so starting another instance cannot detach a
running one.

On supported kernels, connect and sendmsg programs first compare the current
TGID with the sing-box process and immediately bypass matching sockets. The
socket-cookie mechanism remains active for protected sockets owned by another
TGID. If the kernel verifier rejects the TGID helper for any required cgroup
attach type, sing-box automatically reloads the original cookie-only program
set. The startup message reports `self_bypass=tgid` or
`self_bypass=socket_cookie` according to the loaded path.

For the cookie path, sing-box registers the `SO_COOKIE` value of each socket it
creates in an eBPF LRU map. The cgroup programs consult this map before
redirecting traffic, which prevents sing-box outbound connections and UDP
listeners from being captured again. Recvmsg programs continue to use the
normal restoration path and do not apply TGID bypass.

For locally redirected connections, sing-box preserves the socket's source
port and replaces the listener-observed loopback IP with the preferred source
from the route to the original destination using the originating UID. This
keeps `source_ip_cidr` route rules and Clash API metadata meaningful, including
with Android UID-based policy routing. If the route lookup fails, traffic
continues with the listener-observed loopback source instead of rejecting the
connection. Explicitly bound non-loopback source addresses are preserved.

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
running; the same interface name is attached again when it reappears. sing-box
uses its network update monitor to reconcile the list immediately. A
three-second fallback is used only when the platform does not provide that
monitor.

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
different hotspot clients cannot alias each other's flow state. TCP flow state
is released when the routed connection closes. UDP flow state is
reference-counted by client and token, then released when its NAT session
closes. Each release removes the original-to-token, reply-translation, and
listener-lookup entries together.

An additional LRU map keeps CIDR bypass decisions stable across rule-set
reloads. A bypassed TCP flow keeps its decision until the same tuple starts a
new connection with a different SYN sequence, or until its inactive entry is
evicted under map pressure. A bypassed UDP flow refreshes its timestamp on each
packet and is re-evaluated after being idle for `udp_timeout`. Proxied TCP and
UDP flows keep their token decision until their normal connection or NAT
lifetimes end. Consequently, a rule-set reload applies to new flows without
switching an active flow between direct forwarding and proxying.

`shared_network.map_capacity` controls the three shared proxy flow maps and the
LRU bypass-decision map. It defaults to `65536` and accepts `1` through
`1048576`; increasing it raises locked kernel-memory use for all four maps. The
three proxy maps are regular hash maps with explicit flow cleanup, rather than
LRU maps that may silently evict an active proxied flow. If a selected flow
cannot allocate or update all required proxy state, its packets are dropped
instead of falling back to a direct connection.

DHCP ports 67, 68, 546, and 547 always bypass TC. In `dns_mode: hijack`,
destination port 53 is captured before host, private-network, or
`bypass_rule_set` checks, including DNS queries sent to the hotspot gateway. In
`dns_mode: off`, destination port 53 always keeps its normal forwarding path.
Other host, private, link-local, multicast, and configured bypass CIDRs also
keep their normal forwarding path.

Packets that policy explicitly bypasses return `TC_ACT_PIPE` and continue to
later TC filters. Once a packet has been selected for interception, token
allocation, state lookup, and packet rewrite failures are fail-closed. An IPv4
TCP/UDP fragment or truncated transport header selected for interception is
also dropped because it cannot be transparently rewritten without risking a
direct leak. Avoid IPv4 fragmentation on the downstream path by using a
suitable MTU and MSS policy.

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

The eBPF inbound does not emit per-connection Info logs. When the Clash API is
enabled, use its connection view for source, destination, traffic, and rule
metadata. Startup, attachment, cleanup, and error messages remain in the log.
Repeated UDP packet-info, original-destination lookup, and flow-cleanup
warnings are limited independently to one report per ten seconds. A resumed
report includes the number of similar warnings suppressed in the preceding
window.

### Kernel capability probe

The repository provides `common/ebpf/check-kernel.sh`, a non-disruptive
capability probe for Android, standard Linux, and OpenWrt. It does not attach
BPF programs, create qdiscs, change routes or sysctls, or affect traffic. When
`bpftool` is available, the script uses its transient program, map, and helper
probes and removes the temporary objects immediately. Otherwise it falls back
to the running kernel configuration, cgroup mounts, and sysfs state and
reports capabilities that cannot be proven as `UNKNOWN`.

Run the probe as root so that its result reflects the privileges used by
sing-box:

```sh
# Check locally generated traffic interception.
sh common/ebpf/check-kernel.sh --mode local

# Check an OpenWrt/Linux TC-only gateway and its downstream interface.
sh common/ebpf/check-kernel.sh --mode shared-network --interface br-lan

# Check both Android paths. The interface may be absent while the hotspot is off.
su -c 'sh /data/local/tmp/check-kernel.sh --mode all --interface wlan2'
```

Use `--cgroup PATH` when the inbound has an explicit `cgroup_path`. A proven
missing required capability makes the script exit with status `1`. `WARN`
identifies an available compatibility path or an operational issue, while
`UNKNOWN` means that a safe static probe cannot prove the result. In
particular, `bpftool` exposes the `cgroup_sock_addr` program type but cannot
distinguish every connect/sendmsg/recvmsg attach subtype without loading the
actual sing-box programs. A real sing-box startup remains the definitive
verifier and attachment test.

| Data path | Capability | Level | Purpose and behavior when absent |
|-----------|------------|-------|----------------------------------|
| All | Effective BPF/network-administration privileges, `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, and sufficient locked memory | Required | Creates maps/programs and performs the selected attachments. No eBPF data path can start without these basics. |
| All | HASH, LRU HASH, and LPM trie maps | Required | Store redirect/flow state, bounded UDP and self-protection caches, UID policy, local-interface CIDRs, and rule-set CIDRs. |
| All | `CONFIG_BPF_JIT` | Performance | Runs compiled native BPF instead of the interpreter. It is strongly recommended on Android and routers but is not required for correctness. |
| Local cgroup | cgroup v2, `CONFIG_CGROUPS`, `CONFIG_CGROUP_BPF`, and `cgroup_sock_addr` | Required | Selects locally generated traffic and runs the connect/sendmsg/recvmsg redirect programs. |
| Local cgroup | connect4/connect6 and, for UDP, UDP4/UDP6 sendmsg and recvmsg attach types | Required | Redirect TCP/UDP destinations and restore the original UDP peer. The default IPv4 path also handles IPv4-mapped IPv6 sockets and therefore uses IPv6 attach types. |
| Local cgroup | map lookup/update/delete, plus socket-cookie for UDP or the cookie fallback | Required | Evaluates policy, identifies UDP sockets, protects sing-box sockets, and manages redirect state. The UID helper is configuration-dependent on Linux and is required on Android for the automatic `dns_tether` exclusion. |
| Local cgroup | `BPF_CGROUP_INET_SOCK_RELEASE` and `cgroup_sock` | Compatible fallback | Precisely removes connected-UDP state and enables the unconnected-UDP flow cache. Without it, sing-box uses bounded LRU maps and disables that cache. |
| Local cgroup | `bpf_get_current_pid_tgid` for `cgroup_sock_addr` | Performance | Provides a fast TGID self-bypass. Without it, sing-box reloads the programs with socket-cookie self-protection. |
| Local cgroup | `BPF_MAP_LOOKUP_AND_DELETE_ELEM` | Performance | Combines TCP original-destination lookup and deletion. Without it, sing-box uses separate lookup and delete syscalls, including the Android private-`ENOTSUPP` fallback. |
| `shared_network` | `CONFIG_NET_SCHED`, `CONFIG_NET_SCH_INGRESS`, `CONFIG_NET_CLS_ACT`, `CONFIG_NET_CLS_BPF`, and `sched_cls` | Required | Creates the clsact ingress/egress gateway path. These are not required when `shared_network` is disabled. |
| `shared_network` | ARRAY/PERCPU ARRAY maps and sched_cls map, time, writable-skb, and checksum helpers | Required | Store control/scratch state and implement token rewrite, reply restoration, flow expiry, DNS hijack, and checksum repair. |
| `shared_network` | Ethernet-like downstream TC path and writable per-interface `route_localnet` for IPv4 | Required | Lets the parser read Ethernet frames and routes IPv4 token addresses to the internal listener. An interface that appears only while an Android hotspot is enabled is not itself a kernel-capability failure. |

`bpftool` is useful for this diagnostic script but is not a runtime dependency of
sing-box. The target does not need a compiler, libbpf, or libelf either.

### OpenWrt

OpenWrt is within the standard Linux support scope, but an arbitrary official
or vendor firmware must not be assumed to work. A gateway that needs only TC
forwarding can set `cgroup_enabled: false`; in that mode cgroup support is not
required and the shared-network backend owns its bypass maps. Keep the default
`cgroup_enabled: true` only when locally generated traffic must also be
intercepted.

Verify the **effective kernel configuration on the target device** before use:

- `CONFIG_BPF` and `CONFIG_BPF_SYSCALL` must be enabled. With
  `cgroup_enabled: true`, `CONFIG_CGROUPS` and `CONFIG_CGROUP_BPF` are also
  required, a writable cgroup v2 must be mounted, and the kernel must provide
  the configured connect and UDP sendmsg/recvmsg attach types. Socket-release
  is used for exact cleanup when available and otherwise falls back to LRU
  compatibility mode. `CONFIG_BPF_JIT` is not functionally required, but is
  strongly recommended on a router.
- `shared_network` additionally needs `CONFIG_NET_SCHED`,
  `CONFIG_NET_SCH_INGRESS`, `CONFIG_NET_CLS_ACT`, and `CONFIG_NET_CLS_BPF`.
  On common OpenWrt releases these are usually supplied by
  `kmod-sched-core` and `kmod-sched-bpf`; package names and built-in/module
  choices can vary between releases and vendor trees.
- sing-box must run as root or with equivalent permission to use the BPF
  syscall, attach cgroup and TC programs, create maps, manage local routes,
  and write per-interface `route_localnet`. A procd jail, container, or
  capability set must not remove those permissions. The kernel must also
  allow enough locked memory for the configured maps.

`shared_network` does not replace OpenWrt network services. The firewall, IP
forwarding, IPv4 NAT, DHCP, DNS, and IPv6 router advertisements and neighbor
discovery remain the responsibility of firewall4, dnsmasq, odhcpd, or another
system component. `include_interface` must identify the interface whose TC
ingress and egress actually see client frames. With DSA, a Linux bridge, or a
wireless AP this may be a client-facing port or AP interface rather than
`br-lan`; verify the path for the specific driver instead of relying only on
the logical network name.

Hardware flow offload, NSS/PPE or shortcut forwarding, switch or wireless
hardware acceleration, and XDP cannot be intercepted when they bypass the
selected Linux TC hook. If only DNS, initial packets, or a subset of
connections is visible, disable hardware offload first. Whether software flow
offload preserves the relevant TC path should also be verified for the
OpenWrt release and driver. IPv6 additionally requires working forwarding,
RA/NDP, and an explicit IPv6 ULA `/64` in `redirect_address`.

An OpenWrt build should use an OpenWrt SDK/toolchain matching the target
architecture and ABI, with cgo and `with_ebpf` enabled. A dynamically linked
binary must also match the target firmware's libc. A BPF-capable Clang on the
build host compiles the TC object, which is then embedded in the binary. The
target does not need Clang, `tc`, `bpftool`, libbpf, or libelf at runtime;
`tc` and `bpftool` are useful only for diagnostics.

### Build

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
the generated object is ignored by Git and must not be committed.

With `cgroup_enabled: true`, the device kernel must provide cgroup2 and the
cgroup attach types required by `network`. IPv4 interception uses connect4 and
connect6 for IPv4-mapped IPv6 sockets; enabling UDP additionally uses UDP4 and
UDP6 sendmsg and recvmsg. Native IPv6 interception uses the same IPv6 attach
types.
`BPF_CGROUP_INET_SOCK_RELEASE` is an optional UDP lifecycle optimization; its
absence selects the LRU compatibility mode. With `cgroup_enabled: false`, none
of those cgroup capabilities are probed. The process still needs permission to
create and attach BPF maps/programs and to manage local routes. Only when
enabled, `shared_network` additionally requires sched_cls TC, `clsact`, writable
per-interface `route_localnet` for IPv4, and `CAP_NET_ADMIN`.

### Credits

Thanks to [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
for the original eBPF interception implementation on which this inbound is
based.
