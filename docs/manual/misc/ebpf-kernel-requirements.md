---
icon: material/chip
---

# eBPF kernel requirements

The eBPF inbound defaults to the cgroup v2 socket-address backend for local
interception and TC `packet_rewrite` for shared interception. Local interception
may explicitly select TC, while shared interception may explicitly select the
tuple-preserving `socket_assign` data plane instead.
Support is determined by runtime map, program-load, helper, and attachment results
rather than a minimum Linux version. Vendor kernels may backport, disable, or
restrict individual facilities. The LPM-trie safety exception described below
uses a conservative release check because affected kernels can fault while
that capability is being probed. When TCX link creation is available it is
preferred; otherwise sing-box uses the compatible `clsact` attachment.

## Platform profiles

There are two practical deployment profiles. They share the same eBPF objects,
but their kernel ownership, permissions, and link topology are different.

### Standard Linux and OpenWrt

For a normal Linux host or OpenWrt router, run sing-box as root or grant the
equivalent capabilities, normally `CAP_BPF` and `CAP_NET_ADMIN` (older kernels
may also require `CAP_SYS_ADMIN`). The selected configuration must expose the
required BPF syscall, maps, helpers and TC classifiers. Both local socket assignment and shared
`socket_assign` isolate TCP/UDP in a private namespace: they require
`CONFIG_NET_NS`, `CONFIG_VETH`, `CAP_SYS_ADMIN` for creation/reentry (including
on newer kernels), and `CAP_NET_ADMIN` for links/routes/transparent sockets.
These mechanisms predate `bpf_sk_assign` and do not raise the existing upstream
socket-assignment feature floor, but minimal firmware can omit them. Netkit,
`bpf_redirect_peer` and TCX are not mandatory. Local `cgroup` additionally needs a visible writable cgroup v2
hierarchy. Mount cgroup2 before startup when the distribution does not mount it
automatically; bpffs is only needed where pinned netd or other pin-based
integration is used.

OpenWrt modules must match the exact running kernel and target architecture.
Depending on the selected data plane, the target image commonly needs the BPF,
TC/scheduler classifier, and veth modules (often packaged as `kmod-bpf`,
`kmod-sched-core`, `kmod-veth`, or split `cls_bpf`/`act_bpf` packages; names vary
by release). No `bpftool`, `tc`, `ip`, libbpf, or clang executable is required at
runtime: sing-box uses BPF syscalls and netlink directly. Use the built-in probe
with the same interface and protocols as the service, then perform a real
startup because route, qdisc, sysctl, and LSM permissions are not proven by the
non-attaching probe.

### Root Android

Root access alone is not a compatibility guarantee. The root service must see
the vendor cgroup v2 hierarchy; bpffs and netd pins are additionally required
when netd coexistence or hook restoration is in use. Android SELinux must
allow the selected BPF, cgroup, TC, route, and sysctl operations. Android 15+
and vendor kernels may place a single-program netd owner on cgroup hooks; the
runtime reports and selects multi-program, legacy, or the narrowly recognized
netd pass-through replacement path. Optional socket-release and process-tracking
hooks can be denied and will fall back to bounded LRU cleanup or userspace
process lookup without disabling the main data plane.

Local socket assignment and shared socket assignment need vendor netns/veth/TC and routing
support, plus SELinux permission for `unshare`/`setns`. Startup verifies actual
creation/reentry and transparent listeners; failures do not silently select
host listeners. Local cgroup does not need netns, veth or TC. `packet_rewrite` needs Ethernet framing, while
`socket_assign` supports the documented raw-IP, PPP, and tunnel links. Validate
the actual device with `sing-box tools ebpf status` and a real start, recording
the kernel release/configuration, build fingerprint, SELinux audit denials,
selected attachment/cleanup paths, and interface framing.

## Data-plane capability summary

| Data plane | Hook and delivery | Link requirement | Main extra requirements |
| --- | --- | --- | --- |
| local `cgroup` | cgroup v2 socket-address hooks rewrite destinations to token addresses | No network-interface attachment | `CONFIG_CGROUP_BPF`, connect hooks, and UDP sendmsg/recvmsg hooks for enabled families |
| local `socket_assign` | default-interface egress → private-netns veth ingress → TCP/UDP socket assignment | Ethernet or supported L3 framing | netns, veth, TC classifiers, private routing, socket lookup/assignment and redirect helpers |
| shared `socket_assign` | downstream ingress → same private netns → TCP/UDP transparent listeners | Ethernet, raw-IP, PPP/SLIP, or supported tunnels | netns, veth, TC classifiers, private routing and socket lookup/assignment helpers |
| shared `packet_rewrite` | downstream ingress rewrites requests; egress restores replies | Ethernet only | TC classifiers, checksum/packet rewrite helpers and per-flow state |

The four paths do not form a version ladder. A vendor kernel may support one
path and reject another at object load or attachment time. Probe the exact path
that will be configured and treat a successful real startup as the final
attachment test.

### Upstream capability floor and validation targets

Upstream Linux 5.7 introduced `bpf_sk_assign`, so older kernels without that
backport cannot use `socket_assign`. netns/veth do not raise this helper floor,
but version 5.7 or later does not prove that the selected programs, permissions,
or routing work. Optional TCX requires newer kernel capabilities.

`cgroup` and `packet_rewrite` are compatibility-oriented paths. The library CI
adds a restricted 4.19.325 profile: local cgroup and shared `packet_rewrite`
TCP/UDP, with IPv4/IPv6 round trips. That stable patch level backports the cgroup
UDP recvmsg hooks introduced in mainline 5.2; do not assume every older 4.19
patch level or vendor kernel has them. The 5.4 profile covers cgroup TCP/UDP
(connected and unconnected UDP), packet rewrite and real reply delivery;
5.10/6.6 cover the complete paths. Required 4.19/5.4 tests fail rather than skip.
This matrix is not a minimum-version promise for all vendor kernels. Validate
the selected objects, attachment, and real traffic on the deployment kernel.

## Kernel configuration

The following options, or their vendor equivalents, are required:

| Option | Purpose |
| --- | --- |
| `CONFIG_BPF` | Core BPF support. |
| `CONFIG_BPF_SYSCALL` | Loads maps and programs. |
| `CONFIG_NET_CLS_BPF` | Runs BPF classifiers at TC hooks. |
| `CONFIG_NET_SCH_INGRESS` | Provides the `clsact` ingress and egress hooks. |
| `CONFIG_NET_CLS_ACT` | Enables direct-action classifier results. |
| `CONFIG_NET_NS` | Isolates local socket assignment and shared socket-assignment TCP/UDP listeners. |
| `CONFIG_VETH` | Provides their bidirectional delivery link. |
| `CONFIG_INET` | IPv4 TCP/UDP and transparent sockets. |
| `CONFIG_IPV6` | Required when local or shared IPv6 interception is enabled. |

`CONFIG_BPF_JIT` is strongly recommended for packet-path performance.

`CONFIG_CGROUP_BPF` and a cgroup v2 mount are required by the default local
`cgroup` data plane. By default, sing-box attaches to the visible cgroup
v2 root; `cgroup_path` may restrict interception to a specific subtree.
`CONFIG_VETH`, TC qdiscs, TC socket lookup, and `bpf_sk_assign` are not required
by a cgroup-only local inbound. They are also not required by shared
`packet_rewrite`, which uses only its configured Ethernet interfaces and local
token routes.

## Required BPF facilities

The selected kernel must support the following facilities for any TC data
plane:

- `SCHED_CLS` programs on TC ingress and egress;
- `ARRAY`, `HASH`, `LRU_HASH`, and `LPM_TRIE` maps;
- `bpf_map_lookup_elem`, `bpf_map_update_elem`, and `bpf_map_delete_elem`.

Shared `packet_rewrite` additionally uses `bpf_ktime_get_ns`, `bpf_csum_diff`,
`bpf_skb_store_bytes`,
  `bpf_l3_csum_replace`, `bpf_l4_csum_replace`, `bpf_skb_load_bytes` and `bpf_skb_pull_data` in
  `SCHED_CLS`.

Shared `socket_assign` and local socket assignment instead require
`bpf_skc_lookup_tcp`, `bpf_sk_lookup_udp`, `bpf_sk_assign`, and
`bpf_sk_release` in `SCHED_CLS`. The requirement follows the enabled protocol;
for example, UDP-only operation does not require the TCP lookup helper.

Both socket-assignment paths use `bpf_redirect`, `bpf_skb_store_bytes`,
`bpf_skb_change_head`, `bpf_skb_change_type` and `bpf_ktime_get_ns` for delivery
and return routing. Only local socket assignment additionally needs `bpf_get_socket_uid` and
`bpf_get_socket_cookie` for local selection. Only L2 framing changes; TCP/UDP
IP addresses and ports do not. Transparent replies also originate in the
private namespace, while proxy outbound dialing stays in the host. No host
conntrack flush or NAT-rule changes are needed.

The private reply route follows the smallest selected interface MTU. TCP
segmentation and opt-in UDP fragmentation run in its IP stack; a bounded,
short-lived fragment cache returns generated IPv4/IPv6 fragments to the client.
This does not change the existing bypass behavior for external input fragments.

Local cgroup mode instead loads
`CGROUP_SOCK_ADDR` connect4/connect6 and UDP sendmsg/recvmsg programs and uses
`bpf_get_socket_cookie`, map lookup/update/delete, and current-UID helpers.
When UDP socket-release attachment is unavailable, sing-box loads a bounded
LRU cleanup variant that does not reference that hook. The selected object is
loaded before interception is attached, so a missing helper or program type
fails startup without relying on the kernel release.
The optional socket-release capability probe is multi-only and never falls back
to an unflagged attach that could replace an existing Android/netd owner. This
probe denial therefore selects the LRU cleanup variant; it does not make the
required cgroup data plane unavailable.

TCP listener SOCKMAP support is optional. When `BPF_MAP_TYPE_SOCKMAP` can be
created, accepts a real TCP listener, and the modern TC sections load successfully, it is used for wildcard
listener fallback. Otherwise sing-box loads a legacy TC section that does not
reference the map and performs direct `bpf_skc_lookup_tcp` lookup. The selected
path is decided by map creation and program loading, not by the kernel release
string. Older kernels commonly gate SOCKMAP behind `CONFIG_BPF_STREAM_PARSER`.

For the local socket assignment data plane, `bpf_get_socket_cookie` in `SCHED_CLS` is required for the
self-bypass cookie map. `CGROUP_SOCK` with `inet_sock_create` and
`inet_sock_release`, together with `bpf_get_socket_cookie`, is an optional
optimization that populates and removes that map in kernel hooks. If the
process cgroup is shared or these hooks cannot be attached, sing-box registers
cookies from its own socket controls.
`CONFIG_CGROUP_BPF` (or its vendor equivalent) is needed only for this optional
optimization.

When local process matching is enabled, sing-box also attempts optional
`CGROUP_SOCK_ADDR` connect/sendmsg hooks with `bpf_get_socket_cookie` and
`bpf_get_current_uid_gid`. They record a bounded cookie-to-process entry so
userspace can resolve `/proc/<pid>/exe` directly instead of scanning every
process file descriptor. Failure to attach these hooks falls back to the normal
process searcher and does not prevent the inbound from starting.

The object contains no BTF or CO-RE dependency. It is generated for both BPF
endiannesses and avoids bounded loops so vendor verifier behavior remains
predictable.

## Object selection and attachment behavior

Capability checks select complete object variants before any path is enabled:

- TC TCP first attempts the SOCKMAP-capable object and falls back to a legacy
  object that does not reference SOCKMAP. A failed modern load is not treated
  as proof that the legacy section will load; the fallback is verified itself.
- Local cgroup UDP uses the socket-release notification variant when its
  program and attachment can be used. Otherwise it selects a bounded LRU
  cleanup variant. Denial of the optional release hook alone must not make the
  entire cgroup data plane unavailable.
- TC attachment prefers TCX only with the default priority. Unsupported TCX
  creation falls back to an owned `clsact` filter; an explicit custom priority
  selects `clsact` directly.
- cgroup programs first request multi-program attachment. Compatible vendor
  failures can fall back to legacy exclusive attachment. Exclusive attachment
  can replace an existing single program and can still conflict with a later
  exclusive netd attach, so this fallback is observable in startup diagnostics.
  The separate socket-release capability probe is multi-only and never uses
  that exclusive fallback.

Preflight object loading proves verifier acceptance and map ABI only. It does
not prove that the service can attach to a specific cgroup or interface, acquire
the per-interface lock, install routes, change sysctls, or coexist with Android
netd. Those operations are deliberately performed only during real startup.

All embedded objects are generated without BTF/CO-RE using Android NDK r29
Clang 21 and include little- and big-endian variants. Ordinary builds do not
compile C and do not require the NDK; changing BPF C or the C/Go ABI requires
regenerating both variants and passing the source/object manifest freshness
check.

## Known LPM trie safety issue

Linux 6.6.0 through 6.6.46 contain an upstream `LPM_TRIE` key-layout defect.
On kernels built with the relevant UBSAN checks, updating an LPM trie can
report an out-of-bounds access and may panic the kernel. The upstream fix,
`bpf: Replace bpf_lpm_trie_key 0-length array with flexible array`, is included
in Linux 6.6.47 and may also be backported by vendors.

This is an LPM update defect, not a missing map-type capability. A generic
`HaveMapType(LPM_TRIE)` probe cannot detect it safely. For a policy that really
needs LPM entries, sing-box first checks the running release and accepts a
positive BTF indication of the fixed `bpf_lpm_trie_key_u8` layout. If a kernel
is in the affected release range and the fix cannot be confirmed, sing-box
rejects the policy before performing any LPM update. Kernels outside that
range continue through the normal runtime map and update checks.

The check is only required when UID, application, source-CIDR, or destination
bypass policies contain entries. Empty policy maps are still created as part
of the TC object but are not updated. The exact host-address policy uses
`HASH` maps and is unaffected. A later dynamic bypass-policy update repeats the
same guard.

## Privileges

Startup needs enough privilege for the selected data plane to:

- load BPF maps and programs;
- create and remove a veth pair for local socket assignment;
- add and remove `clsact` qdiscs and BPF filters;
- add and remove TC policy routing or token local routes;
- change `rp_filter` and `accept_local` on the internal delivery peer;
- enable `IP_TRANSPARENT` or `IPV6_TRANSPARENT`;
- attach the process cgroup socket hooks when the local self-bypass fast path is
  available; otherwise, read `SO_COOKIE` and update the cookie map for each
  sing-box socket;

Running as root is the most portable arrangement. Capability-only deployments
depend on kernel version, distribution policy, LSM rules, and Android SELinux
policy; they commonly require `CAP_NET_ADMIN`, `CAP_BPF`, and on older kernels
`CAP_SYS_ADMIN`.

No `bpftool`, `tc`, or `ip` executable is required at runtime. sing-box uses BPF
syscalls and netlink directly.

## Interface requirements

Local socket assignment mode attaches to the network manager's current default interface.
Shared mode attaches to each configured downstream interface. The default
`packet_rewrite` data plane requires Ethernet framing. `socket_assign` supports
Ethernet/IPoE and L3-only raw-IP, PPP, SLIP, and IPIP/SIT/GRE tunnel links.
Source MAC policy also requires Ethernet framing.
Loopback and unrecognized link encapsulations are not supported.

Local attachments follow default-interface changes. Configured shared
interfaces are attached when present, except while an interface is acting as the
current default upstream. `shared.default_interface` explicitly retains that
shared attachment for a single-interface gateway whose client ingress and
default upstream use the same interface. Link and route events trigger
validation and repair of
managed attachments and network state. A low-frequency drift check also repairs
kernel state changed without a matching netlink notification.

This mode adds no BPF helper or kernel-version requirement, but the host
must separately provide IP forwarding, same-interface firewall forwarding and,
where required, NAT. It does not turn a Wi-Fi station into a hotspot and cannot
override access-point client isolation. A hotspot interface whose upstream is a
different cellular or Wi-Fi interface remains a normal downstream interface and
does not need this mode, even if an older device calls that interface
`wlan0`.

One sing-box eBPF inbound may manage an interface at a time. Existing unrelated
`clsact` filters are preserved, but a conflicting sing-box filter handle or
interface lock prevents startup.

The local socket assignment delivery veth requires writable per-interface IPv4 sysctls under
`/proc/sys/net/ipv4/conf`. Original values are restored during cleanup.

## Runtime policy updates

`local.bypass_rule_set` and `shared.bypass_rule_set` are independent policies.
Each is applied transactionally across the active backends for its own path. A
failed update reverts already-updated backends and retries with
bounded exponential backoff while their state remains usable. If an internal
rollback fails and a backend disables itself as requiring rebuild, retries stop
and runtime diagnostics report `needs_attention`; restart the inbound to build
a fresh backend. This is not a traffic-policy "fail closed" mode: disabling an
untrusted backend avoids running with mismatched maps and control flags.

## Probe

Use the built-in kernel probe with the same data planes, protocols, and IPv6
setting as the intended configuration. Select concrete paths with
`--local-data-plane=socket_assign|cgroup` and
`--shared-data-plane=socket_assign|packet_rewrite`; omit either flag to disable
that path. For shared mode, pass one active downstream interface so its link
type can be checked.

```sh
sing-box tools ebpf status --local-data-plane socket_assign --network tcp,udp --json
sing-box tools ebpf status --shared-data-plane packet_rewrite --interface br-lan --json
sing-box tools ebpf status --local-data-plane socket_assign --shared-data-plane socket_assign --interface wlan1 --json
```

The `--mode local|shared|all` form selects the default local `cgroup`, shared
`packet_rewrite`, or both. Use the explicit data-plane flags for the optional
TC or `socket_assign` paths.

For local socket assignment, `--local-interface <name>` performs a read-only check of the
interface and any existing clsact qdisc. For local cgroup, `--cgroup-path
<path>` checks a selected cgroup v2 path; when omitted, the current process's
cgroup is checked. These checks do not create qdiscs, attach hooks, or modify
system state.

The command also prints a one-shot occupancy diagnostic for visible `sb_` maps.
Runtime state maps use `healthy`, `warning`, and `degraded` thresholds. Maps
whose capacity is derived from the current compiled policy use `configured`;
being full is expected and is not runtime pressure. Fixed-layout maps that
cannot be safely iterated use `not_applicable`, while an actual iteration error
uses `recovery_failed`. This diagnostic never runs periodically while sing-box
is active and does not modify maps or data paths.

The probe uses the selected protocols, address families, data planes, and shared interface.
For local socket assignment mode it reports the required TC socket-cookie helper and the optional
cgroup socket-cookie hooks. Add `--process-tracking` to inspect the optional
socket-address process tracker and socket-release cleanup capabilities. A real
startup determines whether the process cgroup is
exclusive and uses cgroup registration when possible, otherwise enabling the
userspace cookie registration path.
The command also loads and immediately closes the generated eBPF objects selected
by these options. This validates their real map ABI and verifier-visible program
variants without attaching them.
It reports `FAIL` for a conclusive missing facility and `UNKNOWN` when the
process cannot determine a facility, such as when a security policy denies the
probe. Both statuses make the command exit non-zero for required checks.
Repeat it with the same privileges used to run sing-box. A real startup remains
necessary because the non-mutating probe does not attach TC filters or cgroup
hooks, create a veth, install routes, or change sysctls; those operations are
checked and fail during startup.
Use `--ipv6=false` when the intended configuration disables IPv6.

## Packet limitations

- Fragmented IPv4 datagrams and non-atomic IPv6 fragments bypass interception.
  IPv6 atomic fragments are processed normally.
- IPv6 parsing accepts at most four hop-by-hop, routing, destination-options,
  or authentication extension headers before TCP/UDP.
- Up to two VLAN headers are parsed on Ethernet-framed links.
- DHCP and DHCPv6 service traffic bypasses.
- Forwarded traffic bypasses the local egress path through the TC ingress
  interface metadata.
- sing-box-originated local packets bypass interception through a socket-cookie
  map. The process cgroup can maintain the map in kernel hooks; otherwise the
  default dialer and transparent UDP reply sockets register their cookies once.
  Shared-only mode installs neither mechanism.
