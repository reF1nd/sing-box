---
icon: material/linux
---

# eBPF kernel requirements

The eBPF inbound uses TC classifiers, transparent sockets, socket lookup and
`bpf_sk_assign`. Support is determined by runtime capability probes rather than
by a Linux version number. Vendor kernels may backport, disable, or restrict
individual facilities. When TCX link creation is available it is preferred;
otherwise sing-box uses the compatible `clsact` attachment.

## Kernel configuration

The following options, or their vendor equivalents, are required:

| Option | Purpose |
| --- | --- |
| `CONFIG_BPF` | Core BPF support. |
| `CONFIG_BPF_SYSCALL` | Loads maps and programs. |
| `CONFIG_NET_CLS_BPF` | Runs BPF classifiers at TC hooks. |
| `CONFIG_NET_SCH_INGRESS` | Provides the `clsact` ingress and egress hooks. |
| `CONFIG_NET_CLS_ACT` | Enables direct-action classifier results. |
| `CONFIG_VETH` | Provides the local delivery link in local and hybrid modes. |
| `CONFIG_INET` | IPv4 TCP/UDP and transparent sockets. |
| `CONFIG_IPV6` | Required when local or shared IPv6 interception is enabled. |

`CONFIG_BPF_JIT` is strongly recommended for packet-path performance.

## Required BPF facilities

The selected kernel must support:

- `SCHED_CLS` programs on TC ingress and egress;
- `ARRAY`, `HASH`, `LRU_HASH`, and `LPM_TRIE` maps;
- `bpf_map_lookup_elem`, `bpf_map_update_elem`, and `bpf_map_delete_elem`;
- `bpf_get_socket_uid` in `SCHED_CLS`;
- `bpf_redirect` in `SCHED_CLS`;
- `bpf_skb_store_bytes` and `bpf_skb_change_head` in `SCHED_CLS`;
- `bpf_skc_lookup_tcp`, `bpf_sk_lookup_udp`, `bpf_sk_assign`, and
  `bpf_sk_release` in `SCHED_CLS`.

TCP listener SOCKMAP support is optional. When `BPF_MAP_TYPE_SOCKMAP` can be
created and the modern TC sections load successfully, it is used for wildcard
listener fallback. Otherwise sing-box loads a legacy TC section that does not
reference the map and performs direct `bpf_skc_lookup_tcp` lookup. The selected
path is decided by map creation and program loading, not by the kernel release
string. Older kernels commonly gate SOCKMAP behind `CONFIG_BPF_STREAM_PARSER`.

For local mode, `bpf_get_socket_cookie` in `SCHED_CLS` is required for the
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

## Known LPM trie safety issue

Some kernels may contain an LPM trie update defect. sing-box probes an actual
temporary LPM update at startup instead of relying on a version string.
The default exact host-address policy uses `HASH` maps and is unaffected.
Configured UID/package filters, source CIDR filters, and destination bypass
CIDR and UID policies use LPM tries and are rejected when that probe fails.

## Privileges

Startup needs enough privilege to:

- load BPF maps and programs;
- create and remove a veth pair in local or hybrid mode;
- add and remove `clsact` qdiscs and BPF filters;
- add and remove policy-routing rules and local routes;
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

Local mode attaches to the network manager's current default interface. Shared
mode attaches to each configured downstream interface. Ethernet/IPoE and
L3-only raw-IP or PPP links are supported. Source MAC policy requires Ethernet
framing. Loopback and unrecognized link encapsulations are not supported.

Local attachments follow default-interface changes. Configured shared
interfaces are attached when present, except while an interface is acting as the
current default upstream. Link and route events trigger validation and repair of
managed attachments and network state; no periodic polling is used.

One sing-box eBPF inbound may manage an interface at a time. Existing unrelated
`clsact` filters are preserved, but a conflicting sing-box filter handle or
interface lock prevents startup.

The local delivery veth requires writable per-interface IPv4 sysctls under
`/proc/sys/net/ipv4/conf`. Original values are restored during cleanup.

## Probe

Use the built-in kernel probe with the same mode and protocols as the intended
configuration. For shared mode, pass one active downstream interface so its
link type can be checked.

The probe uses the selected protocols, address families, and shared interface.
For local mode it reports the required TC socket-cookie helper and the optional
cgroup socket-cookie hooks. It also reports the optional socket-address process
tracker capabilities. A real startup determines whether the process cgroup is
exclusive and uses cgroup registration when possible, otherwise enabling the
userspace cookie registration path.
It reports `FAIL` for a conclusive missing facility and `UNKNOWN` when the
process cannot determine a facility, such as when a security policy denies the
probe. Both statuses make the command exit non-zero for required checks.
Repeat it with the same privileges used to run sing-box. A real startup remains
necessary because the non-mutating probe does not attach TC filters, create a
veth, or change sysctls; those operations are checked and fail during startup.
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
