# sing-box eBPF inbound comparison

This document compares the sing-box eBPF inbound with
[dae](https://github.com/daeuniverse/dae) and the TUN, Redirect, and TProxy
inbounds.

The dae comparison is based on
[`caa6f5e9`](https://github.com/daeuniverse/dae/commit/caa6f5e91776bc86d5b0edc940bb7d264359863c).

## Data paths

The eBPF inbound provides two independent data paths:

- Local cgroup programs rewrite socket destinations when applications call
  connect or UDP send/receive operations. Packets are not classified by TC.
- Optional `shared_network` TC programs rewrite forwarded packets from
  selected downstream interfaces.

Both paths send selected traffic to the normal sing-box routing pipeline.
`bypass_rule_set` can keep pure destination CIDRs entirely in the kernel.

## Comparison with dae

Both projects use eBPF, but they have different goals. The sing-box inbound is
a transparent entry into sing-box; dae places a larger classifier and direct
forwarding path in the kernel.

| Dimension | sing-box eBPF inbound | dae |
|-----------|------------------------|-----|
| Primary use | Rooted Android local traffic, with optional hotspot or Linux gateway support | Linux router and gateway traffic |
| Local capture | cgroup socket-address hooks | TC data path with cgroup metadata collection |
| Gateway capture | Optional TC on selected downstream interfaces | TC on LAN/WAN interfaces is the main path |
| Routing policy | Full policy remains in sing-box; UID and pure CIDR preselection can run in eBPF | More IP, domain, port, MAC, and process policy can run in eBPF |
| Direct traffic | Built-in and `bypass_rule_set` matches stay in the kernel; normal `direct` routes still enter sing-box | Direct decisions can remain in the kernel forwarding path |
| DNS | Port 53 can be captured or bypassed; queries then follow normal sing-box routing and DNS rules | DNS is part of dae's domain-to-IP policy model |
| Self-protection | TGID fast path with automatic socket-cookie fallback | Uses dae's cgroup, socket, and namespace design |
| System changes | Local mode needs no firewall or TC; shared mode changes selected TC hooks and IPv4 `route_localnet` | Manages TC, namespace links, sysctls, and related maps |
| Kernel baseline | Capability-based; no fixed version guarantees because vendor kernels vary | Officially requires Linux 5.17 or newer |
| BTF/CO-RE | Not required | Required |
| Main advantage | Short local capture path and direct access to all sing-box features | Strong kernel-direct path when a gateway has a large direct share |
| Main cost | Non-bypassed traffic still crosses sing-box user space; shared mode performs TC work per packet | All selected-interface traffic passes through a larger TC/eBPF data plane |

It is not useful to declare either design universally faster. Results depend
on connection rate, packet size, proxy/direct ratio, rules, kernel JIT, and
hardware offload. A gateway with many direct flows favors dae's in-kernel
classifier. A rooted Android device that proxies most local applications fits
the sing-box cgroup path more closely.

## Comparison with other sing-box inbounds

| Inbound | Capture method | Scope | Configuration | Typical use |
|---------|----------------|-------|---------------|-------------|
| eBPF | cgroup socket hooks, plus optional TC | Local TCP/UDP and selected downstream clients | Simple JSON, but requires a compatible BPF kernel, cgo build, and root | Rooted Android, phone hotspots, specialized Linux gateways |
| TUN | Virtual network interface and userspace network stack | Broad IP traffic and multiple platforms | Usually the easiest general solution with `auto_route` | General desktops, servers, and mobile VPN applications |
| TUN + `auto_redirect` | nftables preselection plus TUN | Linux TCP/UDP and broader IP traffic | Mostly automatic | Recommended general Linux transparent proxy path |
| Redirect | netfilter REDIRECT/DNAT and `SO_ORIGINAL_DST` | TCP | Requires external firewall rules | Simple Linux TCP interception |
| TProxy | netfilter TPROXY, marks, policy routing, transparent sockets | TCP/UDP with original address semantics | Most complex | Conventional Linux routers and gateways |

The eBPF local cgroup path does not restore the application's source IP at the
internal listener, so local `source_ip_cidr` rules are not meaningful. UID and
Android package preselection remain available. `shared_network` preserves the
downstream client's source IP and source MAC.

## Kernel and platform differences

Local interception requires cgroup v2, `CONFIG_CGROUP_BPF`, and the selected
connect/sendmsg/recvmsg hooks. `BPF_CGROUP_INET_SOCK_RELEASE` is optional;
older kernels use a bounded UDP compatibility path.

`shared_network` requires TC `sched_cls`, `clsact`, packet rewrite and checksum
helpers, and Ethernet-like frames on the selected interface. It can run on
Android, standard Linux, or OpenWrt. A TC-only gateway may set
`cgroup_enabled: false`.

Android and vendor kernels often backport individual BPF features. Check the
target with `sing-box tools ebpf status`; kernel version alone is not a
reliable compatibility test.

## Selection guidance

- Prefer TUN with `auto_route` and `auto_redirect` for a general Linux host.
- Consider the eBPF inbound for rooted Android local traffic or a phone
  hotspot when the required kernel hooks are available.
- Consider dae for a Linux gateway that benefits from rich in-kernel direct
  classification.
- Use Redirect for a simple TCP-only Linux setup.
- Use TProxy when conventional transparent socket semantics are required and
  its firewall and policy-routing complexity is acceptable.

Measure the intended device and traffic mix before selecting a data path.

## References

- [eBPF inbound documentation](/configuration/inbound/ebpf/)
- [TUN inbound documentation](/configuration/inbound/tun/)
- [How dae works](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/how-it-works.md)
- [dae kernel requirements](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/README.md#linux-kernel-requirement)
