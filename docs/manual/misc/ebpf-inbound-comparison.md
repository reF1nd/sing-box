# sing-box eBPF inbound comparison

This page is a selection guide. The complete eBPF configuration reference is
in the [eBPF inbound reference](/configuration/inbound/ebpf/); kernel symbols,
runtime prerequisites, and Linux/OpenWrt packages are listed in the [eBPF
kernel requirements](/manual/misc/ebpf-kernel-requirements/).

## Choose a capture path

| Option | Capture path | Scope | Best fit |
|--------|--------------|-------|----------|
| eBPF `local` | cgroup socket-address hooks | Local TCP/UDP sockets, with UID and Android package preselection | Rooted Android or Linux hosts with cgroup v2 |
| eBPF `shared` | TC ingress/egress on selected interfaces | Forwarded clients such as hotspots and OpenWrt LANs | A gateway that needs sing-box routing for selected clients |
| TUN + `auto_route` | Virtual interface and userspace network stack | Broad IP traffic on supported platforms | General-purpose transparent proxying |
| Redirect | netfilter REDIRECT/DNAT | TCP | A simple TCP-only Linux setup |
| TProxy | netfilter TPROXY, marks, and policy routing | TCP/UDP with transparent socket semantics | A conventional Linux router that already uses firewall policy routing |

The eBPF inbound is an entry into the normal sing-box routing pipeline. It does
not replace sing-box routing with an in-kernel policy engine. Pure destination
CIDR bypasses can remain in eBPF; other traffic enters userspace. See the
[configuration reference](/configuration/inbound/ebpf/) for DNS, UID, package,
and bypass semantics.

## Compared with dae and bpf2socks

These projects solve related but different problems. The dae comparison is
based on [caa6f5e9](https://github.com/daeuniverse/dae/commit/caa6f5e91776bc86d5b0edc940bb7d264359863c).

| Dimension | sing-box eBPF inbound | dae | bpf2socks |
|-----------|----------------------|-----|-----------|
| Main role | Transparent capture into sing-box | Gateway classifier and direct-forwarding datapath | Native BPF redirect core used with a SOCKS bridge |
| Local traffic | cgroup socket hooks | TC plus cgroup metadata | Android-oriented native interception |
| Forwarded traffic | Optional TC on selected interfaces | TC on LAN/WAN interfaces is central | Depends on the selected integration and interface setup |
| Policy location | UID and pure CIDR preselection in BPF; full routing in sing-box | More IP, domain, port, MAC, and process decisions can stay in BPF | Redirects traffic; proxy policy is supplied by the bridge |
| Runtime integration | Directly owns maps, programs, listeners, and normal sing-box routes | Own gateway datapath and system integration | Separate native interception and SOCKS forwarding components |
| Kernel assumptions | Capability-based; no BTF/CO-RE requirement | Officially Linux 5.17+ with BTF/CO-RE | Check the target branch and device kernel capabilities |

There is no universal performance winner. A gateway with a high direct-traffic
ratio may benefit from dae's kernel-direct decisions. A rooted Android device
that sends most traffic through sing-box usually benefits more from the short
cgroup capture path. Packet rate, connection rate, rule complexity, kernel JIT,
and hardware offload matter more than the project name.

## Limitations to account for

- The local cgroup path does not restore an application's source IP at the
  sing-box listener. UID and Android package policies are available; local
  `source_ip_cidr` matching is not meaningful.
- Shared mode preserves the downstream client's source IP and source MAC, but
  does not create hotspot, DHCP, NAT, IPv6 RA, or forwarding services.
- Vendor kernels frequently backport individual BPF features. Run
  `sing-box tools ebpf status` on the target instead of relying only on the
  reported kernel version.

## References

- [eBPF inbound reference](/configuration/inbound/ebpf/)
- [TUN inbound](/configuration/inbound/tun/)
- [dae: how it works](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/how-it-works.md)
- [dae: kernel requirement](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/README.md#linux-kernel-requirement)
- [bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
