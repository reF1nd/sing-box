# sing-box eBPF inbound comparison

This document compares this project's eBPF inbound with
[daeuniverse/dae](https://github.com/daeuniverse/dae) and the sing-box TUN,
Redirect, and TProxy inbounds.

The document is maintained with the current eBPF implementation. The dae
comparison is based on
[`caa6f5e9`](https://github.com/daeuniverse/dae/commit/caa6f5e91776bc86d5b0edc940bb7d264359863c)
from its main branch on 2026-07-31.

## Summary

Both implementations use eBPF, but their goals and data paths differ:

- The sing-box inbound uses eBPF in place of transparent-proxy firewall rules
  and sends selected traffic into the normal sing-box routing pipeline.
- dae places much more of the traffic classifier in TC/eBPF, so traffic chosen
  as direct can remain in the kernel data path.

## DNS capture modes

The top-level `dns_mode` applies to both the local cgroup path and the optional
`shared_network` path:

```json
{
  "type": "ebpf",
  "network": [
    "tcp",
    "udp"
  ],
  "dns_mode": "hijack",
  "shared_network": {
    "enabled": true,
    "include_interface": "wlan2"
  }
}
```

| Mode | Local traffic | Hotspot/shared traffic | Intended use |
|---|---|---|---|
| `hijack` (default) | TCP/UDP destination port 53 enters sing-box before destination-address and `bypass_rule_set` CIDR checks | TC still captures port 53 sent to the gateway, a private DNS server, or a bypass CIDR | Default choice; prevents direct DNS leakage through a bypass range and keeps hotspot DNS usable |
| `off` | TCP/UDP destination port 53 bypasses before redirect state is created | TC leaves port 53 on the normal forwarding path | The host already provides an independent DNS service and DNS is intentionally kept outside sing-box |

DNS priority does not skip safety boundaries. sing-box self-bypass, the
selected `network`, UID include/exclude policy, Android `dns_tether` UID 1052,
and DHCP protection are evaluated first. `hijack` changes only the priority of
DNS relative to local, private, multicast, and CIDR bypass checks. Hotspot DNS
hijacking requires UDP; `off` permits a TCP-only shared-network configuration.

`dns_mode: hijack` means that traditional TCP/UDP port 53 is delivered to
sing-box. It is not the same as the `hijack-dns` route action. A captured query
still follows normal routing and may reach its original DNS server through an
outbound, or a route rule may send it to the sing-box DNS module with
`hijack-dns`. DoT, DoH, and DoQ do not use traditional port 53 and require
separate domain, IP, port, or protocol rules.

Unlike dae, this DNS capture is an ingress policy and does not maintain a
domain-to-IP routing map inside eBPF. Both modes add only constant port checks;
`hijack` can skip the DNS destination CIDR lookup, while `off` returns earlier.
The impact on ordinary non-DNS traffic is small.

## Comparison with dae

| Dimension | sing-box eBPF inbound | dae |
|---|---|---|
| Local traffic entry | cgroup `connect4/6` and UDP `sendmsg/recvmsg` rewrite destinations at socket operations | WAN TC ingress/egress processes packets; cgroup hooks mainly collect PID, process name, and socket cookie metadata |
| Gateway/hotspot traffic | Optional `shared_network` attaches TC ingress/egress to selected downstream interfaces | LAN/WAN TC is the primary operating mode |
| Redirection | Destinations become loopback/ULA token addresses; maps retain the original destination for the listener | TC performs classification; proxied traffic crosses netkit/veth and a separate netns, then reaches a TProxy listener through mechanisms such as `bpf_sk_assign` |
| Routing decision | Complete rules remain in sing-box user space; the kernel handles UID policy, fixed safety bypasses, and pure-CIDR `bypass_rule_set` entries | Domain mappings, IP, port, protocol, MAC, process name, and other rules can be placed in eBPF maps and evaluated in TC |
| Direct traffic | Only built-in and `bypass_rule_set` matches completely avoid user space; an ordinary sing-box `direct` route still crosses the user-space relay | A direct decision uses native kernel L3 forwarding without entering dae user space |
| Proxied traffic | Local capture runs at socket operations without per-packet TC/netfilter classification; shared-network traffic still requires per-packet TC rewrites | Every bound-interface packet is parsed and classified in TC before proxied traffic enters the control plane |
| DNS | sing-box DNS/routing handles the query; port 53 defaults to prioritized `hijack` and can be set to `off` | DNS must pass through dae to build its domain-to-IP routing state |
| Self-bypass | Supported kernels use a map-free TGID fast path; the socket-cookie map is created only when verifier compatibility requires the cookie fallback | Uses dae's own cgroup/socket metadata and namespace data path |
| Android | Explicitly supports a rooted Android native binary and dynamically appearing hotspot interfaces | Primarily targets standard Linux routers and gateways |
| System changes | Local mode uses no nftables, marks, policy routing, or TC; shared mode changes only selected downstream TC and IPv4 `route_localnet` | Manages LAN/WAN TC, netns, netkit/veth, sysctl, and BPF maps |
| sing-box feature compatibility | Captured traffic can use the full sing-box routing, DNS, sniffing, and outbound implementation | Bound to dae's routing language and outbound implementation |
| Implementation complexity | Smaller kernel programs, but token maps, UDP lifetime handling, and a custom loader still require maintenance | A substantially larger eBPF data plane implements connection state, DNS/IP mapping, in-kernel rules, and netns reinjection |
| Main performance advantage | Short local interception path; accurate pure-CIDR bypass is close to native direct traffic | Strong advantage when a gateway has a large direct share because rich direct decisions remain in the kernel |
| Main performance cost | Non-offloaded `direct` traffic still enters sing-box and cannot gain dae's kernel-direct advantage | All selected-interface traffic pays per-packet TC parsing and map lookup; the more complex data plane increases verifier and maintenance cost |
| Kernel version | No hard-coded version gate; mainline TCP-only capabilities are roughly available from 4.17, while UDP attach types must be tested on the actual kernel; missing socket-release uses an LRU compatibility mode | Officially requires Linux 5.17 or newer |
| BTF/CO-RE | Does not require kernel BTF; both cgroup and TC programs are Clang-built BPF objects without CO-RE relocations | Requires BTF, CO-RE, and a broader eBPF/kprobe feature set |
| Additional kernel features | Local mode needs cgroup v2, `CONFIG_CGROUP_BPF`, and the selected sock-address hooks; socket-release is optional. TC-only gateway mode can set `cgroup_enabled: false` and needs sched_cls, clsact, and `CAP_NET_ADMIN` instead | TC ingress/egress, cgroup2, BTF, kprobe, ring buffer, `bpf_loop`, and socket lookup/assignment; netkit is an optional optimization |
| New-kernel optimization | Uses TGID self-bypass when accepted by the verifier and lazily creates the socket-cookie fallback only when required | Linux 6.7+ may use netkit; suitable Linux 6.8+ setups may use `bpf_redirect_peer`, otherwise dae falls back to veth or normal redirect |

### `shared_network` on standard Linux

`shared_network` is not Android-only. A standard Linux router, wireless AP, or
host with an existing downstream LAN can attach the TC path to Ethernet-like
client interfaces. sing-box does not create the bridge or AP and remains
dependent on the host for IP forwarding, IPv4 NAT, IPv6 RA/NDP, DHCP, and any
DNS service needed while interception is disabled.

OpenWrt can run only this TC gateway path with `cgroup_enabled: false`. In that
mode sing-box does not probe cgroup2 and the shared-network backend creates its
own bypass maps. Keep cgroup interception enabled only when locally generated
traffic must also be captured. See the
[eBPF inbound documentation](/configuration/inbound/ebpf/#openwrt) for kernel,
package, permission, cleanup, and build requirements.

On a Linux bridge, select the member interface where client frames actually
enter TC ingress; the bridge master may not see the same hook path on every
kernel and driver. This is a routed-downstream gateway feature, not a general
transparent layer-2 bridge proxy. sing-box uses TC priority `1` by default and bypassed
traffic continues to later filters, but earlier XDP, hardware offload, or a
vendor filter at the same or an earlier priority can make traffic invisible.
Android should retain priority `1`; standard Linux and OpenWrt may configure a
different priority to fit their existing TC filter ordering.

It is therefore not correct to claim that dae is always faster:

- A Linux gateway with a high direct share and domain/MAC/port classification
  is structurally favorable to dae.
- A rooted Android device that needs global local-app proxying and optional
  hotspot support is closer to the sing-box inbound's intended data path.
- Proxied traffic ultimately requires user-space protocol processing in both
  projects. dae's largest architectural gain is keeping direct traffic out of
  user space.
- With an accurate pure-CIDR `bypass_rule_set`, sing-box checks the map at
  socket establishment/send time and later packets stay native. It cannot
  offload composite domain, port, MAC, or process rules in the same way as dae.

## Comparison with other sing-box inbounds

| Inbound | Capture mechanism | Protocol/scope | Performance characteristics | Configuration complexity | Linux kernel requirements | Best fit |
|---|---|---|---|---|---|---|
| eBPF | cgroup socket-address plus optional TC shared-network | TCP/UDP; local traffic and selected downstream interfaces | Low local capture overhead; CIDR bypass is close to native; non-bypassed traffic still enters user space | Simple JSON, but the most demanding build, permission, and kernel compatibility requirements | Local mode needs cgroup2 and selected attach types; old-kernel UDP can use LRU cleanup; TC-only mode can disable cgroup | Rooted Android, local transparent proxying, and phone hotspots |
| TUN | Routes L3 packets into a virtual interface and processes them through the system, gVisor, or mixed stack | Broadest capture scope and best cross-platform coverage | Usually adds packet copies and L3-to-L4 processing; Linux `auto_redirect` can significantly improve the path | Relatively simple with `auto_route`; complex networks still require routing, DNS, and MTU care | `CONFIG_TUN`; `auto_redirect` also needs nftables and policy routing | General desktops, mobile VPNs, and compatibility-first deployments |
| Redirect | nftables/iptables REDIRECT or DNAT; listener reads `SO_ORIGINAL_DST` | TCP only in sing-box | Mature and low overhead, but no UDP | External firewall and loop-prevention rules are required | Common netfilter NAT/conntrack; lowest requirements | Simple Linux TCP transparent proxying |
| TProxy | nftables/iptables TPROXY, fwmark, policy routing, and an `IP_TRANSPARENT` listener | TCP/UDP with original source/destination semantics | Mature and stable, but packets traverse netfilter; often slower than an optimized TUN `auto_redirect` or a specialized socket-operation fast path | Highest; requires marks, rules, local routes, and dual-stack loop prevention | Netfilter TPROXY, policy routing, and transparent sockets | Linux routers needing conventional transparent-proxy semantics |
| TUN + auto_redirect | nftables pre-classification sends selected traffic into TUN | TCP/UDP and broader IP-layer traffic | Documented by sing-box as faster than traditional TProxy while retaining the mature TUN model | Mostly automatic and usually simpler than hand-written TProxy rules | TUN, nftables, and policy routing | Default recommendation on standard Linux |

## Selection guidance

- Rooted Android and hotspot deployments can use the eBPF inbound when the
  required kernel hooks are available.
- A normal standard-Linux endpoint should generally prefer
  `tun + auto_route + auto_redirect` for maturity and feature coverage.
- A high-throughput Linux gateway with a large direct share may benefit more
  from dae's in-kernel classifier.
- Do not replace a mature data path only for the eBPF label. Measure the real
  direct/proxy ratio, connection rate, packet size, CPU, and memory with the
  [transparent inbound benchmark protocol](./interception-benchmark.md).

## References

- [eBPF inbound documentation](/configuration/inbound/ebpf/)
- [TUN inbound documentation](/configuration/inbound/tun/)
- [Transparent inbound benchmark protocol](./interception-benchmark.md)
- [Android tethering BPF TC priorities](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/main/Tethering/src/com/android/networkstack/tethering/BpfUtils.java)
- [How dae works](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/how-it-works.md)
- [dae kernel requirements](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/README.md#linux-kernel-requirement)
- [dae eBPF data plane](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/control/kern/tproxy.c)
