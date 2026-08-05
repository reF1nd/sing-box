# sing-box eBPF 入站实现对比

本文对比当前项目的 eBPF 入站、
[daeuniverse/dae](https://github.com/daeuniverse/dae)，以及 sing-box 的 TUN、
Redirect、TProxy 入站。

本文随当前项目的 eBPF 实现维护；dae 对比基于
[`caa6f5e9`](https://github.com/daeuniverse/dae/commit/caa6f5e91776bc86d5b0edc940bb7d264359863c)（2026-07-31 主分支）。

## 总体结论

两者都使用 eBPF，但目标和数据路径不同：

- 当前项目更像是“用 eBPF 代替透明代理规则，把流量送进 sing-box”。
- dae 则是“把分流器本身放进 TC/eBPF，只有需要代理的流量才进入用户态”。

## DNS 捕获模式

eBPF 入站提供顶层 `dns_mode` 配置，并同时作用于本机 cgroup 路径和
`shared_network` 热点路径：

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

| 模式 | 本机流量 | 热点/共享网络流量 | 适用场景 |
|---|---|---|---|
| `hijack`（默认） | TCP/UDP 目标端口 53 在目标地址和 `bypass_rule_set` CIDR 检查之前进入 sing-box | 发往热点网关、私网 DNS 或命中绕过 CIDR 的 TCP/UDP 53 仍由 TC 捕获 | 默认选择；避免 DNS 服务器地址位于绕过网段时出现直连泄漏，并保证热点客户端 DNS 可用 |
| `off` | TCP/UDP 目标端口 53 在创建重定向状态前直接放行 | TC 不捕获目标端口 53，保留系统原有转发路径 | 主机已经提供独立 DNS 服务，且明确允许 DNS 不经过 sing-box |

DNS 优先级不会绕过必要的安全边界。sing-box 自身 socket cookie、`network` 协议选择、
UID 包含/排除策略、Android `dns_tether` UID 1052 排除以及 DHCP 端口保护仍先执行；
`hijack` 只提高 DNS 相对于本机/私网/多播地址和 CIDR 绕过规则的优先级。热点使用
`hijack` 时必须启用 UDP，使用 `off` 时则允许只启用 TCP。

这里的 `dns_mode: hijack` 表示“确保传统 TCP/UDP 53 进入 sing-box”，不等同于路由规则
动作 `hijack-dns`。捕获后的查询仍进入正常路由流程：可以通过代理出站访问原 DNS
服务器，也可以再用 `hijack-dns` 交给 sing-box DNS 模块处理。DoT、DoH 和 DoQ 不使用
传统 53 端口，不受此选项直接控制，仍需通过域名、IP、端口或协议规则处理。

与 dae 相比，本项目的 DNS 捕获仍只是透明入口策略，不在 eBPF 中维护域名到 IP 的
分流映射。两种 `dns_mode` 都只增加常量端口判断：`hijack` 可跳过 DNS 目的地址的 CIDR
查询，`off` 会更早返回，因此对普通非 DNS 流量的性能影响很小。

## 与 dae 对比

| 维度 | 本项目 eBPF 入站 | dae |
|---|---|---|
| 本机流量入口 | cgroup `connect4/6`、UDP `sendmsg/recvmsg`，在 socket 操作时改写目的地址 | WAN TC ingress/egress 按包处理；cgroup hook 主要用于记录 PID、进程名和 socket cookie |
| 网关/热点流量 | 仅开启 `shared_network` 后，在指定下游接口挂 TC ingress/egress | 直接在 LAN/WAN 接口挂 TC，是主要工作模式 |
| 重定向原理 | 将目的地址改成 loopback/ULA “令牌地址”，由 map 保存原目标；listener 查询 map 后交给 sing-box | TC 内完成分流；代理流量经 netkit/veth 与独立 netns，使用 `bpf_sk_assign` 等交给 TProxy listener |
| 路由决策位置 | 完整规则仍在 sing-box 用户态；内核仅支持 UID、固定绕过和纯 CIDR `bypass_rule_set` | 域名映射、IP、端口、协议、MAC、进程名等规则可下沉到 eBPF map，由 TC 直接决策 |
| 直连流量 | 只有命中 `bypass_rule_set`/内置绕过时才完全不进用户态；普通 sing-box `direct` 仍经过用户态中继 | 分流结果为 direct 时直接走内核 L3 转发，不进入 dae 用户态 |
| 代理流量 | 本机流量在 socket 调用处拦截，没有每包 TC/netfilter 分类；热点模式仍需每包 TC 改写 | 每包执行 TC 解析和 map 查询，再把代理流量送进控制面 |
| DNS | 由 sing-box DNS/路由系统处理；`dns_mode` 默认 `hijack`，本机与热点 TCP/UDP 53 优先捕获，也可设为 `off` 放行 | DNS 必须经过 dae，以建立域名到 IP 的规则映射 |
| 自身防回环 | 支持时使用不创建 map 的 TGID 快速路径；仅在 verifier 兼容性要求回退时才创建 socket-cookie map | 使用 dae 自己的 cgroup/socket metadata 与 netns 数据路径 |
| Android | 明确支持 root Android 原生二进制，且热点接口可动态出现/消失 | 主要面向标准 Linux 路由器/网关，不是 Android 方案 |
| 系统侵入性 | 本机模式不使用 nftables、mark、策略路由或 TC；热点模式只操作指定下游 TC 和 `route_localnet` | 管理 LAN/WAN TC、netns、netkit/veth、sysctl、BPF map，系统拓扑改动更多 |
| sing-box 功能兼容 | 进入用户态后可直接使用全部 sing-box 路由、DNS、嗅探和出站能力 | 与 dae 自己的路由语言和出站实现绑定 |
| 实现复杂度 | 内核程序较小，但令牌映射、UDP 生命周期和自定义加载器仍有维护成本 | eBPF 数据面非常复杂，具有连接状态、DNS/IP 映射、内核规则执行、netns 回注等模块 |
| 性能优势 | 本机全代理场景入口更短；纯 CIDR 绕过后接近原生直连 | 直连占比较高的网关场景优势明显，丰富规则也能保持内核直连 |
| 性能劣势 | 未下沉的 `direct` 流量仍需进入 sing-box，不能获得 dae 的内核直连优势 | 所有绑定接口流量都要经过按包 TC 分类；复杂数据面增加 verifier、map 和维护成本 |
| 内核版本 | 没有硬编码版本判断；TCP-only 主线能力约从 4.17 起；UDP sendmsg/recvmsg 需按实际内核测试，缺少较新的 `INET_SOCK_RELEASE` 时自动使用 LRU 兼容模式 | 官方明确要求 Linux 5.17+ |
| BTF/CO-RE | 不需要内核 BTF；cgroup 与 TC 程序均由 Clang 编译为不含 CO-RE 重定位的 BPF 对象 | 需要 BTF、CO-RE 及更完整的 eBPF/kprobe 配置 |
| 额外内核能力 | 本机模式需要 cgroup v2、`CONFIG_CGROUP_BPF` 及所启用协议的 sock_addr hook；sock_release 可选；只启用热点 TC 时可关闭 `cgroup_enabled`，仅要求 sched_cls、clsact、`CAP_NET_ADMIN` | TC ingress/egress、cgroup2、BTF、kprobe、ring buffer、`bpf_loop`、socket lookup/assignment；netkit 为可选优化 |
| 新内核优化 | verifier 接受时使用 TGID 自身绕过，仅在需要时延迟创建 socket-cookie 回退 | 6.7+ 可尝试 netkit；满足安全条件的 6.8+ 可使用 `bpf_redirect_peer`，否则回退 veth/普通 redirect |

### `shared_network` 在标准 Linux 上的定位

`shared_network` 不只适用于 Android。标准 Linux 路由器、无线 AP 或已有下游 LAN
也可以使用它，但 sing-box 只负责在指定的 Ethernet-like 下游接口上挂载 TC，并将
捕获的 TCP/UDP 交给自身路由。bridge、IP forwarding、IPv4 NAT、IPv6 RA/NDP、DHCP
和未代理时的 DNS 服务仍由系统或其他守护进程负责。

OpenWrt 也属于这一范围。只需要 TC 网关路径时可设置 `cgroup_enabled: false`，此时
不探测 cgroup2，并由 shared-network backend 自建绕过 map；需要同时代理本机流量时
才保留 cgroup 要求。完整的内核、软件包、权限、卸载路径和构建要求见
[eBPF 入站文档](/zh/configuration/inbound/ebpf/#openwrt)。

在 Linux bridge 上应选择客户端报文实际进入 TC ingress 的成员端口；bridge master
是否能看到同一批帧取决于内核和驱动。该实现适合以本机为默认网关的路由下游，不是
通用二层透明桥代理。sing-box 默认使用 TC 优先级 `1`，绕过流量会继续交给后续 filter；
但先于 TC 执行的 XDP、硬件 offload 或同优先级的厂商程序仍可能使其看不到流量。
Android 应保持优先级 `1`；标准 Linux 和 OpenWrt 可按现有 TC filter 顺序配置其他
优先级。

因此，不能简单断言 dae 总是更快：

- **Linux 网关、直连流量很多、希望按域名/MAC/端口分流**：dae 的架构更有优势。
- **已获取 root 权限的 Android、本机应用全局代理、热点只是附加功能**：当前实现更贴合场景，系统改动也更少。
- **代理流量本身**：两者最终都需要用户态协议处理。dae 官方也只声称代理性能“略高，差距不大”；它最大的性能收益来自直连流量不进入用户态。
- **当前实现若配置了准确的纯 CIDR `bypass_rule_set`**：这些直连流量同样只在 socket 建立/发送阶段查一次 map，后续数据包不再经过 eBPF，性能会非常接近原生连接。但它无法像 dae 一样对域名、端口、MAC 等复合规则做内核直连。

## 与其他入站对比

| 入站 | 捕获方式 | 协议/范围 | 性能特征 | 配置复杂度 | Linux 内核要求 | 更适合 |
|---|---|---|---|---|---|---|
| 当前 eBPF | cgroup socket-address；可选 TC shared-network | TCP/UDP；本机及指定下游接口 | 本机捕获开销低；CIDR 绕过近似原生；未绕过流量仍进用户态 | JSON 较简单，但构建、权限和内核兼容最复杂 | 本机模式需要 cgroup2 及已启用协议的 attach type；旧内核 UDP 可回退 LRU；仅 TC 网关模式可关闭 cgroup | root Android、本机透明代理、手机热点 |
| TUN | 路由把 L3 数据包送入虚拟网卡，再由 system/gVisor/mixed 栈处理 | 捕获范围最广，跨平台能力最好 | 一般有额外包复制和 L3 到 L4 处理；Linux `auto_redirect` 可明显优化 | `auto_route` 后较简单，复杂网络需处理路由、DNS、MTU | `CONFIG_TUN`；`auto_redirect` 还需 nftables、策略路由 | 通用桌面、移动 VPN、兼容性优先 |
| Redirect | nftables/iptables REDIRECT/DNAT，listener 用 `SO_ORIGINAL_DST` 取原目标 | sing-box 中仅 TCP | 成熟且开销较低，但只有 TCP | 需要外部防火墙规则和防环配置 | 常规 netfilter/NAT/conntrack，要求最低 | 简单 Linux TCP 透明代理 |
| TProxy | nftables/iptables TPROXY + fwmark + 策略路由，`IP_TRANSPARENT` listener | TCP/UDP，保留原源/目标语义 | 成熟、性能稳定，但按包经过 netfilter；通常不如优化后的 TUN `auto_redirect` 或特定 eBPF 快路径 | 最高，需要 mark、rule、local route、IPv4/IPv6 防环规则 | netfilter TPROXY、策略路由、透明 socket | Linux 路由器、需要标准透明代理语义 |
| TUN + auto_redirect | nftables 预分流，再把需代理流量送进 TUN | TCP/UDP 及更广的 IP 层流量 | 本项目文档明确认为其优于传统 TProxy；仍保留 TUN 的成熟性 | 多数规则自动管理，通常低于手写 TProxy | TUN、nftables、策略路由 | 标准 Linux 上的默认推荐方案 |

## 选型建议

- 已获取 root 权限的 Android 及热点场景可继续使用当前 eBPF 入站。
- 标准 Linux 普通终端优先选择 `tun + auto_route + auto_redirect`，成熟度和功能覆盖更均衡。
- 标准 Linux 高吞吐网关若直连比例很高，dae 的内核分流架构更强。
- 不建议为了追求“eBPF”标签而替换成熟方案；应按
  [透明入站基准协议](/manual/misc/interception-benchmark/) 测量真实的直连/代理比例、
  短连接、长连接吞吐、UDP PPS、CPU 和内存。

## 参考资料

- [当前项目 eBPF 入站文档](/zh/configuration/inbound/ebpf/)
- [当前项目 TUN 入站文档](/zh/configuration/inbound/tun/)
- [透明入站基准协议](/manual/misc/interception-benchmark/)
- [Android tethering BPF TC 优先级](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/main/Tethering/src/com/android/networkstack/tethering/BpfUtils.java)
- [dae 工作原理](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/how-it-works.md)
- [dae 内核要求](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/README.md#linux-kernel-requirement)
- [dae eBPF 数据面实现](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/control/kern/tproxy.c)
