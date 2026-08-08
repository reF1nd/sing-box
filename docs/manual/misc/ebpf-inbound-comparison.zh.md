# sing-box eBPF 入站对比

本文对比 sing-box eBPF 入站、[dae](https://github.com/daeuniverse/dae)，以及
TUN、Redirect 和 TProxy 入站。

dae 对比基于
[`caa6f5e9`](https://github.com/daeuniverse/dae/commit/caa6f5e91776bc86d5b0edc940bb7d264359863c)。

## 数据路径

eBPF 入站提供两条相互独立的数据路径：

- 本机 cgroup 程序在应用执行 connect 或 UDP 发送/接收操作时改写套接字目的地址，
  不使用 TC 按包分类。
- 可选的 `shared_network` TC 程序改写所选下游接口的转发流量。

两条路径都会将选中的流量送入常规 sing-box 路由。`bypass_rule_set` 可以让纯目的
CIDR 流量完全留在内核。

## 与 dae 对比

两者都使用 eBPF，但目标不同。sing-box eBPF 入站是进入 sing-box 的透明入口；dae
将更完整的分流器和直连转发路径放在内核中。

| 维度 | sing-box eBPF 入站 | dae |
|------|---------------------|-----|
| 主要场景 | root Android 本机流量，以及可选热点或 Linux 网关 | Linux 路由器和网关 |
| 本机捕获 | cgroup socket-address hook | TC 数据路径配合 cgroup metadata 收集 |
| 网关捕获 | 可选，在所选下游接口使用 TC | LAN/WAN TC 是主要路径 |
| 路由策略 | 完整策略保留在 sing-box；UID 和纯 CIDR 预分流可在 eBPF 执行 | 更多 IP、域名、端口、MAC 和进程策略可以在 eBPF 执行 |
| 直连流量 | 内置绕过和 `bypass_rule_set` 命中留在内核；普通 `direct` 路由仍进入 sing-box | direct 决定可以留在内核转发路径 |
| DNS | 可捕获或绕过 53 端口，查询随后使用常规 sing-box 路由和 DNS 规则 | DNS 属于 dae 域名到 IP 分流模型的一部分 |
| 自身防回环 | TGID 快速路径，自动回退到 socket-cookie | 使用 dae 的 cgroup、socket 和 namespace 设计 |
| 系统改动 | 本机模式不需要防火墙或 TC；shared 模式只修改所选 TC hook 和 IPv4 `route_localnet` | 管理 TC、namespace 链路、sysctl 和相关 map |
| 内核基线 | 按能力探测；厂商内核差异使固定版本无法保证兼容 | 官方要求 Linux 5.17 或更高版本 |
| BTF/CO-RE | 不需要 | 需要 |
| 主要优势 | 本机捕获路径短，可以直接使用全部 sing-box 功能 | 网关直连占比较高时，内核直连路径优势明显 |
| 主要成本 | 未绕过流量仍经过 sing-box 用户态；shared 模式需要 TC 按包处理 | 所选接口全部流量经过更大的 TC/eBPF 数据路径 |

不能简单判断哪一种方案始终更快。结果取决于连接速率、包大小、代理/直连比例、
规则、内核 JIT 和硬件卸载。大量直连流量的网关更适合 dae 的内核分流；主要代理
本机应用的 root Android 更符合 sing-box cgroup 路径的设计目标。

## 与其他 sing-box 入站对比

| 入站 | 捕获方式 | 范围 | 配置 | 常见场景 |
|------|----------|------|------|----------|
| eBPF | cgroup socket hook，可选 TC | 本机 TCP/UDP 和所选下游客户端 | JSON 简单，但需要兼容的 BPF 内核、cgo 构建和 root | root Android、手机热点、特定 Linux 网关 |
| TUN | 虚拟网卡和用户态网络栈 | 跨平台的广泛 IP 流量 | 配合 `auto_route` 通常最简单 | 通用桌面、服务器和移动 VPN 应用 |
| TUN + `auto_redirect` | nftables 预分流配合 TUN | Linux TCP/UDP 和更广的 IP 流量 | 大部分配置自动管理 | 通用 Linux 透明代理的推荐路径 |
| Redirect | netfilter REDIRECT/DNAT 和 `SO_ORIGINAL_DST` | TCP | 需要外部防火墙规则 | 简单 Linux TCP 拦截 |
| TProxy | netfilter TPROXY、mark、策略路由和透明套接字 | TCP/UDP，保留原地址语义 | 最复杂 | 传统 Linux 路由器和网关 |

eBPF 本机 cgroup 路径不会在内部监听器恢复应用的源 IP，因此本机
`source_ip_cidr` 规则没有实际意义；仍可使用 UID 和 Android 包名预分流。
`shared_network` 会保留下游客户端的真实源 IP 和源 MAC。

## 内核和平台差异

本机拦截需要 cgroup v2、`CONFIG_CGROUP_BPF` 和所选协议的
connect/sendmsg/recvmsg hook。`BPF_CGROUP_INET_SOCK_RELEASE` 是可选能力，旧内核
会使用有界 UDP 兼容路径。

`shared_network` 需要 TC `sched_cls`、`clsact`、包改写和校验和 helper，并要求
所选接口向 TC 提供以太网形式的数据帧。它可以运行在 Android、标准 Linux 或
OpenWrt；只运行 TC 的网关可以设置 `cgroup_enabled: false`。

Android 和厂商内核经常单独回移 BPF 特性。请使用 `sing-box tools ebpf status`
检查目标设备，不能只根据内核版本判断兼容性。

## 选型建议

- 通用 Linux 主机优先使用 TUN、`auto_route` 和 `auto_redirect`。
- root Android 本机流量或手机热点在内核能力满足时可考虑 eBPF 入站。
- 需要丰富内核直连分流的 Linux 网关可考虑 dae。
- 简单 TCP-only Linux 配置可使用 Redirect。
- 需要传统透明套接字语义，并能接受防火墙和策略路由复杂度时使用 TProxy。

选择前应在目标设备和实际流量模型上测试。

## 参考资料

- [eBPF 入站文档](/zh/configuration/inbound/ebpf/)
- [TUN 入站文档](/zh/configuration/inbound/tun/)
- [dae 工作原理](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/how-it-works.md)
- [dae 内核要求](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/README.md#linux-kernel-requirement)
