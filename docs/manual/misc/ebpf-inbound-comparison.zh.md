# sing-box eBPF 入站对比

本文是选型指南。完整的 eBPF 配置字段请参阅 [eBPF 入站配置参考]
(/zh/configuration/inbound/ebpf/)；内核配置项、运行时前提和 Linux/OpenWrt
软件包请参阅 [eBPF 入站内核要求](/zh/manual/misc/ebpf-kernel-requirements/)。

## 选择拦截路径

| 选项 | 拦截路径 | 范围 | 适合场景 |
|------|----------|------|----------|
| eBPF `local` | cgroup socket-address hook | 本机 TCP/UDP socket，可按 UID 和 Android 包名预筛选 | 使用 cgroup v2 的 root Android 或 Linux 主机 |
| eBPF `shared` | 所选接口上的 TC ingress/egress | 热点、OpenWrt LAN 等下游客户端转发流量 | 网关需要将选定客户端交给 sing-box 路由 |
| TUN + `auto_route` | 虚拟接口和用户态网络栈 | 支持平台上的广泛 IP 流量 | 通用透明代理 |
| Redirect | netfilter REDIRECT/DNAT | TCP | 简单的 Linux TCP-only 配置 |
| TProxy | netfilter TPROXY、mark 和策略路由 | TCP/UDP，保留透明 socket 语义 | 已使用防火墙策略路由的传统 Linux 路由器 |

eBPF 入站是进入 sing-box 常规路由的入口，不会把 sing-box 路由替换成内核中的
完整分流器。纯目的 CIDR 绕过可以留在 eBPF 中，其他流量进入用户态。DNS、UID、
包名和绕过语义请参阅[配置参考](/zh/configuration/inbound/ebpf/)。

## 与 dae 和 bpf2socks 对比

这些项目解决的是相关但不同的问题。dae 的对比基于
[`caa6f5e9`](https://github.com/daeuniverse/dae/commit/caa6f5e91776bc86d5b0edc940bb7d264359863c)。

| 维度 | sing-box eBPF 入站 | dae | bpf2socks |
|------|-------------------|-----|-----------|
| 主要角色 | 透明捕获并进入 sing-box | 网关分流器和内核直连数据路径 | 配合 SOCKS bridge 使用的原生 BPF 重定向核心 |
| 本机流量 | cgroup socket hook | TC 配合 cgroup metadata | 面向 Android 的原生拦截 |
| 转发流量 | 可选，在所选接口使用 TC | LAN/WAN TC 是核心路径 | 取决于所选集成方式和接口配置 |
| 策略位置 | BPF 预筛选 UID 和纯 CIDR，完整路由在 sing-box | 更多 IP、域名、端口、MAC 和进程决策可留在 BPF | 负责重定向，代理策略由 bridge 提供 |
| 运行时集成 | 直接管理 map、程序、监听器和 sing-box 路由 | 自有网关数据路径和系统集成 | 原生拦截与 SOCKS 转发分离 |
| 内核假设 | 按能力探测，不要求 BTF/CO-RE | 官方要求 Linux 5.17+ 和 BTF/CO-RE | 需按目标分支和设备内核能力判断 |

不存在始终更快的方案。直连流量比例高的网关可能受益于 dae 的内核直连决策；大多数
流量都需要进入 sing-box 的 root Android 通常更适合短路径的 cgroup 捕获。包速率、
连接速率、规则复杂度、内核 JIT 和硬件卸载的影响都大于项目名称本身。

## 使用时的限制

- 本机 cgroup 路径不会在 sing-box 监听器恢复应用源 IP，因此本机
  `source_ip_cidr` 匹配没有实际意义；仍可使用 UID 和 Android 包名策略。
- shared 模式会保留下游客户端源 IP 和源 MAC，但不会创建热点、DHCP、NAT、IPv6 RA
  或转发服务。
- 厂商内核经常单独回移 BPF 能力。请在目标设备运行
  `sing-box tools ebpf status`，不要只依赖内核版本号。

## 参考资料

- [eBPF 入站配置参考](/zh/configuration/inbound/ebpf/)
- [TUN 入站](/zh/configuration/inbound/tun/)
- [dae 工作原理](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/how-it-works.md)
- [dae 内核要求](https://github.com/daeuniverse/dae/blob/caa6f5e91776bc86d5b0edc940bb7d264359863c/docs/en/README.md#linux-kernel-requirement)
- [bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
