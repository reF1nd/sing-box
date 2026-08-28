# eBPF 入站内核要求

本文是 eBPF 入站的部署检查清单。[配置参考](/zh/configuration/inbound/ebpf/)
负责配置语义，[排障指南](/zh/manual/misc/ebpf-troubleshooting/) 负责问题报告
和诊断材料。

## 能力级别

sing-box 启动时会直接探测实际使用的能力。厂商内核可能回移某项能力而不匹配
上游版本，因此探测结果比版本号更可靠。

| 能力 | 对应 eBPF 入站功能 | 级别 |
|---|---|---|
| `CONFIG_BPF_SYSCALL` | BPF map、程序加载、helper 和 link | 所有模式必需 |
| `CONFIG_CGROUPS`、`CONFIG_CGROUP_BPF` | local 的 cgroup v2 socket-address 拦截 | `local`、`hybrid` 必需 |
| `CONFIG_INET` | IPv4 TCP/UDP 及 IPv4 BPF helper | TCP/UDP 必需 |
| `CONFIG_IPV6` | 原生 IPv6 拦截和 IPv6 报文解析 | 启用原生 IPv6 时必需 |
| `CONFIG_NET_SCHED`、`CONFIG_NET_CLS_ACT`、`CONFIG_NET_CLS_BPF`、`CONFIG_NET_SCH_INGRESS` | TC ingress/egress classifier 和 clsact 回退 | `shared`、`hybrid` 必需 |
| `CONFIG_BPF_JIT`、架构能力 `CONFIG_HAVE_EBPF_JIT` | 将 BPF 程序编译为原生指令执行 | 性能优化 |

`CONFIG_BPF` 由 `CONFIG_NET` 选择。以下符号通常由依赖自动选择：
`CONFIG_SOCK_CGROUP_DATA`、`CONFIG_NET_XGRESS`、`CONFIG_NET_INGRESS`、
`CONFIG_NET_EGRESS` 和 `CONFIG_NET_CLS`。在内建配置中，它们也应能在
`/proc/config.gz` 中看到启用状态。

本入站使用的 Hash、Array、LRUHash、LPMTrie、PerCPUArray 没有分别的可选
Kconfig 开关，均由 `CONFIG_BPF_SYSCALL` 提供。
`tools ebpf status` 报告的 map/helper 也一样。

本入站不使用 `CONFIG_BPF_STREAM_PARSER`。该选项用于为 SOCKMAP/SOCKHASH 挂载
SK_SKB stream parser/verdict；当前实现已经删除 TCP splice 路径。旧版检查结果中
该能力失败，只影响已经移除的实验优化，不影响当前 local 或 shared 拦截。
`CONFIG_BPF_LSM`、`CONFIG_BPF_EVENTS`、`CONFIG_BPF_KPROBE_OVERRIDE`、
`CONFIG_DEBUG_INFO_BTF` 和 CO-RE 同样不是必需项。

## 推荐配置片段

要同时支持 local TCP/UDP 和 shared 模式，至少使用：

```text
CONFIG_NET=y
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_NET_SCHED=y
CONFIG_NET_CLS_ACT=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_SCH_INGRESS=y
CONFIG_BPF_JIT=y
```

若需要通过 `/proc/config.gz` 查看配置，可额外启用：

```text
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
```

这两个选项只提供诊断可见性，不增加 eBPF 运行能力。

在标准 Linux 中，`CONFIG_NET_CLS_BPF` 和 `CONFIG_NET_SCH_INGRESS` 可以编译为
模块，但模块必须安装并在 shared 挂载 TC filter 前加载。Android 或固件内核建议
直接编译为 `y`。

## 版本和运行时前提

- shared 和仅启用 TCP 的 local 最低兼容目标为 Linux 4.19。
- local UDP 需要上游 Linux 5.2 加入的 cgroup UDP4/UDP6 `recvmsg` hook，或厂商
  回移。版本号较新并不能单独证明 hook 已启用。
- local 需要已挂载的 cgroup v2 文件系统，以及该挂载点下可写的路径。sing-box
  不会替你挂载或创建 cgroup 层级。
- 进程需要 root 或等效的 BPF、系统管理和网络管理权限。新内核通常对应
  `CAP_BPF`，以及内核要求时的 `CAP_SYS_ADMIN`、`CAP_NET_ADMIN`。
- shared 需要真正的 Ethernet-like 下游接口、TC 支持，以及可写的
  `/proc/sys/net/ipv4/conf/<interface>/route_localnet`。它不会提供转发、NAT、
  DHCP、热点服务或 IPv6 RA。
- 本入站不要求 `CONFIG_DEBUG_INFO_BTF`、CO-RE、`CONFIG_BPF_LSM`、tracing、
  kprobe 或 bpffs pinning。
- shared ingress 会绕过真实 IPv4 分片和非原子 IPv6 分片；shared egress 若发现
  其源地址为内部 token 地址则会丢弃，避免该地址泄漏到下游网络。IPv6 atomic
  fragment 正常解析，不需要任何分片跟踪内核能力。

检查实际内核配置：

```sh
zcat /proc/config.gz | grep -E \
'CONFIG_(NET|INET|IPV6|BPF|CGROUP|NET_SCHED|NET_CLS|NET_SCH|NET_XGRESS|SOCK_CGROUP_DATA)'
```

只有同时启用 `CONFIG_IKCONFIG` 和 `CONFIG_IKCONFIG_PROC` 时才会提供
`/proc/config.gz`；它们是诊断选项，不是 eBPF 运行时能力。

## 标准 Linux 软件包

标准 Linux 上，sing-box 不需要系统的 libbpf 或 cilium 软件包。eBPF 对象已经
随二进制发布，使用 `with_ebpf` 构建时运行时是纯 Go。

建议安装 `iproute2`，用于 `ip`、`tc` 命令以及接口、qdisc、filter、路由和策略
规则检查。只有需要底层检查或 profiling 时才安装 `bpftool`；它不是 sing-box
运行时依赖。不同发行版可能拆分为 `iproute2`、`iproute2-tc` 或
`linux-tools-common`/`linux-tools-<version>`。

## OpenWrt 软件包

shared 模式需要安装与当前 OpenWrt 内核匹配的模块包：

```sh
opkg update
opkg install kmod-sched-core kmod-sched-bpf ip-full tc-bpf
```

`kmod-sched-core` 提供 scheduler/clsact 组件，`kmod-sched-bpf` 提供 BPF TC
classifier。`ip-full` 提供完整的 `ip` 工具，`tc-bpf` 提供带 BPF 支持的 `tc`
工具，用于设置和诊断；sing-box 不会链接它们。部分 OpenWrt 版本会把这些模块直接编入内核，或采用不同的包拆分，
应使用 `opkg list` 和 `lsmod` 确认。若它们是模块，加载：

```sh
modprobe sch_ingress
modprobe cls_bpf
```

OpenWrt 仍需满足上面的内核配置和 cgroup v2 挂载要求。安装软件包不能补上缺失
的 `CONFIG_CGROUP_BPF`、TC 支持或其他被裁剪的内核能力；这些必须重新编译内核。
部分镜像提供 `cgroupfs-mount` 便捷包来挂载 cgroup v2；若 init 系统已经完成挂载，
则不需要该包。

## 验证

使用与配置路径对应的探测命令：

```sh
sing-box tools ebpf status --mode local --network tcp,udp --json
sing-box tools ebpf status --mode shared-network --interface br-lan --json
```

`required` 下的 `FAIL` 表示所选路径无法提供正常正确性保证；`performance` 下的
`FAIL` 表示优化不可用，将使用文档说明的回退路径。
