---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

eBPF 入站透明拦截本机或下游网络的 TCP/UDP 流量。`local` 数据路径使用
cgroup socket-address 程序拦截本机 socket，`shared` 数据路径使用 TC
拦截热点、路由器或其他下游接口的转发流量。

该入站只在使用 `with_ebpf` 构建标签的 Android 和 Linux 版本中可用。
运行时不需要 cgo，但需要 root 或等效的 BPF、cgroup 和网络管理权限。

!!! warning "Linux 6.6 LPM trie 兼容性"

    Linux 6.6.0 至 6.6.46 在更新 BPF LPM trie 时可能因 UBSAN 触发内核
    panic。默认 `shared_network` 的本机地址策略使用精确匹配 HASH map，
    不受影响。本机 UID/包名筛选、`bypass_rule_set` 和 shared 来源 CIDR
    筛选会写入 LPM trie，需要 Linux 6.6.47，或包含上游修复
    `896880ff30866f386ebed14ab81ce1ad3710cfc4` 的厂商内核。对于已知未修复
    的内核，sing-box 会拒绝这些策略，而不是冒险触发内核崩溃。

### 结构

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "mode": "local",
  "network": ["tcp", "udp"],
  "udp_timeout": "5m",
  "bypass_rule_set": ["geoip-cn"],
  "local": {
    "dns_mode": "respect_policy",
    "cgroup_path": "",
    "ipv6": true,
    "bypass_private_address": true,
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": []
  },
  "shared": {
    "dns_mode": "respect_policy",
    "interface": [],
    "ipv6": true,
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "advanced": {
      "tc_priority": 1
    }
  }
}
```

eBPF 入站不使用[监听字段](/zh/configuration/shared/listen/)。内部监听端口和
重定向地址前缀由 sing-box 自动分配并检查冲突。

### mode

| 值 | 数据路径 |
|----|----------|
| `local` | 仅拦截本机 cgroup 流量。 |
| `shared` | 仅拦截所选下游接口的转发流量。 |
| `hybrid` | 同时启用两条数据路径；共享规则集绕过，私网绕过则分别配置。 |

默认值为 `local`。`local` 字段只能用于 `local` 或 `hybrid`，`shared` 字段
只能用于 `shared` 或 `hybrid`。

### network

启用的网络协议，可选值为 `tcp` 和 `udp`，默认同时启用。

### udp_timeout

UDP 会话超时，默认值为 `5m`。


### bypass_rule_set

目的 IP CIDR 需要绕过 eBPF 入站的规则集。只提取 CIDR；域名、端口、进程和
其他条件不会在内核中求值。规则集更新时会刷新 map，已有流在过期前保持原决定。

配置 FakeIP DNS 服务器时，其 IPv4/IPv6 分配范围会在私网和规则集绕过之前强制
进入代理。UID、包名、shared 来源、协议、自身防回环和本机真实地址的精确匹配
仍然优先。FakeIP 与规则集 CIDR 重叠会在启动时告警；
若它与未指定地址、回环、多播或内部重定向范围冲突，启动会直接拒绝该配置。

### local

#### local.dns_mode

控制 local 数据路径对目标端口 53 的拦截顺序：

| 值 | 行为 |
|----|------|
| `hijack` | 在 local UID/包名和目的地址绕过策略之前拦截。 |
| `respect_policy` | 遵守 local UID/包名筛选；对选中主体的 DNS 忽略目的地址绕过并拦截。 |
| `off` | 在 local 用户策略之前直接放行目标端口 53。 |

默认值为 `respect_policy`。它遵守 UID/包名筛选，但选中主体的 DNS 不再受
本机地址、私网和 `bypass_rule_set` 影响。显式配置 `hijack` 还会忽略 UID/包名
筛选，对所有可见的 53 端口流量强制拦截。
自身与内部重定向防回环、协议选择、DHCP 安全放行、报文有效性以及
`local.ipv6: false` 在所有模式下仍是优先级更高的正确性门控。只处理
`network` 已启用协议的 TCP/UDP 53，因此可使用仅 TCP 或仅 UDP 的配置。
该选项不能识别 DoH/DoT，也不等同于路由规则中的 `hijack-dns` 动作。

#### local.cgroup_path

要拦截的 cgroup v2 绝对路径。留空时自动使用 cgroup v2 根目录。
每个 sing-box 进程只支持一个 `local` 或 `hybrid` eBPF 入站。所属 Box 会把
sing-box 自身创建的 socket cookie 注册到 local 绕过 map。保护范围限定在该
Box，不再使用进程全局回调；但同一 Box 中的第二个 local 后端仍会被拒绝。

#### local.ipv6

是否在 local cgroup 数据路径拦截原生 IPv6，默认值为 `true`。主机需要让原生
IPv6 绕过本入站时设为 `false`。该值在入站生命周期内保持不变，sing-box 不会
根据当前默认路由自动推断。IPv4-mapped IPv6 socket 仍按 IPv4 处理。该选项不
影响 shared 数据路径的 IPv6；shared 使用独立的 `shared.ipv6`。

#### local.bypass_private_address

是否在 local 数据路径绕过内建私网、运营商级 NAT 和链路本地目的地址，默认值
为 `true`。设置为 `false` 不会关闭普通非 DNS 流量对未指定地址、回环、多播和
本机真实地址精确匹配等安全绕过。如 `local.dns_mode` 所述，`hijack` 会在所有
目的地址绕过之前处理 53 端口。

#### local.include_uid

需要拦截的 UID。配置任意 include UID、范围或包名后，其他 UID 默认绕过。

#### local.include_uid_range

需要拦截的 UID 范围，格式为 `start:end`。

#### local.exclude_uid

需要绕过的 UID；exclude 优先于 include。

#### local.exclude_uid_range

需要绕过的 UID 范围，格式为 `start:end`。

#### local.include_android_user

需要拦截的 Android 用户 ID，仅支持 Android。

#### local.include_package

需要拦截的 Android 包名。包名在启动时转换为 UID。

#### local.exclude_package

需要绕过的 Android 包名。共享同一 UID 的包无法由 eBPF 区分。

包名策略只保证直接由目标 UID 创建的 socket。系统 DNS resolver、
`DownloadManager`、isolated process、SDK sandbox 等代应用创建的流量可能使用
其他 UID。启动日志会输出最终 include/exclude UID ranges，用于确认实际策略。

### shared

shared 模式不会创建热点、DHCP、NAT、IPv6 RA 或 IP 转发，这些仍由系统负责。

#### shared.dns_mode

控制 shared 数据路径对目标端口 53 的拦截顺序：

| 值 | 行为 |
|----|------|
| `hijack` | 在 shared 客户端和目的地址绕过策略之前拦截。 |
| `respect_policy` | 遵守 shared 来源 CIDR/MAC 筛选；对选中客户端的 DNS 忽略目的地址绕过并拦截。 |
| `off` | 在 shared 用户策略之前直接放行目标端口 53。 |

默认值为 `respect_policy`。它遵守来源 CIDR/MAC 筛选，但选中客户端的 DNS
不再受本机地址、私网和 `bypass_rule_set` 影响。显式配置 `hijack` 还会忽略
来源筛选，对所有可见的 53 端口流量强制拦截。
协议选择、DHCP 安全放行、报文有效性以及 `shared.ipv6: false` 在所有
模式下仍是优先级更高的正确性门控。只处理 `network` 已启用协议的 TCP/UDP
53；仅启用 TCP 时，shared DNS 拦截不再强制要求 UDP。该选项不能识别
DoH/DoT，也不等同于路由规则中的 `hijack-dns` 动作。

#### shared.interface

==shared 或 hybrid 模式必填==

客户端报文进入 TC ingress 的下游接口。接口可在启动后出现或消失，sing-box
会自动挂载和卸载。shared eBPF 程序和 map 只在首个已配置接口出现时加载；
接口暂时消失后仍保留 backend，避免重复执行 verifier 和 map 初始化。不要选择
`lo`、上游接口或仅支持三层报文的接口。热点与
Wi-Fi 上游共用接口名时，应使用源 CIDR 或 MAC 筛选客户端流量。

#### shared.ipv6

是否拦截所选下游接口的 IPv6 流量，默认值为 `true`。设为 `false` 不会阻断
IPv6；系统能够转发 IPv6 时，这些流量会绕过 sing-box。该值在入站生命周期内
保持不变。shared 不会根据主机默认 IPv6 路由推断下游 IPv6 或代理出口是否可用。

shared 对分片流量采用 best-effort 语义。ingress 上的所有真实 IPv4 分片（包括
设置 More Fragments 的首片）和所有非原子 IPv6 分片都会原样绕过，避免同一
数据报的一部分进入代理、另一部分直连。egress 上若真实分片的源地址属于 sing-box
内部 token 前缀，则会直接丢弃，避免把 token 地址泄漏到下游网络。IPv6 atomic
fragment 不属于真实分片，会继续按普通报文解析。

#### shared.bypass_private_address

是否在 shared 数据路径绕过内建私网、运营商级 NAT 和链路本地目的地址，默认值
为 `true`，与 `local.bypass_private_address` 相互独立。设置为 `false` 后，普通
非 DNS 流量仍会绕过 IPv4 未指定地址范围（`0.0.0.0/8`）、完整 IPv4 回环范围
（`127.0.0.0/8`）、IPv6 未指定地址和回环地址、IPv4/IPv6 多播目的地址以及本机
精确地址。如 `shared.dns_mode` 所述，`hijack` 会在所有目的地址绕过之前处理
53 端口。

#### shared.include_source_cidr

允许进入代理路径的客户端源 CIDR。非空时，未匹配流量绕过。

#### shared.exclude_source_cidr

需要绕过的客户端源 CIDR，优先于 include。

#### shared.include_mac_address

允许进入代理路径的 48-bit 客户端源 MAC。

#### shared.exclude_mac_address

需要绕过的客户端源 MAC，优先于 include。

#### shared.advanced.tc_priority

TC filter 优先级，有效范围为 1 到 65535，默认值为 `1`。仅在与现有 OpenWrt、
Android tethering 或其他 TC 程序协调时修改。无论优先级是否相同，一个接口只能
由一个 eBPF 入站管理。
使用默认优先级时，sing-box 会在内核支持时采用 TCX，否则自动回退到 clsact。
非默认优先级会固定使用 clsact，以确保配置的排序语义仍然有效。

### 内核兼容性

完整的 Kconfig、运行时和 Linux/OpenWrt 软件包清单请参阅
[eBPF 入站内核要求](/zh/manual/misc/ebpf-kernel-requirements/)。

shared 模式和仅启用 TCP 的 local 模式最低兼容目标为 Linux 4.19。local UDP
还需要上游 Linux 5.2 加入的 cgroup UDP4/UDP6 recvmsg hook，因此默认同时启用
TCP/UDP 的 local 或 hybrid 配置需要 Linux 5.2，或包含相应回移的厂商内核。
Android 的主要验证目标仍为 GKI 5.10 及以上。

生成的程序使用 BPF ISA v1，不要求 BTF 或 CO-RE。sing-box 会直接探测所需的
map、program、helper 和挂载能力，而不是只根据内核版本选择路径；新内核挂载与
batch 操作不可用时会自动回退。启动日志会以
`udp_state_cleanup=socket_release` 或 `udp_state_cleanup=lru_fallback` 报告最终
采用的 local UDP 清理路径。shared 模式始终在 ingress 使用 TC 目标 token 改写，
并在 egress 恢复源地址。

即使能力探测成功，本页开头的 Linux 6.6 LPM trie 警告仍然适用。

### 诊断

请以 root 使用与配置一致的模式和协议运行无侵入的纯 Go 探测器：

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
sing-box tools ebpf status --mode all --interface br-lan --json
```

该命令只创建并立即关闭临时探测对象，不会挂载程序，也不会修改 cgroup、qdisc、
路由、sysctl 或流量状态。使用 `--json` 可生成适合附加到问题报告的结果。

普通构建会在启动日志中报告所选清理和挂载模式，不会遍历 map 或启用全局内核
统计。临时使用 `ebpf_debug` tag 构建时，会输出详细的启动、策略和清理日志，
并按事件生成快照，其中包含 map 占用，以及内核支持时的逐程序 BPF 运行统计。
采集材料时请参阅
[eBPF 排障指南](/zh/manual/misc/ebpf-troubleshooting/)；`ebpf_debug` 不适合日常
release 构建。
