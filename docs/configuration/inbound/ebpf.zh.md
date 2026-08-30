---
icon: material/lan-connect
---

# eBPF

!!! quote "sing-box 1.14.0 中的更改"

    eBPF 入站仍为实验功能，仅在带有 `with_ebpf` 编译标签的 Linux 和 Android
    构建中可用。

eBPF 入站透明接管选中的本机或下游 TCP/UDP 流量，被接管的连接仍进入 sing-box
常规路由流程。所需的系统网络状态由 sing-box 自动创建并清理。

eBPF 入站不使用[监听字段](/zh/configuration/shared/listen/)。

### 结构

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "network": ["tcp", "udp"],
  "udp_timeout": "5m",
  "tc_priority": 1,
  "bypass_rule_set": [],
  "local": {
    "enabled": true,
    "data_plane": "cgroup",
    "dns_mode": "respect_policy",
    "ipv6": true,
    "bypass_private_address": true,
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": [],
    "bypass_port": [],
    "bypass_port_range": []
  },
  "shared": {
    "enabled": true,
    "data_plane": "packet_rewrite",
    "dns_mode": "respect_policy",
    "interface": ["wlan1"],
    "ipv6": true,
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "bypass_port": [],
    "bypass_port_range": []
  }
}
```

### 字段

#### network

启用的传输协议，可选 `tcp` 和/或 `udp`，默认同时启用。

#### udp_timeout

UDP 会话超时，默认 `5m`。

#### tc_priority

TC filter 优先级，范围为 1 至 65535，默认 `1`。仅在需要与相同接口上的其他 TC
filter 协调顺序时修改。
保持默认值时，支持 TCX 的内核会优先使用 TCX link；配置自定义优先级时继续使用
传统 `clsact` 挂载，以保持数值排序语义。

#### bypass_rule_set

匹配这些规则集中目标 IP CIDR 的流量绕过此入站，非 IP 规则会被忽略。

### local

#### local.enabled

启用本机产生流量的接管。只要任一路径使用了新的 `enabled` 字段，另一路径省略
`enabled` 时即视为 `false`。至少需要启用一条路径。

默认的 cgroup 数据面接管当前可见 cgroup v2 层级中的 socket，不依赖网络接口。
可选的 TC 数据面跟随系统当前默认网络接口；默认网络变化时会自动切换，没有可用默认
接口时会保留旧 attachment，待新接口准备好后切换。

#### local.data_plane

选择本机接管的数据面。默认值 `cgroup` 接管当前可见 cgroup v2 层级中的 socket；
如需在当前默认接口接管流量，应显式配置 `tc`。

#### local.cgroup_path

将 `data_plane: cgroup` 的接管范围限制到指定的绝对 cgroup v2 子树。省略时接管
当前可见的 cgroup v2 根层级及其所有子 cgroup。它不是 sing-box 服务自身 cgroup
的配置项，除非用户确实只希望接管该服务子树。

#### local.dns_mode

| 值 | 行为 |
| --- | --- |
| `hijack` | 接管已启用 TCP/UDP 协议的目标端口 53 流量。 |
| `respect_policy` | 先应用本机 UID 与包名选择，再接管目标端口 53。 |
| `off` | 不接管目标端口 53。 |

默认值为 `respect_policy`。该设置仅应用于已启用的 TCP/UDP 协议，不识别 DoH 或
DoT 流量。

#### local.ipv6

启用本机 IPv6 接管，默认 `true`。禁用后，本机 IPv6 流量绕过此入站。

#### local.bypass_private_address

绕过私有和特殊用途目标地址，默认 `true`。

#### local.include_uid

需要接管的 UID。只要配置了 include UID、UID 范围或包名，其他 UID 默认绕过。

#### local.include_uid_range

需要接管的 UID 范围，格式为 `start:end`。

#### local.exclude_uid

需要绕过的 UID。exclude 策略优先于 include 策略。

#### local.exclude_uid_range

需要绕过的 UID 范围，格式为 `start:end`。

#### local.include_android_user

需要接管的 Android 用户 ID，仅 Android。

#### local.include_package

需要接管的 Android 包名，仅 Android。

#### local.exclude_package

需要绕过的 Android 包名，仅 Android。无法区分共用同一 UID 的包。

#### local.bypass_port

绕过本机接管的目标端口。local `tc` 和 `cgroup` 两种数据面均支持；启用的
`network` 协议（TCP 和/或 UDP）分别适用。该选项只匹配目标端口。FakeIP 始终强制
接管。DNS 处理也优先于此设置：`hijack` 始终接管 53 端口，`respect_policy` 先应用
UID 策略再处理 DNS，`off` 已经绕过 DNS。配置 53 端口时 sing-box 会在启动时告警。

#### local.bypass_port_range

需要绕过的目标端口范围，格式为 `start:end`，范围包含两端端口。

### shared

#### shared.enabled

启用从配置的下游接口进入流量的接管。

#### shared.data_plane

| 值 | 行为 |
| --- | --- |
| `socket_assign` | 将选中的流量直接分配给内部透明监听器。 |
| `packet_rewrite` | 将选中的流量改写到内部 token 地址，并在下游接口恢复回复报文。默认值。 |

`packet_rewrite` 要求下游接口使用以太网帧，不使用 `socket_assign` 所需的策略路由。
两种 shared 数据面均不会创建 local TC 使用的 delivery veth。local 与 shared 数据面
可以独立选择。

#### shared.dns_mode

取值与 `local.dns_mode` 相同。`respect_policy` 模式会先应用来源 CIDR 与 MAC
选择，再接管目标端口 53。

#### shared.interface

==启用 shared 接管时必填==

客户端流量进入本机的下游接口。默认的 `packet_rewrite` 数据面要求接口使用以太网
帧；Ethernet/IPoE、raw-IP（包括 Android rmnet）、PPP/PPPoE 或 IPIP/SIT/GRE 隧道接口应显式配置
`socket_assign`。也可同时配置多个接口。暂时不存在的接口会在网络更新后重试，
当某个接口成为当前默认上游时，会停止其 shared 接管；该接口重新作为下游后自动
恢复。不接受 loopback。

#### shared.ipv6

启用 shared IPv6 接管，默认 `true`。禁用后，shared 接口上的 IPv6 流量绕过此入站。

#### shared.bypass_private_address

绕过私有和特殊用途目标地址，默认 `true`。

#### shared.include_source_cidr

需要接管的客户端来源 CIDR。列表非空时，不匹配的来源绕过。

#### shared.exclude_source_cidr

需要绕过的客户端来源 CIDR。exclude 策略优先于 include 策略。

#### shared.include_mac_address

需要接管的 48 位客户端来源 MAC 地址。

仅适用于使用以太网帧的 shared 接口。

#### shared.exclude_mac_address

需要绕过的 48 位客户端来源 MAC 地址。exclude 策略优先于 include 策略。

仅适用于使用以太网帧的 shared 接口。

#### shared.bypass_port

绕过 shared 接管的目标端口。`socket_assign` 和 `packet_rewrite` 两种 shared 数据面
均支持；启用的 `network` 协议（TCP 和/或 UDP）分别适用。该选项只匹配目标端口；
FakeIP 和 DNS 的优先级与 `local.bypass_port` 相同，配置 53 端口时会在启动时告警。

#### shared.bypass_port_range

需要绕过的目标端口范围，格式为 `start:end`，范围包含两端端口。

!!! note

    shared 模式不会启用 IP 转发，也不提供 NAT、DHCP、IPv6 路由器通告或热点管理。
    请在 Android、Linux 或路由器系统中配置这些功能。可以同时配置 Wi-Fi、USB
    网络共享等多个下游接口。

### 限制

- 一个 sing-box 实例中只能有一个启用 local 接管的 eBPF 入站；其他 eBPF 入站必须
  仅启用 shared 接管。
- 已分片的 IPv4 和 IPv6 数据报绕过接管；IPv6 atomic fragment 作为普通 IPv6
  报文处理。
- 网络变化后会自动恢复接管状态。

在供应商内核或 Android 内核上启用前，请阅读
[eBPF 内核要求](/zh/manual/misc/ebpf-kernel-requirements/)。
