---
icon: material/lan-connect
---

# eBPF

!!! quote "sing-box 1.15.0 中的更改"

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
  "fakeip_icmp": "off",
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

匹配这些规则集中目标 IP CIDR 的流量绕过此入站，非 IP 规则会被忽略。运行时更新只会
在所有已启用数据面均接受新策略后生效；此前继续保留上一份已确认策略。若更新和补偿
回滚均失败，`GET /ebpf` 会报告 `needs_attention`；此时应重启入站，使所有数据面按同一
策略重新构建。

#### fakeip_icmp

| 值 | 行为 |
| --- | --- |
| `off` | 不响应发往 FakeIP 地址池的 ICMP Echo Request，默认值。 |
| `reply` | 为发往已配置 FakeIP 地址池的 ICMP Echo Request 合成本地 Echo Reply。 |

`reply` 从不代理 ICMP：它只识别发往 FakeIP 地址池的 ICMP Echo Request，并立即
在本地原地合成 Echo Reply 作为响应，不会联系该请求 DNS 映射的真实目标。这使得
FakeIP 地址能够响应 `ping`，部分客户端以此判断目标是否可达。回复的源地址、
标识符、序列号和负载均与请求保持一致，且回复长度不会超过请求。因此该响应
反映的不是被代理目标的可达性或往返延迟，而只是本机自身的本地响应时间。

启用 `reply` 要求至少配置一个 FakeIP 前缀（IPv4 或 IPv6），并且至少存在下表中
一种可用的接管路径。若配置了 `reply` 但没有可用路径，将在启动时报错并指明不受
支持的组合，而不是静默失效。

`reply` 仅响应目标 ICMP 报文中可验证的安全子集：无选项且未分片的 IPv4，以及
前面没有扩展头的 IPv6 Echo。其余情况——包括分片报文、非 Echo 的 ICMP，或本对象
无法完整安全解析的报文——均原样放行。

##### 支持矩阵

| 数据面 | `fakeip_icmp: reply` |
| --- | --- |
| `local.data_plane: tc` | 支持 |
| `local.data_plane: cgroup` | 不支持本机流量 |
| `shared.data_plane: socket_assign` | 支持 shared 客户端 |
| `shared.data_plane: packet_rewrite` | 支持 shared 客户端 |

`local.data_plane: cgroup` 通过在报文构造之前改写 socket 目标地址来实现接管，
不挂载在任何网络接口上，因此没有可用来响应的位置——这是唯一被直接拒绝的组合。
两种 shared 数据面都会在各自的接口上挂载同一个 responder 程序（分别通过各自的
后端——`socket_assign` 用 `TCBackend`，`packet_rewrite` 用
`SharedNetworkBackend`），因此任意一种都能单独响应 shared 客户端。

只有当启用组合中仍包含 `local.data_plane: cgroup` 时，支持能力才按路径分别
计算：

- `local: cgroup` + 任一 shared 路径可以启动，但只响应 shared 客户端；本机
  cgroup 内进程产生的流量不会收到 FakeIP ICMP 回复。

本机流量需要使用 `local.data_plane: tc`。两种 shared 数据面都能响应 shared
客户端；将 `local: tc` 与任一 shared 数据面组合即可覆盖两条路径。

即使路径本身受支持，客户端仍需可用的源地址，以及能够将请求送到 responder 的路由。
在 Android 上，移动数据和 Wi-Fi 之间的上游切换可能使热点撤销全局 IPv6 前缀和
默认路由。IPv6 是否继续可用取决于设备和新的上游网络，不能仅凭连接了 Wi-Fi 就
判断 IPv6 必然失效。

`local.data_plane: tc` 在另一个方向上有对应的前提：`local_reply` 只能看到系统
路由已经将 FakeIP IPv6 前缀内的目标发送到本机 TC 接口。匹配该前缀的路由或经过
该接口的默认路由均可；没有可用路由时 sing-box 会记录警告。

### 策略优先级

程序首先处理协议选择、分片、DHCP/服务流量、自身绕过和强制安全地址绕过。随后，
FakeIP 目标会在 DNS、UID/来源、端口、主机地址、私网地址和规则集绕过策略之前被强制
接管。对于其他目标，DNS `off` 先绕过，DNS `hijack` 在 UID 或 shared 来源策略之前
接管；DNS `respect_policy` 先应用 UID/来源策略，再在端口和目标地址绕过策略之前接管。

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

在 Android 上，netd 可能在根 cgroup 使用独占 socket hook。sing-box 使用多程序
挂载且不会替换已有的独占程序，但如果 sing-box 先挂载，netd 随后重新执行独占挂载，
内核仍可能拒绝 netd。受影响的设备可改用 `local.data_plane: tc`。

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
`network` 协议（TCP 和/或 UDP）分别适用。该选项只匹配目标端口。在强制安全门槛
之后，FakeIP 始终强制接管。DNS 处理也优先于此设置：`hijack` 始终接管 53 端口，`respect_policy` 先应用
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

在 Android 上，`shared.ipv6: true` 只启用接管，不会为热点客户端分配 IPv6 地址
或发送路由器通告。普通客户端使用 shared IPv6，依赖 Android 实际向客户端提供
可用的 IPv6 地址和路由。若上游切换撤销了热点的全局前缀和默认路由，客户端的普通
IPv6 连通性可能丢失，而 link-local 通信仍可能可用。启用 `shared.ipv6` 或
`fakeip_icmp` 无法恢复这些已撤销的网络配置。

已报告的移动数据上游实测支持 shared IPv4 和 IPv6。Wi-Fi 上游下能否双栈工作，
仍取决于热点是否保留有效的 IPv6 配置和可用的交付路径，不能由上述 link-local
诊断测试推导为已验证。仅撤销 IPv6 前缀或路由不会影响 shared IPv4。

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

### 诊断

- `sing-box tools ebpf status` 探测当前内核所需的 eBPF 能力，不检查运行中的入站。
- 启用 Clash API 且至少存在一个 eBPF 入站后，`GET /ebpf` 可查看运行中的
  eBPF 入站、attachment、恢复状态、资源使用量与失败计数：

  ```
  curl -H "Authorization: Bearer $SECRET" http://127.0.0.1:9090/ebpf
  ```

### 限制

- 一个 sing-box 实例中只能有一个启用 local 接管的 eBPF 入站；其他 eBPF 入站必须
  仅启用 shared 接管。
- 已分片的 IPv4 和 IPv6 数据报绕过接管；IPv6 atomic fragment 作为普通 IPv6
  报文处理。
- 网络变化后会自动恢复接管状态。

在供应商内核或 Android 内核上启用前，请阅读
[eBPF 内核要求](/zh/manual/misc/ebpf-kernel-requirements/)。
