---
icon: material/chip
---

# eBPF 内核要求

eBPF 入站的 local 接管默认使用 cgroup v2 socket-address 数据面，shared 接管默认
使用 TC `packet_rewrite`。local 可显式选择 `socket_assign`，shared 也可显式选择保留 tuple 的
`socket_assign`。是否支持由实际 map、程序加载、helper 与挂载结果决定，
不使用最低 Linux 版本号判断。供应商内核可能回移、禁用或限制单项能力。下述 LPM
trie 安全检查是例外：受影响内核可能在探测动作本身执行时出错，因此需要保守地检查
版本范围。若 TCX link 能力可用则优先使用，否则回退兼容的 `clsact` 挂载。

## 平台部署要求

实际部署分为两种场景。两者使用相同的 eBPF 对象，但内核资源所有权、权限和链路
拓扑不同。

### 标准 Linux 与 OpenWrt

在普通 Linux 主机或 OpenWrt 路由器上，应以 root 运行 sing-box，或授予等价能力，通常
需要 `CAP_BPF` 和 `CAP_NET_ADMIN`；旧内核还可能需要 `CAP_SYS_ADMIN`。目标配置必须
提供所需的 BPF syscall、map、helper、TC classifier。local socket assignment 和 shared `socket_assign`
的 TCP/UDP 均使用专用 netns，需要 `CONFIG_NET_NS`、`CONFIG_VETH`，以及创建/切换
命名空间所需的 `CAP_SYS_ADMIN`（新内核也需要）和配置链路/路由所需的 `CAP_NET_ADMIN`。
这些机制早于 `bpf_sk_assign`，不会提高已有 socket-assignment 路径的主线内核能力门槛；
但精简固件可能缺少这些配置。不会强制要求 Netkit、`bpf_redirect_peer` 或 TCX。
local `cgroup` 还需要可见且可写的 cgroup v2 层级。如果发行版没有自动挂载，应在启动
前挂载 cgroup2；只有使用 pinned netd 或其他 pin 集成时才需要 bpffs。

OpenWrt 内核模块必须与正在运行的目标内核和架构完全匹配。根据数据面，固件通常需要
BPF、TC/scheduler classifier 和 veth 模块，常见包名包括 `kmod-bpf`、`kmod-sched-core`、
`kmod-veth`，或拆分出的 `cls_bpf`/`act_bpf` 包；实际名称随发行版和版本变化。运行时
不需要 `bpftool`、`tc`、`ip`、libbpf 或 clang 可执行文件，sing-box 直接使用 BPF syscall
和 netlink。请用与服务相同的接口、协议和数据面运行内置探测，再执行真实启动；非挂载
探测不能证明路由、qdisc、sysctl 和 LSM 权限可用。

### Root Android

拥有 root 并不等于兼容。root service 必须能看到厂商 cgroup v2 层级；只有需要与 netd
共存或恢复 hook 时才额外需要 bpffs 和 netd pin。Android SELinux 也必须允许所选 BPF、
cgroup、TC、路由和 sysctl 操作。Android 15+ 及部分
厂商内核可能在 cgroup hook 上放置 netd 单程序 owner；运行时会报告并分别选择多程序、旧式
挂载或严格识别的 netd 放行程序替换路径。可选的 socket-release 和进程追踪 hook 被拒绝时，
会回退有界 LRU 清理或用户态进程查询，不会自动判定主数据面不可用。

local socket assignment 和 shared `socket_assign` 需要厂商 netns/veth/TC 与策略路由能力，SELinux
还必须允许 `unshare`/`setns`。创建、切换和透明监听会在启动时实际验证；不支持时明确
报错，不静默退回宿主监听。local cgroup 不需要 netns、veth 或 TC。
`packet_rewrite` 要求以太网帧，`socket_assign` 支持文档中列出的 raw-IP、PPP 和隧道链路。
应使用 `sing-box tools ebpf status` 和真实启动验证设备，并记录内核版本/配置、build
fingerprint、SELinux 拒绝日志、实际挂载/清理路径和接口帧类型。

## 数据面能力概要

| 数据面 | hook 与交付方式 | 链路要求 | 主要额外要求 |
| --- | --- | --- | --- |
| local `cgroup` | cgroup v2 socket-address hook 将目标改写为 token 地址 | 不挂载网络接口 | `CONFIG_CGROUP_BPF`、connect hook，以及启用地址族的 UDP sendmsg/recvmsg hook |
| local `socket_assign` | 默认接口 egress → 专用 netns 的 veth ingress → TCP/UDP socket assignment | 以太网或受支持的 L3 帧 | netns、veth、TC classifier、私有策略路由、socket lookup/assignment 与 redirect helper |
| shared `socket_assign` | 下游 ingress → 同一专用 netns → TCP/UDP 透明监听器 | 以太网、raw-IP、PPP/SLIP 或受支持隧道 | netns、veth、TC classifier、私有策略路由和 socket lookup/assignment helper |
| shared `packet_rewrite` | 下游 ingress 改写请求，egress 恢复回复 | 仅以太网 | TC classifier、校验和/报文改写 helper 与逐 flow 状态 |

这四条路径不是按内核版本递进的能力层级。厂商内核可能支持其中一条，却在另一条的
对象加载或挂载阶段拒绝。应探测实际准备配置的路径，并以真实启动成功作为最终挂载验证。

### 主线能力门槛与验证目标

上游 Linux 5.7 才引入 `bpf_sk_assign`，因此没有相应回移的更旧内核不能使用
`socket_assign`。netns/veth 本身不会进一步抬高这一 helper 门槛；但 5.7 或更新版本
也不代表所选程序、权限和路由一定可用。可选 TCX 需要更晚的内核能力。

`cgroup` 与 `packet_rewrite` 是兼容性优先路径。库的 CI 增加受限的 4.19.325 配置：
local cgroup 和 shared `packet_rewrite` 均测试 TCP/UDP，验证 IPv4/IPv6 双向流量。
该稳定补丁版本已回移主线 5.2 引入的 cgroup UDP recvmsg hook，但不能假设所有更早的
4.19 补丁版本或厂商内核都具备它。5.4 配置覆盖 cgroup TCP/UDP（包括 connected
和 unconnected UDP）、packet rewrite 及真实回包；5.10、6.6 验证完整路径。
4.19/5.4 的必选测试遇到跳过会失败。该矩阵不是对所有厂商内核的最低版本承诺，
部署仍以所选对象加载、挂载和真实流量验证为准。

## 内核配置

必须启用以下选项或供应商内核中的等价能力：

| 选项 | 用途 |
| --- | --- |
| `CONFIG_BPF` | BPF 核心支持。 |
| `CONFIG_BPF_SYSCALL` | 加载 map 和程序。 |
| `CONFIG_NET_CLS_BPF` | 在 TC hook 运行 BPF 分类器。 |
| `CONFIG_NET_SCH_INGRESS` | 提供 `clsact` ingress/egress hook。 |
| `CONFIG_NET_CLS_ACT` | 支持 direct-action 分类结果。 |
| `CONFIG_NET_NS` | local socket assignment 与 shared socket assignment 的 TCP/UDP 监听隔离。 |
| `CONFIG_VETH` | local socket assignment 与 shared socket assignment 的双向交付链路。 |
| `CONFIG_INET` | IPv4 TCP/UDP 和透明 socket。 |
| `CONFIG_IPV6` | 启用 local 或 shared IPv6 接管时必需。 |

强烈建议启用 `CONFIG_BPF_JIT`，否则报文路径性能可能明显下降。

默认的 local `cgroup` 数据面需要 `CONFIG_CGROUP_BPF` 和 cgroup v2 挂载。sing-box
默认挂载到当前可见的 cgroup v2 根层级；可使用 `cgroup_path` 将
接管范围限制到指定子树。仅使用 cgroup local 的入站不要求 `CONFIG_VETH`、TC
qdisc、TC socket lookup 或 `bpf_sk_assign`；shared `packet_rewrite` 也不要求这些
delivery 能力，只使用配置接口和 token local route。

## 必需的 BPF 能力

任一 TC 数据面都必须支持：

- TC ingress 和 egress 上的 `SCHED_CLS` 程序；
- `ARRAY`、`HASH`、`LRU_HASH` 和 `LPM_TRIE`；
- `bpf_map_lookup_elem`、`bpf_map_update_elem` 和 `bpf_map_delete_elem`。

shared `packet_rewrite` 另外使用 `SCHED_CLS` 中的 `bpf_ktime_get_ns`、`bpf_csum_diff`、
  `bpf_skb_store_bytes`、`bpf_l3_csum_replace`、`bpf_l4_csum_replace` 和
  `bpf_skb_pull_data`、`bpf_skb_load_bytes`。

shared `socket_assign` 和 local socket assignment 则需要 `SCHED_CLS` 中的
`bpf_skc_lookup_tcp`、`bpf_sk_lookup_udp`、`bpf_sk_assign` 和 `bpf_sk_release`。
实际要求会随启用协议收敛，例如 UDP-only 不要求 TCP lookup helper。

两种 socket-assignment 路径都使用 `bpf_redirect`、`bpf_skb_store_bytes`、
`bpf_skb_change_head`、`bpf_skb_change_type` 和 `bpf_ktime_get_ns` 完成交付与返程。
只有 local socket assignment 还需要本机选择使用的 `bpf_get_socket_uid`、`bpf_get_socket_cookie`。
仅改变必要的二层封装，不改写 TCP/UDP 的 IP 地址或端口。透明回包 socket 也在专用
netns 内，代理出站拨号仍在宿主；不需要清理系统 conntrack 或修改宿主 NAT 规则。

私有回包路由使用所选接口的最小 MTU。TCP 分段及显式开启的 UDP 分片由该
命名空间的 IP 栈完成；有界、短生命周期的分片缓存把生成的 IPv4/IPv6 分片送回
客户端。这不改变外部入站分片原有的旁路策略。

local cgroup 数据面改为加载 `CGROUP_SOCK_ADDR` 的
connect4/connect6 和 UDP sendmsg/recvmsg 程序，并使用 `bpf_get_socket_cookie`、
map lookup/update/delete 与 current-UID helper。若 UDP socket-release hook 不可用，
sing-box 会加载不引用该 hook 的有界 LRU 清理变体。所选对象会在开始接管前实际加载，
因此缺少 helper 或程序类型会直接导致启动失败，而不依赖内核版本字符串。
可选的 socket-release 能力探测只使用多程序挂载，不会回退到可能替换 Android/netd
现有 owner 的无标志挂载。因此该探测被拒绝时只选择 LRU 清理变体，不会让必需的
cgroup 数据面不可用。

TCP listener 的 SOCKMAP 是可选能力。内核能够创建 `BPF_MAP_TYPE_SOCKMAP`、
实际插入 TCP 监听 socket，且现代 TC section 能通过 verifier 时，优先使用它处理 wildcard listener；
否则加载不引用 SOCKMAP 的 legacy TC section，直接调用
`bpf_skc_lookup_tcp`。路径选择依据实际 map 创建和程序加载结果，不依据内核
版本字符串。旧内核通常需要 `CONFIG_BPF_STREAM_PARSER` 才能提供 SOCKMAP。

local socket assignment 数据面还要求 `SCHED_CLS` 中的 `bpf_get_socket_cookie`，用于自身绕过的
socket-cookie map。`CGROUP_SOCK` 的 `inet_sock_create` 和 `inet_sock_release` hook
以及同一 helper 是可选优化：在进程 cgroup 独占时由内核自动写入和删除 cookie。
如果 cgroup 共享或 hook 无法挂载，sing-box 会在自己创建的 socket 上通过 control
回调登记 cookie。
`CONFIG_CGROUP_BPF`（或供应商内核中的等价能力）只在启用这个可选优化时需要。

启用 local 进程匹配时，sing-box 还会尝试使用 `CGROUP_SOCK_ADDR` 的 connect/sendmsg
hook 以及 `bpf_get_socket_cookie`、`bpf_get_current_uid_gid`。它们将 socket cookie、PID
和 UID 写入有界 map，用户态随后只读取对应的 `/proc/<pid>/exe`，不再扫描所有进程的
文件描述符。该优化挂载失败时回退现有进程搜索，不会阻止入站启动。

对象不依赖 BTF 或 CO-RE，同时生成 BPF 大端和小端版本，并避免使用有界循环，
以降低供应商 verifier 差异。

## 对象选择与挂载行为

能力检查会在启用路径前选择完整对象变体：

- TC TCP 先尝试支持 SOCKMAP 的对象，失败后回退到完全不引用 SOCKMAP 的 legacy
  对象。现代对象加载失败并不能证明 legacy section 可用，因此回退对象仍会单独通过
  verifier 验证。
- local cgroup UDP 在程序和挂载均可用时使用 socket-release 通知变体；否则选择有界
  LRU 清理变体。仅可选 release hook 被拒绝时，不应导致整个 cgroup 数据面不可用。
- TC 仅在默认优先级下优先尝试 TCX；TCX 创建不受支持时回退到自有 `clsact` filter。
  显式配置自定义优先级时直接选择 `clsact`。
- cgroup 程序先请求多程序挂载；厂商内核返回兼容错误时可回退旧式独占挂载。独占
  挂载可能替换已有单程序，也可能与 netd 后续的独占挂载冲突，因此启动诊断会明确
  报告实际采用的方式。独立的 socket-release 能力探测只使用多程序挂载，不使用该
  独占回退。

预检对象加载只证明 verifier 接受对象且 map ABI 可用，并不能证明服务有权挂载到特定
cgroup/接口、取得接口锁、安装路由、修改 sysctl 或与 Android netd 共存。这些操作只在
真实启动时执行。

所有内嵌对象均使用 Android NDK r29 Clang 21 生成，不含 BTF/CO-RE，同时提供大端与
小端版本。普通构建不会编译 C，也不需要 NDK；修改 BPF C 或 C/Go ABI 后必须重新生成
两种对象，并通过源码/对象 manifest 新鲜度检查。

## 已知 LPM trie 安全问题

Linux 6.6.0 至 6.6.46 包含一个上游 `LPM_TRIE` key 布局缺陷。在启用相关 UBSAN
检查的内核上，更新 LPM trie 可能报告越界访问，甚至导致内核 panic。上游修复提交
`bpf: Replace bpf_lpm_trie_key 0-length array with flexible array` 已包含在 Linux
6.6.47，也可能由厂商回移植。

这是 LPM 更新路径缺陷，不是 map 类型缺失。通用的 `HaveMapType(LPM_TRIE)` 探测无法
安全发现它。对于确实需要写入 LPM 项的策略，sing-box 会先检查运行内核版本，并在
BTF 中确认存在修复后的 `bpf_lpm_trie_key_u8` 布局。若内核处于受影响范围且无法
确认修复，sing-box 会在执行任何 LPM 更新前拒绝该策略。其他版本继续执行常规的
运行时 map 和更新能力检查。

只有 UID、应用、源 CIDR 或目标 bypass 策略实际包含条目时才需要这项检查。TC 对象
仍会创建空的策略 map，但不会写入。精确主机地址策略使用 `HASH` map，不受此问题
影响。后续动态更新 bypass 策略时也会重复执行同一保护。

## 权限

启动时需要足够权限执行以下操作：

- 加载 BPF map 和程序；
- 在 local 或 hybrid 模式创建和删除 veth；
- 添加和删除 `clsact` qdisc 与 BPF filter；
- 添加和删除策略路由规则与 local route；
- 修改内部 delivery 对端的 `rp_filter` 和 `accept_local`；
- 启用 `IP_TRANSPARENT` 或 `IPV6_TRANSPARENT`；
- local 自身绕过可用时挂载 cgroup socket hook；否则读取每个 sing-box socket 的
  `SO_COOKIE` 并更新 cookie map；

以 root 运行兼容性最好。仅使用 capability 时会受内核版本、发行版策略、LSM
规则和 Android SELinux 策略影响，通常需要 `CAP_NET_ADMIN`、`CAP_BPF`，旧内核
还可能需要 `CAP_SYS_ADMIN`。

运行时不依赖 `bpftool`、`tc` 或 `ip` 命令，sing-box 直接使用 BPF syscall 和
netlink。

## 接口要求

local socket assignment 模式挂载到网络管理器当前的默认接口；shared 模式挂载到配置的下游接口。
默认的 `packet_rewrite` 要求接口使用以太网帧；`socket_assign` 支持 Ethernet/IPoE
以及仅含 L3 的 raw-IP、PPP、SLIP 和 IPIP/SIT/GRE 隧道链路。来源 MAC 策略同样要求以太网帧。不支持
loopback 和无法识别的链路封装。

local attachment 会跟随默认接口变化。配置的 shared 接口存在时会自动挂载，但该接口
作为当前默认上游期间会停止 shared 接管。`shared.default_interface` 可为客户端入口与默认
上游共用同一接口的单接口旁路网关显式保留 shared attachment。链路和路由事件会触发受管
attachment 与网络状态的检查和修复；低频漂移检查还会修复未产生相应 netlink 通知的内核
状态漂移。

此模式不会增加 BPF helper 或内核版本要求，但宿主仍须另行提供 IP forwarding、同接口
防火墙转发，并在需要时配置 NAT。它不会把 Wi-Fi STA 变成热点，也无法绕过 AP 的客户端
隔离。若热点接口的上游是另一个蜂窝或 Wi-Fi 接口，则即使旧设备仍把热点接口命名为
`wlan0`，它也只是普通下游接口，不需要此模式。

同一时间一个接口只能由一个 sing-box eBPF 入站管理。已有的无关 `clsact` filter
会保留，但 sing-box filter handle 或接口锁冲突会阻止启动。

本机 delivery veth 需要 `/proc/sys/net/ipv4/conf` 下对应接口的 sysctl 可写，清理
时会恢复原值。

## 运行时策略更新

`local.bypass_rule_set` 与 `shared.bypass_rule_set` 是相互独立的策略，分别跨各自已启用
的数据面事务式应用。更新失败时回滚已经更新的后端，
只要后端状态仍可用，就通过有上限的指数退避重试。若内部回滚也失败，后端会禁用自身
并标记为需要重建，此时停止无效重试，运行时诊断报告 `needs_attention`；需要重启入站
以创建新后端。这不是流量策略意义上的“fail-closed”，而是避免继续运行 map 与控制
状态已经不一致的数据面。

## 探测

使用与计划配置相同的数据面、协议和 IPv6 设置运行内置内核探测。通过
`--local-data-plane=socket_assign|cgroup` 和
`--shared-data-plane=socket_assign|packet_rewrite` 选择具体路径；未指定对应参数表示
禁用该路径。shared 模式应传入一个当前存在的下游接口，以检查链路类型。

```sh
sing-box tools ebpf status --local-data-plane socket_assign --network tcp,udp --json
sing-box tools ebpf status --shared-data-plane packet_rewrite --interface br-lan --json
sing-box tools ebpf status --local-data-plane socket_assign --shared-data-plane socket_assign --interface wlan1 --json
```

`--mode local|shared|all` 分别选择默认的 local `cgroup`、shared
`packet_rewrite` 以及两者同时启用；可使用显式 data-plane 参数探测可选的 TC 或
`socket_assign` 路径。

local socket assignment 可使用 `--local-interface <name>` 只读检查接口状态和现有 clsact qdisc；local
cgroup 可使用 `--cgroup-path <path>` 检查指定 cgroup v2 路径，省略时检查当前进程所在的路径。
这些检查不会创建 qdisc、挂载 hook 或修改系统状态。

命令末尾会显示 `sb_` map 的一次性 occupancy 诊断；不支持安全遍历的 map 会标为
`not_applicable`。运行时状态 map 使用 `healthy`、`warning`、`degraded` 阈值；容量按当前
编译策略条目数确定的 map 使用 `configured`，填满是预期状态，不代表运行时压力；实际遍历
失败则使用 `recovery_failed`。该诊断不会在 sing-box 运行期间周期执行，也不会改变 map
或数据面。

探测会针对所选协议、地址族、数据面和 shared 接口。local socket assignment 模式会报告必需的 TC socket-cookie
helper 以及可选的 cgroup socket-cookie hook。添加 `--process-tracking` 可检查可选的
socket-address 进程追踪和 socket-release 清理能力。启动时会判断进程 cgroup 是否独占，能挂载时使用内核登记，否则启用用户态
cookie 登记路径。命令还会加载并立即关闭这些选项实际选择的 eBPF 对象，在不挂载程序的
前提下验证真实 map ABI 和 verifier 可见的程序变体。明确缺少
能力会报告 `FAIL`，安全策略
拒绝探测等无法判断的情况会报告 `UNKNOWN`；必需检查出现任一状态时命令都会以非零
状态退出。请用实际运行 sing-box 的权限重新探测。非变更型探测不会挂载 TC filter 或
cgroup hook、创建 veth、安装路由或修改 sysctl；这些操作会在启动时实际检查，失败则启动退出。
如果目标配置禁用了 IPv6，请使用 `--ipv6=false`。

## 报文限制

- 已分片的 IPv4 数据报和非 atomic IPv6 分片直接绕过；IPv6 atomic fragment
  正常处理。
- IPv6 最多解析四个 hop-by-hop、routing、destination-options 或 authentication
  扩展头，然后必须到达 TCP/UDP。
- 使用以太网帧的链路最多解析两层 VLAN 头。
- DHCP 和 DHCPv6 服务流量绕过。
- 转发流量通过 TC ingress interface 元数据绕过 local egress 路径。
- sing-box 进程通过 socket-cookie map 绕过 local 接管。进程 cgroup 可在内核 hook 中
  维护该 map；否则默认 dialer 与透明 UDP 回复 socket 只在创建时登记一次 cookie。
  纯 shared 模式不会启用自身绕过机制。
