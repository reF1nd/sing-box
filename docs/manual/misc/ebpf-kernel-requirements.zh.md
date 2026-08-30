---
icon: material/linux
---

# eBPF 内核要求

eBPF 入站的 local 接管默认使用 cgroup v2 socket-address 数据面，shared 接管默认
使用 TC `packet_rewrite`。local 可显式选择 TC，shared 也可显式选择保留 tuple 的
`socket_assign`。是否支持由实际 map、程序加载、helper 与挂载结果决定，
不使用最低 Linux 版本号判断。供应商内核可能回移、禁用或限制单项能力。下述 LPM
trie 安全检查是例外：受影响内核可能在探测动作本身执行时出错，因此需要保守地检查
版本范围。若 TCX link 能力可用则优先使用，否则回退兼容的 `clsact` 挂载。

## 内核配置

必须启用以下选项或供应商内核中的等价能力：

| 选项 | 用途 |
| --- | --- |
| `CONFIG_BPF` | BPF 核心支持。 |
| `CONFIG_BPF_SYSCALL` | 加载 map 和程序。 |
| `CONFIG_NET_CLS_BPF` | 在 TC hook 运行 BPF 分类器。 |
| `CONFIG_NET_SCH_INGRESS` | 提供 `clsact` ingress/egress hook。 |
| `CONFIG_NET_CLS_ACT` | 支持 direct-action 分类结果。 |
| `CONFIG_VETH` | local TC 的 delivery 链路。 |
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
  `bpf_skb_pull_data`。

shared `socket_assign` 和 local TC 则需要 `SCHED_CLS` 中的
`bpf_skc_lookup_tcp`、`bpf_sk_lookup_udp`、`bpf_sk_assign` 和 `bpf_sk_release`。
实际要求会随启用协议收敛，例如 UDP-only 不要求 TCP lookup helper。

只有 local TC 还使用 `bpf_get_socket_uid`、`bpf_get_socket_cookie`、
`bpf_redirect`、`bpf_skb_store_bytes`，以及 raw-IP 链路所需的
`bpf_skb_change_head`。shared-only `socket_assign` 不要求这些本机选择和 delivery helper。

local cgroup 数据面改为加载 `CGROUP_SOCK_ADDR` 的
connect4/connect6 和 UDP sendmsg/recvmsg 程序，并使用 `bpf_get_socket_cookie`、
map lookup/update/delete 与 current-UID helper。若 UDP socket-release hook 不可用，
sing-box 会加载不引用该 hook 的有界 LRU 清理变体。所选对象会在开始接管前实际加载，
因此缺少 helper 或程序类型会直接导致启动失败，而不依赖内核版本字符串。

TCP listener 的 SOCKMAP 是可选能力。内核能够创建 `BPF_MAP_TYPE_SOCKMAP`
且现代 TC section 能通过 verifier 时，优先使用它处理 wildcard listener；
否则加载不引用 SOCKMAP 的 legacy TC section，直接调用
`bpf_skc_lookup_tcp`。路径选择依据实际 map 创建和程序加载结果，不依据内核
版本字符串。旧内核通常需要 `CONFIG_BPF_STREAM_PARSER` 才能提供 SOCKMAP。

local TC 数据面还要求 `SCHED_CLS` 中的 `bpf_get_socket_cookie`，用于自身绕过的
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

local TC 模式挂载到网络管理器当前的默认接口；shared 模式挂载到配置的下游接口。
默认的 `packet_rewrite` 要求接口使用以太网帧；`socket_assign` 支持 Ethernet/IPoE
以及仅含 L3 的 raw-IP、PPP、SLIP 和 IPIP/SIT/GRE 隧道链路。来源 MAC 策略同样要求以太网帧。不支持
loopback 和无法识别的链路封装。

local attachment 会跟随默认接口变化。配置的 shared 接口存在时会自动挂载，但该接口
作为当前默认上游期间会停止 shared 接管。链路和路由事件会触发受管 attachment 与网络
状态的检查和修复，不使用周期轮询。

同一时间一个接口只能由一个 sing-box eBPF 入站管理。已有的无关 `clsact` filter
会保留，但 sing-box filter handle 或接口锁冲突会阻止启动。

本机 delivery veth 需要 `/proc/sys/net/ipv4/conf` 下对应接口的 sysctl 可写，清理
时会恢复原值。

## 探测

使用与计划配置相同的数据面、协议和 IPv6 设置运行内置内核探测。通过
`--local-data-plane=tc|cgroup` 和
`--shared-data-plane=socket_assign|packet_rewrite` 选择具体路径；未指定对应参数表示
禁用该路径。shared 模式应传入一个当前存在的下游接口，以检查链路类型。

```sh
sing-box tools ebpf status --local-data-plane tc --network tcp,udp --json
sing-box tools ebpf status --shared-data-plane packet_rewrite --interface br-lan --json
sing-box tools ebpf status --local-data-plane tc --shared-data-plane socket_assign --interface wlan1 --json
```

`--mode local|shared|all` 分别选择默认的 local `cgroup`、shared
`packet_rewrite` 以及两者同时启用；可使用显式 data-plane 参数探测可选的 TC 或
`socket_assign` 路径。

探测会针对所选协议、地址族、数据面和 shared 接口。local TC 模式会报告必需的 TC socket-cookie
helper 以及可选的 cgroup socket-cookie hook，同时报告可选的 socket-address 进程
追踪能力。启动时会判断进程 cgroup 是否独占，能挂载时使用内核登记，否则启用用户态
cookie 登记路径。明确缺少
能力会报告 `FAIL`，安全策略
拒绝探测等无法判断的情况会报告 `UNKNOWN`；必需检查出现任一状态时命令都会以非零
状态退出。请用实际运行 sing-box 的权限重新探测。非变更型探测不会挂载 TC filter、
创建 veth 或修改 sysctl；这些操作会在启动时实际检查，失败则启动退出。
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
