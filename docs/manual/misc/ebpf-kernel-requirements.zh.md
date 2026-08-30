---
icon: material/linux
---

# eBPF 内核要求

eBPF 入站使用 TC 分类器、透明 socket、socket lookup 和 `bpf_sk_assign`。是否支持
由运行时能力探测决定，不使用 Linux 版本号判断。供应商内核可能回移、禁用或限制
单项能力。若 TCX link 能力可用则优先使用，否则回退兼容的 `clsact` 挂载。

## 内核配置

必须启用以下选项或供应商内核中的等价能力：

| 选项 | 用途 |
| --- | --- |
| `CONFIG_BPF` | BPF 核心支持。 |
| `CONFIG_BPF_SYSCALL` | 加载 map 和程序。 |
| `CONFIG_NET_CLS_BPF` | 在 TC hook 运行 BPF 分类器。 |
| `CONFIG_NET_SCH_INGRESS` | 提供 `clsact` ingress/egress hook。 |
| `CONFIG_NET_CLS_ACT` | 支持 direct-action 分类结果。 |
| `CONFIG_VETH` | local 和 hybrid 模式的内部 delivery 链路。 |
| `CONFIG_INET` | IPv4 TCP/UDP 和透明 socket。 |
| `CONFIG_IPV6` | 启用 local 或 shared IPv6 接管时必需。 |

强烈建议启用 `CONFIG_BPF_JIT`，否则报文路径性能可能明显下降。

## 必需的 BPF 能力

目标内核必须支持：

- TC ingress 和 egress 上的 `SCHED_CLS` 程序；
- `ARRAY`、`HASH`、`LRU_HASH` 和 `LPM_TRIE`；
- `bpf_map_lookup_elem`、`bpf_map_update_elem` 和 `bpf_map_delete_elem`；
- `SCHED_CLS` 中的 `bpf_get_socket_uid`；
- `SCHED_CLS` 中的 `bpf_redirect`；
- `SCHED_CLS` 中的 `bpf_skb_store_bytes` 和 `bpf_skb_change_head`；
- `SCHED_CLS` 中的 `bpf_skc_lookup_tcp`、`bpf_sk_lookup_udp`、
  `bpf_sk_assign` 和 `bpf_sk_release`。

TCP listener 的 SOCKMAP 是可选能力。内核能够创建 `BPF_MAP_TYPE_SOCKMAP`
且现代 TC section 能通过 verifier 时，优先使用它处理 wildcard listener；
否则加载不引用 SOCKMAP 的 legacy TC section，直接调用
`bpf_skc_lookup_tcp`。路径选择依据实际 map 创建和程序加载结果，不依据内核
版本字符串。旧内核通常需要 `CONFIG_BPF_STREAM_PARSER` 才能提供 SOCKMAP。

local 模式还要求 `SCHED_CLS` 中的 `bpf_get_socket_cookie`，用于自身绕过的
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

部分内核可能包含 LPM trie 更新缺陷。sing-box 启动时会实际更新临时 LPM map 探测，
而不是依赖版本字符串；探测失败时拒绝需要 LPM 的 UID、应用或 CIDR 策略。

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

local 模式挂载到网络管理器当前的默认接口；shared 模式挂载到配置的下游接口。
支持 Ethernet/IPoE，以及仅含 L3 的 raw-IP 或 PPP 链路；来源 MAC 策略要求接口使用
以太网帧。不支持 loopback 和无法识别的链路封装。

local attachment 会跟随默认接口变化。配置的 shared 接口存在时会自动挂载，但该接口
作为当前默认上游期间会停止 shared 接管。链路和路由事件会触发受管 attachment 与网络
状态的检查和修复，不使用周期轮询。

同一时间一个接口只能由一个 sing-box eBPF 入站管理。已有的无关 `clsact` filter
会保留，但 sing-box filter handle 或接口锁冲突会阻止启动。

本机 delivery veth 需要 `/proc/sys/net/ipv4/conf` 下对应接口的 sysctl 可写，清理
时会恢复原值。

## 探测

使用与计划配置相同的模式和协议运行内置内核探测。shared 模式应传入一个当前
存在的下游接口，以检查链路类型。

探测会针对所选协议、地址族和 shared 接口。local 模式会报告必需的 TC socket-cookie
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
