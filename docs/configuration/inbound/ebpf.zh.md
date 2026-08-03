---
icon: material/lan-connect
---

eBPF 入站通过 cgroup socket-address 程序拦截本机产生的 TCP 和 UDP 流量。
可选的 `shared_network` 模式通过 TC 令牌改写，代理来自指定下游接口的转发流量；
不使用 TUN、TProxy、iptables、skb mark、策略路由、loopback TC、socket assignment
或 SOCKS 中间层。

此入站用于以 root 权限直接运行 Android 或 Linux 原生 sing-box 二进制的场景。
构建时必须启用 cgo 和 `with_ebpf` 构建标签。

### 结构

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",

  "network": "",
  "udp_timeout": "5m",
  "dns_mode": "hijack",
  "cgroup_enabled": true,
  "cgroup_path": "",
  "redirect_address": [
    "127.128.0.0/9",
    "fd53:696e:672d:626f::/64"
  ],
  "bypass_rule_set": [
    "geoip-cn"
  ],
  "include_uid": [],
  "include_uid_range": [],
  "exclude_uid": [],
  "exclude_uid_range": [],
  "map_capacity": {
    "tcp_redirect": 65536,
    "udp_redirect": 65536,
    "socket_bypass": 65536
  },
  "shared_network": {
    "enabled": false,
    "include_interface": [],
    "map_capacity": 65536
  }
}
```

eBPF 入站不提供 [监听字段](/zh/configuration/shared/listen/)。本机 cgroup 和
`shared_network` 数据路径分别使用独立的内部通配 listener，并由系统各自随机
分配端口。这些 listener 是重定向端点，并非公开代理服务器；启动日志会显示实际
端口，但用户不能配置。

### 字段

#### network

监听的网络协议，`tcp` `udp` 之一。

默认所有。

未被 `network` 选中的协议会绕过 eBPF 入站。

`shared_network` 在 `dns_mode` 为 `hijack` 时必须启用 UDP，因为热点 DNS
由代理处理。

#### udp_timeout

本机及 `shared_network` 被拦截 UDP 流量的 NAT 会话超时。

默认值为 `5m`。

#### dns_mode

DNS 处理模式。可选值：

| 模式 | 行为 |
|------|------|
| `hijack` | 在目标地址及 `bypass_rule_set` 检查之前拦截 TCP/UDP 目标端口 53。 |
| `off` | 始终放行 TCP/UDP 目标端口 53。 |

默认值为 `hijack`。

此模式只作用于 `network` 已启用的协议。socket 保护、UID 包含/排除策略、Android
`dns_tether` 排除及 DHCP 安全绕过仍先于 DNS 处理执行。`hijack` 模式下，目标端口
53 随后优先于未指定、本机、私网、多播及 `bypass_rule_set` 目标检查，避免 DNS
服务器地址恰好位于绕过 CIDR 中时查询绕过 sing-box 而泄露。

同一模式也作用于 `shared_network`。热点场景建议保持默认的 `hijack`；只有主机已
提供可用的独立 DNS 服务，并且明确希望热点 DNS 不经过 sing-box 时才应使用 `off`。
`off` 模式不会代理热点 DNS，如果没有独立 DNS 路径，查询可能泄露或失败。

关于该选项的数据路径、性能边界以及与 dae、TUN、Redirect 和 TProxy 的区别，参阅
[eBPF 入站实现对比](/zh/manual/misc/ebpf-inbound-comparison/)。

#### cgroup_enabled

是否通过 cgroup 程序拦截本机产生的流量。

默认值为 `true`。关闭时必须启用 `shared_network.enabled`；sing-box 不会探测
cgroup2、加载或挂载 cgroup 程序、打开本机 redirect listener，也不会注册 socket
protector。这样，缺少 cgroup 支持的 Linux 网关仍可只运行 TC shared-network 数据
路径。

关闭后不能配置 `cgroup_path`、UID 策略字段及顶层 `map_capacity`。
`bypass_rule_set` 仍然可用，并会写入 standalone shared-network backend 自己持有的
bypass map。

#### cgroup_path

需要拦截其本机流量的 cgroup v2 层级绝对路径。留空时，sing-box 自动发现
cgroup2 挂载点并使用其根层级。在标准 Linux 上，如不希望拦截系统全部本机流量，
可把指定服务放入专用 cgroup 并配置此路径。此字段不限制 `shared_network`
选中的转发流量。

#### map_capacity

本机流量使用的内核 map 容量。`tcp_redirect` 控制 TCP 重定向状态；
`udp_redirect` 同时控制 UDP 重定向、connected token、peer，以及可选的无连接 flow
map；`socket_bypass` 控制受保护出站 socket 的 cookie map。

各字段默认值均为 `65536`，允许范围为 `1` 到 `1048576`。较大的容量可以容纳更多
并发状态，但会消耗更多锁定的内核内存。修改会在重启该入站后生效。redirect map
过小会拒绝新流量；`socket_bypass` map 过小则可能淘汰仍在使用的受保护 socket，
造成自身流量被再次拦截。

#### include_uid

需要拦截的进程 UID 列表。

当 `include_uid` 或 `include_uid_range` 非空时，未被这两个字段匹配的 UID
产生的流量会绕过 eBPF 入站。

#### include_uid_range

需要拦截的进程 UID 范围列表，格式为 `start:end`。

#### exclude_uid

需要绕过的进程 UID 列表。

exclude 规则的优先级高于 include 规则。

在 Android 上始终自动排除 UID `1052`（`dns_tether`），避免平台热点 DNS 服务
和热点客户端的回包进入本机 cgroup 重定向；此排除不依赖 `shared_network`。

#### exclude_uid_range

需要绕过的进程 UID 范围列表，格式为 `start:end`。

UID 规则匹配执行 socket 操作的进程有效 UID。UID 范围会被压缩为 eBPF LPM
trie 条目，不会展开为逐 UID 条目。

#### bypass_rule_set

目标 IP CIDR 条目需要绕过 eBPF 入站的规则集列表。

启动时，sing-box 调用现有的规则集 CIDR 提取接口，将结果合并到 IPv4 和 IPv6
eBPF LPM trie map。目标地址命中任一 map 时，cgroup 程序保持原始目标不变；
应用 socket 直接使用内核网络栈，不会进入 eBPF listener、嗅探、普通路由规则
或出站。

此字段执行的是 CIDR 提取，并不执行完整规则集匹配。仅提取目标 `ip_cidr` 和
二进制 IP set 条目；eBPF 程序不会判断域名、端口、网络、进程、来源、逻辑分组
或反选条件。特别是，当 `ip_cidr` 与其他条件组合时，CIDR 仍会被单独提取，
其他条件不会保留。因此，此字段应只引用纯 CIDR 规则集。

多个规则集及其中提取出的所有 CIDR 按并集合并。选择 `direct` 出站的普通
路由规则不会自动下沉；只有此处显式列出的规则集会启用内核直连绕过。

引用的本地或远程规则集重新加载后，sing-box 会再次提取 CIDR 并原地更新 map，
无需重新加载或挂载 eBPF 程序。若更新无法应用，会记录错误并保留上一次成功
应用的策略。

`shared_network` 会使用同一批提取出的 CIDR。启用本机 cgroup 拦截时，TC 程序复用
cgroup bypass map；`cgroup_enabled: false` 时，standalone shared-network backend
会创建并维护等价的 map。匹配的转发报文保留普通内核转发路径，不进入 shared
redirect listener。

#### redirect_address

将被拦截连接重定向到 sing-box listener 时使用的内部地址前缀。

每个地址族最多配置一个前缀。配置 IPv4 前缀会启用 IPv4 拦截，配置 IPv6
前缀会启用原生 IPv6 拦截，同时配置两者则启用双栈拦截。IPv4-mapped IPv6
socket 按 IPv4 处理。

省略时使用 `127.128.0.0/9`，且仅启用 IPv4 拦截。IPv4 前缀必须位于
`127.0.0.0/8` 内，并使用 `/8` 到 `/10`；IPv6 前缀必须位于 ULA
`fc00::/7` 内，并使用 `/64`。

这些前缀是流量令牌地址池，并不是 TUN 入站所使用的接口子网。无连接 UDP 根据
原始地址、端口和协议确定性生成稳定的主机令牌，发往同一目的地的后续数据包会
复用已有 map 条目。TCP、已连接 UDP，以及内核支持 flow cache 时的无连接 UDP
还会把 socket `SO_COOKIE` 混入令牌，避免发往同一目的地的并发 socket 错误共享
生命周期状态。

TCP 和 UDP 使用由 `map_capacity` 分别配置容量的 redirect map。支持 cgroup
socket-release 的内核不会淘汰或覆盖已有条目；令牌冲突时最多执行四次确定性探测，
map 容量耗尽时会拒绝新流量，而不会将其错误路由到其他目的地。较大的前缀可使热路径
通常只需一次探测。
默认值使用 IPv4 回环范围中较少被显式使用的后半段，同时保留 23 位令牌空间；IPv6
示例使用 sing-box 专用的 ULA 前缀。安装本地路由前，sing-box 会拒绝与非 loopback
接口地址或主路由表中非默认路由重叠的前缀。

redirect 条目会按照实际所有者回收。TCP listener 读取原始目的地址后立即删除对应
条目；无连接 UDP 条目在 sing-box UDP NAT 会话之间进行引用计数，并在最后一个
会话关闭时删除；已连接 UDP 以 socket cookie 保存 redirect 令牌，并在应用 socket
关闭时由 cgroup socket-release 程序删除 redirect、令牌和 peer cache 条目。UDP
socket 重新 connect 时，也会先删除此前的已连接映射再安装新映射。

内核支持 cgroup socket-release 时，无连接 UDP 还会使用以
`(socket cookie, destination)` 为键的 LRU flow cache。命中后会在 CIDR bypass
策略判断之前复用已有令牌，因此活跃代理流不会在 rule-set 重载时切换决策。sing-box
UDP NAT 会话达到 `udp_timeout` 后，flow cache 与 redirect 条目会一起删除；下一包会
按最新策略重新判定。

对于不支持 cgroup socket-release 的旧内核，sing-box 会在启动时自动探测并跳过该
可选程序，同时对 UDP redirect 和 socket-token map 使用 LRU 兼容模式，避免陈旧的
已连接 UDP 条目永久耗尽 map。该模式会记录一次警告；在 map 压力很高时，活跃 UDP
条目可能被提前淘汰。TCP-only 配置不会探测或要求 socket-release。兼容模式会关闭
无连接 UDP flow cache，避免两张独立 LRU map 的淘汰顺序产生缺少 redirect 条目的
悬空令牌。

sing-box 会在当前网络命名空间中，通过 loopback 接口为每个配置前缀自动添加
`RTN_LOCAL` 路由。若已有本地路由能够覆盖该前缀则直接复用；关闭时只删除由
当前入站创建的路由。

除 `dns_mode: hijack` 下的目标端口 53 外，本机 cgroup 路径始终绕过未指定、回环、
多播以及当前本机接口网段，并在网络变化后刷新这些网段。UDP 端口 67、68、546
和 547 也始终绕过。因此，只开启 eBPF 入站而不开启 `shared_network` 时，不会挂载
TC、修改 `route_localnet`、代理热点客户端，也不会干扰热点 DHCP/DNS。

同一 cgroup 层级同时只能由一个 eBPF 入站管理。sing-box 会在入站生命周期内
独占锁定配置的 cgroup 目录。只有成功取得该锁后，才会清理由异常退出遗留的
sing-box eBPF 程序，因此启动第二个实例不会卸载仍在运行的实例所挂载的程序。

在支持的内核上，connect 和 sendmsg 程序会先比较当前 TGID 与 sing-box 进程，匹配
时立即绕过。socket-cookie 机制仍会处理属于其他 TGID 的受保护 socket。如果任一
必需的 cgroup attach type 被内核 verifier 拒绝使用 TGID helper，sing-box 会自动
重新加载原有的纯 cookie 程序。启动日志会按实际加载路径显示
`self_bypass=tgid` 或 `self_bypass=socket_cookie`。

在 cookie 路径中，sing-box 会把自身创建的 socket 的 `SO_COOKIE` 登记到 eBPF LRU
map；cgroup 程序在重定向前查询此 map，从而避免 sing-box 的出站连接和 UDP listener
再次被捕获。recvmsg 程序仍执行正常的源地址恢复，不应用 TGID 绕过。

对于本机重定向连接，sing-box 会保留 socket 的源端口，并使用发起连接的 UID 查询
原目标路由，以路由首选源地址替换 listener 所见的 loopback 源 IP。这使
`source_ip_cidr` 路由规则和 Clash API metadata 保持有效，也能适配 Android 的 UID
策略路由。如果路由查询失败，连接不会被拒绝，而是继续使用 listener 观察到的
loopback 源地址。显式绑定的非 loopback 源地址会原样保留。

#### shared_network

用于热点或其他共享下游网络的可选转发代理。关闭或省略时，不会创建共享 listener、
`clsact` qdisc、TC filter 或修改 sysctl。

此模式同时支持 Android 和标准 Linux。在标准 Linux 上，它为已有路由 LAN、无线 AP
或网关后的客户端提供 TC 透明代理；它本身不会创建下游网络，也不会自动把主机配置成
路由器。

启用后，`include_interface` 必须列出一个或多个 Ethernet-like 下游接口。不要选择
`lo`、上游接口或 TUN、WireGuard、PPP、IPIP 等纯三层设备。接口可以在启动时尚未
出现；此时 eBPF 入站会正常启动并等待，不启用 shared 数据面。已挂载的接口消失后，
sing-box 会卸载其状态，同时保持本机 eBPF 入站运行；同名接口重新出现后会自动重新
挂载。sing-box 会复用自身的网络变化监控器并立即同步接口列表；仅当平台未提供该
监控器时，才使用三秒轮询作为兼容兜底。

应选择客户端帧实际进入 TC ingress 的接口。Linux bridge 场景通常需要选择面向客户端
的各个 bridge port，而不能假定 bridge master 一定能看到这些 ingress 帧；具体 hook
路径取决于 bridge 和驱动。此模式面向客户端以本机为网关的路由下游网络，并非任意的
二层透明网桥。

对于每个已出现的接口，sing-box 先挂载 egress filter，再挂载 ingress filter，全部
就绪后才启用数据面。Ingress 把选中的 TCP/UDP 数据包目标地址和端口改写为逐流令牌
及随机 sing-box listener 端口，egress 则在回包上恢复原始源地址。原目标查询键包含
客户端地址和端口，不同热点客户端不会错误共享流状态。TCP 流状态会在路由连接关闭时
释放。UDP 流状态按客户端和令牌引用计数，并在对应 NAT 会话关闭时释放。每次释放会
一并删除原目标到令牌、回包转换及 listener 查询三张 map 中的条目。

另有一张 LRU map 用于在规则集重载前后固定 CIDR 绕过决策。被绕过的 TCP 流会保持
原决策，直到相同四元组以不同 SYN 序列号建立新连接，或其非活跃条目因 map 压力被
淘汰。被绕过的 UDP 流会在每个数据包上刷新时间戳，并在空闲达到 `udp_timeout` 后
重新判定。已代理的 TCP 和 UDP 流则分别在正常连接及 NAT 生命周期结束前保持令牌
决策。因此，规则集重载会作用于新流，而不会让活跃流在直连转发和代理之间切换。

`shared_network.map_capacity` 同时控制三张 shared 代理 flow map 和一张 LRU 绕过
决策 map。默认值为 `65536`，允许范围为 `1` 到 `1048576`；增大它会同时提高四张
map 的锁定内核内存占用。三张代理 map 使用普通 HASH 并显式清理流状态，不会像
LRU map 一样静默淘汰仍在使用的代理流。如果已选中的流无法完整创建或更新所需代理
状态，其数据包会被丢弃，不会降级为直连。

DHCP 端口 67、68、546 和 547 始终绕过 TC。`dns_mode: hijack` 下，目标端口 53
会在本机地址、私网及 `bypass_rule_set` 判断之前被捕获，包括发给热点网关的 DNS
查询；`dns_mode: off` 下，目标端口 53 始终走普通转发路径。其他本机、私网、链路
本地、多播和已配置绕过 CIDR 也仍走普通转发路径。

策略明确绕过的数据包返回 `TC_ACT_PIPE`，继续交给后续 TC filter。一旦数据包已被
选中代理，令牌分配、状态查询及报文改写失败均采用 fail-closed 行为。被选中代理的
IPv4 TCP/UDP 分片或传输层头不完整的数据包也会被丢弃，因为此时无法在不产生直连
泄漏风险的前提下透明改写。下游网络应通过合适的 MTU 和 MSS 策略避免 IPv4 分片。

IPv4 令牌使用配置的回环重定向前缀。仅当
`net.ipv4.conf.<interface>.route_localnet` 原值为关闭时，sing-box 才会临时启用，
并在 ingress、egress filter 都卸载后恢复；原本已启用的值不会被修改。IPv6 使用
配置的 ULA 令牌前缀及此入站管理的本地路由。只有 `redirect_address` 显式包含 IPv6
`/64` 时才会启用 IPv6 拦截；默认 redirect 配置仅启用 IPv4。

实现会创建或复用 `clsact`，关闭时不会删除它，因此其他 TC filter 保持不变。
使用 TC 优先级 `1`、ingress handle `0x5342` 和 egress handle `0x5343`。绕过流量
返回 `TC_ACT_PIPE` 以继续后续 filter，被捕获流量返回 `TC_ACT_OK`。数字更小的
优先级仍会先执行；sing-box 不会替换占用上述 handle 的其他 filter。

优先级 `1` 会使 sing-box 先于 Android AOSP tethering TC offload（IPv6 优先级 `2`、
IPv4 优先级 `3`）执行。Android 可以在首个连接前建立 IPv6 `/128` 转发表；如果
sing-box 排在其后，公网 IPv6 会先被直接重定向到上游。发给热点网关的 DNS 不属于
这种转发流量，因此“只能看到 IPv6 DNS、看不到后续公网 IPv6 连接”通常意味着公网
流量已被更早的 tethering offload 路径取走。

系统仍负责创建热点或 bridge、IP forwarding、IPv4 NAT、IPv6 RA/NDP、DHCP，以及
`shared_network` 关闭时使用的 DNS 服务。绕过 Linux TC 的 XDP 或硬件热点卸载无法
代理；应在每种 Android 内核上验证实际下游接口及双向流量。在标准 Linux 上还应验证
所选 bridge port 的 hook 路径，以及是否已有优先级 `1` 的 TC filter。

eBPF 入站不输出逐连接 Info 日志。启用 Clash API 后，应通过其连接视图查看源地址、
目标地址、流量和规则 metadata；启动、挂载、清理及错误日志仍会保留。
UDP packet-info、原目标查询和流清理的重复警告分别限制为每十秒最多输出一次；下次
恢复输出时会附带上一窗口中被抑制的同类警告数量。

### 内核能力探测

仓库提供了 `common/ebpf/check-kernel.sh`，用于非侵入式探测 Android、标准 Linux
和 OpenWrt 的内核能力。脚本不会挂载 BPF 程序、创建 qdisc、修改路由或 sysctl，也
不会影响流量。存在 `bpftool` 时，脚本会使用其临时 program、map 和 helper 探测，
并立即删除临时对象；否则退回读取运行内核配置、cgroup 挂载及 sysfs 状态，无法
可靠确认的能力会标记为 `UNKNOWN`。

建议以 root 运行，使探测结果与 sing-box 实际使用的权限一致：

```sh
# 只检查本机流量拦截。
sh common/ebpf/check-kernel.sh --mode local

# 检查 OpenWrt/Linux TC-only 网关及其下游接口。
sh common/ebpf/check-kernel.sh --mode shared-network --interface br-lan

# 检查 Android 的两条数据路径；热点关闭时接口不存在是正常情况。
su -c 'sh /data/local/tmp/check-kernel.sh --mode all --interface wlan2'
```

入站显式配置了 `cgroup_path` 时，应同时传入 `--cgroup PATH`。确认缺少任一必需
能力时，脚本以状态码 `1` 退出；`WARN` 表示使用兼容路径或存在运行环境问题，
`UNKNOWN` 表示只读静态探测无法可靠确认。特别是，`bpftool` 可以探测
`cgroup_sock_addr` program type，却无法在不加载 sing-box 实际程序的情况下区分
所有 connect/sendmsg/recvmsg attach subtype。因此，真实启动 sing-box 仍是 verifier
及挂载能力的最终判断。

| 数据路径 | 内核能力 | 等级 | 用途及缺失时的行为 |
|----------|----------|------|--------------------|
| 全部 | 有效的 BPF/网络管理权限、`CONFIG_BPF`、`CONFIG_BPF_SYSCALL` 及足够的锁定内存 | 必需 | 用于创建 map/program 并执行所选挂载；缺少这些基础能力时，任何 eBPF 数据路径都无法启动。 |
| 全部 | HASH、LRU HASH 和 LPM trie map | 必需 | 保存 redirect/flow 状态、有界 UDP 与自身保护缓存、UID 策略、本机接口 CIDR 和规则集 CIDR。 |
| 全部 | `CONFIG_BPF_JIT` | 性能 | 让 BPF 以本机代码执行而不是解释执行；Android 和路由器上强烈建议启用，但不影响功能正确性。 |
| 本机 cgroup | cgroup v2、`CONFIG_CGROUPS`、`CONFIG_CGROUP_BPF` 和 `cgroup_sock_addr` | 必需 | 选择本机产生的流量，并运行 connect/sendmsg/recvmsg 重定向程序。 |
| 本机 cgroup | connect4/connect6，以及启用 UDP 时的 UDP4/UDP6 sendmsg、recvmsg attach type | 必需 | 重定向 TCP/UDP 目标并恢复 UDP 原始对端。默认 IPv4 路径还会处理 IPv4-mapped IPv6 socket，因此同样使用 IPv6 attach type。 |
| 本机 cgroup | map lookup/update/delete，以及 UDP 或 cookie 回退路径所需的 socket-cookie | 必需 | 判断策略、识别 UDP socket、保护 sing-box socket 并管理 redirect 状态；UID helper 在 Linux 上取决于配置，在 Android 上则用于自动 `dns_tether` 排除。 |
| 本机 cgroup | `BPF_CGROUP_INET_SOCK_RELEASE` 和 `cgroup_sock` | 兼容回退 | 用于精确删除 connected UDP 状态，并启用未连接 UDP flow cache；不支持时使用有界 LRU map，并关闭该 cache。 |
| 本机 cgroup | `cgroup_sock_addr` 的 `bpf_get_current_pid_tgid` | 性能 | 提供 TGID 快速自身绕过；不支持时，sing-box 会重新加载使用 socket-cookie 自保护的程序。 |
| 本机 cgroup | `BPF_MAP_LOOKUP_AND_DELETE_ELEM` | 性能 | 合并 TCP 原目标查询与删除；不支持时使用独立 lookup、delete syscall，也兼容 Android 内核私有的 `ENOTSUPP` 返回值。 |
| `shared_network` | `CONFIG_NET_SCHED`、`CONFIG_NET_SCH_INGRESS`、`CONFIG_NET_CLS_ACT`、`CONFIG_NET_CLS_BPF` 和 `sched_cls` | 必需 | 建立 clsact ingress/egress 网关路径；未启用 `shared_network` 时完全不要求这些能力。 |
| `shared_network` | ARRAY/PERCPU ARRAY map，以及 sched_cls 的 map、时间、skb 写入和 checksum helper | 必需 | 保存控制/临时状态，实现 token 改写、回包恢复、流过期、DNS 劫持及校验和修复。 |
| `shared_network` | Ethernet-like 下游 TC 路径，以及 IPv4 下可写的逐接口 `route_localnet` | 必需 | 让程序解析 Ethernet 帧，并把 IPv4 token 地址路由到内部 listener。Android 热点关闭时接口暂时不存在，并不代表内核能力不足。 |

`bpftool` 只用于辅助此诊断脚本，不是 sing-box 的运行时依赖；目标设备同样不需要
编译器、libbpf 或 libelf。

### OpenWrt

OpenWrt 属于标准 Linux 支持范围，但不应假定任意官方或厂商固件都能直接使用。只需
TC 转发代理的网关可设置 `cgroup_enabled: false`；此时不要求 cgroup 支持，且
shared-network backend 会持有自己的 bypass map。只有还需要拦截本机流量时，才应
保留默认的 `cgroup_enabled: true`。

运行前应在**目标设备的实际内核配置**中确认：

- 必须启用 `CONFIG_BPF` 和 `CONFIG_BPF_SYSCALL`。当
  `cgroup_enabled: true` 时，还必须启用 `CONFIG_CGROUPS` 和
  `CONFIG_CGROUP_BPF`、挂载可写的 cgroup v2，并支持当前配置所需的 cgroup
  connect 以及 UDP sendmsg/recvmsg attach type。socket-release 可用时会用于精确
  清理，不可用时自动回退到 LRU 兼容模式。`CONFIG_BPF_JIT` 不是功能必需项，但
  路由器场景强烈建议启用。
- 使用 `shared_network` 时，还需要 `CONFIG_NET_SCHED`、
  `CONFIG_NET_SCH_INGRESS`、`CONFIG_NET_CLS_ACT` 和 `CONFIG_NET_CLS_BPF`。
  在常见 OpenWrt 版本中，这部分通常由 `kmod-sched-core` 和 `kmod-sched-bpf`
  提供；软件包名称和内置/模块状态可能随版本及厂商源码变化。
- sing-box 必须以 root 或等效权限运行，能够执行 BPF syscall、挂载 cgroup/TC
  程序、创建 map、管理本地路由和写入逐接口 `route_localnet`。procd jail、容器或
  capability 裁剪不能移除这些权限；内核还必须允许足够的锁定内存用于配置的 map。

`shared_network` 不替代 OpenWrt 的网络服务。防火墙、IP forwarding、IPv4 NAT、
DHCP、DNS 以及 IPv6 RA/NDP 仍由 firewall4、dnsmasq、odhcpd 或其他系统组件负责。
`include_interface` 应填写客户端帧实际经过 TC ingress/egress 的接口；在 DSA、
Linux bridge 和无线 AP 配置中，这可能是面向客户端的端口或 AP 接口，而不一定是
`br-lan`。应按具体驱动验证，不能只根据逻辑网络名称判断。

硬件 flow offload、NSS/PPE/shortcut forwarding、交换芯片或无线硬件加速、XDP 等
路径如果绕过所选接口的 Linux TC hook，`shared_network` 就无法捕获对应流量。遇到
只有 DNS、首包或部分连接可见时，应先关闭硬件卸载再测试；软件 flow offload 是否
保留 TC 路径也应按 OpenWrt 版本和驱动验证。IPv6 还需要正常的转发、RA/NDP，并在
`redirect_address` 中显式配置 IPv6 ULA `/64`。

为 OpenWrt 构建时应使用匹配目标架构和 ABI 的 OpenWrt SDK/toolchain，并启用 cgo
与 `with_ebpf`；动态链接的产物还必须匹配目标固件的 libc。TC eBPF 对象在构建
主机上由带 BPF 后端的 Clang 编译后嵌入二进制。目标设备运行时不依赖 Clang、
`tc`、`bpftool`、libbpf 或 libelf；`tc` 和 `bpftool` 仅对诊断有帮助。

### 构建

继续使用现有的 `make build` 目标。构建时需要启用 cgo，并在平时使用的
构建标签中追加 `with_ebpf`。例如，在 Linux 上保留 sing-box 标准构建标签：

```sh
CGO_ENABLED=1 \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

为 Android 构建时，在同一个 `make build` 目标上指定目标架构和 Android NDK
编译器：

```sh
CGO_ENABLED=1 \
GOOS=android \
GOARCH=arm64 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang" \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

当 `TAGS` 包含 `with_ebpf` 时，`make build` 会先使用 `-target bpfel` 编译 TC
程序，因此需要支持 BPF 后端的 Clang 和 Linux UAPI 头文件。生成的对象文件由 Git
忽略，不应提交。

当 `cgroup_enabled: true` 时，设备内核必须提供 cgroup2，以及 `network` 所需的
cgroup attach type。IPv4 拦截会使用 connect4，并为 IPv4-mapped IPv6 socket 使用
connect6；启用 UDP 后还会使用 UDP4/UDP6 sendmsg、recvmsg，原生 IPv6 拦截复用同一
组 IPv6 attach type。`BPF_CGROUP_INET_SOCK_RELEASE` 是可选的 UDP 生命周期优化；
不支持时会使用 LRU 兼容模式。`cgroup_enabled: false` 时不会探测上述 cgroup 能力。
进程仍需具备创建并挂载 BPF map/program 及管理本地路由的权限。`shared_network`
仅在启用时额外要求 sched_cls TC、`clsact`、IPv4 下可写的逐接口 `route_localnet`
和 `CAP_NET_ADMIN`。

### 鸣谢

感谢 [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
项目提供了本入站所基于的原始 eBPF 流量拦截实现。
