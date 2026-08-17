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
  "dns_mode": "hijack",
  "bypass_rule_set": ["geoip-cn"],
  "local": {
    "cgroup_path": "",
    "ipv6_mode": "auto",
    "bypass_private_address": true,
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": [],
    "state_capacity": 0
  },
  "shared": {
    "interface": [],
    "ipv6_mode": "always",
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "state_capacity": 0,
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

### dns_mode

控制目标端口 53 与绕过策略的顺序：

| 值 | 行为 |
|----|------|
| `hijack` | 在私网和规则集绕过前拦截 DNS。 |
| `respect_bypass` | 先执行私网和规则集绕过，再决定是否拦截 DNS。 |
| `off` | 不拦截目标端口 53。 |

默认值为 `hijack`。UID、协议、自身防回环、DHCP 和 shared 客户端筛选仍然
先于 DNS 策略执行。此选项只捕获 TCP/UDP 53 端口，不等同于路由规则中的
`hijack-dns` 动作。shared 模式启用 DNS 拦截时必须启用 UDP。

### bypass_rule_set

目的 IP CIDR 需要绕过 eBPF 入站的规则集。只提取 CIDR；域名、端口、进程和
其他条件不会在内核中求值。规则集更新时会刷新 map，已有流在过期前保持原决定。

配置 FakeIP DNS 服务器时，其 IPv4/IPv6 分配范围会在私网和规则集绕过之前强制
进入代理。这也保证 `local.ipv6_mode` 为 `auto` 且本机暂时没有可用原生 IPv6
路由时，FakeIP IPv6 仍可被拦截。UID、包名、shared 来源、协议、自身防回环和
本机真实地址的精确匹配仍然优先。FakeIP 与规则集 CIDR 重叠会在启动时告警；
若它与未指定地址、回环、多播或内部重定向范围冲突，启动会直接拒绝该配置。

### local

#### local.cgroup_path

要拦截的 cgroup v2 绝对路径。留空时自动使用 cgroup v2 根目录。
同一个 cgroup 路径同时只能由一个 eBPF 入站管理。

#### local.ipv6_mode

| 值 | 行为 |
|----|------|
| `auto` | 仅在存在可用原生 IPv6 路由时拦截新 IPv6 流。 |
| `always` | 始终启用原生 IPv6 拦截。 |
| `off` | 不拦截原生 IPv6。 |

默认值为 `auto`。IPv4-mapped IPv6 socket 仍按 IPv4 处理。该选项不影响
shared 数据路径的 IPv6；shared 使用独立的 `shared.ipv6_mode`。
普通原生 IPv6 仍遵循路由可用性探测；配置的 FakeIP IPv6 不受该门控影响，
避免 DNS 已合成 FakeIP 地址却被 eBPF 绕过而形成不可达路径。

#### local.bypass_private_address

是否在 local 数据路径绕过内建私网、运营商级 NAT 和链路本地目的地址，默认值
为 `true`。设置为 `false` 不会关闭协议、自身防回环、DHCP、未指定地址、回环、
多播和本机真实地址精确匹配等安全绕过。在 `dns_mode: "hijack"` 下，目标端口
53 会先于目的地址绕过处理。

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

#### local.state_capacity

本机重定向、UDP flow 和 socket-cookie 回退状态的容量。`0` 使用实现默认值
（当前为 65536）；允许范围为 `0` 到 `1048576`。增大会占用更多锁定内核内存。

### shared

shared 模式不会创建热点、DHCP、NAT、IPv6 RA 或 IP 转发，这些仍由系统负责。

#### shared.interface

==shared 或 hybrid 模式必填==

客户端报文进入 TC ingress 的下游接口。接口可在启动后出现或消失，sing-box
会自动挂载和卸载。不要选择 `lo`、上游接口或仅支持三层报文的接口。热点与
Wi-Fi 上游共用接口名时，应使用源 CIDR 或 MAC 筛选客户端流量。

#### shared.ipv6_mode

| 值 | 行为 |
|----|------|
| `always` | 始终拦截所选下游接口的 IPv6 流量。 |
| `off` | 不拦截 shared 数据路径的 IPv6 流量。 |

默认值为 `always`，保持旧版本行为。`off` 不会阻断 IPv6；系统能够转发 IPv6
时，这些流量会绕过 sing-box。shared 不使用本机原生 IPv6 路由探测，因为无法
从主机默认 IPv6 路由准确推断下游 IPv6 和代理出口是否可用。

#### shared.bypass_private_address

是否在 shared 数据路径绕过内建私网、运营商级 NAT 和链路本地目的地址，默认值
为 `true`，与 `local.bypass_private_address` 相互独立。设置为 `false` 后，仍会
保留 IPv4 未指定地址范围（`0.0.0.0/8`）、完整 IPv4 回环范围
（`127.0.0.0/8`）、IPv6 未指定地址和回环地址，以及 IPv4/IPv6 多播目的地址；
分配给本机的精确地址也始终绕过。`dns_mode: "hijack"` 下，目标端口 53 继续保持
文档所述的兼容优先级。

#### shared.include_source_cidr

允许进入代理路径的客户端源 CIDR。非空时，未匹配流量绕过。

#### shared.exclude_source_cidr

需要绕过的客户端源 CIDR，优先于 include。

#### shared.include_mac_address

允许进入代理路径的 48-bit 客户端源 MAC。

#### shared.exclude_mac_address

需要绕过的客户端源 MAC，优先于 include。

#### shared.state_capacity

shared proxy、bypass 和分片状态容量。`0` 使用实现默认值：proxy 为 65536，
分片为 8192；配置 bypass rule-set 或来源策略时 bypass 为 65536，否则未使用的
bypass 缓存缩减为 1（包括显式设置容量时）。显式设置的值会应用于实际启用的
map。允许范围为 `0` 到 `1048576`。
当代理状态持续承压或 token 预留开始失败时，sing-box 会暂时缩短孤立流清理
周期以恢复容量，同时保留仍被活跃 TCP 或 UDP 会话引用的流。

#### shared.advanced.tc_priority

TC filter 优先级，有效范围为 1 到 65535，默认值为 `1`。仅在与现有 OpenWrt、
Android tethering 或其他 TC 程序协调时修改。无论优先级是否相同，一个接口只能
由一个 eBPF 入站管理。
使用默认优先级时，sing-box 会在内核支持时采用 TCX，否则自动回退到 clsact。
非默认优先级会固定使用 clsact，以确保配置的排序语义仍然有效。

### 内核兼容性

shared 模式和仅启用 TCP 的 local 模式最低兼容目标为 Linux 4.19。local UDP
还需要上游 Linux 5.2 加入的 cgroup UDP4/UDP6 recvmsg hook，因此默认同时启用
TCP/UDP 的 local 或 hybrid 配置需要 Linux 5.2，或包含相应回移的厂商内核。
Android 的主要验证目标仍为 GKI 5.10 及以上。

生成的程序只使用 BPF v1 指令集，不包含 verifier 可见的反向跳转，并且每个
程序不超过 Linux 4.19 的 4096 条指令上限。实现不依赖内核 BTF、CO-RE、
bounded-loop verifier、BPF timer、dynptr 或 kfunc。local 需要 cgroup v2 和所选
协议对应的 socket-address hook；shared 需要 `sched_cls`、报文写入及校验和
helper。TCX 作为新内核可选挂载路径使用，不可用时自动回退到 clsact。厂商内核
可能单独回移、禁用或修改某项能力，因此实际能力探测
比版本号更可靠。

local UDP 启动时会先在目标 cgroup 上执行一次无副作用的真实挂载/卸载测试，再
决定状态 map 的布局。`cgroup/sock_release` 测试成功时使用普通 Hash map，并在
每个 UDP socket 关闭时精确清理；该 hook 不可用时则改用有界 LRU map，避免旧
内核或厂商内核永久耗尽 UDP redirect 状态。启动日志会以
`udp_state_cleanup=socket_release` 或 `udp_state_cleanup=lru_fallback` 报告最终
采用的路径。

请以 root 使用与配置一致的模式和协议运行无侵入的纯 Go 探测器：

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
sing-box tools ebpf status --mode all --interface br-lan --json
```

该命令直接使用 `cilium/ebpf`，不依赖 shell、`bpftool` 或 `tc`。它只创建并立即
关闭临时探测对象，不会挂载程序，也不会修改 cgroup、qdisc、路由、sysctl 或
流量状态。
使用 `--json` 可生成适合附加到问题报告的机器可读结果。
流量路径警告会限频。如果运行期间出现本机或 shared 查询、packet-info、binding
或清理错误，关闭日志会输出一条包含完整计数的汇总诊断。

启用 Debug 日志后，入站会在启动完成、每 10 分钟以及关闭前分别输出一条 JSON
运行状态记录，其中包括：

- map 名称、类型、ID、key/value 大小、内核 memlock、当前条目数和容量；
- 已加载程序的名称、section、ID 和实际挂载查询结果；
- local UDP 清理模式，以及 TCP、UDP redirect token 预留失败计数；
- 每个 shared 接口的 ifindex，以及当前使用的 `tcx` 或 `clsact` 挂载方式；
- TCX link ID、挂载健康状态、生命周期修复计数和流量诊断计数。

`entries_known: false` 或单项中的 `error` 表示内核拒绝了该项查询，不会因此改变
拦截状态。Array map 显示固定槽位数；LRU map 只遍历 key，避免状态采集刷新其
淘汰顺序；HASH 和 LPM map 在内核支持时使用 batch lookup，旧内核会自动回退。
非 Debug 日志级别不会启动周期 reporter，也不会执行 map 扫描和挂载查询，因此
默认 Info 级别没有这部分 timer 和采集开销。

`udp_redirect_reservation_failures` 非零表示内核无法预留 redirect token；采用
Hash 的 UDP redirect/token map 达到 90% 容量后也会输出限频警告。任一信号都
是 UDP 状态承压的直接证据，反馈时应提供重启 sing-box 之前的完整 runtime-status
记录。

`sing-box tools ebpf status` 是不执行挂载的启动前能力估计；对于
`cgroup/sock_release`，应以入站启动时的真实挂载/卸载测试为准。该命令也无法
查看另一个运行中
sing-box 所持有的实时 map 和挂载状态，因为入站不会把这些对象 pin 到 bpffs。
排查运行中的拦截故障时，请提供 Debug 运行状态记录。
需要采集 Go CPU、heap、RSS、GC 和维护任务耗时时，请使用临时的
[`ebpf_debug` 排障流程](/zh/manual/misc/ebpf-troubleshooting/)。
