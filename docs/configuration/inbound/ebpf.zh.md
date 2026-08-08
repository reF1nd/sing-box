---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

eBPF 入站通过 cgroup 程序透明拦截本机 TCP 和 UDP 流量。可选的
`shared_network` 模式通过 TC 拦截热点或其他下游网络的转发流量。

该入站支持使用 cgo 和 `with_ebpf` 构建标签编译的 Android 与 Linux 版本，
需要 root 或等效的 BPF 和网络管理权限。

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
  "cgroup_ipv6_mode": "always",
  "redirect_address": [
    "127.128.0.0/9",
    "fd53:696e:672d:626f::/64"
  ],
  "bypass_private_address": true,
  "bypass_rule_set": [
    "geoip-cn"
  ],
  "include_uid": [],
  "include_uid_range": [],
  "exclude_uid": [],
  "exclude_uid_range": [],
  "include_android_user": [],
  "include_package": [],
  "exclude_package": [],
  "map_capacity": {
    "tcp_redirect": 65536,
    "udp_redirect": 65536,
    "socket_bypass": 65536
  },
  "shared_network": {
    "enabled": false,
    "include_interface": [],
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "tc_priority": 1,
    "map_capacity": {
      "proxy": 65536,
      "bypass": 65536,
      "fragment": 65536
    }
  }
}
```

eBPF 入站不使用[监听字段](/zh/configuration/shared/listen/)。内部重定向监听器
使用系统分配的端口，不是对外提供服务的代理端口。

### 字段

#### network

启用的网络协议，可选值为 `tcp` `udp`。

默认同时启用两者。未启用的协议会绕过该入站。

#### udp_timeout

UDP NAT 会话超时。

默认值为 `5m`。

#### dns_mode

DNS 拦截模式，可选值为：

| 值 | 行为 |
|----|------|
| `hijack` | 在目的 CIDR 绕过判断前拦截 TCP 和 UDP 目标端口 53。 |
| `off` | TCP 和 UDP 目标端口 53 保持系统原有路径。 |

默认值为 `hijack`。

该模式同时作用于本机 cgroup 和 `shared_network`。热点通常应保留 `hijack`，
除非主机已经提供独立 DNS 服务。它只负责捕获 53 端口，不等同于
`hijack-dns` 路由动作。

DHCP、自身防回环、协议选择、UID 策略和 shared-network 客户端筛选会先于
DNS 拦截执行。

#### cgroup_enabled

启用本机流量拦截。

默认值为 `true`。

关闭后必须启用 `shared_network.enabled`，并且不能配置 cgroup 专属字段。
该模式适合只运行 TC shared-network 路径的 Linux 或 OpenWrt 网关。

#### cgroup_path

需要拦截的 cgroup v2 绝对路径。

留空时使用自动探测到的 cgroup v2 根目录。

#### cgroup_ipv6_mode

本机原生 IPv6 拦截模式，可选值为：

| 值 | 行为 |
|----|------|
| `always` | 配置 IPv6 `redirect_address` 时始终拦截 IPv6。 |
| `auto` | 仅在当前网络存在可用 IPv6 路由时拦截新 IPv6 流。 |
| `off` | 不拦截原生 IPv6。 |

默认值为 `always`。

该字段不影响 IPv4、IPv4-mapped IPv6 套接字或 `shared_network` IPv6。

#### redirect_address

内部重定向监听器使用的令牌地址前缀。

每个地址族最多配置一个前缀。IPv4 必须位于 `127.0.0.0/8`，前缀长度为
`/8` 到 `/10`；IPv6 必须是 ULA `/64`。

默认值为 `127.128.0.0/9`，仅启用 IPv4。配置 IPv6 前缀后才会启用 IPv6
拦截。这些前缀是内部令牌池，不是 TUN 接口地址。

sing-box 会创建所需的本地路由，关闭时只删除由当前入站创建的路由。

#### bypass_private_address

在进入 sing-box 路由前绕过内建的私网和特殊用途目的地址范围。

默认值为 `true`。当发往私网、运营商级 NAT、链路本地、回环、多播或其他非公网
地址的流量也需要进入 sing-box 路由时，请设为 `false`。该选项同时作用于本机
cgroup 和 `shared_network` 流量。

#### bypass_rule_set

目的 IP CIDR 需要绕过 eBPF 入站的规则集列表。

只会提取目的 IP CIDR。域名、端口、进程、逻辑条件和其他规则条件不会被
eBPF 处理，建议仅使用纯 CIDR 规则集。

命中后流量直接留在内核，不进入 sing-box 路由。规则集更新时会刷新 map；
已有流在超时前保持原有代理或绕过决定。

#### include_uid

需要拦截的进程 UID 列表。

配置 include UID 或 UID 范围后，未匹配的 UID 会绕过该入站。

#### include_uid_range

需要拦截的进程 UID 范围列表，格式为 `start:end`。

#### exclude_uid

需要绕过的进程 UID 列表。

exclude 优先于 include。Android 上始终排除 UID `1052`（`dns_tether`），
以保护系统热点 DNS 路径。

#### exclude_uid_range

需要绕过的进程 UID 范围列表，格式为 `start:end`。

#### include_android_user

允许拦截应用流量的 Android 用户 ID 列表。

仅支持启用了 `cgroup_enabled` 的 Android。

#### include_package

需要拦截的 Android 包名列表。

解析出的 UID 会与 `include_uid` 和 `include_uid_range` 合并。

#### exclude_package

需要绕过的 Android 包名列表。

解析出的 UID 会与 `exclude_uid` 和 `exclude_uid_range` 合并，exclude 优先。

包名只在启动时解析。包不存在时会记录警告，PackageManager 不可用时会拒绝启动。
安装、删除或重装相关应用后需要重启 sing-box。共享同一 Android UID 的应用无法由
eBPF 区分。

#### map_capacity

本机 cgroup 路径的内核 map 容量。

| 字段 | 用途 |
|------|------|
| `tcp_redirect` | TCP 原始目的地址状态。 |
| `udp_redirect` | UDP 重定向和流状态。 |
| `socket_bypass` | socket-cookie 回退使用的自身防回环状态。 |

每项默认值为 `65536`，允许范围为 `1` 到 `1048576`。容量越大，可保存的并发
状态越多，但会占用更多锁定内核内存。

内核支持时，sing-box 使用 TGID 自身绕过快速路径，不创建 socket-cookie map。
如果内核拒绝该路径，则自动加载 socket-cookie 回退。启动日志会显示
`self_bypass=tgid` 或 `self_bypass=socket_cookie`。

### 共享网络字段

#### shared_network.enabled

拦截所选下游接口的转发流量。

默认值为 `false`。关闭时会忽略其他所有 `shared_network` 字段。

该选项不会创建热点、网桥、DHCP、NAT、IPv6 路由通告或 IP 转发，这些服务仍由
Android、Linux 或 OpenWrt 负责。

#### shared_network.include_interface

==启用 `shared_network.enabled` 时必填==

客户端报文进入 TC ingress 的下游接口列表。

sing-box 启动时接口可以不存在；接口出现时会自动挂载，消失时会自动卸载。
不要选择 `lo`、上游接口或仅支持三层报文的接口。

如果设备使用同一个接口名承载 Wi-Fi 上游和热点流量，请使用
`include_source_cidr` 限制热点客户端网段。

#### shared_network.include_source_cidr

允许进入 shared-network 代理路径的客户端源 CIDR 列表。

非空时，未匹配的客户端会绕过该入站。如果只配置一个地址族，另一个地址族不会
被拦截。

#### shared_network.exclude_source_cidr

需要绕过的客户端源 CIDR 列表。

exclude 优先于 include。

#### shared_network.include_mac_address

允许进入 shared-network 代理路径的客户端源 MAC 地址列表。非空时，未匹配的客户端
会绕过该入站。

MAC 地址直接从 TC 以太网头读取，并传递给 `source_mac_address` 路由和 DNS 规则。

#### shared_network.exclude_mac_address

需要绕过的客户端源 MAC 地址列表。

exclude 优先于 include。MAC 地址可以随机化或伪造，不能作为身份认证手段。

#### shared_network.tc_priority

ingress 和 egress 使用的 TC filter 优先级。

默认值为 `1`。Android 建议保留默认值，使 sing-box 先于系统热点 offload filter
执行。Linux 和 OpenWrt 可以根据已有 TC filter 使用 `1` 到 `65535` 的其他值。

#### shared_network.map_capacity

shared-network 路径的内核 map 容量。

| 字段 | 用途 |
|------|------|
| `proxy` | 代理流的令牌、监听器和回包状态。 |
| `bypass` | 已缓存的绕过流决策。 |
| `fragment` | IPv4 与 IPv6 分片关联状态。 |

每项默认值为 `65536`，允许范围为 `1` 到 `1048576`。

### 共享网络行为

shared-network 对新流按以下顺序执行策略：

1. 源 MAC exclude/include。
2. 源 CIDR exclude/include。
3. DHCP 绕过。
4. `dns_mode`。
5. 分配给本机的地址。
6. 启用 `bypass_private_address` 时的内建私网和特殊用途目的地址。
7. `bypass_rule_set` 目的 CIDR。

DHCP 端口 67、68、546 和 547 始终绕过。选中的 TCP 和 UDP 流量会被改写到
内部令牌地址，回包由 TC egress 恢复。下游客户端的真实源 IP 和源 MAC 会保留在
路由 metadata 中。

IPv4 shared-network 会在挂载期间启用接口的 `route_localnet`。IPv6 需要在
`redirect_address` 中显式配置 IPv6 `/64`。

选中的 TCP 和 UDP 流支持 IPv4 与 IPv6 分片，首片会建立双向改写状态。先于首片
到达的后续片，或者首片状态超过 30 秒后才到达的后续片会被丢弃，避免绕过代理
策略进入直连路径。

所选接口必须向 TC 提供以太网形式的数据帧。绕过 TC 的 XDP、硬件流量卸载或厂商
热点卸载无法被拦截。

### 内核要求

部署前建议运行内核能力探测：

```sh
sing-box tools ebpf status --mode local
sing-box tools ebpf status --mode shared-network --interface br-lan
```

也可以单独运行 `common/ebpf/check-kernel.sh`。

| 数据路径 | 必需能力 |
|----------|----------|
| 全部 | BPF syscall、所需 map 类型、足够的锁定内存，以及 BPF/网络管理权限。 |
| 本机 cgroup | cgroup v2、`CONFIG_CGROUP_BPF`，以及已启用协议的 connect/sendmsg/recvmsg attach type。 |
| `shared_network` | `sched_cls`、`clsact`、可写包和校验和 helper，以及 TC 管理权限。 |

`BPF_CGROUP_INET_SOCK_RELEASE` 是可选能力，旧内核会对 UDP 状态使用有界 LRU
兼容模式。TGID 自身绕过和 map lookup-and-delete 是可选性能优化。内核支持时，
batch map 操作会加快大型 UID 和 CIDR 策略更新；旧内核会自动使用逐条 map 操作。
强烈建议启用 `CONFIG_BPF_JIT`。

不能只根据内核版本判断兼容性，因为 Android 和厂商内核经常单独回移 eBPF 特性。
目标内核能否成功加载程序才是最终判断标准。

### OpenWrt

OpenWrt 可以同时运行两条数据路径，也可以设置 `cgroup_enabled: false`，只运行
`shared_network`。

shared-network 通常需要 `kmod-sched-core` 和 `kmod-sched-bpf`，具体包名可能随
版本变化。如果硬件流量卸载绕过所选 TC hook，需要将其关闭。构建时应使用与目标
架构和 libc 匹配的 OpenWrt SDK/工具链。

目标设备运行时不需要 Clang、`tc`、`bpftool`、libbpf 或 libelf；`tc` 和
`bpftool` 仅用于诊断。

### 构建

启用 cgo，并在常规构建标签后添加 `with_ebpf`：

```sh
CGO_ENABLED=1 \
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf" \
make build
```

Android 构建还需要设置 `GOOS`、`GOARCH` 和 Android NDK 编译器。构建主机需要
支持 BPF target 的 Clang 和 Linux UAPI 头文件。生成的 BPF 对象会嵌入二进制，
不提交到 Git。

### 鸣谢

感谢 [Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks)
提供本入站最初参考的 eBPF 拦截实现。
