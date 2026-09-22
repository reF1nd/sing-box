---
icon: material/stethoscope
---

# eBPF 入站问题排查

问题报告应覆盖进程启动、一次完整复现和停止过程。只有启动日志通常无法解释间歇性
丢包、attachment 变化或资源持续增长。

## 按现象快速定位

| 现象 | 首要证据 | 主要区分方向 |
| --- | --- | --- |
| 启动在对象加载阶段失败 | `tools ebpf status --json`、verifier 日志、完整错误 | helper/program/map 能力缺失，或安全策略拒绝 |
| 启动在挂载阶段失败 | 启动日志、目标 cgroup/接口、SELinux/LSM 日志 | 对象受支持，但真实 hook 无权限或已被占用 |
| 启动成功但流量绕过 | `api ebpf`、attachment、filter 与放行/分片计数 | 路径/接口错误，或命中有意的策略/分片绕过 |
| UDP 间歇异常 | 首条告警、UDP NAT 计数、map 占用、网络切换时间 | 队列/map 压力、assignment 过期、release 通知丢失或上游丢包 |
| Wi-Fi/移动数据/热点切换后异常 | 切换前后运行报告、路由、链路和 TC filter | 等待新接口、受管状态恢复中，或系统热点状态已撤销 |
| CPU 或内存持续增长 | pprof、活动 UDP 会话、回复 socket 池、map 占用 | Go heap/goroutine、用户态会话抖动或内核 map 分配 |
| 设备重启或 kernel panic | `/sys/fs/pstore`、内核版本、已启用策略 | 内核 verifier/map/驱动问题，仅用户态日志不足以判断 |

不要只凭“eBPF”一词推断责任路径。local `cgroup`、local `tc`、shared
`socket_assign` 和 shared `packet_rewrite` 使用不同 hook、map、交付和清理机制。

## 最低限度材料

请提供：

1. 准确的 sing-box commit、完整 `sing-box version` 输出和编译 tags。
2. eBPF 入站配置及相关 route rules。可以删除凭据，但应保留 enabled/data_plane、接口、UID 或
   来源策略、DNS/IPv6 设置、TC priority 和绕过策略。
3. 设备型号、系统版本、完整内核版本；Android 还需 build fingerprint。
4. 从启动、复现到正常停止的 Debug 级别日志。
5. 复现步骤、预期和实际行为、受影响协议、影响本机还是下游流量，以及重启
   sing-box 后是否变化。
6. 与预期路径一致的能力探测结果：

```sh
sing-box tools ebpf status --local-data-plane cgroup --network tcp,udp --json
sing-box tools ebpf status --shared-data-plane packet_rewrite --interface br-lan --json
```

如果入站配置禁用了 IPv6，请添加 `--ipv6=false`。必需能力缺失或无法验证时，命令会以非零状态退出。

同时启用两条路径的配置可在同一条命令中传入两个 data-plane 参数。探测权限应与服务实际运行权限一致。

7. 若配置了 sing-box API 服务，还请提供 `sing-box api ebpf` 的运行实例报告（参见
   [eBPF 配置](/zh/configuration/inbound/ebpf/#诊断)）：

```sh
sing-box api ebpf --url http://127.0.0.1:9090 --secret "$SECRET"
```

这与第 6 项的能力探测不同：它报告的是运行中的入站实际在做什么（attachment、
活动 program、map 占用、待处理的恢复、最近的错误与计数器），而不是内核理论上支持什么。当问题涉及
"是否真的在接管流量"而非"内核是否支持"时，请一并提供此报告。

常用系统信息：

```sh
uname -a
cat /proc/version
cat /proc/meminfo
ip -details link show
tc -details qdisc show
tc -statistics -details filter show
```

Android 还应提供 `getprop ro.build.fingerprint` 和完整 `logcat -b all -d`；OpenWrt
还应提供 `/etc/openwrt_release` 和 `ubus call system board`。

## 内核崩溃或设备重启

重启后应在下一次崩溃覆盖内容前复制 `/sys/fs/pstore`：

```sh
ls -la /sys/fs/pstore
cp -a /sys/fs/pstore ./pstore-copy
dmesg -T > dmesg-after-reboot.txt
```

存在时请提供 `console-ramoops-*`、`dmesg-ramoops-*` 和 `pmsg-ramoops-*`，并说明
是 local、shared，还是只有网络接口变化时触发。内核记录通常比故障前提前中断的
用户态日志更有价值。

## 日志与运行状态

启动成功后会在 Debug 级别输出一条简要的 `eBPF inbound started` 摘要：启用的路径、
每个 attachment 实际挂载的接口与机制、仍在等待接口的路径，以及 `fakeip_icmp`
实际覆盖的范围。Debug 日志还会输出 `eBPF cgroup active` 或 `eBPF TC active`
摘要，其中包括选中的
数据面及实际运行路径。TC 摘要还会按需列出默认接口、
attachment、内部监听器、路由状态和 delivery 接口，每个 attachment 会标明
local/shared 角色和帧格式。网络事件仅在 attachment 或受管
网络状态发生变化时输出 Debug 日志，修复失败会输出限频的 Warn 日志。用户态 handoff
异常会输出限频后的 Warn 或 Error 日志；BPF 报文返回路径不输出逐包日志。接口生命周期
主要由事件驱动，并使用低频漂移检查修复没有产生相应通知的内核状态变化。shared
`packet_rewrite` 会在 flow 事件、释放期限或 map 压力需要时执行有界维护；这些任务
不会定期输出状态日志。

如果日志报告 assignment 或 UDP 原目标读取失败，请保留首次错误前后的完整日志，
并同时采集下文的 TC attachment 信息。

### 解读 `sing-box api ebpf`

顶层状态是运行情况摘要：

| 状态 | 含义 | 操作 |
| --- | --- | --- |
| `normal` | 所有已配置路径均已挂载，且没有待处理恢复。 | 对一次受控流量比较前后计数。 |
| `waiting_for_interface` | 已配置 TC 路径，但当前没有合适接口。 | 检查默认/下游接口选择；这本身不是恢复失败。 |
| `recovering` | 拓扑或策略错误仍可恢复，已安排重试。 | 保存 `last_error`、`next_retry_at` 和稍后的第二份快照。 |
| `needs_attention` | 协调或策略回滚无法安全继续。 | 保存诊断，然后重启入站重建状态。 |

attachment 列表是实际运行机制的准确信息。已配置路径没有对应 attachment 时，可能只是
等待接口；cgroup attachment 本来就不存在网络接口 filter。

local cgroup 还应记录 API 返回的实际运行字段：`local_cgroup_attach_mode`
（`link_create`、`legacy_multi`、`legacy_exclusive` 或 `mixed`）、
`local_udp_cleanup_mode`、`local_udp_userspace_cleanup_mode`、
`local_udp_storage_mode` 和 `local_udp_time_mode`。这些字段表示厂商内核或安全策略
触发回退后真正选中的路径，不是能力猜测。

local TC 或 shared `socket_assign` 启用时，API 还会返回 `tc_*` 运行态字段：实际
`tcx`/`clsact`/`mixed` 挂载机制、TCP listener 的 `sockmap`/`direct` 查找方式、delivery
接口及其 ifindex、策略路由 mark/table/priority、活动和待回收资源数量、健康状态、最近
health check/reconcile 时间以及网络代数。它们来自运行中的资源快照，不是按内核版本推测；
`tc_network_generation` 在受管网络切换时递增，可用于把切换前后的连接和计数分开分析。
这些字段不会触发逐包统计、map 全量扫描或新的后台定时器。

计数器通常在当前进程或缓存生命周期内累计。应在一个小规模受控测试前后各取快照，
不要脱离时间窗口解释单个大数值：

- assignment、socket lookup、`sk_assign`、token reservation 或 rewrite 失败增加，
  表示内核交付/丢弃点发生异常，应同时保存首条告警与 attachment 状态；
- fragment-pass 增加表示 IPv4 分片或非 atomic IPv6 分片按设计放行，并非 parser
  静默漏流量；
- shared ingress/egress pass 覆盖所有显式放行出口，可用于识别不对称绕过或回复路径；
- UDP `capacity_evictions`、`queue_drops`、pending-release 拒绝和 release 通知丢失是
  不同压力信号，并不都代表 BPF assignment map 缺项；
- map occupancy 只在显式请求诊断时采集。`UNKNOWN` 表示该 map 类型无法安全遍历或
  检查被拒绝，不表示占用为零。

program/map 枚举按 `sb_` 命名约定筛选，同一内核中其他可见的 sing-ebpf 进程也可能
出现；每个入站自身的 attachment、策略状态、用户态会话和计数才是实例级证据。

## 启动与挂载失败

应以服务相同的 UID、capability、namespace、cgroup 视图和 SELinux/LSM domain 执行
不挂载探测。交互 shell 中的 root 结果可能与服务管理器不同。

- 对象加载时的 `operation not permitted` 通常指向 BPF syscall、verifier、capability、
  lockdown 或 LSM 策略；存在 verifier 日志时必须保留。
- 对象已成功加载，但 cgroup 程序挂载时报 `operation not permitted`，应检查所选层级、
  delegation、multi/独占挂载支持和 Android netd 等现有 hook，并记录启动时最终选择的
  cgroup 挂载方式。
- 探测成功后 TC 挂载仍失败，需要实际链路类型、qdisc/filter 清单、接口锁结果和
  netlink 错误；探测命令按设计不会修改 qdisc。
- SOCKMAP 失败后可以正常选择 legacy TC 对象；只有回退对象也失败或入站未激活时，
  才应作为启动故障报告。
- 可选 cgroup socket-release observer 被拒绝后可以正常选择有界 LRU 清理；应检查
  实际程序/attachment，而不是直接断定 local cgroup 不可用。

## CPU 和内存 profile

在 loopback 开启标准 debug endpoint 即可使用 Go pprof：

```json
{
  "experimental": {
    "debug": {
      "listen": "127.0.0.1:6060"
    }
  }
}
```

围绕复现过程采集 CPU、heap 和 goroutine：

```sh
curl -o cpu.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
curl -o heap.pprof 'http://127.0.0.1:6060/debug/pprof/heap?gc=1'
curl -o goroutine.txt 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=2'
go tool pprof -top cpu.pprof
go tool pprof -top heap.pprof
```

pprof 只测量 Go 用户态 CPU 和内存，不包含 BPF 执行和内核 map 内存。内核侧应结合
TC 状态、`dmesg` 和目标系统可用的 BPF 检查工具判断。

## attachment 和接口检查

local `cgroup` 模式跟随选中的 cgroup v2 层级，不挂载网络接口；local `tc` 才跟随
当前默认接口。shared 模式跟随配置的下游接口，并会重试启动时不存在的接口。配置的
shared 接口成为当前默认上游时会停止接管，重新成为下游后恢复。网络
事件也会检查受管 TC filter、策略路由和 delivery 链路。如果接口事件前后接管行为发生
变化，请分别保存以下输出：

```sh
ip -details link show
ip route show table all
ip -6 route show table all
tc -details qdisc show
tc -statistics -details filter show
```

同时保留启动时的 `eBPF TC active` 摘要。sing-box 运行期间不要手动删除内部 veth
或其管理的 TC filter。

排查 local `tc` 接管时，可对比默认接口 egress filter 和日志所示 delivery 接口
ingress filter 的报文计数：

```sh
tc -statistics filter show dev wlan0 egress
tc -statistics filter show dev sbdXXXXXXXX ingress
```

请将两个接口名替换为启动日志中的实际值。如果 local filter 计数增长而 delivery
filter 不增长，请同时保留两条 filter 输出和对应的 `ip -details link show` 输出。

## 流量绕过、丢弃与分片

分别测试一个确认不会命中绕过规则的 TCP 和 UDP flow，记录目标、来源 UID 或下游
来源、DNS 模式，以及测试前后诊断。按以下顺序检查：

1. `attachments` 中存在预期角色和接口；
2. 对应 TC filter 报文计数增长，或 cgroup 程序确实处于 active；
3. 流量没有被地址族、协议、服务流量、自身绕过、UID/来源、端口、私网地址或规则集
   策略排除；
4. fragment-pass 或一般 pass 计数不能解释该结果；
5. assignment/rewrite 失败计数没有增加；
6. sing-box listener 和 router 收到了该 flow。

IPv4 分片与非 atomic IPv6 分片按设计绕过，因为各 hook 上不一定存在完整传输层
tuple；五元组代理不能安全地单独重定向后续分片。若不应出现分片，应抓取受影响接口
两侧报文，判断 MTU、PMTU discovery、上游隧道或发送端是否制造了分片。

怀疑校验和或硬件 offload 时，请使用专门的
[校验和/offload 验证流程](/zh/manual/misc/ebpf-checksum-offload-verification/)。发送侧抓包
可能在网卡完成 offload 前看到不完整校验和，应以接收 payload 与远端抓包为准。

## 网络切换与恢复

在切换前、故障期间和预期恢复后分别保存 `sing-box api ebpf`，关联
`last_error_at`、`last_recovery_at`、`next_retry_at`、attachment ifindex 变化与
route/link 事件。

local TC 跟随当前默认接口。shared 接口仅在作为下游时可接管；暂时成为默认上游时会
按设计卸载。旧 local attachment 可保留到新默认接口准备完成，以减少不必要的空窗。
这些机制不会重新创建被 Android 撤销的热点 IPv6 前缀、默认路由、DHCP、NAT 或转发。

状态持续为 `recovering` 时，应等待报告中的下一重试时间并再次采样。变为
`needs_attention` 后，不应手工拼接不同 generation 的 route/filter；保存证据并重启。

## 停止与残留状态

优先正常停止并保存关闭日志。进程退出后，检查内部 delivery 链路、自有 filter handle、
策略规则、路由、接口锁和修改过的 sysctl 是否已删除或恢复。不要仅因其他 `clsact`
qdisc/filter 位于同一接口就删除它们。

清理报错时，保留准确对象/接口标识；在人工删除前，优先尝试使用同一构建重新启动并
正常停止。人工清理只能针对已明确确认由 sing-box 创建的状态。

## 隐私

日志和 profile 可能包含目的地址、域名、接口名、包名、文件路径和配置片段。公开
前可以删除凭据及无关个人信息，但应保留时间戳、错误号、program/map ID、UID
范围、内核调用栈和事件顺序。
