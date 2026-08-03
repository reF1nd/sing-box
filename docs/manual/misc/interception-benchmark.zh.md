# 透明入站基准测试协议

本协议使用相同的流量生成器和远端端点，对比 eBPF、Redirect、TProxy 和 TUN
透明入站。它用于可重复的工程测量，并不是适用于所有环境的统一排名；内核、网卡、
硬件卸载、CPU 频率、路由规则以及直连/代理流量比例都可能改变结果。

## 负载场景

| 场景 | 测量值 | 目的 |
|------|--------|------|
| `tcp-short` | 每秒完成的 TCP 请求/响应连接数 | 测量连接建立、拦截、map/conntrack 及用户态分发开销 |
| `tcp-upload` | 持久 TCP 连接中由服务器确认的 bit/s | 测量客户端到服务器的长连接吞吐 |
| `tcp-download` | 持久 TCP 连接中客户端实际收到的 bit/s | 测量服务器到客户端的长连接吞吐 |
| `udp-pps` | connected UDP socket 每秒完成的 echo 数据报数量 | 测量 connected UDP 拦截及 NAT/session 处理开销 |
| `udp-unconnected-pps` | unconnected UDP socket 每秒完成的 echo 数据报数量 | 测量逐目标 sendmsg 拦截及 flow cache 开销 |

sing-box 的 Redirect 只支持 TCP，因此其 UDP 结果应标记为不适用，不能把其他 UDP
实现的结果放到 Redirect 名下。

## 构建流量生成器

```sh
go build -o interception-bench ./cmd/internal/interception_bench
```

在设备可访问的另一台空闲机器上启动服务器。TCP 与 UDP 使用同一端口：

```sh
./interception-bench -mode server -listen :5201
```

启用透明入站前先运行 Direct 基线，然后对每种入站执行相同命令：

```sh
./interception-bench -mode client \
  -target 192.0.2.2:5201 \
  -scenario all \
  -duration 30s \
  -warmup 5s \
  -concurrency 16 \
  -payload-size 1200 > result.json
```

客户端会输出一份 JSON 报告。长连接上传使用带长度前缀的数据帧和显式结束帧，
服务器返回实际收到的 payload 字节数；因此不会只统计写入本机 socket buffer 的
字节，也不依赖透明拦截路径是否正确处理 TCP half-close。UDP 每个流先发送请求，
收到 echo 后才继续，因此结果是完成往返处理的 PPS，而不是未经确认的发送 PPS。

## 可比测试环境

所有测试必须使用相同的 sing-box 二进制、服务器地址、路由、出站、日志等级、CPU
affinity、并发数、持续时间和 payload 大小。关闭嗅探、协议多路复用、DNS 规则以及
无关规则集。使用 `direct` 出站，并从外部 Redirect/TProxy 防火墙规则中排除
sing-box 进程，避免流量回环。

建议的入站配置为：

| 变体 | 必需配置 |
|------|----------|
| eBPF | 本机 cgroup 拦截、`dns_mode: off`、不配置 `bypass_rule_set`、不启用 `shared_network` |
| Redirect | TCP listener，以及只匹配测试服务器和端口的 nftables/iptables Redirect 规则 |
| TProxy | TCP/UDP listener、匹配的 TProxy 规则、独立 mark、策略规则及 local route |
| TUN | `auto_route: true`、`auto_redirect: true`、`stack: system`，且 `route_address` 只包含测试服务器前缀 |

拦截范围应只包含测试目标。全设备 catch-all 会混入不可控的后台流量，使 CPU 样本
失去可比性。所有变体应保持相同的硬件和内核卸载状态；记录这些状态，不要只为某个
变体单独修改。

eBPF 测试客户端应位于配置的 `cgroup_path` 中。Redirect 和 TProxy 应使用专用测试
UID 或 cgroup 进行防火墙匹配，并显式绕过 sing-box 服务 UID。TUN 应使用等价的
include/exclude UID 设置，以保证各变体捕获相同的进程集合。

## 重复测试与系统指标

每种配置至少执行五次，并随机化或轮换执行顺序。保留中位数以及全部原始 JSON。
每次正式测量前重启 sing-box，完成预热，并确认服务器没有其他客户端。

同时记录 sing-box CPU 时间和最大常驻内存。在标准 Linux 上，可使用：

```sh
/usr/bin/time -v ./sing-box run -c benchmark.json 2> sing-box-resource.txt
```

还应记录：

- sing-box commit 和构建标签；
- 内核版本及架构；
- 设备型号、CPU governor 和热状态；
- 网卡、MTU、链路速度和卸载状态；
- 入站配置以及防火墙/策略路由规则；
- Direct 基线和每一份原始 JSON；
- 丢包或报告中非零的 `errors`。

出现错误、热降频、链路重新协商或无关流量时，应丢弃该轮。既要比较绝对结果，
也要比较相对同一轮 Direct 基线的开销。eBPF 无 bypass 规则和使用代表性 CIDR
bypass 规则时属于两条不同数据路径，应分别测试，不能合并为同一个数字。

## Android 真机参考结果

以下数据来自 2026-08-03 的一次参考测量，并不是性能承诺或适用于所有设备的入站
排名。它用于展示预期产物、数据解释方式以及 root Android 上的复现过程。

测试源码树在压缩 eBPF 开发历史前记录为 `55095cf9`；其数据路径实现已包含在当前
`Implement eBPF inbound` 提交中。之后增加的 Android lookup-and-delete 改动属于
兼容回退，在内核接受合并 syscall 时不会改变快速路径。

| 项目 | 数值 |
|------|------|
| 设备 | OPPO PKX110 |
| 系统 | Android 16（SDK 36），arm64 |
| 内核 | 6.6.89 Android common kernel 衍生版本 |
| 构建标签 | `with_ebpf,with_gvisor` |
| 拓扑 | 私有 mount、cgroup、network namespace，以及两对内核 veth |
| 测量时间 | 预热 1 秒后测量 5 秒 |
| 重复次数 | 5 次，轮换各入站的起始顺序 |
| 并发与 payload | 16 个流，1200 字节 |
| TUN 变体 | `stack: system`、`auto_redirect: true` |
| 错误 | 所有正式测量均为 0 |

中位数结果如下：

| 变体 | TCP 短连接 | TCP 上传 | TCP 下载 | Connected UDP | Unconnected UDP |
|------|-------------:|---------:|---------:|--------------:|----------------:|
| Direct | 9.648k op/s | 6.725 Gbit/s | 83.952 Gbit/s | 53.161k PPS | 51.815k PPS |
| eBPF | 8.704k（90.2%） | 6.536 Gbit/s（97.2%） | 65.632 Gbit/s（78.2%） | 21.877k（41.2%） | 22.621k（43.7%） |
| Redirect | 8.749k（90.7%） | 6.398 Gbit/s（95.1%） | 65.872 Gbit/s（78.5%） | 不适用 | 不适用 |
| TProxy | 9.162k（95.0%） | 5.493 Gbit/s（81.7%） | 68.198 Gbit/s（81.2%） | 22.558k（42.4%） | 22.326k（43.1%） |
| TUN | 3.924k（40.7%） | 524.809 Mbit/s（7.8%） | 280.913 Mbit/s（0.3%） | 22.573k（42.5%） | 22.291k（43.0%） |

发布的中位数及环境信息也提供了
[机器可读 JSON 摘要](interception-benchmark-android-20260803.json)。

在此拓扑中，eBPF 与 Redirect 的 TCP 结果基本相当，细小差异低于实际观察到的
轮次波动。TProxy 的透明入站 TCP 短连接中位数最高，但上传吞吐低于 eBPF 和
Redirect。eBPF 的 connected 与 unconnected UDP 均接近 TProxy 和 TUN；Redirect
仅支持 TCP，因此不存在 UDP 结果。

Direct 下载的异常高吞吐来自同一设备内的内核 veth，不经过物理网卡。这会使需要
较多复制和用户态处理的数据路径，特别是 TUN，相对 Direct 的百分比显得远低于真实
网络；真实网络通常先受到链路速率限制。因此，有意义的是该设备上相对于 Direct
的拦截开销，而不是表中的绝对 Gbit/s。

完整矩阵中，CPU 相关温度传感器约在 36.4 C 到 73.4 C 之间。测试没有停止 Android
后台服务，没有锁定 CPU 频率，也没有开启飞行模式。中位数可以降低但不能消除这些
噪声。本结果只覆盖本机 cgroup 拦截，不代表 `shared_network`、Wi-Fi 热点、蜂窝
网络或硬件热点卸载性能。

### 在 root Android 上复现

测试需要使用 `/data/local/tmp/sing` 等独立临时目录，并要求 root、cgroup v2、
network namespace、veth、iptables，以及支持 `netns` 的 `ip`。除非操作者理解
临时 namespace、cgroup、路由及防火墙修改，否则不应在重要的日常使用设备上执行。
所有名称和路径应使用唯一的 benchmark 前缀，并安装完整的 cleanup trap。

从同一源码树构建 Android sing-box 和流量生成器：

```sh
CGO_ENABLED=1 \
GOOS=android \
GOARCH=arm64 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang" \
TAGS="with_ebpf,with_gvisor" \
make build

CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
  go build -o build/interception-bench ./cmd/internal/interception_bench

adb shell su -c 'mkdir -p /data/local/tmp/sing'
adb push sing-box build/interception-bench /data/local/tmp/sing/
adb shell su -c 'chmod 700 /data/local/tmp/sing/sing-box /data/local/tmp/sing/interception-bench'
```

建立三个 network namespace 和两对 veth，使用固定拓扑：

| Namespace | 接口和地址 | 对端 |
|-----------|------------|------|
| Application | `sba0`，`10.89.0.2/24` | Router `sbr0`，`10.89.0.1/24` |
| Router | `srr0`，`10.89.1.1/24` | Server `sbs0`，`10.89.1.2/24` |

Android 通常没有可写的 `/run/netns`。兼容做法之一是保持三个 `unshare -n`
namespace holder 进程运行，并通过 `nsenter -t PID -n` 进入，同时把这些 PID 写入
测试记录。不同厂商的 Toybox 能力并不一致，可能需要 Termux 或推送静态编译的
iproute2/util-linux 工具。

只在 Router namespace 内启用 IPv4 forwarding，并在其私有防火墙中允许转发；
Application 使用 `10.89.0.1` 作为默认网关，Server 添加返回路由。使用私有 mount
namespace，在 `/data/local/tmp/sing/cgroup` 下挂载 cgroup v2，创建 `client` 子
cgroup，并只把 benchmark client 放入其中。

Direct 直接使用 namespace 路由，不启动 sing-box。eBPF 在 Application namespace
中运行，`cgroup_path` 指向 `client` cgroup，使用 `dns_mode: off`、不配置 bypass
rule-set，并把 direct 出站绑定到 `sba0`。Redirect、TProxy、TUN 在 Router
namespace 中运行；Redirect/TProxy 规则只匹配 `10.89.1.2:5201`，各自使用独立
端口，并在切换变体前删除上一变体的规则。TUN 的 `route_address` 仅配置
`10.89.1.2/32`，并记录 stack 和 `auto_redirect`。

在 Server namespace 中启动服务器：

```sh
/data/local/tmp/sing/interception-bench \
  -mode server -listen :5201
```

每种变体都把 client shell 加入测试 cgroup，然后执行：

```sh
echo $$ > /data/local/tmp/sing/cgroup/client/cgroup.procs
exec /data/local/tmp/sing/interception-bench \
  -mode client \
  -target 10.89.1.2:5201 \
  -scenario all \
  -duration 5s \
  -warmup 1s \
  -concurrency 16 \
  -payload-size 1200
```

每个变体重复五次，并在每轮轮换起始变体。每次测量前重启 sing-box，只清除当前
变体的防火墙和策略路由状态。保存全部 JSON、生成的配置、sing-box 日志、内核和
设备信息、namespace 拓扑及温度样本；确认错误数为零后再计算中位数。测试完成后，
必须删除 benchmark 进程、规则、路由、cgroup、namespace，以及测试创建的
`/data/local/tmp/sing` 内容。

namespace 和各入站的设置应与 `.github/benchmark/run-inbound-benchmark.sh` 中的
对应函数保持一致；该 runner 也可作为 cleanup 顺序的参考。它面向 GNU/Linux
用户态，不能不作修改地直接在 Android Toybox 中运行。

## GitHub Actions

手动触发的 `Inbound benchmark` workflow 会建立包含 Application、Router、Server
三个 network namespace 的 IPv4 Linux 拓扑，以随机顺序运行 Direct、eBPF、
Redirect、TProxy 和 TUN，上传全部原始 JSON 及环境记录，并在 job summary 中输出
中位数以及相对 Direct 的比例。由于 Redirect 只支持 TCP，它不会运行两个 UDP
场景。

workflow 还会执行一轮独立的 eBPF 防漏验证：使用未授权 UID 运行 TCP 短连接和两个
UDP 负载，同时由 owner 防火墙规则禁止该 UID 直连服务器。只有所有测试 socket
都经过 cgroup 程序重定向后才能成功；其 JSON 保存在 `results/validation`，不会
计入性能中位数。

当 `profile_seconds` 大于零时，workflow 还会执行一次 connected eBPF UDP profile。
它使用独立的 sing-box 二进制，避免 mutex/blocking profile 收集影响普通 benchmark。
artifact 会在 `results/profiles` 下保存 CPU、allocation、mutex、blocking 原始
profile，以及 `go tool pprof -top` 文本。无需 profile 时应把该值设为零。

workflow 可使用 `ubuntu-24.04` hosted runner，或带有自定义
`inbound-benchmark` label 的 Linux self-hosted runner。只有 hosted runner 会自动
安装依赖；固定 runner 应提前准备 workflow 所检查的命令。GitHub hosted runner
适合确认每条数据路径可用，以及发现同一 job 中的明显回归，但其虚拟 CPU、邻居负载
和频率行为不够稳定，不能用于发布绝对性能数据或判断入站之间的微小差异。

应优先比较同一个 job 内、相对于该 job Direct 基线的结果。不能把不同 hosted
runner job 的绝对数值当作来自同一机器。CPU steal time、宿主调度、turbo 状态、
runner image 更新及 noisy neighbor 都会移动个别结果。较短的默认持续时间适合 CI
回归检测，但会放大启动和频率切换影响；需要发布的数据应使用更长测试时间和固定的
self-hosted 物理机。namespace/veth 拓扑本身也偏向内核数据路径，无法代表 Android
策略路由、物理网卡、无线电源管理、热点 TC hook 或硬件卸载。

workflow 参数还可以选择 TUN `stack`（`system`、`gvisor`、`mixed`）以及是否启用
`auto_redirect`，两者都会写入环境记录。每种组合都属于独立变体，不能合并为同一
份 TUN 数据。

直接运行 shell runner 时，可通过 `--variants` 和 `--scenarios` 把工程 A/B 测试
限制到特定数据路径。workflow 则有意保留完整默认矩阵，使发布的 artifact 保持可比。

用于文档或推广的数据应来自固定的 bare-metal self-hosted Linux runner，每种配置
至少重复五次，在不同日期重复整个 workflow，并同时发布原始 artifact 和中位数。
runner 内核、固件、CPU governor、网卡/卸载状态以及 sing-box 构建必须保持不变。
Android cgroup eBPF 行为仍需在 Android 真机上测量；Linux workflow 无法代表其
内核、热点路径或热限制。
