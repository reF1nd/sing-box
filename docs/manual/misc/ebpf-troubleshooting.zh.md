# eBPF 入站问题反馈与排查指南

本文是 eBPF 入站测试阶段的临时材料收集指南。请尽量提供能够完整复现问题的最小
报告。对于间歇性拦截失效、资源持续增长或设备重启，只有启动日志通常不足以定位。

## 最低限度材料

请同时提供以下内容：

1. 准确的 sing-box commit、完整 `sing-box version` 输出和编译 tags。
2. eBPF 入站配置及相关路由规则。可以删除密码、私钥、token 和无关节点凭据，但
   不要删除 eBPF mode、接口、UID 范围、DNS mode、IPv6 开关和绕过策略。
3. 设备型号、系统版本和完整内核版本。Android 还需提供 build fingerprint，
   OpenWrt 还需提供 `/etc/openwrt_release`。
4. 从进程启动、完成一次复现到正常关闭的 Debug 级别日志，并注明故障发生的
   实际时间。无法正常关闭时请保留日志末尾。
   对于长时间运行后出现的 local UDP 故障，还应保留启动日志中包含
   `udp_state_cleanup` 的行。使用 `ebpf_debug` 构建时，同时保留全部 `eBPF debug
   snapshot` 行及其附近的详细 Debug 日志。
5. 准确复现步骤、预期结果、实际结果、受影响协议、影响本机还是下游流量，以及
   重启 sing-box 后是否暂时恢复。
6. 与配置路径对应的内核能力探测 JSON：

```sh
sing-box tools ebpf status --mode local --network tcp,udp --json
sing-box tools ebpf status --mode shared-network --interface br-lan --json
```

hybrid 模式请分别探测两条路径，或使用带下游接口的 `--mode all`。

通用系统信息：

```sh
uname -a
cat /proc/version
cat /proc/meminfo
cat /proc/self/mountinfo
```

Android：

```sh
getprop ro.product.model
getprop ro.build.fingerprint
getprop ro.build.version.release
logcat -b all -d > logcat-all.txt
```

OpenWrt：

```sh
cat /etc/openwrt_release
ubus call system board
ip -details link show
tc -details qdisc show
tc -details filter show
```

## 内核崩溃或设备重启

设备重启后，应在下一次崩溃覆盖内容前复制 `/sys/fs/pstore` 下的全部文件。存在时
重点提供 `console-ramoops-*`、`dmesg-ramoops-*` 和 `pmsg-ramoops-*`：

```sh
ls -la /sys/fs/pstore
cp -a /sys/fs/pstore ./pstore-copy
dmesg -T > dmesg-after-reboot.txt
```

同时说明是 local、shared，还是只有开启热点时才会重启。内核故障发生时用户态
日志可能提前中断，因此 pstore 是此类问题的主要证据。

## 调试构建

在正常编译 tags 中加入 `ebpf_debug`。Android arm64 和 NDK r29 示例：

```sh
TAGS=with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0,with_provider,with_ebpf,ebpf_debug \
CGO_ENABLED=1 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
GOARCH=arm64 GOOS=android make build
```

配置中还需将日志级别设为 `debug`。调试构建会在启动完成后、关闭前，以及有效的
local 或 shared TCP token 丢失重定向状态时输出 `eBPF debug snapshot` JSON，其中
包含 map 类型、key/value 大小、容量、当前条目数、内核 memlock、map/program ID，
以及每个 program 的运行次数、内核累计耗时、平均 ns/run 和 recursion miss。
此外还会记录详细启动配置、绕过策略变更和 janitor 成功删除结果。采集只由事件
触发，不启动周期 reporter，也不会在转发热路径加入诊断计数。普通 `with_ebpf`
构建即使启用 Debug 日志也不会遍历 map 或启用 program runtime 统计。

`ebpf_debug` 构建会在至少一个 eBPF inbound 运行期间临时启用内核
`BPF_STATS_RUN_TIME`。这是衡量 BPF 数据面开销最直接的指标，但属于全系统内核
统计并有可测量的额外开销，因此只应用于排障，不应用于日常 release 构建。低于
5.8 的内核或拒绝该能力的 vendor 内核会继续启动，只是不提供 program runtime
统计；读取失败原因会记录在 program 的 `error` 字段。

排查 local UDP 时，对比 `cgroup_udp_redirect`、`cgroup_udp_token`、
`cgroup_udp_peer`、`cgroup_udp_flow` 的条目数和容量。启动日志中的
`udp_state_cleanup=socket_release` 表示启用了精确的 `cgroup/sock_release` 清理；
`lru_fallback` 则使用有界 LRU 状态。排查 shared 容量压力时，检查
`shared_flow_by_original` 与 `shared_flow_by_token`，两个方向的占用应大致接近。

## CPU 和内存 profile

Go pprof 由 sing-box 自身提供，不要求 `ebpf_debug`。在配置中开启统一的 debug
HTTP 入口：

```json
{
  "experimental": {
    "debug": {
      "listen": "127.0.0.1:6060"
    }
  }
}
```

应只监听 `127.0.0.1`。Android 可转发到电脑：

```sh
adb forward tcp:6060 tcp:6060
```

在 30 秒 CPU 采样期间复现问题，然后采集 heap 和 goroutine：

```sh
curl -o cpu.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
curl -o heap.pprof 'http://127.0.0.1:6060/debug/pprof/heap?gc=1'
curl -o goroutine.txt 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=2'
go tool pprof -top cpu.pprof
go tool pprof -top heap.pprof
```

排查内存持续增长时，分别在启动稳定后和增长明显后采集 heap，并同时提供两次
采样对应的 eBPF debug 快照以及 `/proc/<pid>/status`。采集结束后停止调试版。

pprof 只能测量 Go 用户态 CPU 和 heap，不能测量内核执行 BPF 程序的时间或内核
map 内存。后者需要结合 debug 快照中的 `memlock_bytes`、program ID、启动时的
挂载模式和内核日志判断。只有在内核具备相应 perf/BPF 权限且维护者提出要求时，
再采集 `bpftool prog profile id <id>`；不要自行开启全局 BPF kernel statistics，
它会影响整个系统。

## 运行期维护

shared flow 清理、attachment 自愈和 local TCP 清理用于保证长期运行正确性，
在普通构建中也会启用。大部分工作由事件或 deadline 驱动；对于没有
可靠用户态事件的内核状态，仅保留低频 watchdog。如果 CPU 占用呈周期性，请
同时提供 `ebpf_debug` 快照和 CPU profile，不要直接关闭这些任务；否则
可能造成 map 耗尽、redirect 过期或接口脱挂。

## 隐私和打包

日志和 profile 可能包含目的地址、域名、接口名、包名、文件路径和部分配置。
公开前请删除凭据和无关个人信息，但应保留时间戳、errno、program/map ID、UID
范围、内核调用栈和故障前后的事件顺序。建议将配置、日志、能力探测 JSON、profile
和 pstore 与一份简短时间线一起打包。
