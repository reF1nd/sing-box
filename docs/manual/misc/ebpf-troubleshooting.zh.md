# eBPF 入站问题排查

问题报告应覆盖进程启动、一次完整复现和停止过程。只有启动日志通常无法解释间歇性
丢包、attachment 变化或资源持续增长。

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

Debug 日志级别下，启动成功后会输出一条 `eBPF cgroup active` 或 `eBPF TC active`
摘要，其中包括选中的数据面及实际运行路径。TC 摘要还会按需列出默认接口、
attachment、内部监听器、路由状态和 delivery 接口，每个 attachment 会标明
local/shared 角色和帧格式。网络事件仅在 attachment 或受管
网络状态发生变化时输出 Debug 日志，修复失败会输出限频的 Warn 日志。用户态 handoff
异常会输出限频后的 Warn 或 Error 日志；BPF 报文返回路径不输出逐包日志，接口生命周期
也不使用周期轮询。shared `packet_rewrite` 会执行有界的自适应清理来回收孤立 flow
状态，但该维护任务不会定期输出状态日志。

如果日志报告 assignment 或 UDP 原目标读取失败，请保留首次错误前后的完整日志，
并同时采集下文的 TC attachment 信息。

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

## 隐私

日志和 profile 可能包含目的地址、域名、接口名、包名、文件路径和配置片段。公开
前可以删除凭据及无关个人信息，但应保留时间戳、错误号、program/map ID、UID
范围、内核调用栈和事件顺序。
