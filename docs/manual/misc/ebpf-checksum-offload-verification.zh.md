# eBPF 校验和/卸载验证

本流程验证 eBPF TC 数据面改写后的报文在启用校验和与分段卸载时仍然能以正确
格式到达线缆。覆盖 `shared.data_plane: packet_rewrite`、FakeIP ICMP 回复，
以及一个完全不改写的 bypass 对照流。

测试必须使用真实硬件。veth、loopback 和 virtio 都在软件中完成卸载，无法暴露
网卡固件或驱动问题。请使用物理网卡或 SR-IOV/直通 VF，并随报告记录网卡型号、
驱动、固件和内核版本。

## 主机角色

- **DUT**：运行 sing-box 和本工具；`LOCAL_IFACE` 是承载 eBPF attachment
  的物理接口。
- **REMOTE_HOST**：DUT 可访问且可免交互 SSH 登录的真实目的主机，负责接收
  对照、TCP 和 UDP 流量，并抓取远端报文。
- **DOWNSTREAM_HOST**：shared 测试必需。它从 DUT 的 shared 接口一侧发起
  流量；DUT 自己发出的流量无法覆盖 shared ingress。

需要明确归因时，仅启用被测角色。同时启用 local 和 shared 时，`/ebpf` 计数器
会汇总多个后端。

## 前置条件

- 所有相关主机具有 root 权限，DUT 可使用密钥免交互 SSH 登录其他主机。
- DUT 安装 Go、`ethtool`、`tcpdump` 和 `nc`。
- `REMOTE_HOST` 安装 `tcpdump` 和 `nc`；`DOWNSTREAM_HOST` 安装 `nc`。
- sing-box eBPF 入站已运行并挂载到 `LOCAL_IFACE`。
- ICMP 检查要求启用 `fakeip_icmp: reply`。
- shared TCP/UDP 检查要求 `shared.data_plane: packet_rewrite`。
- 可选启用 Clash API `/ebpf`，用于计数器归因。

先确认接口使用真实硬件驱动：

```sh
ethtool -i eth0
```

`ixgbe`、`i40e`、`mlx5_core`、`r8169`、`igc` 等适合测试；`veth`、
`virtio_net` 和 `vmxnet3` 不适合。

## 配置

必需环境变量：

| 变量 | 含义 |
|---|---|
| `LOCAL_IFACE` | DUT 上承载 eBPF attachment 的接口 |
| `REMOTE_HOST` | 可通过 SSH 到达的接收主机 |
| `FAKEIP_PREFIX` | 已配置的 FakeIP CIDR |
| `REMOTE_FAKEIP_TARGET` | `FAKEIP_PREFIX` 内的地址 |

可选变量：

| 变量 | 默认值 | 含义 |
|---|---:|---|
| `TEST_ROLE` | `both` | `local`、`shared` 或 `both` |
| `DOWNSTREAM_HOST` | — | `shared` 和 `both` 必需 |
| `REMOTE_SSH_USER` | `root` | 远端 SSH 用户 |
| `DOWNSTREAM_SSH_USER` | 同远端用户 | 下游 SSH 用户 |
| `SSH` | `ssh -o BatchMode=yes -o ConnectTimeout=5` | 远端 SSH 命令 |
| `DOWNSTREAM_SSH` | 同上 | 下游 SSH 命令 |
| `REMOTE_IPV6` | — | FakeIP IPv6 目标；启用 IPv6 ping |
| `REMOTE_PORT_TCP` | — | 启用 TCP 内容校验 |
| `REMOTE_PORT_UDP` | — | 启用 UDP 内容校验 |
| `DUT_DIAGNOSTICS_URL` | — | Clash API `/ebpf` 地址 |
| `DUT_DIAGNOSTICS_TOKEN` | — | 可选 bearer token |
| `PING_COUNT` | `20` | 每组 ICMP 的请求数 |
| `TRANSFER_BYTES` | `8388608` | TCP payload 大小 |
| `OUT_DIR` | `./checksum-offload-report` | 报告和抓包目录 |

`TEST_ROLE=shared` 和 `TEST_ROLE=both` 必须配置 `DOWNSTREAM_HOST`。未选择的
角色会记录为 `NOT_TESTED`，不会静默省略。

## 运行

先以普通用户构建，再以 root 运行产物：

```sh
go build -o /tmp/sing-box-checksumoffload github.com/CHIZI-0618/sing-ebpf/testing/checksumoffload

sudo LOCAL_IFACE=eth0 \
    REMOTE_HOST=192.0.2.10 \
    REMOTE_SSH_USER=root \
    DOWNSTREAM_HOST=192.0.2.20 \
    DOWNSTREAM_SSH_USER=root \
    DUT_DIAGNOSTICS_URL=http://127.0.0.1:9090/ebpf \
    FAKEIP_PREFIX=198.18.0.0/15 \
    REMOTE_FAKEIP_TARGET=198.18.0.1 \
    REMOTE_IPV6=fdfe:dcba:9876::1 \
    REMOTE_PORT_TCP=15000 \
    REMOTE_PORT_UDP=15001 \
    TEST_ROLE=both \
    /tmp/sing-box-checksumoffload
```

工具会保存原始卸载状态，并在正常退出、失败、SIGINT 或 SIGTERM 时恢复。默认
测试四个完整组合：

- 所有相关特性开启；
- 所有相关特性关闭；
- 仅关闭 TX checksum offload；
- 关闭 TSO、GSO 和 UDP segmentation。

每项设置都会读取确认。若驱动拒绝设置或不支持某特性，该组合会标记为
`UNSUPPORTED`，不会在错误的状态标签下继续跑流量测试。

每个成功应用的组合依次执行：

1. 在 DUT 和远端启动抓包。
2. 验证完全不改写的 SSH 对照流。
3. 执行 local 和/或下游发起的 FakeIP ICMP 检查。
4. 执行可选 TCP/UDP 传输并比较完整 payload 的 SHA-256。
5. 配置诊断接口时检查 shared FakeIP 和 rewrite 计数器。
6. 在 `OUT_DIR` 写入 `report.tsv` 和两端 PCAP。

以接收端 payload 为准。发送侧抓包发生在网卡完成 TX offload 之前，可能把正常
报文标成 checksum incorrect。

## 退出码

- `0`：至少一项通过，且没有失败或不支持的组合。
- `1`：至少一项失败。
- `2`：无结论；没有任何检查通过。
- `3`：部分通过；有检查通过，但至少一个组合不受支持。
- `4`：创建或写入报告失败。

`UNSUPPORTED` 描述的是网卡/驱动状态，不是 eBPF 结论。若 bypass 对照失败，
应先修复硬件或卸载设置；若对照通过而改写流失败，优先检查远端抓包，并随报告
附上两端 PCAP。

## 限制

- Android 硬件和工具链需要单独的真机流程。
- 工具不选择 TCX 或 `clsact`；需要分别启动相应 sing-box 配置进行测试。
- 如需覆盖厂商特性，请扩展 Go 源码中的 `offloadFeatures` 和
  `offloadMatrix`，并在每个组合中为所有特性赋值。
- local 与 shared 同时承载 FakeIP responder 时，汇总诊断无法完成精确归因。
