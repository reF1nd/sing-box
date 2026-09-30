!!! quote "sing-box 1.15.0 中的更改"

    :material-plus: [on_demand](#on_demand)

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [udp_mapping](/zh/configuration/shared/udp-nat/#udp_mapping)  
    :material-plus: [udp_filtering](/zh/configuration/shared/udp-nat/#udp_filtering)  
    :material-plus: [udp_nat_max](/zh/configuration/shared/udp-nat/#udp_nat_max)

!!! question "自 sing-box 1.11.0 起"

### 结构

```json
{
  "type": "wireguard",
  "tag": "wg-ep",

  // "tcp_congestion_control": "bbr",
  "system": false,
  "name": "",
  "gso": false,
  "mtu": 1408,
  "address": [],
  "private_key": "",
  "listen_port": 10000,
  "peers": [
    {
      "address": "127.0.0.1",
      "port": 10001,
      "public_key": "",
      "pre_shared_key": "",
      "allowed_ips": [],
      "persistent_keepalive_interval": 0,
      "reserved": [0, 0, 0]
    }
  ],

  ... // UDP NAT 字段

  "workers": 0,
  "on_demand": false,
  "inner_domain_resolver": "", // 或 {}

  ... // 拨号字段
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

### 字段

#### tcp_congestion_control

选择此端点内部 Go TCP 栈发送方向的拥塞控制算法。

可选值：`reno`、`cubic`、`bbr`。省略时保留默认值 CUBIC；不支持空值或 `none`。

仅影响由此端点内部 Go TCP 栈终结或发起的 TCP 连接，不影响系统内核 TCP、纯 L3 转发的 TCP、UDP 或内层 QUIC。两端可以选择不同的算法。配置仅影响此端点发送的数据：包括经隧道发起的 TCP 连接中的上传数据，以及对端经此端点转发流量时，内部栈向对端回传的 TCP 数据。

`system` 为 `false` 或 `true` 时均可配置，但只对经过内部 Go TCP 栈的连接生效。启用系统接口不会使此设置影响内核 TCP。

切换算法不保证提高吞吐量，应结合实际链路测试。

#### system

使用系统设备。

需要特权且不能与已有系统接口冲突。

#### name

为系统接口自定义设备名称。

#### gso

!!! quote ""

    仅支持 Linux。

尝试启用通用分段卸载。

当 `system` 为 true 时，默认启用。

此选项控制系统接口。连接对端所用 UDP socket 的 GSO 参阅 [拨号字段](/zh/configuration/shared/dial/#udp_gso) 中的 `udp_gso`。

#### mtu

WireGuard MTU。

默认使用 1408。

#### address

==必填==

接口的 IPv4/IPv6 地址或地址段的列表。

要分配给接口的 IP（v4 或 v6）地址段列表。

#### private_key

==必填==

WireGuard 需要 base64 编码的公钥和私钥。 这些可以使用 wg(8) 实用程序生成：

```shell
wg genkey
echo "private key" || wg pubkey
```

或 `sing-box generate wg-keypair`.

#### peers

==必填==

WireGuard 对等方的列表。

#### peers.address

对等方的 IP 地址。

#### peers.port

对等方的 WireGuard 端口。

#### peers.public_key

==必填==

对等方的 WireGuard 公钥。

#### peers.pre_shared_key

对等方的预共享密钥。

#### peers.allowed_ips

==必填==

对等方的允许 IP 地址。

#### peers.persistent_keepalive_interval

对等方的持久性保持活动间隔，以秒为单位。

默认禁用。

#### peers.reserved

对等方的保留字段字节。

#### workers

WireGuard worker 数量。

默认使用 CPU 数量。

#### on_demand

!!! question "自 sing-box 1.15.0 起"

允许该 endpoint 在需要时断开连接。

#### inner_domain_resolver

设置用于解析通过 WireGuard 隧道的连接的域名解析器。

当此端点被选中用于 L3 转发时，它也用于解析尚未解析的域名目标。

此选项与 [domain_resolver](/zh/configuration/shared/dial/#domain_resolver) 格式相同。

未设置时使用默认 DNS。

### UDP NAT 字段

参阅 [UDP NAT 字段](/zh/configuration/shared/udp-nat/)。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
