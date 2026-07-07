---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

### 结构

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 4,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "network": "tcp",
  "obfs_mode": "",
  "obfs_host": "",

  ... // 拨号字段
}
```

### 版本 6 结构

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 6,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "network": "tcp",
  "mode": "",

  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### version

Snell 协议版本，可选值为 `1` `2` `3` `4` `5` `6`，默认 `4`。

| 版本 | TCP | UDP |
|------|-----|-----|
| 1, 2 | 支持 | 不支持 |
| 3 | 支持 | UDP over TCP |
| 4 | 支持 | UDP over TCP |
| 5 | 支持 | QUIC 使用 QUIC Proxy，其他 UDP 使用 UDP over TCP |
| 6 | 支持 | UDP over TCP |

v4 与 v5 的 TCP 线路协议完全相同，v5 仅额外启用 QUIC Proxy Mode。

#### psk

==必填==

预共享密钥。

版本 6 要求 PSK 长度为 12 到 255 字节。

#### userkey

用户密钥，用于向多用户服务器进行认证。

#### reuse

启用连接复用。

仅支持 Snell 协议版本 `4` 或更高版本。

#### network

启用的网络协议。

`tcp` 或 `udp`。

v1/v2 默认仅启用 TCP；v3-v6 默认同时启用 TCP 与 UDP。v1/v2 不能启用 UDP。

#### obfs_mode

==仅版本 1-5==

Simple-obfs 模式。v1-v3 支持 `http`、`tls`；v4/v5 仅支持 `http`。

默认为 `none`。

TLS simple-obfs 仅用于兼容旧版 v1-v3，v4/v5 不支持。如需 TLS 流量伪装，
请配置 [ShadowTLS](/zh/configuration/outbound/shadowtls/) 作为前置出站。

#### obfs_host

==仅版本 1-5==

`obfs_mode` 为 `http` 时发送的 HTTP `Host` 头。

默认为 `bing.com`。

#### mode

==仅版本 6==

流量整形模式，`default` `unshaped` `unsafe-raw` 之一。

默认为 `default`。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
