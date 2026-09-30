# MASQUE 客户端

!!! question "自 sing-box 1.15.0 起"

`masque-client` endpoint 是一个基于 HTTP 的 IP 代理（[RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)，CONNECT-IP）客户端。

## 结构

```json
{
  "type": "masque-client",
  "tag": "masque-client",

  "server": "127.0.0.1",
  "server_port": 443,
  "username": "",
  "password": "",
  "path": "",
  "headers": {},
  "version": 0,
  // "h3_congestion_control": "bbr",
  "disable_version_fallback": false,
  "tls": {},
  "advertise_routes": [],
  "system": false,
  "gso": false,
  "inner_domain_resolver": "", // or {}
  "name": "",
  "mtu": 1280,
  "on_demand": false,

  ... // HTTP2 字段 / QUIC 字段
  ... // UDP NAT 字段
  ... // 拨号字段
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

## 字段

### server

==必填==

服务器地址。

### server_port

==必填==

服务器端口。

### username

Basic 认证用户名。

### password

Basic 认证密码。

### path

IP 代理资源的 URI 模板路径，可以包含 `target` 和 `ipproto` 变量。

默认使用 `/.well-known/masque/ip/{target}/{ipproto}/`。

### headers

HTTP 请求的额外标头。

### version

HTTP 版本。

可用值：`1`、`2`、`3`。

默认使用 `3`。

当为 `2` 时，[QUIC 字段](#quic-字段) 替换为 [HTTP2 字段](#http2-字段)。

### disable_version_fallback

禁用自动回退到更低的 HTTP 版本。

### h3_congestion_control

HTTP/3 连接的本端发送拥塞控制算法。仅在 HTTP/3 生效。

支持 `new_reno`、`cubic`、`bbr`、`none`。

省略时保留现有行为：客户端使用 NewReno，服务端使用 BBR。BBR 使用 Standard profile，不提供 profile 或带宽参数。配置仅影响本端发送，两端可以使用不同算法。

配置本字段时，`version` 必须为 `3` 或省略；`0` 按默认版本 `3` 处理。不包含 QUIC 支持的构建拒绝此配置。

本字段不改变版本回退策略。客户端是否允许回退仍由 `disable_version_fallback` 控制；回退到 HTTP/1 或 HTTP/2 后，本字段不生效。

`none` 仅免除承载 IP 的 QUIC DATAGRAM 包的外层拥塞窗口和 pacing。控制流、握手和可靠 Capsule 仍受正常拥塞控制；DATAGRAM 不可用时仍允许 Capsule 回退。豁免包保留 ACK、丢包追踪、路径 MTU 和资源限制，并使用 Not-ECT。

使用 `none` 前应确认被代理流量具有适当的拥塞控制或部署环境具备相应的流量管理；仅知道内层是 UDP 或 KCP 并不足以判断。此选项不保证更低延迟。双向豁免需要两端分别配置。

### tls

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#outbound)。

HTTP/3 需要 TLS。

### advertise_routes

向服务器声明的 IP 前缀列表。

服务器会把发往这些前缀的流量路由到此 endpoint，并在此作为入站流量处理。

### system

使用系统接口。

需要特权且不能与已有系统接口冲突。

如果禁用，sing-box 将使用内部网络栈。

### gso

!!! quote ""

    仅支持 Linux。

尝试为系统接口启用通用分段卸载。

当 `system` 为 `true` 时，默认启用。设为 `false` 可禁用。

当 `system` 为 `false` 时，此选项不生效。

### inner_domain_resolver

指定将此 endpoint 用作出站时，解析目标域名所使用的 DNS 解析器。适用于 TCP 和 UDP。

当此端点被选中用于 L3 转发时，也使用此解析器解析尚未解析的目标域名。

此选项使用与 [domain_resolver](/zh/configuration/shared/dial/#domain_resolver) 相同的格式。

未设置时，使用现有 DNS 路由规则及默认 DNS。目标为 IP 地址时不进行域名解析。

此选项不影响 MASQUE 服务器地址的解析，后者仍使用拨号字段中的 `domain_resolver`。

### name

系统接口的自定义接口名称。

默认使用自动生成的 `masque` 接口名称。

### mtu

隧道 MTU。

默认使用 `1280`。

### on_demand

允许该 endpoint 在需要时断开连接。

## HTTP2 字段

当 `version` 为 `2` 时。

参阅 [HTTP2 字段](/zh/configuration/shared/http2/)。

## QUIC 字段

当 `version` 为 `3`（默认）时。

参阅 [QUIC 字段](/zh/configuration/shared/quic/)。

## UDP NAT 字段

参阅 [UDP NAT 字段](/zh/configuration/shared/udp-nat/)。

## 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
