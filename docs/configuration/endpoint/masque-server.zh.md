# MASQUE 服务器

!!! question "自 sing-box 1.15.0 起"

`masque-server` endpoint 是一个基于 HTTP 的 IP 代理（[RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)，CONNECT-IP）服务器。

## 结构

```json
{
  "type": "masque-server",
  "tag": "masque-server",

  ... // 监听字段

  "version": [],
  // "h3_congestion_control": "bbr",
  "users": [
    {
      "username": "",
      "password": ""
    }
  ],
  "tls": {},
  "path": "",
  "address": [],
  "advertise_routes": [],
  "system": false,
  "gso": false,
  "inner_domain_resolver": "", // or {}
  "name": "",
  "mtu": 1280,

  ... // HTTP2 字段 / QUIC 字段
  ... // UDP NAT 字段
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

## 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。`udp_timeout` 属于下方的 [UDP NAT 字段](#udp-nat-字段)。

## 字段

### version

提供的 HTTP 版本列表。

可用值：`1`、`2`、`3`。

默认提供全部版本。

`3` 需要 TLS。

### users

HTTP 用户，通过 `Authorization` 标头验证。

如果为空则不需要验证。

### h3_congestion_control

HTTP/3 连接的本端发送拥塞控制算法。仅在 HTTP/3 生效。

支持 `new_reno`、`cubic`、`bbr`、`none`。

省略时保留现有行为：客户端使用 NewReno，服务端使用 BBR。BBR 使用 Standard profile，不提供 profile 或带宽参数。配置仅影响本端发送，两端可以使用不同算法。

配置本字段时，`version` 必须包含 `3`。省略 `version` 时默认包含 `3`。不包含 QUIC 支持的构建拒绝此配置。

本字段不改变版本回退策略。客户端是否允许回退仍由 `disable_version_fallback` 控制；回退到 HTTP/1 或 HTTP/2 后，本字段不生效。

`none` 仅免除承载 IP 的 QUIC DATAGRAM 包的外层拥塞窗口和 pacing。控制流、握手和可靠 Capsule 仍受正常拥塞控制；DATAGRAM 不可用时仍允许 Capsule 回退。豁免包保留 ACK、丢包追踪、路径 MTU 和资源限制，并使用 Not-ECT。

使用 `none` 前应确认被代理流量具有适当的拥塞控制或部署环境具备相应的流量管理；仅知道内层是 UDP 或 KCP 并不足以判断。此选项不保证更低延迟。双向豁免需要两端分别配置。

### tls

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#inbound)。

IP 代理必须运行在 TLS 或 QUIC 之上。仅当服务器位于终止 TLS 的 HTTP 中间层之后时才可以不启用。

### path

IP 代理资源的 URI 模板路径，可以包含 `target` 和 `ipproto` 变量。

默认使用 `/.well-known/masque/ip/{target}/{ipproto}/`。

### address

==必填==

隧道网络的 IP 前缀列表，每个 IP 版本最多一个。

前缀中的地址由服务器自己使用，前缀内的其他地址分配给客户端。

### advertise_routes

除隧道网络外，向客户端声明的 IP 前缀列表。

客户端发往其他目的地址的流量会被拒绝。

默认声明全部地址。

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

此解析器也用于解析 CONNECT-IP 请求路径中 `target` 指定的域名；解析结果仍受 `advertise_routes` 限制。

### name

系统接口的自定义接口名称。

默认使用自动生成的 `masque` 接口名称。

### mtu

隧道 MTU。

默认使用 `1280`。

## HTTP2 字段

当 `version` 包含 `2` 时。

参阅 [HTTP2 字段](/zh/configuration/shared/http2/)。

## QUIC 字段

当 `version` 包含 `3`（默认）时，[HTTP2 字段](#http2-字段) 替换为 QUIC 字段。

参阅 [QUIC 字段](/zh/configuration/shared/quic/)。

## UDP NAT 字段

参阅 [UDP NAT 字段](/zh/configuration/shared/udp-nat/)。
