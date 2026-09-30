`http` 出站是一个 HTTP CONNECT 代理客户端

### 结构

```json
{
  "type": "http",
  "tag": "http-out",
  
  "server": "127.0.0.1",
  "server_port": 1080,
  "username": "sekai",
  "password": "admin",
  "path": "",
  "headers": {},
  "version": 0,
  // "h3_congestion_control": "bbr",
  "disable_version_fallback": false,
  "tls": {},

  ... // HTTP2 字段 / QUIC 字段
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

#### username

Basic 认证用户名。

#### password

Basic 认证密码。

#### path

HTTP 请求路径。

#### headers

HTTP 请求的额外标头。

#### version

!!! question "自 sing-box 1.15.0 起"

HTTP 版本。

可用值：`1`、`2`、`3`。

默认使用 `2`；设置了 `path` 或 `Host` 头时默认使用 `1`。

`path` 和 `Host` 头仅在 `1` 时可用。

当为 `3` 时，[HTTP2 字段](#http2-字段) 替换为 [QUIC 字段](#quic-字段)。

#### disable_version_fallback

!!! question "自 sing-box 1.15.0 起"

禁用自动回退到更低的 HTTP 版本。

#### h3_congestion_control

HTTP/3 连接的本端发送拥塞控制算法。仅在 HTTP/3 生效。

支持 `new_reno`、`cubic`、`bbr`。HTTP 代理不支持 `none`，配置后将拒绝启动。

省略时保留现有行为：客户端使用 NewReno，服务端使用 BBR。BBR 使用 Standard profile，不提供 profile 或带宽参数。配置仅影响本端发送，两端可以使用不同算法。

配置本字段时，必须显式设置 `version: 3`。不包含 QUIC 支持的构建拒绝此配置。

本字段不改变版本回退策略。客户端是否允许回退仍由 `disable_version_fallback` 控制；回退到 HTTP/1 或 HTTP/2 后，本字段不生效。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#出站)。

### HTTP2 字段

!!! question "自 sing-box 1.15.0 起"

当 `version` 为 `2`（默认）时。

参阅 [HTTP2 字段](/zh/configuration/shared/http2/) 了解详情。

### QUIC 字段

!!! question "自 sing-box 1.15.0 起"

当 `version` 为 `3` 时。

参阅 [QUIC 字段](/zh/configuration/shared/quic/) 了解详情。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
