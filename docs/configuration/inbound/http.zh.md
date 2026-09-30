### 结构

```json
{
  "type": "http",
  "tag": "http-in",

  ... // 监听字段

  "version": [],
  // "h3_congestion_control": "bbr",
  "users": [
    {
      "username": "admin",
      "password": "admin"
    }
  ],
  "tls": {},
  "set_system_proxy": false,

  ... // HTTP2 字段 / QUIC 字段
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### version

!!! question "自 sing-box 1.15.0 起"

提供的 HTTP 版本列表。

可用值：`1`、`2`、`3`。

默认为 `1` 和 `2`。

`3` 需要 TLS。

#### h3_congestion_control

HTTP/3 连接的本端发送拥塞控制算法。仅在 HTTP/3 生效。

支持 `new_reno`、`cubic`、`bbr`。HTTP 代理不支持 `none`，配置后将拒绝启动。

省略时保留现有行为：客户端使用 NewReno，服务端使用 BBR。BBR 使用 Standard profile，不提供 profile 或带宽参数。配置仅影响本端发送，两端可以使用不同算法。

配置本字段时，`version` 必须包含 `3`。默认版本不包含 `3`，需要显式启用。不包含 QUIC 支持的构建拒绝此配置。

本字段不改变版本回退策略。客户端是否允许回退仍由 `disable_version_fallback` 控制；回退到 HTTP/1 或 HTTP/2 后，本字段不生效。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#入站)。

#### users

HTTP 用户

如果为空则不需要验证。

#### set_system_proxy

!!! quote ""

    仅支持 Linux、Android、Windows 和 macOS。

!!! warning ""

    要在无特权的 Android 和 iOS 上工作，请改用 tun.platform.http_proxy。

启动时自动设置系统代理，停止时自动清理。

### HTTP2 字段

!!! question "自 sing-box 1.15.0 起"

当 `version` 包含 `2` 时。

参阅 [HTTP2 字段](/zh/configuration/shared/http2/)。

### QUIC 字段

!!! question "自 sing-box 1.15.0 起"

当 `version` 包含 `3` 时，[HTTP2 字段](#http2-字段) 被 QUIC 字段替代。

参阅 [QUIC 字段](/zh/configuration/shared/quic/)。
