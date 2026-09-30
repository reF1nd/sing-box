`http` outbound is a HTTP CONNECT proxy client.

### Structure

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

  ... // HTTP2 Fields / QUIC Fields
  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### username

Basic authorization username.

#### password

Basic authorization password.

#### path

Path of HTTP request.

#### headers

Extra headers of HTTP request.

#### version

!!! question "Since sing-box 1.15.0"

HTTP version.

Available values: `1`, `2`, `3`.

`2` is used by default, or `1` if `path` or the `Host` header is set.

`path` and the `Host` header are only available for `1`.

When `3`, [HTTP2 Fields](#http2-fields) are replaced by [QUIC Fields](#quic-fields).

#### disable_version_fallback

!!! question "Since sing-box 1.15.0"

Disable automatic fallback to lower HTTP version.

#### h3_congestion_control

Selects the local sender congestion controller for HTTP/3 connections. Applies only to HTTP/3.

Available values: `new_reno`, `cubic`, `bbr`. HTTP proxies reject `none` at startup.

Omitting the field preserves the existing defaults: NewReno on the client and BBR on the server. BBR uses the Standard profile; profile and bandwidth parameters are not exposed. The setting affects only local sending, so the two peers may select different algorithms.

When configured, `version` must explicitly be `3`. Builds without QUIC support reject this setting.

This field does not change version fallback. Client fallback remains controlled by `disable_version_fallback`; the setting has no effect after fallback to HTTP/1 or HTTP/2.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

### HTTP2 Fields

!!! question "Since sing-box 1.15.0"

When `version` is `2` (default).

See [HTTP2 Fields](/configuration/shared/http2/) for details.

### QUIC Fields

!!! question "Since sing-box 1.15.0"

When `version` is `3`.

See [QUIC Fields](/configuration/shared/quic/) for details.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
