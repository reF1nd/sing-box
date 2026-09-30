### Structure

```json
{
  "type": "http",
  "tag": "http-in",
  
  ... // Listen Fields
  
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

  ... // HTTP2 Fields / QUIC Fields
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### version

!!! question "Since sing-box 1.15.0"

List of HTTP versions to serve.

Available values: `1`, `2`, `3`.

`1` and `2` are used by default.

TLS is required for `3`.

#### h3_congestion_control

Selects the local sender congestion controller for HTTP/3 connections. Applies only to HTTP/3.

Available values: `new_reno`, `cubic`, `bbr`. HTTP proxies reject `none` at startup.

Omitting the field preserves the existing defaults: NewReno on the client and BBR on the server. BBR uses the Standard profile; profile and bandwidth parameters are not exposed. The setting affects only local sending, so the two peers may select different algorithms.

When configured, `version` must include `3`. The default version list does not include `3`; enable it explicitly. Builds without QUIC support reject this setting.

This field does not change version fallback. Client fallback remains controlled by `disable_version_fallback`; the setting has no effect after fallback to HTTP/1 or HTTP/2.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

#### users

HTTP users.

No authentication required if empty.

#### set_system_proxy

!!! quote ""

    Only supported on Linux, Android, Windows, and macOS.

!!! warning ""

    To work on Android and Apple platforms without privileges, use tun.platform.http_proxy instead.

Automatically set system proxy configuration when start and clean up when stop.

### HTTP2 Fields

!!! question "Since sing-box 1.15.0"

When `version` contains `2`.

See [HTTP2 Fields](/configuration/shared/http2/) for details.

### QUIC Fields

!!! question "Since sing-box 1.15.0"

When `version` contains `3`, [HTTP2 Fields](#http2-fields) are replaced by QUIC Fields.

See [QUIC Fields](/configuration/shared/quic/) for details.
