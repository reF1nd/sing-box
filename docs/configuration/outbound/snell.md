---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

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

  ... // Dial Fields
}
```

### Version 6 Structure

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

#### version

The Snell protocol version, one of `1` `2` `3` `4` `5` `6`. Defaults to `4`.

| Version | TCP | UDP |
|---------|-----|-----|
| 1, 2 | Yes | No |
| 3 | Yes | UDP over TCP |
| 4 | Yes | UDP over TCP |
| 5 | Yes | QUIC Proxy for QUIC; UDP over TCP otherwise |
| 6 | Yes | UDP over TCP |

Versions 4 and 5 use the same TCP wire protocol. Version 5 only adds QUIC Proxy Mode.

#### psk

==Required==

The pre-shared key.

Version 6 requires a PSK between 12 and 255 bytes.

#### userkey

The user key, used to authenticate against a multi-user server.

#### reuse

Enable connection reuse.

Only supported for Snell protocol version `4` or above.

#### network

Enabled network

One of `tcp` `udp`.

TCP is enabled by default for v1/v2. TCP and UDP are enabled by default for
v3-v6. UDP cannot be enabled for v1/v2.

#### obfs_mode

==Version 1-5 only==

Simple-obfs mode. v1-v3 support `http` and `tls`; v4/v5 support `http`.

`none` is used by default.

TLS simple-obfs is intentionally limited to legacy v1-v3 compatibility and is
not supported for v4/v5. Use a [ShadowTLS](/configuration/outbound/shadowtls/)
detour when TLS camouflage is required.

#### obfs_host

==Version 1-5 only==

The HTTP `Host` header sent when `obfs_mode` is `http`.

`bing.com` is used by default.

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
