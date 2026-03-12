`socks` 出站是 socks4/socks4a/socks5 客户端

### 结构

```json
{
  "type": "socks",
  "tag": "socks-out",
  
  "server": "127.0.0.1",
  "server_port": 1080,
  "version": "5",
  "username": "sekai",
  "password": "admin",
  "network": "udp",
  "udp_over_tcp": false,
  "inner_domain_resolver": "", // 或 {}

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

SOCKS 版本, 可为 `4` `4a` `5`.

默认使用 SOCKS5。

#### username

SOCKS 用户名。

#### password

SOCKS5 密码。

#### network

启用的网络协议

`tcp` 或 `udp`。

默认所有。

#### udp_over_tcp

UDP over TCP 配置。

参阅 [UDP Over TCP](/zh/configuration/shared/udp-over-tcp/)。

#### inner_domain_resolver

!!! note ""

    仅当 `version` 为 `4` 时生效。SOCKS4 协议不支持传输域名，因此必须在本地解析后再连接。

设置用于解析经由 SOCKS4 转发的连接的域名解析器。

此选项与 [domain_resolver](/zh/configuration/shared/dial/#domain_resolver) 格式相同。

未设置时使用默认DNS。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
