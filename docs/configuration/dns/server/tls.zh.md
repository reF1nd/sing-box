---
icon: material/new-box
---

!!! question "自 sing-box 1.12.0 起"

# DNS over TLS (DoT)

### 结构

```json
{
  "dns": {
    "servers": [
      {
        "type": "tls",
        "tag": "",

        "server": "",
        "server_port": 853,

        "tls": {},

        "pipeline": false,
        "max_queries": 0,

        // 拨号字段
      }
    ]
  }
}
```

!!! info "与旧版 TLS 服务器的区别"

    * 旧服务器默认使用默认出站，除非指定了绕行；新服务器像出站一样使用拨号器，相当于默认使用空的直连出站。
    * 旧服务器使用 `address_resolver` 和 `address_strategy` 来解析服务器中的域名；新服务器改用 [拨号字段](/zh/configuration/shared/dial/) 中的 `domain_resolver` 和 `domain_strategy`。

### 字段

#### server

==必填==

DNS 服务器的地址。

如果使用域名，还必须设置 `domain_resolver` 来解析 IP 地址。

#### server_port

DNS 服务器的端口。

默认使用 `853`。

#### tls

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#出站)。

#### pipeline

启用 DNS 管线化（[RFC 7766](https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.1.1)）。启用后，可以在单条 TLS 连接上并发发送多个 DNS 查询，无需等待前一个响应。

默认禁用。

#### max_queries

管线化模式下每条连接的最大并发查询数。当连接达到此限制时，新查询将通过新连接发送。

仅在启用 `pipeline` 时生效。`0` 表示不限制。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/) 了解详情。