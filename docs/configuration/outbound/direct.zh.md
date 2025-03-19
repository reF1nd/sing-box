---
icon: material/alert-decagram
---

!!! quote "sing-box 1.11.0 中的更改"

    :material-alert-decagram: [override_address](#override_address)  
    :material-alert-decagram: [override_port](#override_port)

`direct` 出站直接发送请求。

### 结构

```json
{
  "type": "direct",
  "tag": "direct-out",
  
  "override_address": "1.0.0.1",
  "override_port": 53,
  "proxy_protocol": 0,

  ... // 拨号字段
}
```

### 字段

#### override_address

!!! failure "已在 sing-box 1.11.0 废弃"

    目标覆盖字段在 sing-box 1.11.0 中已废弃，并将在 sing-box 1.13.0 中被移除，参阅 [迁移指南](/migration/#migrate-destination-override-fields-to-route-options)。

覆盖连接目标地址。

#### override_port

!!! failure "已在 sing-box 1.11.0 废弃"

    目标覆盖字段在 sing-box 1.11.0 中已废弃，并将在 sing-box 1.13.0 中被移除，参阅 [迁移指南](/migration/#migrate-destination-override-fields-to-route-options)。

覆盖连接目标端口。

#### proxy_protocol

写出 [代理协议](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) 到连接头。

可用协议版本值：`1` 或 `2`。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
