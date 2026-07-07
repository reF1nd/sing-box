---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

### 结构

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // 监听字段

  "version": 5,
  "psk": "password",
  "multi_user_authentication": "userkey",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "obfs_mode": ""
}
```

### 版本 6 结构

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // 监听字段

  "version": 6,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "mode": ""
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### version

==必填==

Snell 协议版本，`5` `6` 之一。

版本 `5` 支持 HTTP 混淆与 QUIC Proxy Mode；版本 `6` 以流量整形（`mode`）取而代之，
并要求 PSK 长度为 12 到 255 字节。

#### psk

单用户模式和 `userkey` 多用户模式下必填；`psk` 多用户模式下必须省略。

#### users

Snell 用户。

`multi_user_authentication: userkey` 时，每个用户必须配置 `userkey` 且不能出现 `psk`；
选择 `psk` 时，每个用户必须配置独立 `psk` 且不能出现 `userkey`。

#### multi_user_authentication

多用户认证模式，可选值为 `userkey`、`psk`，默认 `userkey`。仅配置 `users` 时可用。

`psk` 模式支持 v5，以及 v6 的 `default` / `unshaped`；v6 `unsafe-raw` 不使用 PSK，
因此该组合会直接报错。

#### obfs_mode

==仅版本 5==

HTTP 混淆模式，`none` `http` 之一。

默认为 `none`。

不支持 TLS simple-obfs。如需 TLS 流量伪装，请在 Snell 前配置
[ShadowTLS](/zh/configuration/inbound/shadowtls/) 入站。

#### mode

==仅版本 6==

流量整形模式，`default` `unshaped` `unsafe-raw` 之一。

默认为 `default`。
