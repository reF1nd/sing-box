> Sponsored by [Warp](https://go.warp.dev/sing-box), built for coding with multiple AI agents

<a href="https://go.warp.dev/sing-box">
<img alt="Warp sponsorship" width="400" src="https://github.com/warpdotdev/brand-assets/raw/refs/heads/main/Github/Sponsor/Warp-Github-LG-02.png">
</a>

---

# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## Inbound TLS

```json
{
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "tls": {
        "enabled": true,
        "server_name": "sekai.love",
        "certificate_path": "cert.pem",
        "key_path": "key.key",
        "reject_unknown_sni": true
      }
    }
  ]
}
```

Reject unknown sni: If the server name of connection is not equal to `server_name` and not be included in certificate,
it will be rejected.

拒绝未知 SNI：如果连接的 server name 与 `server_name` 不符 且 证书中不包含它，则拒绝连接。

## URLTest Fallback 支持

按照**可用性**和**顺序**选择出站

可用：指 URL 测试存在有效结果

配置示例：
```
{
    "tag": "fallback",
    "type": "urltest",
    "outbounds": [
        "A",
        "B",
        "C"
    ],
    "fallback": {
        "enabled": true, // 开启 fallback
        "max_delay": "200ms" // 可选配置
        // 若某节点可用，但是延迟超过 max_delay，则认为该节点不可用，淘汰忽略该节点，继续匹配选择下一个节点
        // 但若所有节点均不可用，但是存在被 max_delay 规则淘汰的节点，则选择延迟最低的被淘汰节点
    }
}
```
以上配置为例子：
1. 当 A, B, C 都可用时，优选选择 A。当 A 不可用时，优选选择 B。当 A, B 都不可用时，选择 C，若 C 也不可用，则返回第一个出站：A
2. (配置了 max_delay) 当 A, C 都不可用，B 延迟超过 200ms 时（在第一轮选择时淘汰，被认为是不可用节点），则选择 B

For extended features

- Providers: [中文](./docs/configuration/provider/index.zh.md), [English](./docs/configuration/provider/index.md)

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```