# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## Support

https://community.sagernet.org/c/sing-box/

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

## 额外功能

---

#### 1. SideLoad 出站支持 (with_sideload)
对于 Sing-box 不支持的出站类型，可以通过侧载方式与 Sing-box 共用。只需暴露 Socks 端口，即可与 Sing-box 集成

编译时加入 tag ```with_sideload```

**!! 注意**：若 sing-box 被 kill / 发生panic后退出，侧载的程序并**不会退出**，需要**自行终止**，再重新启动sing-box

<p align="center">
  <img width="350px" src="https://raw.githubusercontent.com/yaotthaha/static/master/sideload.png">
</p>

例子：侧载 tuic 代理

Sing-box 配置：
```
{
  "tag": "sideload-out",
  "type": "sideload",
  "server": "www.example.com", // tuic 服务器地址
  "server_port": 443, // tuic 服务器端口
  "listen_port": 50001, // tuic 本地监听端口
  "listen_network": "udp", // 监听从tuic连接的协议类型，tcp/udp，留空都监听
  "socks5_proxy_port": 50023, // tuic 暴露的socks5代理端口
  "command": [ // tuic 侧启动命令：/usr/bin/tuic --server www.example.com --server-port 50001 --server-ip 127.0.0.1 --token token123 --local-port 50023
    "/usr/bin/tuic",
    "--server",
    "www.example.com",
    "--server-port",
    "50001",
    "--server-ip",
    "127.0.0.1",
    "--token",
    "token123",
    "--local-port",
    "50023"
  ],
  // Dial Fields
}
```

#### 2. RandomAddr 出站支持 (with_randomaddr)

- 编译时需要使用 `with_randomaddr` tag

支持随机不同 IP:Port 连接，只需要将 Detour 设置为这个出站，即可随机使用不同的 IP:Port 组合连接，需要配合其他出站使用，~~可以躲避基于目的地址的审查~~

```json5
{
    "tag": "randomaddr-out",
    "type": "randomaddr",
    "udp": true, // 为 true 时，替换 NewPakcetConn，开启 UDP 支持
    "ignore_fqdn": false, // 为 true 时，对有 FQDN 的连接不处理
    "delete_fqdn": false, // 为 true 时，删除连接中的 FQDN
    "addresses": [ // 地址重写规则
        {
            "ip": "100.64.0.1", // IP 地址，支持 192.168.2.0/24、192.168.2.0、192.168.2.0-192.168.2.254 三种写法
            "port": 80, // 连接端口
        }
    ],
}
```

用法范例：配合 WebSocket + CloudFront CDN **（请勿滥用，后果自负）**

```json5
[
    {
        "tag": "ws-out",
        "type": "vmess",
        ...
        "transport": {
            "type": "ws",
            ...
        },
        "detour": "randomaddr-out"
    },
    {
        "tag": "randomaddr-out",
        "type": "randomaddr",
        "delete_fqdn": true,
        "addresses": [
            {
                "ip": "13.33.100.0/24",
                "port": 80
            }
        ]
    }
]
```