# sing-box

这是一个第三方 Fork 仓库，在原有基础上添加一些强大功能

### 1. Outbound Provider 支持 (with_outbound_provider)

允许从远程获取 ```Outbound``` ，支持普通链接、Clash订阅、Sing-box订阅。并在此基础上对 ```Outbound``` 进行配置修改

编译时加入 tag ```with_outbound_provider```

#### 配置详解

```json5
{
  "outbounds": [
    {
      "tag": "direct-out",
      "type": "direct"
    },
    {
      "tag": "direct-mark-out", // 该 Outbound 流量会打上 SO_MARK 0xff
      "type": "direct",
      "routing_mark": 255
    },
    {
      "tag": "global",
      "type": "selector",
      "outbounds": [
        "Sub1", // 使用 Outbound Provider 暴露的同名 Selector Outbound
        "Sub2"
      ]
    }
  ],
  "outbound_providers": [
    {
      "tag": "Sub1", // Outbound Provider 标签，必填，用于区分不同 Outbound Provider 以及创建同名 Selector Outbound
      "url": "http://example.com", // 订阅链接
      "cache_tag": "", // 保存到缓存的 Tag，请开启 CacheFile 以使用缓存，若为空，则使用 tag 代替
      "update_interval": "", // 自动更新间隔，Golang Duration 格式，默认为空，不自动更新
      "request_timeout": "", // HTTP 请求的超时时间
      "http3": false, // 使用 HTTP/3 请求
      "headers": {}, // HTTP Header 头，键值对
      "optimize": false, // 自动优化
      "selector": { // 暴露的同名 Selector Outbound 配置
        // 与 Selector Outbound 配置一致
      },
      "actions": [], // 生成 Outbound 时对配置进行的操作，具体见下
      // Outbound Dial 配置，用于获取 Outbound 的 HTTP 请求
    },
    {
      "tag": "Sub2",
      "url": "http://2.example.com",
      "detour": "Sub1" // 使用 Sub1 的 Outbound 进行请求
    }
  ]
}
```

#### Action

```action``` 提供强大的对 ```Outbound``` 配置的自定义需求，```action``` 可以定义多个，按顺序执行，目前有以下操作：

###### 全局文档 - Rules

```json5
{
  "type": "...",
  "rules": [], // 匹配 Outbound 的规则，具体见下
  "logical": "or", // 匹配逻辑，要求全部匹配还是任一匹配
}
```
```
Rules 支持匹配 Tag 或 Type：

1. 若匹配 Tag ，格式：`tag:HK$`，以 `tag:` 开头，后面是 Golang 正则表达式
2. 若匹配 Type，格式：`type:trojan`，以 `type:` 开头，后面是 Outbound 类型名
3. 若无 `$*:` 开头，则默认以 `tag:` 开头
```

##### 1. Filter

过滤 ```Outbound``` ，建议放置在最前面

```json5
{
  "type": "filter",
  //
  "rules": [],
  "logical": "or", // 默认为 or
  //
  "invert": false, // 默认为 false ，对匹配到规则的 Outbound 进行过滤剔除；若为 true ，对未匹配到规则的 Outbound 进行过滤剔除
}
```

##### 2. TagFormat

对 ```Outbound``` 标签进行格式化，对于拥有多个 ```Outbound Provider``` ，并且 ```Outbound Provider``` 间 ```Outbound``` 存在命名冲突，可以使用该 action 进行重命名

```json5
{
  "type": "tagformat",
  //
  "rules": [],
  "logical": "or", // 默认为 or
  //
  "invert": false, // 默认为 false ，对匹配到规则的 Outbound 进行格式化；若为 true ，对未匹配到规则的 Outbound 进行格式化
  "format": "Sub1 - %s", // 格式化表达式，%s 代表旧的标签名
}
```

##### 3. Group

对 ```Outbound``` 进行筛选分组，仅支持 ```Selector Outbound``` 和 ```URLTest Outbound```

```json5
{
  "type": "group",
  //
  "rules": [],
  "logical": "or", // 默认为 or
  //
  "invert": false, // 默认为 false ，对匹配到规则的 Outbound 加入分组；若为 true ，对未匹配到规则的 Outbound 加入分组
  "outbound": {
    "tag": "group1",
    "type": "selector", // 使用 Selector 分组，也可以使用 URLTest 分组
    // "outbounds": [], 筛选的 Outbound 会自动添加到 Outbounds 中，可以预附加 Outbound ，造成的预期外问题自负
    // "default": "" // 仅 Selector 可用，默认为空，可以预附加 Outbound ，造成的预期外问题自负
  }
}
```

##### 4. SetDialer

对 ```Outbound``` 进行筛选修改 ```Dial``` 配置
```json5
{
  "type": "setdialer",
  //
  "rules": [],
  "logical": "and", // 默认为 and
  //
  "invert": false, // 默认为 false ，匹配到的 Outbound 才会被执行操作；若为 true ，没有匹配到的 Outbound 才会被执行操作
  "dialer": {
    "set_$tag": ..., // 以 set_ 开头，覆写原配置 $tag 项，覆写注意值类型
    "del_$tag": null // 以 del_ 开头，删除原配置 $tag 项，键值任意
  }
}
```

#### 示例配置

```json5
{
  "log": {
    "timestamp": true,
    "level": "info"
  },
  "experimental": {
    "cache_file": { // 开启缓存，缓存 Outbound Provider 数据
      "enabled": true,
      "path": "/etc/sing-box-cache.db"
    }
  },
  "outbounds": [
    {
      "tag": "direct-out",
      "type": "direct"
    },
    {
      "tag": "proxy-out",
      "type": "selector",
      "outbounds": [
        "sub"
      ]
    }
  ],
  "outbound_providers": [
    {
      "tag": "sub",
      "url": "http://example.com", // 订阅链接
      "update_interval": "24h",
      "actions": [
        {
          "type": "filter",
          "rules": [
            "剩余",
            "过期",
            "更多"
          ]
        },
        {
          "type": "group",
          "rules": [
            "香港",
            "Hong Kong",
            "HK"
          ],
          "outbound": {
            "tag": "sub - HK",
            "type": "selector"
          }
        }
      ],
      "detour": "direct-out",
      "selector": {
        "default": "sub - HK"
      }
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-cn.srs",
        "update_interval": "24h",
        "download_detour": "sub"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-cn.srs",
        "update_interval": "24h",
        "download_detour": "sub"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "geosite-cn",
          "geoip-cn"
        ],
        "outbound": "direct-out"
      },
      {
        "inbound": [
          "mixed-in"
        ],
        "outbound": "sub"
      }
    ]
  },
  "inbounds": [
    {
      "tag": "mixed-in",
      "type": "mixed",
      "listen": "::",
      "listen_port": 2080,
      "sniff": true
    }
  ]
}
```

#### Group Outbound 添加 Outbound Provider 中的 Outbound

#### 示例配置
```json5
{
  "outbounds": [
    {
      "tag": "HK",
      "type": "selector", // 支持 Selector 和 URLTest
      // "outbounds": [
      //   ...
      // ]
      "providers": [ // 添加 Outbound Provider 中的 Outbound
        {
          "tag": "sub", // Outbound Provider Tag
          // 参考上面
          "rules": ["HK"],
          "logical": "or", // 默认为 or
          //
          "invert": false // 默认为 false ，匹配到的 Outbound 才会被添加；若为 true ，没有匹配到的 Outbound 才会被添加
        }
        // 上述配置会把 Tag 为 HK 的 Outbound 添加到 Group Outbound 中
      ]
    }
  ],
  "outbound_providers": [
    {
      "tag": "sub",
      "url": "http://example.com", // 订阅链接
      "update_interval": "24h",
      "actions": [
        {
          "type": "filter",
          "rules": [
            "剩余",
            "过期",
            "更多"
          ]
        }
      ]
    }
  ]
}
```

### 2. SideLoad 出站支持 (with_sideload)

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

### 3. Clash Dashboard 内置支持 (with_clash_dashboard)

- 编译时需要使用 `with_clash_dashboard` tag
- 编译前需要先初始化 web 文件

```
使用 yacd 作为 Clash Dashboard：make init_yacd
使用 metacubexd 作为 Clash Dashboard：make init_metacubexd
清除 web 文件：make clean_clash_dashboard
```

#### 用法

```json5
{
    "experimental": {
        "clash_api": {
            "external_controller": "0.0.0.0:9090",
            //"external_ui": "" // 无需填写
            "external_ui_buildin": true // 启用内置 Clash Dashboard
        }
    }
}
```

### 4. URLTest Fallback 支持

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

### 5. RandomAddr 出站支持 (with_randomaddr)

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

### 6. Tor No Fatal 启动

```json
{
    "outbounds": [
        {
            "tag": "tor-out",
            "type": "tor",
            "no_fatal": true // 启动时将 tor outbound 启动置于后台，加快启动速度，但启动失败会导致无法使用
        }
    ]
}
```

### 7. Geo Resource 自动更新支持

#### 用法
```json5
{
    "route": {
        "geosite": {
            "path": "/temp/geosite.db",
            "auto_update_interval": "12h" // 更新间隔，在程序运行时会间隔时间自动更新
        },
        "geoip": {
            "path": "/temp/geoip.db",
            "auto_update_interval": "12h"
        }
    }
}
```

- 支持在 Clash API 中调用 API 更新 Geo Resource

### 8. JSTest 出站支持 (with_jstest) (*** 实验性 ***)

JSTest 出站允许用户根据 JS 脚本代码选择出站，依附 JS 脚本，用户可以自定义强大的出站选择逻辑，比如：送中节点规避，流媒体节点选择，等等。

你可以在 jstest/javascript/ 目录下找到一些示例脚本。

- 编译时需要使用 `with_jstest` tag
- JS 脚本请自行测试，慎而又慎，不要随意使用不明脚本，可能会导致安全问题或预期外的问题
- JS 脚本运行需要依赖 JS 虚拟机，内存占用可能会比较大（10-20M 左右，视脚本而定），建议使用时注意内存占用情况

- 专门告知使用送中节点的脚本的用户：请**确保 Google 定位已经正常关闭**，否则运行该脚本可能会**导致上游节点全部送中**，~~尤其是机场用户~~，运行所造成的一切后果概不负责

#### 用法
```json5
{
    "outbounds": [
        {
            "tag": "google-cn-auto-switch",
            "type": "jstest",
            "js_path": "/etc/sing-box/google_cn.js", // JS 脚本路径
            "js_base64": "", // JS 脚本 Base64 编码，若遇到某些存储脚本文件困难的情况，如：使用了移动客户端，可以使用该字段
            "interval": "60s", // 脚本执行间隔
            "interrupt_exist_connections": false // 切换时是否中断已有连接
        }
    ]
}
```