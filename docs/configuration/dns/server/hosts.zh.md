---
icon: material/new-box
---

!!! question "自 sing-box 1.12.0 起"

# Hosts

### 结构

```json
{
  "dns": {
    "servers": [
      {
        "type": "hosts",
        "tag": "",

        "path": [],
        "predefined": {}
      }
    ]
  }
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

### 字段

#### path

hosts 文件路径列表。

默认使用 `/etc/hosts`。

在 Windows 上默认使用 `C:\Windows\System32\Drivers\etc\hosts`。

示例：

```json
{
  // "path": "/etc/hosts"

  "path": [
    "/etc/hosts",
    "$HOME/.hosts"
  ]
}
```

#### predefined

预定义的 hosts。

每条记录将一个域名映射到一个或多个 IP 地址，或另一个域名（别名）。

示例：

```json
{
  "predefined": {
    "www.google.com": "127.0.0.1",
    "localhost": [
      "127.0.0.1",
      "::1"
    ],
    "alias.example.com": "www.real-target.com"
  }
}
```

### 示例

=== "如果可用则使用 hosts"

    ```json
    {
      "dns": {
        "servers": [
          {
            ...
          },
          {
            "type": "hosts",
            "tag": "hosts"
          }
        ],
        "rules": [
          {
            "ip_accept_any": true,
            "server": "hosts"
          }
        ]
      }
    }
    ```