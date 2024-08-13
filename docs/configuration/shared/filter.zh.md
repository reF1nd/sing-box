### 结构

```json
{
  "includes": [
    "^HK\\..+",
    "^TW\\..+",
    "^SG\\..+",
  ],
  "excludes": "^JP\\..+",
  "types": [
    "shadowsocks",
    "vmess",
    "vless",
  ],
  "ports": [
    "80",
    "2000:4000",
    "2000:",
    ":4000"
  ]
}
```

#### includes

匹配提供者提供的出站标签正则表达式。

#### excludes

排除提供者提供的出站标签正则表达式。

#### types

匹配提供者提供的出站类型。

#### ports

匹配提供者提供的出站端口。
