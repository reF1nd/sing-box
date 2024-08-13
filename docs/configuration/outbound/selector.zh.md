### 结构

```json
{
  "type": "selector",
  "tag": "select",

  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b",
    "provider-c",
  ],
  "use_all_providers": false,
  "default": "proxy-c",
  "interrupt_exist_connections": false,

  ... // 过滤字段
}
```

!!! quote ""

    选择器目前只能通过 [Clash API](/zh/configuration/experimental#clash-api) 来控制。

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签。

### 字段

#### outbounds

用于选择的出站标签列表。

#### providers

用于填充 `outbounds` 的提供者标签列表。

#### use_all_providers

使用所有提供者填充 `outbounds`。

#### includes

匹配提供者提供的出站标签正则表达式。

#### excludes

排除提供者提供的出站标签正则表达式。

#### types

匹配提供者提供的出站类型。

#### ports

匹配提供者提供的出站端口。

#### default

默认的出站标签。默认使用第一个出站。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。

### 过滤字段

参阅 [过滤字段](/zh/configuration/shared/filter/)。
