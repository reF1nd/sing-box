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
    "provider-b"
  ],
  "exclude": "",
  "include": "",
  "default": "proxy-c",
  "use_all_providers": false,
  "interrupt_exist_connections": false
}
```

!!! quote ""

    选择器目前只能通过 [Clash API](/zh/configuration/experimental/clash-api/) 来控制。

### 字段

#### outbounds

用于选择的出站标签列表。

#### providers

用于选择的[订阅](/zh/configuration/provider)标签列表。

#### exclude

排除 `providers` 节点的正则表达式。

#### include

包含 `providers` 节点的正则表达式。

#### default

启动时选择的出站。订阅节点使用完整标签，例如 `provider-a/node-1`。该订阅必须已加入选择器，且节点须通过 `include` 和 `exclude` 过滤。

通过 API 选择或从[缓存文件](/zh/configuration/experimental/cache-file/)恢复的节点可用时，优先使用该节点。否则使用 `default`，未设置时使用第一个成员。如果所有订阅加载完成后仍找不到指定的默认节点，选择器会记录警告，并按未设置 `default` 处理。组内没有可用成员时使用 `Compatible`。

启动后的订阅更新会保留仍然可用的当前节点。如果之前手动选择的节点重新出现，选择器会切回该节点。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。
