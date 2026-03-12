### 结构

```json
{
  "type": "urltest",
  "tag": "fallback",

  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b"
  ],
  "fallback": {
    "enabled": true,
    "max_delay": "200ms"
  },
  "exclude": "",
  "include": "",
  "url": "",
  "interval": "",
  "idle_timeout": "",
  "ttl": "10m",
  "use_all_providers": false,
  "interrupt_exist_connections": false
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签。

### 字段

#### outbounds

用于测试的出站标签列表。

#### providers

用于测试的[订阅](/zh/configuration/provider)标签列表。

#### fallback
当前节点超时时，则会按代理顺序选择第一个可用节点。

- `enabled` 是否开启自动回退。

- `max_delay` 为可选配置。若某节点可用，但是延迟超过该值，则认为该节点不可用，淘汰忽略该节点，继续匹配选择下一个节点，但若所有节点均不可用，但是存在被该规则淘汰的节点，则选择延迟最低的被淘汰节点。

#### exclude

排除 `providers` 节点的正则表达式。

#### include

包含 `providers` 节点的正则表达式。

#### url

用于测试的链接。默认使用 `https://www.gstatic.com/generate_204`。

#### interval

测试间隔。 默认使用 `3m`。

#### idle_timeout

空闲超时。默认使用 `30m`。

#### ttl

用于 `sticky-sessions` 策略超时的生存时间。默认使用 `10m`。

#### use_all_providers

是否使用所有提供者。默认使用 `false`。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。
