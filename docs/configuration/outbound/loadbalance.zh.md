### 结构

```json
{
  "type": "loadbalance",
  "tag": "balance",
  "strategy": "round-robin",

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

#### strategy

负载均衡策略。

* `round-robin` 将在策略组内的不同代理节点之间分配所有请求。

* `consistent-hashing` 将具有相同 `目标地址` 的请求分配给策略组内的同一代理节点。

* `sticky-sessions`：具有相同 `源地址` 和 `目标地址` 的请求将被导向策略组内的同一代理节点，缓存过期时间为指定的 ttl。

!!! note
    当 `目标地址` 是域名时，使用顶级域名匹配。

#### outbounds

用于测试的出站标签列表。

#### providers

用于测试的[订阅](/zh/configuration/provider)标签列表。

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
