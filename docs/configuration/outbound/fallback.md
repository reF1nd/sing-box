### Structure

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

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### outbounds

List of outbound tags to test.

#### providers

List of [Provider](/configuration/provider) tags to test.

#### fallback
If the current node times out, the first available node will be selected in the order of proxies.

- `enabled` Indicates whether to enable Automatic rollback.

- `max_delay` is an optional configuration. If a node is available but its delay exceeds this value, the node is considered unavailable, discarded, and the matching continues to select the next node. However, if all nodes are unavailable, but there is a node that has been eliminated by this rule, the node with the lowest delay is selected.

#### exclude

Exclude regular expression to filter `providers` nodes.

#### include

Include regular expression to filter `providers` nodes.

#### url

The URL to test. `https://www.gstatic.com/generate_204` will be used if empty.

#### interval

The test interval. `3m` will be used if empty.

#### idle_timeout

The idle timeout. `30m` will be used if empty.

#### ttl

The time to live used for `sticky-sessions` strategy  timeout. `10m` will be used if empty.

#### use_all_providers

Whether to use all providers for testing. `false` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.
