### Structure

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

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### strategy

Load Balancing Strategies.

* `round-robin` will distribute all requests among different proxy nodes within the strategy group.

* `consistent-hashing` will assign requests with the same `target address` to the same proxy node within the strategy group.

* `sticky-sessions`: requests with the same `source address` and `target address` will be directed to the same proxy node within the strategy group, with a cache expiration of specified ttl.

!!! note
    When the `target address` is a domain, it uses top-level domain matching.

#### outbounds

List of outbound tags to test.

#### providers

List of [Provider](/configuration/provider) tags to test.

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
