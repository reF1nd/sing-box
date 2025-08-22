### 结构

```json
{
  "detour": "upstream-out",
  "bind_interface": "en0",
  "inet4_bind_address": "0.0.0.0",
  "inet6_bind_address": "::",
  "routing_mark": 1234,
  "reuse_addr": false,
  "connect_timeout": "5s",
  "tcp_fast_open": false,
  "tcp_multi_path": false,
  "udp_fragment": false,
  "domain_resolver": "", // 或 {}
  "network_strategy": "default",
  "network_type": [],
  "fallback_network_type": [],
  "fallback_delay": "300ms",
  "tcp_keep_alive_interval": "75s",
  "tcp_keep_alive_idle": "10m",

  // 废弃的

  "domain_strategy": "prefer_ipv6"
}
```

### 字段

`detour` `bind_interface` `inet4_bind_address` `inet6_bind_address` `routing_mark` `reuse_addr` `connect_timeout` `tcp_fast_open` `tcp_multi_path` `udp_fragment` `domain_resolver` `network_strategy` `network_type` `fallback_network_type` `fallback_delay` `tcp_keep_alive_interval` `tcp_keep_alive_idle` `domain_strategy` 详情参阅 [拨号字段](/zh/configuration/shared/dial)。
