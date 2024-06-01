### 结构

```json
{
  "force_override": false,
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
  "domain_strategy": "prefer_ipv6",
  "fallback_delay": "300ms"
}
```

### 字段

`detour` `bind_interface` `inet4_bind_address` `inet6_bind_address` `routing_mark` `reuse_addr` `connect_timeout` `tcp_fast_open` `tcp_multi_path` `udp_fragment` `domain_strategy` `fallback_delay` 详情参阅 [拨号字段](/zh/configuration/shared/dial)。

#### force_override

当开启时，强制覆写所有列出的字段。

当关闭时，强制 `reuse_addr` `tcp_fast_open` `tcp_multi_path` `udp_fragment` 字段，其他仅在非空时覆写。
