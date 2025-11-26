---
icon: material/new-box
---

!!! question "Since sing-box 1.12.0"

# TCP

### Structure

```json
{
  "dns": {
    "servers": [
      {
        "type": "tcp",
        "tag": "",
        
        "server": "",
        "server_port": 53,
        
        "reuse": false,
        "pipeline": false,
        "max_queries": 0,
        
        // Dial Fields
      }
    ]
  }
}
```

!!! info "Difference from legacy TCP server"

    * The old server uses default outbound by default unless detour is specified; the new one uses dialer just like outbound, which is equivalent to using an empty direct outbound by default.
    * The old server uses `address_resolver` and `address_strategy` to resolve the domain name in the server; the new one uses `domain_resolver` and `domain_strategy` in [Dial Fields](/configuration/shared/dial/) instead.

### Fields

#### server

==Required==

The address of the DNS server.

If domain name is used, `domain_resolver` must also be set to resolve IP address.

#### server_port

The port of the DNS server.

`53` will be used by default.

#### reuse

Enable connection reuse. When enabled, idle TCP connections are pooled and reused for subsequent queries instead of opening a new connection each time.

Disabled by default.

#### pipeline

Enable DNS pipelining ([RFC 7766](https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.1.1)). When enabled, multiple DNS queries can be sent over a single TCP connection concurrently without waiting for the previous response.

Implicitly enables `reuse`.

Disabled by default.

#### max_queries

Maximum number of concurrent queries per connection in pipeline mode. When a connection reaches this limit, new queries are sent over a new connection.

Only effective when `pipeline` is enabled. `0` means unlimited.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
