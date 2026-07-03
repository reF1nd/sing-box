---
icon: material/alert-decagram
---

!!! quote "Changes in sing-box 1.12.0"

    :material-decagram: [servers](#servers)

!!! quote "Changes in sing-box 1.11.0"

    :material-plus: [cache_capacity](#cache_capacity)

# DNS

### Structure

```json
{
  "dns": {
    "servers": [],
    "rules": [],
    "final": "",
    "strategy": "",
    "disable_cache": false,
    "disable_expire": false,
    "independent_cache": false,
    "round_robin_cache": false,
    "lazy_cache_ttl": 0,
    "cache_capacity": 0,
    "cache_client_subnet": false,
    "min_cache_ttl": 0,
    "max_cache_ttl": 0,
    "reverse_mapping": false,
    "client_subnet": "",
    "fakeip": {}
  }
}

```

### Fields

| Key      | Format                          |
|----------|---------------------------------|
| `server` | List of [DNS Server](./server/) |
| `rules`  | List of [DNS Rule](./rule/)     |
| `fakeip` | [FakeIP](./fakeip/)             |

#### final

Default dns server tag.

The first server will be used if empty.

#### strategy

Default domain strategy for resolving the domain names.

One of `prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`.

#### disable_cache

Disable dns cache.

#### disable_expire

Disable dns cache expire.

#### independent_cache

Make each DNS server's cache independent for special purposes. If enabled, will slightly degrade performance.

#### round_robin_cache

Make the order of cached response addresses rotated in round robin manner.

#### lazy_cache_ttl

Serve expired cached response with given extra ttl. It will attempt to refresh the query in the background.

#### cache_capacity

!!! question "Since sing-box 1.11.0"

LRU cache capacity.

Value less than 1024 will be ignored.

#### cache_client_subnet

!!! question "Since sing-box 1.12.25-reF1nd.2 / 1.13.15-reF1nd / 1.14.0-alpha.38-reF1nd"

Allow storing responses for DNS queries received from clients that contain an EDNS0 Client Subnet (ECS) option. If the upstream response contains an ECS option, it is preserved in the cached response. The same policy applies to rejected DNS response cache (RDRC) entries.

Disabled by default. When disabled, matching existing ECS cache entries can still be used, but cache misses are not stored and stale entries are not refreshed. This option does not affect `client_subnet` configured by sing-box itself, whose responses are cached using the configured prefix as part of the cache key.

Each distinct ECS prefix creates an independent cache entry. Enabling this option can significantly increase in-memory DNS cache usage and, when `store_rdrc` is enabled, the persistent RDRC database size. Do not enable it for DNS listeners accessible by untrusted clients unless the cache capacity and listener exposure are carefully controlled.

#### min_cache_ttl

Extend short TTL values to the time given when caching them.

#### max_cache_ttl

Set a maximum TTL value for entries in the cache.

#### reverse_mapping

Stores a reverse mapping of IP addresses after responding to a DNS query in order to provide domain names when routing.

Since this process relies on the act of resolving domain names by an application before making a request, it can be
problematic in environments such as macOS, where DNS is proxied and cached by the system.

#### client_subnet

!!! question "Since sing-box 1.9.0"

Append a `edns0-subnet` OPT extra record with the specified IP prefix to every query by default.

If value is an IP address instead of prefix, `/32` or `/128` will be appended automatically.

Can be overrides by `servers.[].client_subnet` or `rules.[].client_subnet`.
