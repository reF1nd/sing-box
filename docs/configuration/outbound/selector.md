### Structure

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

    The selector can only be controlled through the [Clash API](/configuration/experimental/clash-api/) currently.

### Fields

#### outbounds

List of outbound tags to select.

#### providers

List of [Provider](/configuration/provider) tags to select.

#### use_all_providers

Include outbounds from all providers. Defaults to `false`.

#### exclude

Exclude regular expression to filter `providers` nodes. The priority of the exclude expression is higher than the include expression.

#### include

Include regular expression to filter `providers` nodes.

#### default

The outbound to select at startup. For a provider member, use its full tag, such as `provider-a/node-1`. The provider must belong to the group and the member must pass the `include` and `exclude` filters.

A member selected through the API or restored from the [cache file](/configuration/experimental/cache-file/) takes precedence when available. Otherwise the selector uses `default`, or the first member if `default` is empty. If the configured provider member is still missing after all providers load, the selector logs a warning and applies the same fallback. A group with no available members uses `Compatible`.

After startup, a provider update preserves the current selection while it is available. An explicit selection takes effect again if its member returns.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.
