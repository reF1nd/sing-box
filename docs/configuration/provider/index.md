# OutboundProvider

### Structure

```json
{
  "outbound_providers": [
    {
      "type": "",
      "tag": "",
      "path": "",
      "enable_healthcheck": false,
      "healthcheck_url": "https://www.gstatic.com/generate_204",
      "healthcheck_interval": "1m",
      "healthcheck_when_network_change": false,
      
      "outbound_override": {},

      ... // Filter Fields
    }
  ]
}
```

### Fields

| Type     | Format             |
|----------|--------------------|
| `remote` | [Remote](./remote) |
| `local`  | [Local](./local)   |

#### tag

The tag of the outbound provider.

#### path

==Required==

The path of the outbound provider file.

#### enable_healthcheck

Health check outbounds in outbound provider or not.

Health check will always happen in init status.

#### healthcheck_url

The url for health check of the outbound provider.

Default is `https://www.gstatic.com/generate_204`.

#### healthcheck_interval

The interval for health check of the outbound provider. `1m` will be used if empty.

An interval string is a possibly signed sequence of
decimal numbers, each with optional fraction and a unit suffix,
such as "300ms", "-1.5h" or "2h45m".
Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".

#### healthcheck_when_network_change

health check when network changed.

#### outbound_override

Override fields of outbounds in provider, see [Outbound Override](/configuration/provider/outbound_override/) for details.

### Filter Fields

See [Filter Fields](/configuration/shared/filter/) for details.
