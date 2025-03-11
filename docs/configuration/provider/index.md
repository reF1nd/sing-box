# Provider

!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [http_client](#http_client)

    :material-delete-clock: [download_detour](#download_detour)

### Structure

List of subscription providers.

=== "Local File"

    ```json
    {
      "providers": [
        {
          "type": "local",
          "tag": "provider",
          "path": "provider.txt",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
          },
          "override_dialer": {},
          "override_tls": {},
          "override_anytls": {}
        }
      ]
    }
    ```

=== "Remote File"

    ```json
    {
      "providers": [
        {
          "type": "remote",
          "tag": "provider",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
          },
          "url": "",
          "path": "",
          "exclude": "",
          "include": "",
          "user_agent": "",
          "http_client": "", // or {}
          "update_interval": "",
          "override_dialer": {},
          "override_tls": {},

          "override_anytls": {},

          // Deprecated

          "download_detour": ""
        }
      ]
    }
    ```

### Fields

#### type

==Required==

Type of the provider. `local` or `remote`.

#### tag

==Required==

Tag of the provider.

The node `node_name` from `provider` will be tagged as `provider/node_name`.

### Local or Remote Fields

#### health_check

Health check configuration.

##### health_check.enabled

Health check enabled.

##### health_check.url

Health check URL.

##### health_check.interval

Health check interval. The minimum value is `1m`, the default value is `10m`.

##### health_check.timeout

Health check timeout. the default value is `3s`.

##### override_anytls

Override AnyTLS fields of outbounds in provider, see [AnyTLS Fields Override](/configuration/provider/override_anytls/) for details.

##### override_dialer

Override dialer fields of outbounds in provider, see [Dialer Fields Override](/configuration/provider/override_dialer/) for details.

##### override_tls

Override TLS fields of outbounds in provider, see [TLS Fields Override](/configuration/provider/override_tls/) for details.

### Local Fields

#### path

==Required==

!!! note ""

    Will be automatically reloaded if file modified since sing-box 1.10.0.

Local file path.

### Remote Fields

#### url

==Required==

URL to the provider.

#### path

Path used to store the downloaded provider.

The cache metadata is stored in `cache.db`.

Conflicts with `initial_path`.

#### initial_path

Path to the initial provider content.

It is loaded only when provider caching in `cache.db` is enabled and no cached provider is available. It is not used as the persistent cache path.

Conflicts with `path`.

#### exclude

Exclude regular expression to filter nodes.

#### include

Include regular expression to filter nodes.

#### user_agent

User agent used to download the provider.

Cannot be combined with a non-empty `http_client` on this provider. Configure `User-Agent` via `http_client.headers` instead.
A `User-Agent` header configured on the default HTTP client also takes precedence over this field.

#### http_client

!!! question "Since sing-box 1.14.0"

HTTP Client for downloading provider.

See [HTTP Client Fields](/configuration/shared/http-client/) for details.

If empty, the default HTTP client is used: the client selected by
[`route.default_http_client`](/configuration/route/#default_http_client), or the first top-level `http_clients` entry if no default tag is specified.

This field cannot be combined with `download_detour`.

!!! failure "Implicit default deprecated in sing-box 1.14.0"

    If neither a client nor the legacy download detour is configured, downloads fall back to the implicit HTTP client using the default outbound.
    This fallback is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0. Define `http_clients` or configure this field explicitly.

#### download_detour

!!! failure "Deprecated in sing-box 1.14.0"

    `download_detour` is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, use `http_client` instead.

Tag of the outbound used to download from the provider.

#### update_interval

Update interval. The minimum value is `1h`, the default value is `24h`.
