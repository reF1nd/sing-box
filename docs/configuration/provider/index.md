# Provider

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
          "override_dialer": {}
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
          "download_detour": "",
          "update_interval": "",
          "override_dialer": {}
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

##### override_dialer

Override dialer fields of outbounds in provider, see [Dialer Fields Override](/configuration/provider/override_dialer/) for details.

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

#### download_detour

The tag of the outbound used to download from the provider.

Default outbound will be used if empty.

#### update_interval

Update interval. The minimum value is `1h`, the default value is `24h`.
