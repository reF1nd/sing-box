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
          "exclude": "",
          "include": "",
          "user_agent": "",
          "http_client": "", // or {}
          "update_interval": "",
          "override_dialer": {},

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

#### exclude

Exclude regular expression to filter nodes.

#### include

Include regular expression to filter nodes.

#### user_agent

User agent used to download the provider.

#### http_client

!!! question "Since sing-box 1.14.0"

HTTP Client for downloading provider.

See [HTTP Client Fields](/configuration/shared/http-client/) for details.

Default transport will be used if empty.

#### download_detour

!!! failure "Deprecated in sing-box 1.14.0"

    `download_detour` is deprecated in sing-box 1.14.0 and will be removed in sing-box 1.16.0, use `http_client` instead.

Tag of the outbound used to download from the provider.

#### update_interval

Update interval. The minimum value is `1m`, the default value is `24h`.
