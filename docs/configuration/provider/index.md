# Provider

### Structure

List of subscription providers.

=== "Local File"

    ```json
    {
      "providers": [
        {
          "tag": "provider",
          "type": "local",
          "path": "provider.txt"
        }
      ]
    }
    ```

=== "Remote File"

    ```json
    {
      "providers": [
        {
          "tag": "provider",
          "type": "remote",
          "url": "https://url.to/provider.txt",
          "update_interval": "24h",
          "exclude": "",
          "include": "",
          "download_detour": "",
          "path": "provider.txt"
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

The node `node_name` from `provider` will be tagged as `provider node_name`.

### Local Fields

#### path

==Required==

!!! note ""

    Will be automatically reloaded if file modified since sing-box 1.10.0.

File path.

### Remote Fields

#### url

==Required==

URL to the provider.

#### update_interval

Update interval. The minimum value is `1m`, the default value is `1h`.

#### exclude

Exclude regular expression to filter nodes. The priority of the exclude expression is higher than the include expression.

#### include

Include regular expression to filter nodes.

#### download_detour

The tag of the outbound used to download from the provider.

Default outbound will be used if empty.

#### path

Downloaded content will be cached in this file.

> When `sing-box` is running as a system service, it may not have network access when it starts. Using cache file can avoid the fetch failing for the first time.
