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
          "type": "remote",
          "tag": "provider",
          "path": "provider.txt",
          "url": "https://url.to/provider.txt",
          "exclude": "",
          "include": "",
          "user_agent": "",
          "download_detour": "",
          "update_interval": "24h"
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

### Local or Remote Fields

#### path

==Required==

!!! note ""

    Will be automatically reloaded if file modified since sing-box 1.10.0.

Local file path or remote file cache path.

### Remote Fields

#### url

==Required==

URL to the provider.

#### exclude

Exclude regular expression to filter nodes. The priority of the exclude expression is higher than the include expression.

#### include

Include regular expression to filter nodes.

#### user_agent

User agent used to download the provider.

#### download_detour

The tag of the outbound used to download from the provider.

Default outbound will be used if empty.

#### update_interval

Update interval. The minimum value is `1m`, the default value is `24h`.
