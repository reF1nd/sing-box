# 订阅

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [http_client](#http_client)  
    :material-delete-clock: [download_detour](#download_detour)

### 结构

订阅源列表。

=== "本地文件"

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

=== "远程文件"

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

### 字段

#### type

==必填==

订阅源的类型。`local` 或 `remote`。

#### tag

==必填==

订阅源的标签。

来自 `provider` 的节点 `node_name`，导入后的标签为 `provider/node_name`。

### 本地或远程字段

#### health_check

健康检查配置。

##### health_check.enabled

是否启用健康检查。

##### health_check.url

健康检查的 URL。

##### health_check.interval

健康检查的时间间隔。最小为 `1m`，默认为 `10m`。

##### health_check.timeout

健康检查的超时时间。默认为 `3s`。

##### override_dialer

覆写订阅内容的拨号字段, 参阅 [拨号字段覆写](/zh/configuration/provider/override_dialer/)。

### 本地字段

#### path

==必填==

!!! note ""

    自 sing-box 1.10.0 起， 文件更改将自动重新加载。

本地文件路径。

### 远程字段

#### url

==必填==

订阅源的 URL。

#### exclude

排除节点的正则表达式。

#### include

包含节点的正则表达式。

#### user_agent

用于下载订阅内容的 User-Agent。

#### http_client

!!! question "自 sing-box 1.14.0 起"

用于下载订阅内容的 HTTP 客户端。

参阅 [HTTP 客户端字段](/zh/configuration/shared/http-client/) 了解详情。

如果为空，将使用默认传输。

#### download_detour

!!! failure "已在 sing-box 1.14.0 废弃"

    `download_detour` 已在 sing-box 1.14.0 废弃且将在 sing-box 1.16.0 中被移除，请使用 `http_client` 代替。

用于下载订阅内容的出站的标签。

#### update_interval

更新订阅的时间间隔。最小为 `1m`，默认为 `24h`。