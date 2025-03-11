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
          "override_dialer": {},
          "override_tls": {},
          "override_anytls": {}
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

##### override_anytls

覆写订阅内容的 AnyTLS 字段，参阅 [AnyTLS 字段覆写](/zh/configuration/provider/override_anytls/)。

##### override_dialer

覆写订阅内容的拨号字段, 参阅 [拨号字段覆写](/zh/configuration/provider/override_dialer/)。

##### override_tls

覆写订阅内容的 TLS 字段, 参阅 [TLS 字段覆写](/zh/configuration/provider/override_tls/)。

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

#### path

用于存储已下载订阅源的路径。

缓存元数据存储于 `cache.db`。

与 `initial_path` 冲突。

#### initial_path

初始订阅源内容的路径。

仅在启用 `cache.db` 订阅缓存且不存在可用缓存时读取。该路径不会作为持久缓存路径使用。

与 `path` 冲突。

#### exclude

排除节点的正则表达式。

#### include

包含节点的正则表达式。

#### user_agent

用于下载订阅内容的 User-Agent。

不能与此 provider 上的非空 `http_client` 同时配置。请改为通过 `http_client.headers` 设置 `User-Agent`。
默认 HTTP 客户端中配置的 `User-Agent` 标头也会覆盖此字段。

#### http_client

!!! question "自 sing-box 1.14.0 起"

用于下载订阅内容的 HTTP 客户端。

参阅 [HTTP 客户端字段](/zh/configuration/shared/http-client/) 了解详情。

留空时使用默认 HTTP 客户端：即由 [`route.default_http_client`](/zh/configuration/route/#default_http_client)
指定的客户端，或未指定默认标签时使用顶层 `http_clients` 的第一项。

此字段不能与 `download_detour` 同时配置。

!!! failure "隐式默认已在 sing-box 1.14.0 废弃"

    如果既未配置客户端，也未配置旧下载 detour，将回退到通过默认出站连接的隐式 HTTP 客户端。
    此回退已在 sing-box 1.14.0 废弃，将在 sing-box 1.16.0 移除。请定义 `http_clients` 或显式配置此字段。

#### download_detour

!!! failure "已在 sing-box 1.14.0 废弃"

    `download_detour` 已在 sing-box 1.14.0 废弃且将在 sing-box 1.16.0 中被移除，请使用 `http_client` 代替。

用于下载订阅内容的出站的标签。

#### update_interval

更新订阅的时间间隔。最小为 `1h`，默认为 `24h`。
