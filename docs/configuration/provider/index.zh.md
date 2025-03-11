# 订阅

### 结构

订阅源列表。

=== "本地文件"

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

=== "远程文件"

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

### 字段

#### type

==必填==

订阅源的类型。`local` 或 `remote`。

#### tag

==必填==

订阅源的标签。

来自 `provider` 的节点 `node_name`，导入后的标签为 `provider node_name`。

### 本地或远程字段

#### path

==必填==

!!! note ""

    自 sing-box 1.10.0 起， type为local时文件更改将自动重新加载。

本地文件路径或远程文件缓存路径。

### 远程字段

#### url

==必填==

订阅源的 URL。

#### exclude

排除节点的正则表达式。排除表达式的优先级高于包含表达式。

#### include

包含节点的正则表达式。

#### user_agent

用于下载订阅内容的 User-Agent。

#### download_detour

用于下载订阅内容的出站的标签。

如果为空，将使用默认出站。

#### update_interval

更新订阅的时间间隔。最小为 `1m`，默认为 `24h`。