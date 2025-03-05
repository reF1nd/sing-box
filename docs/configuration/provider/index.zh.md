# 订阅

### 结构

订阅源列表。

=== "本地文件"

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

=== "远程文件"

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

### 字段

#### type

==必填==

订阅源的类型。`local` 或 `remote`。

#### tag

==必填==

订阅源的标签。

来自 `provider` 的节点 `node_name`，导入后的标签为 `provider node_name`。

### 本地字段

#### path

==必填==

!!! note ""

    自 sing-box 1.10.0 起， 文件更改时将自动重新加载。

本地文件路径。

### 远程字段

#### url

==必填==

订阅源的 URL。

#### update_interval

更新订阅的时间间隔。最小值为 `1m`，默认值为 `1h`。

#### exclude

排除节点的正则表达式。排除表达式的优先级高于包含表达式。

#### include

包含节点的正则表达式。

#### download_detour

用于下载订阅内容的出站的标签。

如果为空，将使用默认出站。

#### path

将下载的订阅内容缓存到本地的文件的路径。

> 当 `sing-box` 作为系统服务运行，启动时很可能没有网络，利用缓存文件可避免初次获取订阅失败的问题。
