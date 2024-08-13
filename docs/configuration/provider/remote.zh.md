### 结构

```json
{
  "type": "remote",
  "tag": "remote",
  "path": "./remote.json",
  "healthcheck_url": "https://www.gstatic.com/generate_204",
  "healthcheck_interval": "1m",

  "download_url": "http://www.baidu.com",
  "download_ua": "sing-box",
  "download_interval": "1h",
  "download_detour": "",

  "override_dialer": {},

  ... // 过滤字段
}
```

#### download_url

==必填==

指定出站提供者的下载链接。

#### download_ua

指定出站提供者的下载时的 `User-Agent`。

默认为 `sing-box`。

#### download_interval

出站提供者的下载间隔。默认使用 `1h`。

小于 `1h` 的值将不生效。

#### download_detour

用于下载出站提供者的出站的标签。

如果为空，将使用默认出站。
