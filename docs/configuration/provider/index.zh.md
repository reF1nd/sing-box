# 出站提供者

### 结构

```json
{
  "outbound_providers": [
    {
      "type": "",
      "tag": "",
      "path": "",
      "healthcheck_url": "https://www.gstatic.com/generate_204",
      "healthcheck_interval": "1m",
      "override_dialer": {},

      ... // 过滤字段
    }
  ]
}
```

### 字段

| 类型   | 格式            |
|--------|----------------|
| `http` | [HTTP](./http) |
| `file` | [File](./file) |

#### tag

出站提供者的标签。

#### path

==必填==

出站提供者本地文件路径。

#### healthcheck_url

出站提供者健康检查的地址。

默认为 `https://www.gstatic.com/generate_204`。

#### healthcheck_interval

出站提供者健康检查的间隔。默认使用 `1m`。

#### override_dialer

覆写提供者内出站的拨号字段, 参阅 [覆写拨号字段](/zh/configuration/outbound_providers/override_dialer/)。

### 过滤字段

参阅 [过滤字段](/zh/configuration/shared/filter/)。
