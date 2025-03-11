### 结构

```json
{
  "client_metadata": "",
  "disable_reuse": false
}
```

### 字段

`client_metadata` `disable_reuse` 详情参阅 [AnyTLS 出站](/zh/configuration/outbound/anytls/)。

未配置的字段保留订阅中的值。显式配置空的 `client_metadata` 会清空元数据；
`disable_reuse: false` 会显式重新启用复用。
