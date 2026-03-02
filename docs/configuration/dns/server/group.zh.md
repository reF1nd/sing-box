---
icon: material/new-box
---

# Group

### 结构

```json
{
  "dns": {
    "servers": [
      {
        "type": "group",
        "tag": "dns-group",

        "servers": [
          "dns-a",
          "dns-b"
        ]
      }
    ]
  }
}
```

### 字段

#### servers

==必填==

此组包含的 DNS 服务器 tag 列表。

限制：

- 组内不能包含另一个组。
- 组内不能包含 `fakeip` 类型的服务器。

查询时，组内所有服务器将被并发查询，最先返回的成功响应将作为结果使用。
