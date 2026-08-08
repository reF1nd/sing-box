# 连接历史

!!! warning

    此功能仍处于实验阶段，仅在使用 `with_connection_history` 构建标签编译时可用。

### 结构

```json
{
  "enabled": true,
  "path": "history.db",
  "external_ui": "connection-history-ui",
  "retention": "30d"
}
```

### 字段

#### enabled

启用结构化连接历史和流量聚合。

#### path

历史数据库路径，默认使用 `history.db`。

#### external_ui

包含静态面板文件的配置目录相对路径或绝对路径。sing-box 将在
`http://{{external-controller}}/history/ui/` 提供该目录。

源码树的 `experimental/connectionhistory/ui` 中提供了可直接使用的静态文件，
这些文件不会编译进 sing-box 二进制。

#### retention

连接记录、分钟和小时聚合的保留时间，默认为 `30d`。

### API

历史 API 挂载在 Clash API external controller 的 `/history` 下，并复用相同的
Secret 和 CORS 策略。需要配置 `experimental.clash_api.external_controller`
才能访问 API 和面板。

可用端点包括 `summary`、`trend`、`connections`、`domains`、`ips`、
`outbounds`、`rules`、`sources` 和 `status`。
