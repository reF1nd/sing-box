---
icon: material/chart-line
---

# 可观测性

可观测性服务提供运行时指标和近期连接信息，不再维护本地历史数据库。
只有将 `experimental.observability.enabled` 设为 `true` 时才会启用。

长期时序数据应由 Prometheus 保存。sing-box 只保留一个有界的内存连接环，
不会创建、追加或清理本地数据库文件。

### 配置结构

```json
{
  "enabled": true,
  "recent_connections": 1000,
  "recent_ttl": "30m",
  "top_k_size": 100,
  "expose_sensitive": false
}
```

### 字段

#### enabled

启用可观测性服务。该功能包含在普通构建中，不需要额外 build tag。

#### recent_connections

内存中保留的关闭连接数量上限，用于近期连接和 Top-K 接口。默认值为
`1000`，超过 `100000` 会被拒绝。数值越大，内存占用、可观测性接口响应时间，
以及现有 traffic 总量快照的扫描成本越高。除非实测确有必要，否则应保持在几千以内。

该连接环复用现有 traffic tracker，因此 sing-box 原生 API 的连接流和 OOM
报告也可以继续使用这些近期连接。

#### recent_ttl

近期连接和 Top-K 查询接受的最大连接年龄，默认值为 `30m`。这是内存查询
窗口，不是磁盘 retention；sing-box 重启后数据全部消失。

#### top_k_size

Top-K 查询最多返回的条目数，默认 `100`，上限 `1000`。Top-K 只根据内存
连接环计算，不能替代完整历史事件存储。

#### expose_sensitive

允许在 JSON、Top-K 和事件响应中返回域名、源/目的 IP、进程、用户、匹配规则
和来源信息。默认值为 `false`。Prometheus 指标永远不会把这些内容作为标签。
API 可被其他用户或网络访问时应保持关闭。

## 启用 API 监听

同一套专用 API 会同时挂载到 Clash Controller 和 sing-box 原生 API service。
选择其中一个即可，不需要为可观测性再开一套监听器。

### Clash Controller

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "replace-with-a-long-secret"
    },
    "observability": {
      "enabled": true,
      "recent_connections": 2000,
      "recent_ttl": "1h",
      "top_k_size": 100,
      "expose_sensitive": false
    }
  }
}
```

访问地址：

```text
http://127.0.0.1:9090/observability/v1/
```

### sing-box 原生 API service

```json
{
  "services": [
    {
      "type": "api",
      "listen": "127.0.0.1:9091",
      "secret": "replace-with-a-long-secret"
    }
  ],
  "experimental": {
    "observability": {
      "enabled": true
    }
  }
}
```

访问地址为 `http://127.0.0.1:9091/observability/v1/`。原生 API service 的
TLS 配置启用后，也会保护可观测性接口。

设置 Secret 后，两种监听都使用 `Authorization: Bearer <secret>` 认证。监听
绑定到非回环地址时必须设置 Secret。

## 接口

以下路径均相对于 `/observability/v1`，并使用 `GET`：

| 路径 | 内容 | 说明 |
|------|------|------|
| `/` | JSON | API 版本和接口列表 |
| `/capabilities` | JSON | 容量限制、维度和支持的 API 行为 |
| `/metrics` | Prometheus 文本 | 运行时 gauge 和 counter |
| `/status` | JSON | 版本、运行时间、内存、活跃连接和容量限制 |
| `/connections/active` | JSON | 当前连接，按最新启动时间排序 |
| `/connections/recent` | JSON | 内存中保留的关闭连接 |
| `/top` | JSON | 内存连接中的 Top-K |
| `/events` | Server-Sent Events | 开启/关闭事件和 keepalive 注释 |

错误响应提供稳定的 `error` 对象，其中包含 `code`、`message`，适用时还包含
`parameter` 和 `maximum`。未知查询参数会被拒绝。

### 连接分页

两个连接接口均返回 `data`、`total`、`hasMore`，还有存在下一页时返回的
`nextCursor`。活跃连接单次最多返回 500 条：

```text
/connections/active?limit=100
/connections/active?limit=100&cursor=<nextCursor>
```

### 近期连接

```text
/connections/recent?window=30m&limit=100
/connections/recent?window=30m&limit=100&cursor=<nextCursor>
```

`window` 不能超过 `recent_ttl`，结果按最新优先。`total` 只代表内存连接环中的
数量，不代表进程启动以来的全部连接。游标分页能避免翻页期间新增连接造成重复
或遗漏，不支持 offset 分页。

### Top-K

```text
/top?dimension=outbound&window=30m&limit=10
```

支持 `network`、`inbound`、`outbound`、`rule`、`domain`、`destination_ip`、
`source`、`process` 和 `user`。其中 `rule`、`domain`、`destination_ip`、
`source`、`process` 和 `user` 需要开启 `expose_sensitive`。每个条目包含上传、
下载和连接数。

### 事件流

```bash
curl -N \
  -H 'Authorization: Bearer replace-with-a-long-secret' \
  'http://127.0.0.1:9090/observability/v1/events?heartbeat=15s'
```

事件包含在当前流内单调递增的 `id`，使用 `event: open` 或 `event: close`，并附带
JSON `data` 行。ID 表示当前流内的投递顺序，但事件流不支持重放，也不支持
`Last-Event-ID`。sing-box 不会持久化事件；需要精确的长期连接历史时，可以由
外部 collector 写入 Loki、ClickHouse 或其他事件存储。

## Prometheus

Prometheus 应主动抓取 sing-box；sing-box 不向 Pushgateway 或 remote-write
地址主动推送样本。

```yaml
scrape_configs:
  - job_name: sing-box
    scrape_interval: 15s
    metrics_path: /observability/v1/metrics
    authorization:
      type: Bearer
      credentials: replace-with-a-long-secret
    static_configs:
      - targets: [127.0.0.1:9090]
```

导出的有界指标包括：

- `singbox_build_info`、`singbox_uptime_seconds`、`singbox_memory_bytes`、
  `singbox_goroutines`；
- `singbox_connections_active`、`singbox_connections_total`；
- `singbox_traffic_upload_bytes_total`、
  `singbox_traffic_download_bytes_total`；
- 只使用 outbound chain 标签的 `singbox_outbound_*` 指标；
- `singbox_inbound_connections_*` 和 `singbox_network_connections_*`；
- 最新 outbound URLTest 延迟和时间戳 gauge；
- `singbox_recent_connections` 和 `singbox_recent_connections_capacity`；
- `singbox_observability_http_*` API 请求、响应大小和耗时 counter，以及当前
  SSE 订阅者和已发送事件数。

Counter 使用 `rate()` 或 `increase()`：

```promql
rate(singbox_traffic_download_bytes_total[5m]) * 8
topk(10, rate(singbox_outbound_download_bytes_total[5m]))
```

长期 retention 由 Prometheus 负责，并会处理 sing-box 重启后的 counter reset。
Prometheus 不可用时会丢失对应采样，这是设计选择，不会让监控故障阻塞代理流量。

