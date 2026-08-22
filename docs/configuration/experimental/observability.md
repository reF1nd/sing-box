---
icon: material/chart-line
---

# Observability

The observability service exposes runtime metrics and recent connection data
without maintaining a local history database. It is disabled unless
`experimental.observability.enabled` is set to `true`.

Long-term time series are intended to be stored by Prometheus. sing-box keeps
only a bounded in-memory connection ring and does not create, append to, or
prune a local database file.

### Structure

```json
{
  "enabled": true,
  "recent_connections": 1000,
  "recent_ttl": "30m",
  "top_k_size": 100,
  "expose_sensitive": false
}
```

### Fields

#### enabled

Enable the observability service.

The service is available in normal builds. It does not require a build tag.

#### recent_connections

Maximum number of closed connections retained in memory for the recent
connection and Top-K endpoints. The default is `1000`; values above `100000`
are rejected. A larger value increases memory usage, observability response
time, and the scan cost of existing traffic total snapshots. Keep this value
in the low thousands unless measurements justify a larger ring.

The ring is shared with the existing traffic tracker, so it is also available
to the native sing-box API connection stream and OOM reports.

#### recent_ttl

Maximum age accepted by recent and Top-K queries. The default is `30m`.
This is an in-memory query window, not a disk retention period. All values are
lost when sing-box restarts.

#### top_k_size

Maximum number of values returned by a Top-K query. The default is `100` and
the maximum is `1000`.

Top-K results are calculated from the retained recent connection ring. They are
not a replacement for a complete historical event store.

#### expose_sensitive

Expose domains, source and destination IP addresses, process names, users,
matched rules and source metadata in JSON, Top-K and event responses. The
default is `false`.

Prometheus metrics never contain these values as labels. Keep this option
disabled when the API is reachable by other users or networks.

## Enabling an API listener

The same dedicated API is mounted on both the Clash Controller and the native
sing-box API service. Use either one; do not configure a second observability
listener.

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

The API is available below:

```text
http://127.0.0.1:9090/observability/v1/
```

### Native API service

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

The same paths are available at `http://127.0.0.1:9091/observability/v1/`.
The native API's TLS settings also protect the observability endpoints when
TLS is enabled for the service.

Both listeners use `Authorization: Bearer <secret>` when a secret is set.
Always configure a secret before binding either listener to a non-loopback
address.

## Endpoints

All paths below are relative to `/observability/v1` and use `GET`.

| Path | Content | Description |
|------|---------|-------------|
| `/` | JSON | API version and endpoint list |
| `/capabilities` | JSON | Limits, dimensions and supported API behavior |
| `/metrics` | Prometheus text | Runtime gauges and counters |
| `/status` | JSON | Version, uptime, memory, active connections and limits |
| `/connections/active` | JSON | Current connections, newest first |
| `/connections/recent` | JSON | Retained closed connections |
| `/top` | JSON | Top values from retained connections |
| `/events` | Server-Sent Events | Open and close events with keepalive comments |

Errors contain a stable `error` object with `code`, `message`, and, when
applicable, `parameter` and `maximum`. Unknown query parameters are rejected.

### Connection pagination

Both connection endpoints return `data`, `total`, `hasMore` and, when another
page exists, `nextCursor`. Active connections accept at most 500 rows per
request:

```text
/connections/active?limit=100
/connections/active?limit=100&cursor=<nextCursor>
```

### Recent connections

```text
/connections/recent?window=30m&limit=100
/connections/recent?window=30m&limit=100&cursor=<nextCursor>
```

`window` cannot exceed `recent_ttl`. The result is newest first. `total` is
limited to the in-memory ring, not all connections since the process started.
Cursor pagination avoids duplicate or skipped rows while new connections
arrive. Offset pagination is not supported.

### Top-K

```text
/top?dimension=outbound&window=30m&limit=10
```

Supported dimensions are `network`, `inbound`, `outbound`, `rule`, `domain`,
`destination_ip`, `source`, `process` and `user`. The `rule`, `domain`,
`destination_ip`, `source`, `process` and `user` dimensions require
`expose_sensitive: true`. Every item contains upload, download and connection
counts.

### Event stream

```bash
curl -N \
  -H 'Authorization: Bearer replace-with-a-long-secret' \
  'http://127.0.0.1:9090/observability/v1/events?heartbeat=15s'
```

Events include an `id` that increases within the current stream, use
`event: open` or `event: close`, and carry a JSON `data` line. The ID expresses
delivery order within that stream, but the stream is not replayable and
`Last-Event-ID` is not supported. This stream is
intentionally not persisted by sing-box. A collector can write it to Loki,
ClickHouse or another event store when exact long-term connection history is
required.

## Prometheus

Prometheus should scrape sing-box; sing-box does not push samples to
Pushgateway or remote-write endpoints.

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

The exporter exposes bounded metrics including:

- `singbox_build_info`, `singbox_uptime_seconds`, `singbox_memory_bytes` and
  `singbox_goroutines`;
- `singbox_connections_active` and `singbox_connections_total`;
- `singbox_traffic_upload_bytes_total` and
  `singbox_traffic_download_bytes_total`;
- `singbox_outbound_*` counters and gauges labelled only by outbound chain;
- `singbox_inbound_connections_*` and `singbox_network_connections_*`;
- latest outbound URL test delay and timestamp gauges;
- `singbox_recent_connections` and `singbox_recent_connections_capacity`;
- `singbox_observability_http_*` API request, response-size and duration
  counters, plus current SSE subscribers and sent events.

Use `rate()` or `increase()` for counters:

```promql
rate(singbox_traffic_download_bytes_total[5m]) * 8
topk(10, rate(singbox_outbound_download_bytes_total[5m]))
```

Prometheus owns the long-term retention and handles counter resets after a
sing-box restart. If Prometheus is unavailable, samples are missed; this is
intentional and keeps monitoring failures from blocking proxy traffic.

## Grafana dashboard

A complete dashboard is available as a directly importable JSON file:

[Download the sing-box Observability dashboard](../../assets/observability/sing-box-grafana-dashboard.json)

It requires Grafana `11.6` or later and the Infinity data source plugin `4.0`
or later. The dashboard deliberately uses two data sources:

- Prometheus supplies durable time series, rates, increases and scrape health;
- Infinity calls the dedicated API for current status, active connections,
  bounded recent connections and Top-K results.

### Install and configure Infinity

Install the plugin on the Grafana server, then restart Grafana:

```bash
grafana cli plugins install yesoreyeram-infinity-datasource
```

In **Connections > Data sources > Add new data source > Infinity**, configure:

| Setting | Value |
|---------|-------|
| Base URL | `http://127.0.0.1:9090/observability/v1` |
| Authentication | Bearer Token |
| Bearer token | the value of `clash_api.secret` or the native API `secret` |
| Allowed hosts | the scheme and host used by the Base URL, if this field is shown |

Store the token in the data source's secure authentication field; do not add it
to the dashboard JSON. Infinity requests originate from the Grafana server, not
the browser. Therefore `127.0.0.1` works only when Grafana and sing-box share the
same network namespace. For Docker, another host, or another Android namespace,
use an address that the Grafana process can reach and restrict it with a firewall.

Click **Save & test** before importing the dashboard.

### Import

1. Open **Dashboards > New > Import** in Grafana.
2. Upload `sing-box-grafana-dashboard.json`.
3. Select the Prometheus data source that scrapes sing-box.
4. Select the Infinity data source configured above, then click **Import**.

The dashboard defaults to a six-hour range and a 30-second refresh. It includes
runtime overview, global traffic, connection activity, outbound-chain rankings,
inbound and network breakdowns, URLTest latency, Prometheus scrape diagnostics,
runtime status, active connections, recent closed connections and Top-K tables.

Dashboard variables control the selected Prometheus instance, rate interval,
API query window, row limits and Top-K dimension. `API Window` must not exceed
`recent_ttl`; `Top Limit` must not exceed `top_k_size`. The `rule`, `domain`,
`destination_ip`, `source`, `process` and `user` dimensions only contain values
when `expose_sensitive` is enabled.

Prometheus panels follow the dashboard time range and remain available for the
retention period configured in Prometheus. Infinity tables are live snapshots of
sing-box's bounded in-memory ring; changing the Grafana time range does not extend
their history, and the data is cleared when sing-box restarts.

When `expose_sensitive` is enabled, the live tables may contain IP addresses,
domains, process names, users and matched rules. Limit Grafana and API access to
trusted users, keep authentication enabled, and prefer TLS when traffic crosses a
device or untrusted network.
