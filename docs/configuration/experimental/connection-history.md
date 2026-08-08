# Connection History

!!! warning

    This feature is experimental and is only available in builds made with
    the `with_connection_history` build tag.

### Structure

```json
{
  "enabled": true,
  "path": "history.db",
  "external_ui": "connection-history-ui",
  "retention": "30d"
}
```

### Fields

#### enabled

Enable structured connection history and traffic aggregation.

#### path

Path to the history database. `history.db` is used by default.

#### external_ui

A relative path to the configuration directory or an absolute path containing
the static dashboard files. sing-box serves the directory at
`http://{{external-controller}}/history/ui/`.

The ready-to-use static files are in
`experimental/connectionhistory/ui` in the source tree. They are not embedded
in the sing-box binary.

#### retention

Retention period for connection records and minute/hour aggregates. The
default is `30d`.

### API

The history API is mounted under `/history` on the Clash API external
controller and uses the same secret and CORS policy. Configure
`experimental.clash_api.external_controller` to expose the API and dashboard.

Available endpoints are `summary`, `trend`, `connections`, `domains`,
`ips`, `outbounds`, `rules`, `sources`, and `status`.
