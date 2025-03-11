### Structure

```json
{
  "client_metadata": "",
  "disable_reuse": false
}
```

### Fields

`client_metadata` `disable_reuse` see [AnyTLS outbound](/configuration/outbound/anytls/).

Omitted fields preserve the subscription's values. An explicit empty `client_metadata`
clears the metadata, and `disable_reuse: false` explicitly re-enables reuse.
