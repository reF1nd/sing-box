---
icon: material/new-box
---

# Rule Set

!!! question "Since sing-box 1.8.0"

### Structure

```json
{
  "type": "",
  "tag": "",
  "format": "",
  "path": "",
  
  ... // Typed Fields
}
```

#### Local Structure

```json
{
  "type": "local",
  
  ...
}
```

#### Remote Structure

!!! info ""

    Remote rule-set will be cached if `experimental.cache_file.enabled`.

```json
{
  "type": "remote",
  
  ...,
  
  "url": "",
  "download_detour": "",
  "update_interval": ""
}
```

### Fields

#### type

==Required==

Type of Rule Set, `local` or `remote`.

#### tag

==Required==

Tag of Rule Set.

#### format

==Required==

Format of Rule Set, `source` or `binary`.

#### path

File path of Rule Set.

If empty, will use tag name with format suffix. `json` will be used when format is `source`, while `srs` will be used when format is `binary`.

### Remote Fields

#### url

==Required==

Download URL of Rule Set.

#### download_detour

Tag of the outbound to download rule-set.

Default outbound will be used if empty.

#### update_interval

Update interval of Rule Set.

`1d` will be used if empty.
