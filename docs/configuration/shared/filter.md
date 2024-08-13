### Structure

```json
{
  "includes": [
    "^HK\\..+",
    "^TW\\..+",
    "^SG\\..+",
  ],
  "excludes": "^JP\\..+",
  "types": [
    "shadowsocks",
    "vmess",
    "vless",
  ],
  "ports": [
    "80",
    "2000:4000",
    "2000:",
    ":4000"
  ]
}
```

#### includes

List of regular expression used to match tag of outbounds contained by providers which can be appended.

#### excludes

Match tag of outbounds contained by providers which cannot be appended.

#### types

Match type of outbounds contained by providers which cannot be appended.

#### ports

Match port of outbounds contained by providers which cannot be appended.
