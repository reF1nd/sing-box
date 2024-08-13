### Structure

```json
{
  "type": "remote",
  "tag": "remote",
  "path": "./remote.json",
  "healthcheck_url": "https://www.gstatic.com/generate_204",
  "healthcheck_interval": "1m",

  "download_url": "http://www.baidu.com",
  "download_ua": "sing-box",
  "download_interval": "1h",
  "download_detour": "",
  
  "override_dialer": {},

  ... // Filter Fields
}
```

### Fields

#### download_url

==Required==

The download URL of the outbound-provider.

#### download_ua

The `User-Agent` used for downloading outbound-provider.

Default is `sing-box`.

#### download_interval

The interval of downloading outbound-provider. `1h` will be used if empty.

Less than `1h` will not take effect.

#### download_detour

The tag of the outbound to download the database.

Default outbound will be used if empty.
