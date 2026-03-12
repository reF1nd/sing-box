`socks` outbound is a socks4/socks4a/socks5 client.

### Structure

```json
{
  "type": "socks",
  "tag": "socks-out",
  
  "server": "127.0.0.1",
  "server_port": 1080,
  "version": "5",
  "username": "sekai",
  "password": "admin",
  "network": "udp",
  "udp_over_tcp": false,
  "inner_domain_resolver": "", // or {}

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### version

The SOCKS version, one of `4` `4a` `5`.

SOCKS5 used by default.

#### username

SOCKS username.

#### password

SOCKS5 password.

#### network

Enabled network

One of `tcp` `udp`.

Both is enabled by default.

#### udp_over_tcp

UDP over TCP protocol settings.

See [UDP Over TCP](/configuration/shared/udp-over-tcp/) for details.

#### inner_domain_resolver

!!! note ""

    Only effective when `version` is `4`. SOCKS4 does not support domain name transmission, so the domain must be resolved locally before connecting.

Set domain resolver for resolving domain names of connections forwarded through SOCKS4.

This option uses the same format as [domain_resolver](/configuration/shared/dial/#domain_resolver).

When not set, the default DNS is used.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
