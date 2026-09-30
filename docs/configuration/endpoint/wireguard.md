!!! quote "Changes in sing-box 1.15.0"

    :material-plus: [on_demand](#on_demand)

!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [udp_mapping](/configuration/shared/udp-nat/#udp_mapping)  
    :material-plus: [udp_filtering](/configuration/shared/udp-nat/#udp_filtering)  
    :material-plus: [udp_nat_max](/configuration/shared/udp-nat/#udp_nat_max)

!!! question "Since sing-box 1.11.0"

### Structure

```json
{
  "type": "wireguard",
  "tag": "wg-ep",
  
  // "tcp_congestion_control": "bbr",
  "system": false,
  "name": "",
  "gso": false,
  "mtu": 1408,
  "address": [],
  "private_key": "",
  "listen_port": 10000,
  "peers": [
    {
      "address": "127.0.0.1",
      "port": 10001,
      "public_key": "",
      "pre_shared_key": "",
      "allowed_ips": [],
      "persistent_keepalive_interval": 0,
      "reserved": [0, 0, 0]
    }
  ],

  ... // UDP NAT Fields

  "workers": 0,
  "on_demand": false,
  "inner_domain_resolver": "", // or {}
 
  ... // Dial Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### tcp_congestion_control

Selects the congestion controller for the local sender in this endpoint's internal Go TCP stack.

Available values: `reno`, `cubic`, `bbr`. Omitting the field preserves the default, CUBIC. Empty values and `none` are not supported.

Only affects TCP connections terminated or initiated by this endpoint's internal Go TCP stack. It does not affect kernel TCP, TCP forwarded at L3, UDP, or inner QUIC. Peers may select different algorithms. The setting affects only data sent by this endpoint: uploads over TCP connections it initiates through the tunnel and, when peers route traffic through this endpoint, TCP data its internal stack sends back to those peers.

Allowed with either `system: false` or `system: true`, but only applies to connections handled by the internal Go TCP stack. Enabling the system interface does not make this setting affect kernel TCP.

Changing algorithms does not guarantee higher throughput; test on the actual network path.

#### system

Use system interface.

Requires privilege and cannot conflict with exists system interfaces.

#### name

Custom interface name for system interface.

#### gso

!!! quote ""

    Only supported on Linux.

Try to enable generic segmentation offload.

Enabled by default when `system` is true.

This controls the system interface. For the UDP socket used to reach peers, see `udp_gso` in [Dial Fields](/configuration/shared/dial/#udp_gso).

#### mtu

WireGuard MTU.

`1408` will be used by default.

#### address

==Required==

List of IP (v4 or v6) address prefixes to be assigned to the interface.

#### private_key

==Required==

WireGuard requires base64-encoded public and private keys. These can be generated using the wg(8) utility:

```shell
wg genkey
echo "private key" || wg pubkey
```

or `sing-box generate wg-keypair`.

#### peers

==Required==

List of WireGuard peers.

#### peers.address

WireGuard peer address.

#### peers.port

WireGuard peer port.

#### peers.public_key

==Required==

WireGuard peer public key.

#### peers.pre_shared_key

WireGuard peer pre-shared key.

#### peers.allowed_ips

==Required==

WireGuard allowed IPs.

#### peers.persistent_keepalive_interval

WireGuard persistent keepalive interval, in seconds.

Disabled by default.

#### peers.reserved

WireGuard reserved field bytes.

#### workers

WireGuard worker count.

CPU count is used by default.

#### on_demand

!!! question "Since sing-box 1.15.0"

Allow the endpoint to be disconnected when necessary.

#### inner_domain_resolver

Set domain resolver for resolving domain names of connections passing through the WireGuard tunnel.

It is also used to resolve unresolved domain destinations when this endpoint is selected for L3 forwarding.

This option uses the same format as [domain_resolver](/configuration/shared/dial/#domain_resolver).

When not set, the default DNS is used.

### UDP NAT Fields

See [UDP NAT Fields](/configuration/shared/udp-nat/) for details.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
