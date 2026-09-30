# MASQUE Server

!!! question "Since sing-box 1.15.0"

`masque-server` endpoint is an IP proxying over HTTP ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484), CONNECT-IP) server.

## Structure

```json
{
  "type": "masque-server",
  "tag": "masque-server",

  ... // Listen Fields

  "version": [],
  // "h3_congestion_control": "bbr",
  "users": [
    {
      "username": "",
      "password": ""
    }
  ],
  "tls": {},
  "path": "",
  "address": [],
  "advertise_routes": [],
  "system": false,
  "gso": false,
  "inner_domain_resolver": "", // or {}
  "name": "",
  "mtu": 1280,

  ... // HTTP2 Fields / QUIC Fields
  ... // UDP NAT Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

## Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details. `udp_timeout` is part of the [UDP NAT Fields](#udp-nat-fields) below.

## Fields

### version

List of HTTP versions to serve.

Available values: `1`, `2`, `3`.

All versions are used by default.

TLS is required for `3`.

### users

HTTP users, verified by the `Authorization` header.

No authentication required if empty.

### h3_congestion_control

Selects the local sender congestion controller for HTTP/3 connections. Applies only to HTTP/3.

Available values: `new_reno`, `cubic`, `bbr`, `none`.

Omitting the field preserves the existing defaults: NewReno on the client and BBR on the server. BBR uses the Standard profile; profile and bandwidth parameters are not exposed. The setting affects only local sending, so the two peers may select different algorithms.

When configured, `version` must include `3`. The default version list includes `3`. Builds without QUIC support reject this setting.

This field does not change version fallback. Client fallback remains controlled by `disable_version_fallback`; the setting has no effect after fallback to HTTP/1 or HTTP/2.

`none` bypasses the outer congestion window and pacing only for QUIC DATAGRAM packets carrying IP traffic. Control streams, the handshake, and reliable capsules retain normal congestion control. Capsule fallback remains available when DATAGRAM is unsupported. Exempt packets retain ACK/loss tracking, path MTU and resource limits, and use Not-ECT.

Before using `none`, ensure tunneled traffic has appropriate congestion control or that the deployment provides suitable traffic management. UDP or KCP alone does not establish this. Lower latency is not guaranteed. Configure both peers to exempt both sending directions.

### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

IP proxying must be operated over TLS or QUIC. Leave it disabled only when the server is placed behind an HTTP intermediary that terminates TLS.

### path

URI template path of the IP proxying resource, may contain the `target` and `ipproto` variables.

`/.well-known/masque/ip/{target}/{ipproto}/` is used by default.

### address

==Required==

List of IP prefixes of the tunnel network, at most one for each IP version.

The address of the prefix is used by the server itself, other addresses in the prefix are assigned to clients.

### advertise_routes

List of IP prefixes to advertise to clients, in addition to the tunnel network.

Traffic from clients to other destinations is rejected.

All addresses are advertised by default.

### system

Use system interface.

Requires privilege and cannot conflict with existing system interfaces.

If disabled, sing-box uses the internal network stack.

### gso

!!! quote ""

    Only supported on Linux.

Attempt to enable generic segmentation offload for the system interface.

Enabled by default when `system` is `true`. Set to `false` to disable.

This option has no effect when `system` is `false`.

### inner_domain_resolver

Set the DNS resolver used for destination domain names when this endpoint is selected as an outbound. Applies to TCP and UDP.

It is also used to resolve unresolved domain destinations when this endpoint is selected for L3 forwarding.

This option uses the same format as [domain_resolver](/configuration/shared/dial/#domain_resolver).

When unset, existing DNS routing rules and the default DNS apply. IP destinations do not require domain resolution.

This resolver also resolves domain names in the CONNECT-IP request path's `target`. The resolved addresses remain subject to `advertise_routes`.

### name

Custom interface name for system interface.

An automatically generated `masque` interface name is used by default.

### mtu

Tunnel MTU.

`1280` will be used by default.

## HTTP2 Fields

When `version` contains `2`.

See [HTTP2 Fields](/configuration/shared/http2/) for details.

## QUIC Fields

When `version` contains `3` (default), [HTTP2 Fields](#http2-fields) are replaced by QUIC Fields.

See [QUIC Fields](/configuration/shared/quic/) for details.

## UDP NAT Fields

See [UDP NAT Fields](/configuration/shared/udp-nat/) for details.
