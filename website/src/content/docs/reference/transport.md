---
title: Transport configuration
description: Fields, types and serialization rules extracted from Sail configuration source.
---

Generated from the Rust syntax tree. Update source comments and rebuild to change this page. `Option<T>` is optional; `Vec<T>` is an array. Comments retain their source language.

These declarations are not a complete runtime validation schema. Features and platform gates affect availability. Consult the [configuration guide](/sail/configuration/) and linked source for computed defaults, supported combinations and cross-field constraints; validate with `sail -c config.json -T`.

## Listable

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

A string, or a list of strings as sing-box allows in the same place.

Serde: `serde (untagged)`

| Value / shape | Source notes |
| --- | --- |
| `(String)` | — |
| `(Vec < String >)` | — |

## Secret

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

A secret, a private key: read as the value is, printed as none.

Serde: `serde (transparent)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `` | `T` | Required | — |

## OutboundBlocks

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `dial` | `DialFields` | Flattened into this object | How it dials its server, `detour` among them.<br/>`serde (flatten)` |
| `tls` | `Option < OutboundTls >` | Default::default() | —<br/>`serde (default)` |
| `transport` | `Option < OutboundTransport >` | Default::default() | —<br/>`serde (default)` |
| `multiplex` | `Option < OutboundMultiplex >` | Default::default() | —<br/>`serde (default)` |

## OutboundTls

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `server_name` | `Option < String >` | Default::default() | Defaults to the server's address.<br/>`serde (default)` |
| `disable_sni` | `bool` | Default::default() | Sends no SNI. The certificate is still verified against `server_name`, unless `insecure`.<br/>`serde (default)` |
| `insecure` | `bool` | Default::default() | —<br/>`serde (default)` |
| `alpn` | `Option < Listable >` | Default::default() | —<br/>`serde (default)` |
| `certificate` | `Option < Listable >` | Default::default() | An inline PEM certificate to trust.<br/>`serde (default)` |
| `certificate_path` | `Option < String >` | Default::default() | A PEM certificate to trust, by path.<br/>`serde (default)` |
| `client_certificate` | `Option < Listable >` | Default::default() | An inline PEM certificate, its chain after it, presented when the server asks for one; with `client_key`.<br/>`serde (default)` |
| `client_certificate_path` | `Option < String >` | Default::default() | `client_certificate`, by path.<br/>`serde (default)` |
| `client_key` | `Option < Secret < Listable > >` | Default::default() | The inline PEM key of the client certificate.<br/>`serde (default)` |
| `client_key_path` | `Option < String >` | Default::default() | `client_key`, by path.<br/>`serde (default)` |
| `ech` | `Option < OutboundEch >` | Default::default() | —<br/>`serde (default)` |
| `reality` | `Option < OutboundReality >` | Default::default() | —<br/>`serde (default)` |
| `utls` | `Option < OutboundUtls >` | Default::default() | The browser the ClientHello imitates. Unset, it is Chrome's.<br/>`serde (default)` |

## OutboundUtls

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Unlike sing-box, a browser fingerprint is on by default: set `enabled: false` for BoringSSL's own ClientHello.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | default: default_true() | —<br/>`serde (default = "default_true")` |
| `fingerprint` | `String` | default: default_fingerprint() | —<br/>`serde (default = "default_fingerprint")` |

## OutboundEch

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `config` | `Option < Listable >` | Default::default() | An ECHConfigList, base64 or PEM. Looked up in DNS when not set.<br/>`serde (default)` |
| `disable_dns_lookup` | `bool` | Default::default() | Never look the ECHConfigList up in DNS.<br/>`serde (default)` |

## OutboundReality

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `public_key` | `String` | Required | — |
| `short_id` | `String` | Default::default() | —<br/>`serde (default)` |

## OutboundTransport

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (tag = "type" , rename_all = "lowercase" , deny_unknown_fields)`

| Value / shape | Source notes |
| --- | --- |
| `ws { # [serde (default = "default_path")] path : String , # [serde (default)] headers : HashMap < String , String > , # [doc = " How many of the first bytes to carry in the upgrade request."] # [serde (default)] max_early_data : usize , # [doc = " The header they go in; unset, they go in the path."] # [serde (default)] early_data_header_name : Option < String > , }` | — |
| `httpupgrade { # [doc = " Unset, the server's address."] # [serde (default)] host : Option < String > , # [serde (default = "default_path")] path : String , # [serde (default)] headers : HashMap < String , String > , }` | — |
| `grpc { # [serde (default = "default_service_name")] service_name : String , # [doc = " Unset, no keepalive pings."] # [serde (default , with = "crate::config::model::duration")] idle_timeout : Option < std :: time :: Duration > , # [serde (default , with = "crate::config::model::duration")] ping_timeout : Option < std :: time :: Duration > , # [doc = " Whether a connection carrying no calls is pinged too."] # [serde (default)] permit_without_stream : bool , }` | — |
| `http (serde :: de :: IgnoredAny)` | sing-box's HTTP/2 transport: not supported. |
| `quic { }` | Its TLS parameters come from the `tls` block. |

## OutboundMultiplex

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `protocol` | `Option < String >` | Default::default() | sing-box's multiplex, above the protocol: `h2mux`, the default as in sing-box, `smux` or `yamux`. Or `amux`, sail's own, below the protocol, which is to be removed.<br/>`serde (default)` |
| `max_connections` | `Option < usize >` | Default::default() | —<br/>`serde (default)` |
| `min_streams` | `Option < usize >` | Default::default() | —<br/>`serde (default)` |
| `max_streams` | `Option < usize >` | Default::default() | —<br/>`serde (default)` |
| `padding` | `bool` | Default::default() | —<br/>`serde (default)` |
| `brutal` | `Option < MultiplexBrutal >` | Default::default() | sing-mux only: TCP Brutal, negotiated on each new connection.<br/>`serde (default)` |
| `max_accepts` | `Option < usize >` | Default::default() | amux only.<br/>`serde (default)` |
| `concurrency` | `Option < usize >` | Default::default() | —<br/>`serde (default)` |
| `max_recv_bytes` | `Option < usize >` | Default::default() | —<br/>`serde (default)` |
| `max_lifetime` | `Option < u64 >` | Default::default() | —<br/>`serde (default)` |

## InboundBlocks

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `tls` | `Option < InboundTls >` | Default::default() | —<br/>`serde (default)` |
| `transport` | `Option < InboundTransport >` | Default::default() | —<br/>`serde (default)` |
| `multiplex` | `Option < InboundMultiplex >` | Default::default() | —<br/>`serde (default)` |

## InboundTls

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `certificate` | `Option < Listable >` | Default::default() | An inline PEM certificate.<br/>`serde (default)` |
| `certificate_path` | `Option < String >` | Default::default() | —<br/>`serde (default)` |
| `key` | `Option < Listable >` | Default::default() | An inline PEM key.<br/>`serde (default)` |
| `key_path` | `Option < String >` | Default::default() | —<br/>`serde (default)` |
| `alpn` | `Option < Listable >` | Default::default() | —<br/>`serde (default)` |
| `server_name` | `Option < String >` | Default::default() | The name REALITY clients must ask for; only REALITY uses it.<br/>`serde (default)` |
| `reality` | `Option < InboundReality >` | Default::default() | —<br/>`serde (default)` |

## InboundReality

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

A REALITY server in place of a certificate: clients it does not know are relayed to `handshake`.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `handshake` | `RealityHandshake` | Required | — |
| `private_key` | `String` | Required | X25519, hex or base64url. |
| `short_id` | `Listable` | Required | — |
| `max_time_difference` | `Option < std :: time :: Duration >` | Default::default() | How far a client's clock may be from ours, e.g. `1m`. Unset, any time is accepted, as in sing-box.<br/>`serde (default , with = "crate::config::model::duration")` |

## RealityHandshake

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

The site REALITY imitates, dialed for every connection, with sing-box's dial fields; of which it implements the ones that bind the socket, and the connect timeout. `detour` is not among them: inbounds do not reach the outbounds.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `server` | `String` | Required | — |
| `server_port` | `u16` | Required | — |
| `dial` | `DialFields` | Flattened into this object | —<br/>`serde (flatten)` |

## InboundTransport

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (tag = "type" , rename_all = "lowercase" , deny_unknown_fields)`

| Value / shape | Source notes |
| --- | --- |
| `ws { # [serde (default = "default_path")] path : String , # [doc = " The header a trusted reverse proxy in front puts the client's"] # [doc = " address in, such as `X-Forwarded-For`. Unset, no header is"] # [doc = " believed: anyone can send one."] # [serde (default)] forwarded_header : Option < String > , # [doc = " The most early data a client may send in its upgrade request."] # [serde (default)] max_early_data : usize , # [doc = " The header it comes in; unset, it comes in the path."] # [serde (default)] early_data_header_name : Option < String > , }` | — |
| `httpupgrade { # [doc = " The `Host` a request must carry; unset, any."] # [serde (default)] host : Option < String > , # [serde (default = "default_path")] path : String , # [doc = " Added to the response."] # [serde (default)] headers : HashMap < String , String > , }` | — |
| `grpc { # [serde (default = "default_service_name")] service_name : String , # [doc = " Unset, no keepalive pings."] # [serde (default , with = "crate::config::model::duration")] idle_timeout : Option < std :: time :: Duration > , # [serde (default , with = "crate::config::model::duration")] ping_timeout : Option < std :: time :: Duration > , }` | — |
| `http (serde :: de :: IgnoredAny)` | sing-box's HTTP/2 transport: not supported. |
| `quic { }` | Its certificate comes from the `tls` block. |

## InboundMultiplex

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

An inbound's `multiplex` block: sing-box's, which configures its sing-mux server, or with `protocol: "amux"` the amux layer below the protocol.  sing-mux is served, as by sing-box, only where this block enables it: with no block, a connection to the magic destination is refused. amux takes the block's place, so an inbound with amux serves no sing-mux.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `protocol` | `Option < String >` | Default::default() | `amux`; unset, sing-mux, which sing-box's block has no field for: its server takes smux, yamux and h2mux alike.<br/>`serde (default)` |
| `padding` | `bool` | Default::default() | sing-mux: refuse connections that are not padded.<br/>`serde (default)` |
| `brutal` | `Option < MultiplexBrutal >` | Default::default() | sing-mux: TCP Brutal for clients that ask for it; Linux only.<br/>`serde (default)` |

## MultiplexBrutal

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

sing-box's `brutal` block of `multiplex`: the rates this end sends (`up_mbps`) and receives (`down_mbps`) at, in megabits per second.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `up_mbps` | `u64` | Default::default() | —<br/>`serde (default)` |
| `down_mbps` | `u64` | Default::default() | —<br/>`serde (default)` |

## CongestionControl

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/quic/common.rs)

The congestion controllers quinn has, named as in sing-box.

Serde: `serde (rename_all = "snake_case")`

| Value / shape | Source notes |
| --- | --- |
| `cubic` (default) | sing-box's default. |
| `new_reno` | — |
| `bbr` | — |

## UdpOverTcpOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/uot.rs)

The `udp_over_tcp` option of an outbound, as sing-box has it: a bool, or `{enabled, version}`. Only version 2 is supported.

Serde: `serde (untagged)`

| Value / shape | Source notes |
| --- | --- |
| `(bool)` | — |
| `(UdpOverTcpFields)` | — |

## UdpOverTcpFields

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/uot.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `version` | `Option < u8 >` | Default::default() | —<br/>`serde (default)` |

