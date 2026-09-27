---
title: Inbound configuration
description: Fields, types and serialization rules extracted from Sail configuration source.
---

Generated from the Rust syntax tree. Update source comments and rebuild to change this page. `Option<T>` is optional; `Vec<T>` is an array. Comments retain their source language.

These declarations are not a complete runtime validation schema. Features and platform gates affect availability. Consult the [configuration guide](/sail/configuration/) and linked source for computed defaults, supported combinations and cross-field constraints; validate with `sail -c config.json -T`.

## AnyTlsInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/anytls/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `users` | `Vec < AnyTlsUser >` | Required | — |
| `padding_scheme` | `Option < Listable >` | Default::default() | The padding scheme, as lines. Unset, the default.<br/>`serde (default)` |
| `fallback` | `Option < FallbackServer >` | Default::default() | Where a connection that fails to authenticate is relayed.<br/>`serde (default)` |
| `fallback_for_alpn` | `HashMap < String , FallbackServer >` | Default::default() | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`.<br/>`serde (default)` |

## AnyTlsUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/anytls/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | Required | — |

## HcInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hc/inbound/mod.rs)

Answers health checks: `request` on `path` gets `response`.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `path` | `String` | Required | — |
| `request` | `String` | Default::default() | —<br/>`serde (default)` |
| `response` | `String` | Required | — |

## HttpInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/http/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `users` | `Vec < HttpUser >` | Default::default() | Clients must authenticate as one of these with `Proxy-Authorization: Basic`; anyone may connect when there are none.<br/>`serde (default)` |

## HttpUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/http/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `username` | `String` | Required | — |
| `password` | `String` | Required | — |

## MasqueradeOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/inbound/masquerade.rs)

The `masquerade` field, as sing-box takes it: an `http://` URL to proxy to, or an object.

Serde: `serde (untagged)`

| Value / shape | Source notes |
| --- | --- |
| `(String)` | — |
| `(MasqueradeObject)` | — |

## MasqueradeObject

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/inbound/masquerade.rs)

Serde: `serde (tag = "type" , rename_all = "lowercase" , deny_unknown_fields)`

| Value / shape | Source notes |
| --- | --- |
| `proxy { url : String , # [doc = " Sends the site's own host instead of the one asked for."] # [serde (default)] rewrite_host : bool , }` | — |
| `string { # [serde (default)] status_code : Option < u16 > , # [serde (default)] headers : HashMap < String , String > , content : String , }` | — |

## Hysteria2InboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `up_mbps` | `Option < u64 >` | Default::default() | What the server may send at, at most, to each client.<br/>`serde (default)` |
| `down_mbps` | `Option < u64 >` | Default::default() | What the server can receive at, told to clients.<br/>`serde (default)` |
| `obfs` | `Option < Obfs >` | Default::default() | —<br/>`serde (default)` |
| `users` | `Vec < User >` | Required | — |
| `ignore_client_bandwidth` | `bool` | Default::default() | Ignores the rate clients say they receive at, and has them find their own: BBR both ways.<br/>`serde (default)` |
| `tls` | `InboundTls` | Required | — |
| `masquerade` | `Option < MasqueradeOptions >` | Default::default() | What anyone without a password is served.<br/>`serde (default)` |

## User

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | Required | — |

## MixedInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/mixed/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `users` | `Vec < MixedUser >` | Default::default() | Clients must authenticate as one of these, by SOCKS5 username/password or HTTP Basic; anyone may connect when there are none.<br/>`serde (default)` |

## MixedUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/mixed/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `username` | `String` | Required | — |
| `password` | `String` | Required | — |

## MptpInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/mptp/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |

## NfInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/nf/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `driver_name` | `String` | Required | — |
| `nfapi` | `String` | default: default_nfapi() | —<br/>`serde (default = "default_nfapi")` |
| `fake_dns_exclude` | `Vec < String >` | Default::default() | —<br/>`serde (default)` |
| `fake_dns_include` | `Vec < String >` | Default::default() | —<br/>`serde (default)` |

## RedirectInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/redirect/inbound/mod.rs)

It has nothing of its own to configure: the listen fields are common to every inbound.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |

## ShadowsocksInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowsocks/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `method` | `String` | Required | — |
| `password` | `String` | Required | The PSK with a 2022 method; with `users`, the server's identity PSK. |
| `users` | `Option < Vec < ShadowsocksUser > >` | Default::default() | Shadowsocks 2022 users, told apart by identity headers.<br/>`serde (default)` |

## ShadowsocksUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowsocks/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | Required | The user's base64 PSK. |

## SocksInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/socks/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `users` | `Vec < SocksUser >` | Default::default() | Clients must authenticate as one of these; anyone may connect when there are none.<br/>`serde (default)` |

## SocksUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/socks/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `username` | `String` | Required | — |
| `password` | `String` | Required | — |

## TproxyInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tproxy/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `network` | `Option < TproxyNetwork >` | Default::default() | Only `tcp`, or only `udp`; both when unset.<br/>`serde (default)` |

## TrojanInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/trojan/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `users` | `Vec < TrojanUser >` | Required | — |
| `fallback` | `Option < FallbackServer >` | Default::default() | Where a connection that fails to authenticate is relayed.<br/>`serde (default)` |
| `fallback_for_alpn` | `HashMap < String , FallbackServer >` | Default::default() | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`.<br/>`serde (default)` |

## TrojanUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/trojan/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | Required | — |

## TuicInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tuic/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `users` | `Vec < TuicUser >` | Required | — |
| `congestion_control` | `CongestionControl` | Default::default() | —<br/>`serde (default)` |
| `auth_timeout` | `Option < Duration >` | Default::default() | How long a connection may go without authenticating. 3s, as in sing-box, when not set.<br/>`serde (default , with = "crate::config::model::duration")` |
| `zero_rtt_handshake` | `bool` | Default::default() | —<br/>`serde (default)` |
| `heartbeat` | `Option < Duration >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::duration")` |
| `tls` | `InboundTls` | Required | — |

## TuicUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tuic/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `uuid` | `String` | Required | — |
| `password` | `String` | Default::default() | —<br/>`serde (default)` |

## TunInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tun/inbound.rs)

The options of a TUN inbound, as sing-box's `tun` inbound names them.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `interface_name` | `Option < String >` | Default::default() | —<br/>`serde (default)` |
| `address` | `Vec < String >` | Default::default() | The device's addresses with their prefixes: one IPv4, one IPv6, or one of each.<br/>`serde (default , with = "crate::config::model::listable")` |
| `mtu` | `u32` | default: default_mtu() | —<br/>`serde (default = "default_mtu")` |
| `auto_route` | `bool` | Default::default() | Routes the system's traffic into the device.<br/>`serde (default)` |
| `fake_dns_exclude` | `Vec < String >` | Default::default() | Until the DNS section serves fake IPs, the domains that get one, or those that do not.<br/>`serde (default)` |
| `fake_dns_include` | `Vec < String >` | Default::default() | —<br/>`serde (default)` |

## VlessInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vless/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `users` | `Vec < VlessUser >` | Required | — |
| `fallback` | `Option < FallbackServer >` | Default::default() | Where a connection that fails to authenticate is relayed.<br/>`serde (default)` |
| `fallback_for_alpn` | `HashMap < String , FallbackServer >` | Default::default() | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`.<br/>`serde (default)` |

## VlessUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vless/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `uuid` | `String` | Required | — |
| `flow` | `String` | Default::default() | `""` or `xtls-rprx-vision`.<br/>`serde (default)` |

## VMessInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vmess/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `users` | `Vec < VMessUser >` | Required | — |

## VMessUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vmess/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `uuid` | `String` | Required | — |
| `alterId` | `u32` | Default::default() | Only 0: AEAD headers. Legacy VMess is not served.<br/>`serde (default , rename = "alterId")` |

