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

## DirectInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/direct/inbound.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `network` | `Option < DirectNetwork >` | Default::default() | Only `tcp`, or only `udp`; both when unset.<br/>`serde (default)` |
| `override_address` | `Option < String >` | Default::default() | Where what comes in goes, instead of the listener's address.<br/>`serde (default)` |
| `override_port` | `Option < u16 >` | Default::default() | The port it goes to, instead of the listener's.<br/>`serde (default)` |

## DirectNetwork

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/direct/inbound.rs)

Serde: `serde (rename_all = "lowercase")`

| Value / shape | Source notes |
| --- | --- |
| `tcp` | — |
| `udp` | — |

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

## ShadowTlsInboundOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowtls/inbound.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `version` | `u32` | default: version_one() | Must be 3: versions 1 and 2 are not supported. sing-box's default is 1.<br/>`serde (default = "version_one")` |
| `password` | `Option < String >` | Default::default() | Version 2's, and an error: version 3 takes `users`.<br/>`serde (default)` |
| `users` | `Vec < ShadowTlsUser >` | Default::default() | At least one.<br/>`serde (default)` |
| `handshake` | `Option < ShadowTlsHandshake >` | Default::default() | The site whose handshake is relayed, for everyone the other fields do not send elsewhere. Needed unless `wildcard_sni` is on.<br/>`serde (default)` |
| `handshake_for_server_name` | `HashMap < String , ShadowTlsHandshake >` | Default::default() | Handshake servers by the server name the ClientHello asks for.<br/>`serde (default)` |
| `strict_mode` | `bool` | Default::default() | Relays a ServerHello that does not pick TLS 1.3 as it would an unauthenticated client.<br/>`serde (default)` |
| `wildcard_sni` | `WildcardSni` | Default::default() | —<br/>`serde (default)` |
| `detour` | `Option < String >` | Default::default() | The inbound connections go to after the handshake, by tag: needed.<br/>`serde (default)` |

## ShadowTlsUser

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowtls/inbound.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `name` | `String` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | Required | — |

## ShadowTlsHandshake

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowtls/inbound.rs)

A server and port, and sing-box's dial fields, which it is dialled with over the instance's defaults, as REALITY's handshake server is.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `server` | `String` | Default::default() | —<br/>`serde (default)` |
| `server_port` | `u16` | Default::default() | —<br/>`serde (default)` |
| `dial` | `crate :: net :: dial :: DialFields` | Flattened into this object | —<br/>`serde (flatten)` |

## WildcardSni

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowtls/inbound.rs)

Whether the handshake server is the one the ClientHello names, on port 443, when no `handshake_for_server_name` entry does.

Serde: `serde (rename_all = "lowercase")`

| Value / shape | Source notes |
| --- | --- |
| `off` (default) | — |
| `authed` | For authenticated clients; the others go to `handshake`. |
| `all` | — |

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
| `interface_name` | `Option < String >` | Default::default() | The device's name; the system picks one without it.<br/>`serde (default)` |
| `address` | `Vec < String >` | Default::default() | The device's addresses with their prefixes: one IPv4, one IPv6, or one of each.<br/>`serde (default , with = "crate::config::model::listable")` |
| `mtu` | `u32` | default: default_mtu() | 9000 when omitted, as sing-box has it on Android.<br/>`serde (default = "default_mtu")` |
| `auto_route` | `bool` | Default::default() | Routes the system's traffic into the device.<br/>`serde (default)` |
| `auto_redirect` | `bool` | Default::default() | Linux: redirects TCP to sail with nftables and marks the rest into the device, and lets rules bypass sail before a connection is set up (sing-box 1.13).<br/>`serde (default)` |
| `auto_redirect_input_mark` | `Option < u32 >` | Default::default() | The mark that routes a packet into the device (0x2023). Marks are numbers, or strings of hexadecimal ("0x2023"); 0 is the default.<br/>`serde (default , with = "fw_mark")` |
| `auto_redirect_output_mark` | `Option < u32 >` | Default::default() | The mark sail's own sockets carry, and flows that bypass it (0x2024). `route.default_mark` and `routing_mark` conflict with it.<br/>`serde (default , with = "fw_mark")` |
| `auto_redirect_reset_mark` | `Option < u32 >` | Default::default() | The mark of a connection pre-match rejects, which the kernel resets (0x2025).<br/>`serde (default , with = "fw_mark")` |
| `auto_redirect_nfqueue` | `Option < u16 >` | Default::default() | The NFQUEUE pre-match reads first packets from (100). If it cannot be bound, sail runs without pre-match: `bypass` rules are skipped.<br/>`serde (default)` |
| `iproute2_table_index` | `Option < u32 >` | Default::default() | The routing table of the device's routes (2022).<br/>`serde (default)` |
| `iproute2_rule_index` | `Option < u32 >` | Default::default() | The first of auto_redirect's ip rules (9000); the rules from it to 10 after it are sail's, and removed at start and stop.<br/>`serde (default)` |
| `auto_redirect_iproute2_fallback_rule_index` | `Option < u32 >` | Default::default() | The ip rule that sends what the main table has no route for into the device (32768).<br/>`serde (default)` |
| `exclude_mptcp` | `bool` | Default::default() | Lets MPTCP go past sail rather than dropping it, which makes clients fall back to TCP.<br/>`serde (default)` |
| `strict_route` | `bool` | Default::default() | With one family on the device, rejects the other rather than let it go past sail. Linux: with auto_redirect only, for now. Windows: not yet. Elsewhere it changes nothing, as in sing-box.<br/>`serde (default)` |
| `loopback_address` | `Vec < IpAddr >` | Default::default() | Addresses whose TCP goes into the device rather than to the redirect listener: a destination sail's own listeners use, say.<br/>`serde (default , with = "crate::config::model::listable")` |
| `route_address` | `Vec < String >` | Default::default() | Only these destinations are taken...<br/>`serde (default , with = "crate::config::model::listable")` |
| `route_exclude_address` | `Vec < String >` | Default::default() | ...and not these.<br/>`serde (default , with = "crate::config::model::listable")` |
| `route_address_set` | `Vec < String >` | Default::default() | Rule-sets whose destination `ip_cidr` alone are taken, kept up to date as they are downloaded again.<br/>`serde (default , with = "crate::config::model::listable")` |
| `route_exclude_address_set` | `Vec < String >` | Default::default() | Rule-sets whose destination `ip_cidr` are not taken.<br/>`serde (default , with = "crate::config::model::listable")` |
| `include_interface` | `Vec < String >` | Default::default() | Forwarded traffic is taken only from these interfaces...<br/>`serde (default , with = "crate::config::model::listable")` |
| `exclude_interface` | `Vec < String >` | Default::default() | ...or not from these. Naming `lo` in either leaves the host's own traffic out.<br/>`serde (default , with = "crate::config::model::listable")` |
| `include_uid` | `Vec < u32 >` | Default::default() | The host's traffic is taken only from these users...<br/>`serde (default , with = "crate::config::model::listable")` |
| `include_uid_range` | `Vec < String >` | Default::default() | ...and from these ranges, as "1000:2000".<br/>`serde (default , with = "crate::config::model::listable")` |
| `exclude_uid` | `Vec < u32 >` | Default::default() | The host's traffic of these users is not taken...<br/>`serde (default , with = "crate::config::model::listable")` |
| `exclude_uid_range` | `Vec < String >` | Default::default() | ...nor of these ranges.<br/>`serde (default , with = "crate::config::model::listable")` |
| `include_android_user` | `Vec < u32 >` | Default::default() | Android: what the host's VPN takes in, applied by the host.<br/>`serde (default , with = "crate::config::model::listable")` |
| `include_package` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::listable")` |
| `exclude_package` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::listable")` |

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

