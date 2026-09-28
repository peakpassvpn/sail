---
title: 入站配置
description: 从 Sail 配置源码自动提取的字段、类型与序列化规则。
---

本页由 Rust 语法树自动生成，请修改源码注释后重新构建。类型使用源码记法；`Option<T>` 表示可省略，`Vec<T>` 表示数组。源码注释保留原文。

本表反映反序列化声明，不是完整的运行时校验 schema。条件编译可能限制当前平台或构建可用的协议；复杂默认值、组合支持及跨字段约束请结合[配置指南](/sail/zh/configuration/)与所链接源码，并执行 `sail -c config.json -T` 验证。

## AnyTlsInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/anytls/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `users` | `Vec < AnyTlsUser >` | 必填 | — |
| `padding_scheme` | `Option < Listable >` | Default::default() | The padding scheme, as lines. Unset, the default.<br/>`serde (default)` |
| `fallback` | `Option < FallbackServer >` | Default::default() | Where a connection that fails to authenticate is relayed.<br/>`serde (default)` |
| `fallback_for_alpn` | `HashMap < String , FallbackServer >` | Default::default() | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`.<br/>`serde (default)` |

## AnyTlsUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/anytls/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | 必填 | — |

## HcInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hc/inbound/mod.rs)

Answers health checks: `request` on `path` gets `response`.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `path` | `String` | 必填 | — |
| `request` | `String` | Default::default() | —<br/>`serde (default)` |
| `response` | `String` | 必填 | — |

## HttpInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/http/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `users` | `Vec < HttpUser >` | Default::default() | Clients must authenticate as one of these with `Proxy-Authorization: Basic`; anyone may connect when there are none.<br/>`serde (default)` |

## HttpUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/http/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `username` | `String` | 必填 | — |
| `password` | `String` | 必填 | — |

## MasqueradeOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/inbound/masquerade.rs)

The `masquerade` field, as sing-box takes it: an `http://` URL to proxy to, or an object.

Serde: `serde (untagged)`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `(String)` | — |
| `(MasqueradeObject)` | — |

## MasqueradeObject

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/inbound/masquerade.rs)

Serde: `serde (tag = "type" , rename_all = "lowercase" , deny_unknown_fields)`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `proxy { url : String , # [doc = " Sends the site's own host instead of the one asked for."] # [serde (default)] rewrite_host : bool , }` | — |
| `string { # [serde (default)] status_code : Option < u16 > , # [serde (default)] headers : HashMap < String , String > , content : String , }` | — |

## Hysteria2InboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `up_mbps` | `Option < u64 >` | Default::default() | What the server may send at, at most, to each client.<br/>`serde (default)` |
| `down_mbps` | `Option < u64 >` | Default::default() | What the server can receive at, told to clients.<br/>`serde (default)` |
| `obfs` | `Option < Obfs >` | Default::default() | —<br/>`serde (default)` |
| `users` | `Vec < User >` | 必填 | — |
| `ignore_client_bandwidth` | `bool` | Default::default() | Ignores the rate clients say they receive at, and has them find their own: BBR both ways.<br/>`serde (default)` |
| `tls` | `InboundTls` | 必填 | — |
| `masquerade` | `Option < MasqueradeOptions >` | Default::default() | What anyone without a password is served.<br/>`serde (default)` |

## User

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | 必填 | — |

## MixedInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/mixed/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `users` | `Vec < MixedUser >` | Default::default() | Clients must authenticate as one of these, by SOCKS5 username/password or HTTP Basic; anyone may connect when there are none.<br/>`serde (default)` |

## MixedUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/mixed/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `username` | `String` | 必填 | — |
| `password` | `String` | 必填 | — |

## MptpInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/mptp/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |

## NfInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/nf/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `driver_name` | `String` | 必填 | — |
| `nfapi` | `String` | default: default_nfapi() | —<br/>`serde (default = "default_nfapi")` |
| `fake_dns_exclude` | `Vec < String >` | Default::default() | —<br/>`serde (default)` |
| `fake_dns_include` | `Vec < String >` | Default::default() | —<br/>`serde (default)` |

## RedirectInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/redirect/inbound/mod.rs)

It has nothing of its own to configure: the listen fields are common to every inbound.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |

## ShadowsocksInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowsocks/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `method` | `String` | 必填 | — |
| `password` | `String` | 必填 | The PSK with a 2022 method; with `users`, the server's identity PSK. |
| `users` | `Option < Vec < ShadowsocksUser > >` | Default::default() | Shadowsocks 2022 users, told apart by identity headers.<br/>`serde (default)` |

## ShadowsocksUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowsocks/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | 必填 | The user's base64 PSK. |

## SocksInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/socks/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `users` | `Vec < SocksUser >` | Default::default() | Clients must authenticate as one of these; anyone may connect when there are none.<br/>`serde (default)` |

## SocksUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/socks/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `username` | `String` | 必填 | — |
| `password` | `String` | 必填 | — |

## TproxyInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tproxy/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `network` | `Option < TproxyNetwork >` | Default::default() | Only `tcp`, or only `udp`; both when unset.<br/>`serde (default)` |

## TrojanInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/trojan/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `users` | `Vec < TrojanUser >` | 必填 | — |
| `fallback` | `Option < FallbackServer >` | Default::default() | Where a connection that fails to authenticate is relayed.<br/>`serde (default)` |
| `fallback_for_alpn` | `HashMap < String , FallbackServer >` | Default::default() | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`.<br/>`serde (default)` |

## TrojanUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/trojan/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `password` | `String` | 必填 | — |

## TuicInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tuic/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `users` | `Vec < TuicUser >` | 必填 | — |
| `congestion_control` | `CongestionControl` | Default::default() | —<br/>`serde (default)` |
| `auth_timeout` | `Option < Duration >` | Default::default() | How long a connection may go without authenticating. 3s, as in sing-box, when not set.<br/>`serde (default , with = "crate::config::model::duration")` |
| `zero_rtt_handshake` | `bool` | Default::default() | —<br/>`serde (default)` |
| `heartbeat` | `Option < Duration >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::duration")` |
| `tls` | `InboundTls` | 必填 | — |

## TuicUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tuic/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `uuid` | `String` | 必填 | — |
| `password` | `String` | Default::default() | —<br/>`serde (default)` |

## TunInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tun/inbound.rs)

The options of a TUN inbound, as sing-box's `tun` inbound names them.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
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
| `strict_route` | `bool` | Default::default() | With one family on the device, rejects the other rather than let it go past sail.<br/>`serde (default)` |
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
| `fake_dns_exclude` | `Vec < String >` | Default::default() | Until the DNS section serves fake IPs, the domains that get one, or those that do not.<br/>`serde (default)` |
| `fake_dns_include` | `Vec < String >` | Default::default() | —<br/>`serde (default)` |

## VlessInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vless/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `users` | `Vec < VlessUser >` | 必填 | — |
| `fallback` | `Option < FallbackServer >` | Default::default() | Where a connection that fails to authenticate is relayed.<br/>`serde (default)` |
| `fallback_for_alpn` | `HashMap < String , FallbackServer >` | Default::default() | The same, by the ALPN the connection's TLS negotiated; the ones it does not name go to `fallback`.<br/>`serde (default)` |

## VlessUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vless/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `uuid` | `String` | 必填 | — |
| `flow` | `String` | Default::default() | `""` or `xtls-rprx-vision`.<br/>`serde (default)` |

## VMessInboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vmess/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `users` | `Vec < VMessUser >` | 必填 | — |

## VMessUser

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vmess/inbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `name` | `Option < String >` | Default::default() | Who the user is to routing (`auth_user`), statistics and logs.<br/>`serde (default)` |
| `uuid` | `String` | 必填 | — |
| `alterId` | `u32` | Default::default() | Only 0: AEAD headers. Legacy VMess is not served.<br/>`serde (default , rename = "alterId")` |

