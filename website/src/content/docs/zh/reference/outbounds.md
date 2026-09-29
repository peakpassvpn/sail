---
title: 出站与策略组
description: 从 Sail 配置源码自动提取的字段、类型与序列化规则。
---

本页由 Rust 语法树自动生成，请修改源码注释后重新构建。类型使用源码记法；`Option<T>` 表示可省略，`Vec<T>` 表示数组。源码注释保留原文。

本表反映反序列化声明，不是完整的运行时校验 schema。条件编译可能限制当前平台或构建可用的协议；复杂默认值、组合支持及跨字段约束请结合[配置指南](/sail/zh/configuration/)与所链接源码，并执行 `sail -c config.json -T` 验证。

## AnyTlsOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/anytls/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `password` | `String` | 必填 | — |
| `idle_session_check_interval` | `Option < Duration >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::duration")` |
| `idle_session_timeout` | `Option < Duration >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::duration")` |
| `min_idle_session` | `usize` | Default::default() | —<br/>`serde (default)` |

## DirectOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/direct/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |

## BlockOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/drop/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |

## FallbackServer

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/fallback.rs)

Where a fallback goes, as sing-box writes it.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |

## FallbackOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/group/fallback/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `outbounds` | `Vec < String >` | Default::default() | Its members, in order; none may be when its providers give others.<br/>`serde (default)` |
| `providers` | `GroupProviders` | 展开到当前对象，不是独立键 | Members from outbound providers too, a sail extension.<br/>`serde (flatten)` |
| `url` | `String` | default: default_url() | What is requested through each member to test it.<br/>`serde (default = "default_url")` |
| `interval` | `Option < Duration >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::duration")` |
| `timeout` | `Option < Duration >` | Default::default() | How long a test, or a connection attempt that has a member left to fall back to, may take before its member counts as failed.<br/>`serde (default , with = "crate::config::model::duration")` |
| `lazy` | `bool` | default: default_lazy() | Tests only while the group is in use: not when it was not used since the last ones.<br/>`serde (default = "default_lazy")` |
| `interrupt_exist_connections` | `bool` | Default::default() | Ends the connections through the member left once the group switches.<br/>`serde (default)` |

## StrategyKind

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/group/load_balance/mod.rs)

Serde: `serde (rename_all = "kebab-case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `ConsistentHashing` (default) | — |
| `RoundRobin` | — |
| `StickySessions` | — |

## LoadBalanceOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/group/load_balance/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `outbounds` | `Vec < String >` | Default::default() | Its members; none may be when its providers give others.<br/>`serde (default)` |
| `providers` | `GroupProviders` | 展开到当前对象，不是独立键 | Members from outbound providers too, a sail extension.<br/>`serde (flatten)` |
| `strategy` | `StrategyKind` | Default::default() | —<br/>`serde (default)` |
| `url` | `String` | default: default_url() | What is requested through each member to test it.<br/>`serde (default = "default_url")` |
| `interval` | `Option < Duration >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::duration")` |
| `lazy` | `bool` | default: default_lazy() | Tests only while the group is in use: not when it was not used since the last ones.<br/>`serde (default = "default_lazy")` |

## SelectorOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/group/selector/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `outbounds` | `Vec < String >` | Default::default() | Its members; none may be when its providers give others.<br/>`serde (default)` |
| `providers` | `GroupProviders` | 展开到当前对象，不是独立键 | Members from outbound providers too, a sail extension.<br/>`serde (flatten)` |
| `default` | `Option < String >` | Default::default() | Selected when nothing was selected before, or what was is no longer a member; defaults to the first. It may be a member a provider gives, the first so named.<br/>`serde (default)` |
| `interrupt_exist_connections` | `bool` | Default::default() | Ends the connections through the member selected before once another is selected, rather than leaving them on it.<br/>`serde (default)` |

## SmartOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/group/smart/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `outbounds` | `Vec < String >` | Default::default() | Its members; none may be when its providers give others.<br/>`serde (default)` |
| `providers` | `GroupProviders` | 展开到当前对象，不是独立键 | Members from outbound providers too.<br/>`serde (flatten)` |
| `url` | `String` | default: default_url() | What is requested through each member to probe it.<br/>`serde (default = "default_url")` |
| `interval` | `Option < Duration >` | Default::default() | How often members nothing told of lately are probed; 5 minutes.<br/>`serde (default , with = "crate::config::model::duration")` |
| `timeout` | `Option < Duration >` | Default::default() | How long a probe, or a connection attempt that has a member left to try, may take before its member counts as failed; 5 seconds.<br/>`serde (default , with = "crate::config::model::duration")` |
| `idle_timeout` | `Option < Duration >` | Default::default() | Probes pause once the group has not been used for this long; 30 minutes.<br/>`serde (default , with = "crate::config::model::duration")` |
| `tolerance` | `u16` | default: default_tolerance() | Milliseconds: a member whose score is within this of the best may be picked.<br/>`serde (default = "default_tolerance")` |
| `tolerance_ratio` | `f32` | default: default_tolerance_ratio() | A member whose score is within this fraction of the best may be picked too, whichever of the two is the wider.<br/>`serde (default = "default_tolerance_ratio")` |
| `policy_priority` | `Vec < PolicyPriority >` | Default::default() | Factors of the scores of the members whose names match a regular expression, the first that matches: below 1 prefers them, above 1 avoids them. 1 for the others.<br/>`serde (default)` |
| `site_ttl` | `Option < Duration >` | Default::default() | How long a site is kept on its member after its last connection; an hour.<br/>`serde (default , with = "crate::config::model::duration")` |
| `site_capacity` | `usize` | default: default_site_capacity() | How many sites are kept at most; the least recently used goes first.<br/>`serde (default = "default_site_capacity")` |
| `prefer_asn` | `bool` | Default::default() | Destinations known by address alone are sites by their autonomous system, but those of CDNs, rather than by their network. Needs an ASN database: `asn.mmdb` in the asset directory, or `asn_file`.<br/>`serde (default)` |
| `asn_file` | `Option < String >` | Default::default() | The ASN database, for `prefer_asn`; relative to the asset directory.<br/>`serde (default)` |
| `evaluate_before_use` | `bool` | Default::default() | The first connection waits for the first probes, `timeout` at most, rather than going through a member not measured yet.<br/>`serde (default)` |
| `interrupt_exist_connections` | `bool` | Default::default() | Ends the connections through a member once it leaves the group.<br/>`serde (default)` |

## PolicyPriority

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/group/smart/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `regex` | `String` | 必填 | Matched against the member's name. |
| `factor` | `f64` | 必填 | Multiplies the member's score: above 0. |

## TryAllOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/group/tryall/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `outbounds` | `Vec < String >` | 必填 | — |
| `delay_base` | `u32` | Default::default() | Milliseconds to wait before trying each next outbound.<br/>`serde (default)` |

## UrlTestOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/group/urltest/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `outbounds` | `Vec < String >` | Default::default() | Its members; none may be when its providers give others.<br/>`serde (default)` |
| `providers` | `GroupProviders` | 展开到当前对象，不是独立键 | Members from outbound providers too, a sail extension.<br/>`serde (flatten)` |
| `url` | `String` | default: default_url() | What is requested through each member; sing-box's default.<br/>`serde (default = "default_url")` |
| `interval` | `Option < Duration >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::duration")` |
| `tolerance` | `u16` | default: default_tolerance() | Milliseconds.<br/>`serde (default = "default_tolerance")` |
| `idle_timeout` | `Option < Duration >` | Default::default() | Tests pause once the group has not been used for this long.<br/>`serde (default , with = "crate::config::model::duration")` |
| `interrupt_exist_connections` | `bool` | Default::default() | Ends the connections through the member left once the group switches.<br/>`serde (default)` |

## HttpOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/http/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `username` | `Option < String >` | Default::default() | —<br/>`serde (default)` |
| `password` | `Option < String >` | Default::default() | —<br/>`serde (default)` |
| `path` | `Option < String >` | Default::default() | The request target instead of the destination, which then goes only in `Host`, as sing-box sends it.<br/>`serde (default)` |
| `headers` | `BTreeMap < String , Listable >` | Default::default() | Sent with every `CONNECT`.<br/>`serde (default)` |

## Obfs

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/mod.rs)

The `obfs` field: `{"type": "salamander", "password": "..."}`.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `r#type` | `String` | 必填 | — |
| `password` | `String` | Default::default() | —<br/>`serde (default)` |

## Hysteria2OutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/hysteria2/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `Option < u16 >` | Default::default() | The one port; with `server_ports`, not needed.<br/>`serde (default)` |
| `server_ports` | `Option < Listable >` | Default::default() | Ports or ranges ("20000:30000") to hop between.<br/>`serde (default)` |
| `hop_interval` | `Option < Duration >` | Default::default() | How often to hop, 30s unless set.<br/>`serde (default , with = "crate::config::model::duration")` |
| `up_mbps` | `Option < u64 >` | Default::default() | What we may send at; set, it selects Brutal.<br/>`serde (default)` |
| `down_mbps` | `Option < u64 >` | Default::default() | What we can receive at, told to the server.<br/>`serde (default)` |
| `obfs` | `Option < Obfs >` | Default::default() | —<br/>`serde (default)` |
| `password` | `String` | 必填 | — |
| `tls` | `OutboundTls` | 必填 | — |
| `network` | `Option < Listable >` | Default::default() | "tcp" or "udp", or both, as unset.<br/>`serde (default)` |

## MptpOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/mptp/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `outbounds` | `Vec < String >` | 必填 | — |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |

## RedirectOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/redirect/outbound/mod.rs)

Sends every connection to one fixed address.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |

## ShadowsocksOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/shadowsocks/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `method` | `String` | 必填 | — |
| `password` | `String` | 必填 | With a 2022 method, the base64 PSK, or `iPSK:uPSK` for a server with users. |
| `prefix` | `Option < String >` | Default::default() | Bytes sent before the first payload, percent-encoded.<br/>`serde (default)` |
| `plugin` | `Option < String >` | Default::default() | Only `obfs-local` (simple-obfs) is supported.<br/>`serde (default)` |
| `plugin_opts` | `Option < String >` | Default::default() | `obfs=http\|tls;obfs-host=<host>;obfs-uri=<path>`, as simple-obfs takes them.<br/>`serde (default)` |
| `udp_over_tcp` | `Option < uot :: UdpOverTcpOptions >` | Default::default() | UDP over its TCP, to `sp.v2.udp-over-tcp.arpa`, instead of its own UDP.<br/>`serde (default)` |

## SocksOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/socks/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `username` | `String` | Default::default() | —<br/>`serde (default)` |
| `password` | `String` | Default::default() | —<br/>`serde (default)` |
| `udp_over_tcp` | `Option < uot :: UdpOverTcpOptions >` | Default::default() | UDP over its TCP, to `sp.v2.udp-over-tcp.arpa`, instead of UDP ASSOCIATE.<br/>`serde (default)` |

## TproxyNetwork

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tproxy/mod.rs)

Serde: `serde (rename_all = "lowercase")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `tcp` | — |
| `udp` | — |

## TrojanOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/trojan/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `password` | `String` | 必填 | — |

## UdpRelayMode

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tuic/common.rs)

Which way UDP packets travel.

Serde: `serde (rename_all = "snake_case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `native` (default) | QUIC datagrams, fragmented to fit. |
| `quic` | One unidirectional stream per packet. |

## TuicOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tuic/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `uuid` | `String` | 必填 | — |
| `password` | `String` | Default::default() | —<br/>`serde (default)` |
| `congestion_control` | `CongestionControl` | Default::default() | —<br/>`serde (default)` |
| `udp_relay_mode` | `Option < UdpRelayMode >` | Default::default() | —<br/>`serde (default)` |
| `udp_over_stream` | `bool` | Default::default() | UDP over TCP (v2), as sing-box has it: each UDP session a `Connect` stream to `sp.v2.udp-over-tcp.arpa`, instead of TUIC's own relay.<br/>`serde (default)` |
| `zero_rtt_handshake` | `bool` | Default::default() | —<br/>`serde (default)` |
| `heartbeat` | `Option < Duration >` | Default::default() | —<br/>`serde (default , with = "crate::config::model::duration")` |
| `network` | `Option < Network >` | Default::default() | `tcp` or `udp`; both when not set.<br/>`serde (default)` |
| `tls` | `OutboundTls` | 必填 | — |

## Network

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/tuic/outbound/mod.rs)

Serde: `serde (rename_all = "lowercase")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `tcp` | — |
| `udp` | — |

## VlessOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vless/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `uuid` | `String` | 必填 | — |
| `flow` | `String` | Default::default() | `""` or `xtls-rprx-vision`.<br/>`serde (default)` |
| `packet_encoding` | `Option < String >` | Default::default() | How UDP travels: unset means `xudp`, as in sing-box; `""` is VLESS's own UDP, one destination per connection.<br/>`serde (default)` |

## VMessOutboundOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/vmess/outbound/mod.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `uuid` | `String` | 必填 | — |
| `security` | `String` | default: default_security() | `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none` or `zero`.<br/>`serde (default = "default_security")` |
| `alter_id` | `u32` | Default::default() | Only 0: legacy VMess is not spoken.<br/>`serde (default)` |
| `global_padding` | `bool` | Default::default() | Random padding after each chunk, as v2ray pads.<br/>`serde (default)` |
| `packet_encoding` | `String` | Default::default() | `""` (VMess's own UDP) or `xudp`.<br/>`serde (default)` |

## WireGuardOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/wireguard/endpoint/options.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `system` | `bool` | Default::default() | A system interface instead of the userspace stack: not supported.<br/>`serde (default)` |
| `name` | `Option < String >` | Default::default() | The system interface's name, for `system` only.<br/>`serde (default)` |
| `mtu` | `Option < u32 >` | Default::default() | —<br/>`serde (default)` |
| `address` | `Vec < String >` | 必填 | The endpoint's own addresses in the tunnel, as prefixes. |
| `private_key` | `String` | 必填 | — |
| `listen_port` | `Option < u16 >` | Default::default() | —<br/>`serde (default)` |
| `peers` | `Vec < PeerOptions >` | 必填 | — |
| `workers` | `Option < u32 >` | Default::default() | sing-box's worker count; sail has no use for it.<br/>`serde (default)` |

## PeerOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/wireguard/endpoint/options.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `address` | `Option < String >` | Default::default() | Where the peer is: an address or a domain. Without it, it is learnt from the peer's handshake, as a server's peers are.<br/>`serde (default)` |
| `port` | `Option < u16 >` | Default::default() | —<br/>`serde (default)` |
| `public_key` | `String` | 必填 | — |
| `pre_shared_key` | `Option < String >` | Default::default() | —<br/>`serde (default)` |
| `allowed_ips` | `Vec < String >` | 必填 | — |
| `persistent_keepalive_interval` | `Option < u16 >` | Default::default() | Seconds; 0 or unset is off.<br/>`serde (default)` |
| `reserved` | `Option < Reserved >` | Default::default() | Three bytes, or their base64: Cloudflare WARP's client identifier.<br/>`serde (default)` |

## Reserved

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/protocol/wireguard/endpoint/options.rs)

Serde: `serde (untagged)`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `(Vec < u8 >)` | — |
| `(String)` | — |

