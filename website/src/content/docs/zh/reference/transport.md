---
title: 传输层配置
description: 从 Sail 配置源码自动提取的字段、类型与序列化规则。
---

本页由 Rust 语法树自动生成，请修改源码注释后重新构建。类型使用源码记法；`Option<T>` 表示可省略，`Vec<T>` 表示数组。源码注释保留原文。

本表反映反序列化声明，不是完整的运行时校验 schema。条件编译可能限制当前平台或构建可用的协议；复杂默认值、组合支持及跨字段约束请结合[配置指南](/sail/zh/configuration/)与所链接源码，并执行 `sail -c config.json -T` 验证。

## Listable

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

A string, or a list of strings as sing-box allows in the same place.

Serde: `serde (untagged)`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `(String)` | — |
| `(Vec < String >)` | — |

## OutboundBlocks

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `detour` | `Option < String >` | Default::default() | The outbound to dial this one's server through.<br/>`serde (default)` |
| `bind_interface` | `Option < String >` | Default::default() | The interface to send through, by name.<br/>`serde (default)` |
| `inet4_bind_address` | `Option < std :: net :: Ipv4Addr >` | Default::default() | —<br/>`serde (default)` |
| `inet6_bind_address` | `Option < std :: net :: Ipv6Addr >` | Default::default() | —<br/>`serde (default)` |
| `routing_mark` | `Option < u32 >` | Default::default() | `SO_MARK`, Linux only.<br/>`serde (default)` |
| `connect_timeout` | `Option < std :: time :: Duration >` | Default::default() | How long a TCP connect may take, e.g. `5s`.<br/>`serde (default , with = "crate::config::model::duration")` |
| `domain_resolver` | `Option < crate :: config :: model :: DomainResolver >` | Default::default() | The DNS server that resolves the names this outbound dials.<br/>`serde (default)` |
| `skip_default_domain_resolver` | `bool` | Default::default() | A sail extension: without a `domain_resolver` of its own, the names it dials resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers.<br/>`serde (default)` |
| `domain_strategy` | `Option < crate :: config :: model :: DnsStrategy >` | Default::default() | sing-box's deprecated field for the families they resolve to.<br/>`serde (default)` |
| `tcp_keep_alive` | `Option < std :: time :: Duration >` | Default::default() | How long a TCP connection is idle before keepalive probes it; 5m when unset.<br/>`serde (default , with = "crate::config::model::duration")` |
| `tcp_keep_alive_interval` | `Option < std :: time :: Duration >` | Default::default() | Between keepalive probes; 75s when unset.<br/>`serde (default , with = "crate::config::model::duration")` |
| `disable_tcp_keep_alive` | `bool` | Default::default() | —<br/>`serde (default)` |
| `tls` | `Option < OutboundTls >` | Default::default() | —<br/>`serde (default)` |
| `transport` | `Option < OutboundTransport >` | Default::default() | —<br/>`serde (default)` |
| `multiplex` | `Option < OutboundMultiplex >` | Default::default() | —<br/>`serde (default)` |

## OutboundTls

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `server_name` | `Option < String >` | Default::default() | Defaults to the server's address.<br/>`serde (default)` |
| `insecure` | `bool` | Default::default() | —<br/>`serde (default)` |
| `alpn` | `Option < Listable >` | Default::default() | —<br/>`serde (default)` |
| `certificate` | `Option < Listable >` | Default::default() | An inline PEM certificate to trust.<br/>`serde (default)` |
| `certificate_path` | `Option < String >` | Default::default() | A PEM certificate to trust, by path.<br/>`serde (default)` |
| `ech` | `Option < OutboundEch >` | Default::default() | —<br/>`serde (default)` |
| `reality` | `Option < OutboundReality >` | Default::default() | —<br/>`serde (default)` |
| `utls` | `Option < OutboundUtls >` | Default::default() | The browser the ClientHello imitates. Unset, it is Chrome's.<br/>`serde (default)` |

## OutboundUtls

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Unlike sing-box, a browser fingerprint is on by default: set `enabled: false` for BoringSSL's own ClientHello.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | default: default_true() | —<br/>`serde (default = "default_true")` |
| `fingerprint` | `String` | default: default_fingerprint() | —<br/>`serde (default = "default_fingerprint")` |

## OutboundEch

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `config` | `Option < Listable >` | Default::default() | An ECHConfigList, base64 or PEM. Looked up in DNS when not set.<br/>`serde (default)` |
| `disable_dns_lookup` | `bool` | Default::default() | Never look the ECHConfigList up in DNS.<br/>`serde (default)` |

## OutboundReality

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `public_key` | `String` | 必填 | — |
| `short_id` | `String` | Default::default() | —<br/>`serde (default)` |

## OutboundTransport

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (tag = "type" , rename_all = "lowercase" , deny_unknown_fields)`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `ws { # [serde (default = "default_path")] path : String , # [serde (default)] headers : HashMap < String , String > , # [doc = " How many of the first bytes to carry in the upgrade request."] # [serde (default)] max_early_data : usize , # [doc = " The header they go in; unset, they go in the path."] # [serde (default)] early_data_header_name : Option < String > , }` | — |
| `httpupgrade { # [doc = " Unset, the server's address."] # [serde (default)] host : Option < String > , # [serde (default = "default_path")] path : String , # [serde (default)] headers : HashMap < String , String > , }` | — |
| `grpc { # [serde (default = "default_service_name")] service_name : String , # [doc = " Unset, no keepalive pings."] # [serde (default , with = "crate::config::model::duration")] idle_timeout : Option < std :: time :: Duration > , # [serde (default , with = "crate::config::model::duration")] ping_timeout : Option < std :: time :: Duration > , # [doc = " Whether a connection carrying no calls is pinged too."] # [serde (default)] permit_without_stream : bool , }` | — |
| `http (serde :: de :: IgnoredAny)` | sing-box's HTTP/2 transport: not supported. |
| `quic { }` | Its TLS parameters come from the `tls` block. |

## OutboundMultiplex

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
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

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `tls` | `Option < InboundTls >` | Default::default() | —<br/>`serde (default)` |
| `transport` | `Option < InboundTransport >` | Default::default() | —<br/>`serde (default)` |
| `multiplex` | `Option < InboundMultiplex >` | Default::default() | —<br/>`serde (default)` |

## InboundTls

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
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

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

A REALITY server in place of a certificate: clients it does not know are relayed to `handshake`.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `handshake` | `RealityHandshake` | 必填 | — |
| `private_key` | `String` | 必填 | X25519, hex or base64url. |
| `short_id` | `Listable` | 必填 | — |
| `max_time_difference` | `Option < std :: time :: Duration >` | Default::default() | How far a client's clock may be from ours, e.g. `1m`. Unset, any time is accepted, as in sing-box.<br/>`serde (default , with = "crate::config::model::duration")` |

## RealityHandshake

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

The site REALITY imitates, dialed for every connection, with sing-box's dial fields. `detour` is not among them: inbounds do not reach the outbounds.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `server` | `String` | 必填 | — |
| `server_port` | `u16` | 必填 | — |
| `bind_interface` | `Option < String >` | Default::default() | —<br/>`serde (default)` |
| `inet4_bind_address` | `Option < std :: net :: Ipv4Addr >` | Default::default() | —<br/>`serde (default)` |
| `inet6_bind_address` | `Option < std :: net :: Ipv6Addr >` | Default::default() | —<br/>`serde (default)` |
| `routing_mark` | `Option < u32 >` | Default::default() | `SO_MARK`, Linux only.<br/>`serde (default)` |
| `connect_timeout` | `Option < std :: time :: Duration >` | Default::default() | How long the TCP connect may take, e.g. `5s`.<br/>`serde (default , with = "crate::config::model::duration")` |

## InboundTransport

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

Serde: `serde (tag = "type" , rename_all = "lowercase" , deny_unknown_fields)`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `ws { # [serde (default = "default_path")] path : String , # [doc = " The header a trusted reverse proxy in front puts the client's"] # [doc = " address in, such as `X-Forwarded-For`. Unset, no header is"] # [doc = " believed: anyone can send one."] # [serde (default)] forwarded_header : Option < String > , # [doc = " The most early data a client may send in its upgrade request."] # [serde (default)] max_early_data : usize , # [doc = " The header it comes in; unset, it comes in the path."] # [serde (default)] early_data_header_name : Option < String > , }` | — |
| `httpupgrade { # [doc = " The `Host` a request must carry; unset, any."] # [serde (default)] host : Option < String > , # [serde (default = "default_path")] path : String , # [doc = " Added to the response."] # [serde (default)] headers : HashMap < String , String > , }` | — |
| `grpc { # [serde (default = "default_service_name")] service_name : String , # [doc = " Unset, no keepalive pings."] # [serde (default , with = "crate::config::model::duration")] idle_timeout : Option < std :: time :: Duration > , # [serde (default , with = "crate::config::model::duration")] ping_timeout : Option < std :: time :: Duration > , }` | — |
| `http (serde :: de :: IgnoredAny)` | sing-box's HTTP/2 transport: not supported. |
| `quic { }` | Its certificate comes from the `tls` block. |

## InboundMultiplex

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

An inbound's `multiplex` block: sing-box's, which configures its sing-mux server, or with `protocol: "amux"` the amux layer below the protocol.  sing-mux is served, as by sing-box, only where this block enables it: with no block, a connection to the magic destination is refused. amux takes the block's place, so an inbound with amux serves no sing-mux.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `protocol` | `Option < String >` | Default::default() | `amux`; unset, sing-mux, which sing-box's block has no field for: its server takes smux, yamux and h2mux alike.<br/>`serde (default)` |
| `padding` | `bool` | Default::default() | sing-mux: refuse connections that are not padded.<br/>`serde (default)` |
| `brutal` | `Option < MultiplexBrutal >` | Default::default() | sing-mux: TCP Brutal for clients that ask for it; Linux only.<br/>`serde (default)` |

## MultiplexBrutal

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/layers.rs)

sing-box's `brutal` block of `multiplex`: the rates this end sends (`up_mbps`) and receives (`down_mbps`) at, in megabits per second.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `up_mbps` | `u64` | Default::default() | —<br/>`serde (default)` |
| `down_mbps` | `u64` | Default::default() | —<br/>`serde (default)` |

## CongestionControl

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/quic/common.rs)

The congestion controllers quinn has, named as in sing-box.

Serde: `serde (rename_all = "snake_case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `cubic` (default) | sing-box's default. |
| `new_reno` | — |
| `bbr` | — |

## UdpOverTcpOptions

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/uot.rs)

The `udp_over_tcp` option of an outbound, as sing-box has it: a bool, or `{enabled, version}`. Only version 2 is supported.

Serde: `serde (untagged)`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `(bool)` | — |
| `(UdpOverTcpFields)` | — |

## UdpOverTcpFields

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/transport/uot.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default)` |
| `version` | `Option < u8 >` | Default::default() | —<br/>`serde (default)` |

