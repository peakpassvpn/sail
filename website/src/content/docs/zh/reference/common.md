---
title: 通用配置
description: 从 Sail 配置源码自动提取的字段、类型与序列化规则。
---

本页由 Rust 语法树自动生成，请修改源码注释后重新构建。类型使用源码记法；`Option<T>` 表示可省略，`Vec<T>` 表示数组。源码注释保留原文。

本表反映反序列化声明，不是完整的运行时校验 schema。条件编译可能限制当前平台或构建可用的协议；复杂默认值、组合支持及跨字段约束请结合[配置指南](/sail/zh/configuration/)与所链接源码，并执行 `sail -c config.json -T` 验证。

## Config

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `log` | `Log` | Default::default() | —<br/>`serde (default)` |
| `dns` | `Dns` | Default::default() | —<br/>`serde (default)` |
| `inbounds` | `Vec < Inbound >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `outbounds` | `Vec < Outbound >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `endpoints` | `Vec < Endpoint >` | Default::default() | Both an inbound and an outbound under one tag, as sing-box's endpoints: connections routed to the tag go out through it, and what comes in through it is routed with the tag as its inbound.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `route` | `Route` | Default::default() | —<br/>`serde (default)` |
| `api` | `Api` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Api::is_default")` |
| `warnings` | `Vec < String >` | 必填 | What the configuration sets that sail ignores, one line each; the start logs them.<br/>`serde (skip)` |

## Api

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

The control API; a sail extension.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `listen` | `Option < std :: net :: SocketAddr >` | Default::default() | Where the API listens; it is not served when unset.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## LogLevel

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (rename_all = "lowercase")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `trace` | — |
| `debug` | — |
| `info` (default) | — |
| `warn` | — |
| `error` | — |
| `fatal` | As `error`: sail logs nothing more severe. |
| `panic` | As `error`. |

## LogFormat

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (rename_all = "lowercase")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `full` (default) | — |
| `compact` | — |

## Log

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `disabled` | `bool` | Default::default() | Logs nothing.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `level` | `LogLevel` | Default::default() | —<br/>`serde (default)` |
| `output` | `Option < String >` | Default::default() | A file to append to. Logs go to the console when it is not set.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `timestamp` | `bool` | Default::default() | Starts each line with the time.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `format` | `LogFormat` | Default::default() | A sail extension: `compact` writes the message alone.<br/>`serde (default)` |

## Dns

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `servers` | `Vec < DnsServer >` | Default::default() | The servers, each by its tag. None is the system's resolver alone.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `rules` | `Vec < DnsRule >` | Default::default() | Which server a query goes to, matched in order.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `final` | `Option < String >` | Default::default() | The server of the queries no rule matches; the first one when unset.<br/>`serde (rename = "final" , default , skip_serializing_if = "Option::is_none")` |
| `strategy` | `DnsStrategy` | Default::default() | Which address families names resolve to, and in what order.<br/>`serde (default)` |
| `cache_capacity` | `Option < usize >` | Default::default() | Answers kept per address family; 512, or 64 on iOS, when unset.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `timeout` | `Option < std :: time :: Duration >` | Default::default() | How long one query to one server may take; 4s when unset.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `reverse_mapping` | `bool` | Default::default() | Remembers the domain of each address the DNS answers that pass through carry, so that connections to the address are routed by the domain.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |

## DnsServer

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A DNS server. What it takes beyond its type and tag belongs to its type, and is read when the DNS client is built, as an outbound's options are.

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `type` | `String` | 必填 | `udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `local`, `hosts`, or sail's `smart_select`.<br/>`serde (rename = "type")` |
| `tag` | `String` | Default::default() | Defaults to the type.<br/>`serde (default)` |
| `options` | `Options` | 展开到当前对象，不是独立键 | —<br/>`serde (flatten)` |

## DnsRule

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A DNS rule, matched in order against each query. As in a routing rule, the domain conditions match when any of them does; the rule matches when that and every other condition it sets match.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `domain` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain_suffix` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain_keyword` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `geosite` | `Vec < String >` | Default::default() | A sail extension, as in a routing rule.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `external` | `Vec < String >` | Default::default() | A sail extension, as in a routing rule: `site:<file>:<code>`.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `query_type` | `Vec < serde_json :: Value >` | Default::default() | Record types, by name (`A`, `AAAA`, `HTTPS`) or number.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `inbound` | `Vec < String >` | Default::default() | Tags of the inbounds the connection that needs the name came in through.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `auth_user` | `Vec < String >` | Default::default() | Names of the users an inbound authenticated.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `outbound` | `Vec < String >` | Default::default() | Tags of the outbounds that dial the name.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `rule_set` | `Vec < String >` | Default::default() | Tags of rule-sets, any of whose rules matching matches. Their `ip_cidr` rules match no query, which has no address yet.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `rule_set_ip_cidr_match_source` | `bool` | Default::default() | The rule-sets' `ip_cidr` match the source address.<br/>`serde (default , alias = "rule_set_ipcidr_match_source" , skip_serializing_if = "std::ops::Not::not")` |
| `action` | `DnsRuleAction` | Default::default() | —<br/>`serde (default)` |
| `server` | `Option < String >` | Default::default() | `route`: the server a matching query goes to.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `strategy` | `Option < DnsStrategy >` | Default::default() | `route`: the address families, instead of `dns.strategy`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## DnsRuleAction

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

What a matching DNS rule does.

Serde: `serde (rename_all = "snake_case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `route` (default) | Sends the query to `server`. |
| `reject` | Answers that the name does not resolve. |

## DnsStrategy

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Which address families names resolve to, as sing-box names them.

Serde: `serde (rename_all = "snake_case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `prefer_ipv4` (default) | Both, IPv4 first: sing-box's default. |
| `prefer_ipv6` | Both, IPv6 first. |
| `ipv4_only` | IPv4 addresses only. |
| `ipv6_only` | IPv6 addresses only. |

## Inbound

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `type` | `String` | 必填 | —<br/>`serde (rename = "type")` |
| `tag` | `String` | Default::default() | Defaults to the type.<br/>`serde (default)` |
| `listen` | `Option < String >` | Default::default() | The address to listen on; defaults to `127.0.0.1`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `listen_port` | `Option < u16 >` | Default::default() | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `udp_timeout` | `Option < std :: time :: Duration >` | Default::default() | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `options` | `Options` | 展开到当前对象，不是独立键 | —<br/>`serde (flatten)` |

## Outbound

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `type` | `String` | 必填 | —<br/>`serde (rename = "type")` |
| `tag` | `String` | Default::default() | Defaults to the type.<br/>`serde (default)` |
| `options` | `Options` | 展开到当前对象，不是独立键 | —<br/>`serde (flatten)` |

## Endpoint

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

An endpoint: an outbound, and an inbound, under one tag. Like an outbound's, its options belong to its protocol.

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `type` | `String` | 必填 | —<br/>`serde (rename = "type")` |
| `tag` | `String` | Default::default() | Defaults to the type.<br/>`serde (default)` |
| `udp_timeout` | `Option < std :: time :: Duration >` | Default::default() | How long a UDP session coming in through this endpoint lives without traffic; 5m when unset, as for an inbound.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `options` | `Options` | 展开到当前对象，不是独立键 | —<br/>`serde (flatten)` |

## Route

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `rules` | `Vec < Rule >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `rule_set` | `Vec < super :: rule_set :: RuleSet >` | Default::default() | The rule-sets rules name, by tag.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `final` | `Option < String >` | Default::default() | The outbound for connections no rule matches; defaults to the first outbound.<br/>`serde (rename = "final" , default , skip_serializing_if = "Option::is_none")` |
| `default_interface` | `Option < String >` | Default::default() | The interface outbounds that name none of their own send through.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `default_mark` | `Option < u32 >` | Default::default() | The routing mark (`SO_MARK`, Linux) of outbounds that set none.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `auto_detect_interface` | `bool` | Default::default() | Sends outbounds that name no interface of their own through the system's default interface, found at start. Needed when a TUN inbound routes everything, or outbound traffic would loop back into it.<br/>`serde (default)` |
| `default_domain_resolver` | `Option < DomainResolver >` | Default::default() | The DNS server that resolves the names outbounds dial, for those that name no `domain_resolver` of their own. Unset, the DNS rules decide.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## Rule

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A routing rule, matched in order, as sing-box has it. A default rule sets conditions on the things a connection is known by: of the conditions on one thing (the source's address, its port, the destination's address, its port) any matching will do, and the rule matches when each thing it has conditions on matches and every other condition does. A condition listing several values matches when any of them does. A logical rule (`type: logical`) combines the rules in `rules`, all of them (`mode: and`) or any (`mode: or`); `invert` turns either kind's result around.  `route`, `reject` and `hijack-dns` end the matching. `route-options`, `sniff` and `resolve` learn more about the connection or say how it is to be carried, and matching goes on with the next rule.

Serde: `serde (deny_unknown_fields)`

| 字段 | 类型 | 省略 / 展开规则 | 源码说明 |
| --- | --- | --- | --- |
| `type` | `RuleType` | Default::default() | `default`, or `logical`.<br/>`serde (rename = "type" , default , skip_serializing_if = "RuleType::is_default")` |
| `inbound` | `Vec < String >` | Default::default() | Tags of the inbounds a connection came in through.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `ip_version` | `Option < u8 >` | Default::default() | 4 or 6: the family of the destination address.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `network` | `Vec < String >` | Default::default() | `tcp`, `udp`.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `auth_user` | `Vec < String >` | Default::default() | Names of the users an inbound authenticated.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `protocol` | `Vec < String >` | Default::default() | The protocols a `sniff` rule found, by sing-box's names: `tls`, `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain_suffix` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain_keyword` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain_regex` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `geosite` | `Vec < String >` | Default::default() | Site groups, looked up in `site.dat` in the asset directory. A sail extension: sing-box has dropped its GeoIP and GeoSite databases.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `geoip` | `Vec < String >` | Default::default() | Country codes, looked up in `geo.mmdb` in the asset directory; a sail extension, as `geosite` is.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `external` | `Vec < String >` | Default::default() | A sail extension: `mmdb:<file>:<code>` or `site:<file>:<code>`, for data files other than the default ones.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `source_ip_cidr` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `source_ip_is_private` | `bool` | Default::default() | The source address is not a public one.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `ip_cidr` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `ip_is_private` | `bool` | Default::default() | The destination address, or one the domain resolved to, is not a public one.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `source_port` | `Vec < u16 >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `source_port_range` | `Vec < String >` | Default::default() | Inclusive port ranges, as `port_range` writes them.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `port` | `Vec < u16 >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `port_range` | `Vec < String >` | Default::default() | Inclusive port ranges, as sing-box writes them: `1000:2000`, `:1024`, `8000:`.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `process_name` | `Vec < String >` | Default::default() | The name of the program a connection comes from, its path's last part.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `process_path` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `process_path_regex` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `package_name` | `Vec < String >` | Default::default() | Android packages; no platform sail runs on tells them yet.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `package_name_regex` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `user` | `Vec < String >` | Default::default() | The user a connection's process runs as, by name and by id; no platform sail runs on tells them yet.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `user_id` | `Vec < i32 >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `rule_set` | `Vec < String >` | Default::default() | Tags of rule-sets, any of whose rules matching matches.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `rule_set_ip_cidr_match_source` | `bool` | Default::default() | The rule-sets' `ip_cidr` match the source address, not the destination.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `invert` | `bool` | Default::default() | —<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `mode` | `Option < LogicalMode >` | Default::default() | `logical`: `and` or `or`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `rules` | `Vec < Rule >` | Default::default() | `logical`: the rules combined. They take no action of their own.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `action` | `Option < RuleAction >` | Default::default() | `route` when unset.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `outbound` | `Option < String >` | Default::default() | `route`: where a matching connection goes.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `override_address` | `Option < String >` | Default::default() | `route`, `route-options`: connects to this address, an IP or a domain, instead of the one asked for, on the same port.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `override_port` | `Option < u16 >` | Default::default() | `route`, `route-options`: connects to this port instead.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `udp_disable_domain_unmapping` | `bool` | Default::default() | `route`, `route-options`: answers to UDP sent to a domain come back from the address it resolved to, not from the domain.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `udp_connect` | `bool` | Default::default() | `route`, `route-options`: a direct outbound sends UDP from a connected socket.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `udp_timeout` | `Option < std :: time :: Duration >` | Default::default() | `route`, `route-options`: how long a UDP session lasts idle, instead of its inbound's `udp_timeout`.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `tls_fragment` | `bool` | Default::default() | `route`, `route-options`: sends the TLS ClientHello in pieces, cut in the server name, each in a TCP segment of its own.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `tls_fragment_fallback_delay` | `Option < std :: time :: Duration >` | Default::default() | `route`, `route-options`: how long to wait between the pieces; 500ms when unset.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `tls_record_fragment` | `bool` | Default::default() | `route`, `route-options`: sends the TLS ClientHello as several TLS records, cut in the server name.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `method` | `Option < RejectMethod >` | Default::default() | `reject`: how.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `no_drop` | `bool` | Default::default() | `reject`: never drops, however many connections the rule rejects.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `server` | `Option < String >` | Default::default() | `resolve`: the DNS server to ask, rather than the one the DNS rules pick.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `strategy` | `Option < DnsStrategy >` | Default::default() | `resolve`: the address families, instead of `dns.strategy`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `sniffer` | `Vec < Sniffer >` | Default::default() | `sniff`: the protocols to look for; all of them when empty.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `timeout` | `Option < std :: time :: Duration >` | Default::default() | `sniff`: how long to wait for the first bytes; 300ms when unset. `resolve`: how long to wait for the answer; `dns.timeout` when unset.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `override_destination` | `bool` | Default::default() | `sniff`, a sail extension: connects to the sniffed domain rather than to the address the client asked for.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |

## RuleType

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A rule's kind.

Serde: `serde (rename_all = "snake_case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `default` (default) | Conditions of its own. |
| `logical` | Other rules, combined. |

## LogicalMode

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

How a logical rule combines its rules.

Serde: `serde (rename_all = "snake_case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `and` | All of them match. |
| `or` | Any of them does. |

## RuleAction

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

What a matching rule does.

Serde: `serde (rename_all = "kebab-case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `Route` (default) | Sends the connection to `outbound`. |
| `RouteOptions` | Sets how the connection is carried, and lets the next rules decide where it goes. |
| `Reject` | Closes the connection. |
| `HijackDns` | Answers the DNS queries the connection carries. |
| `Sniff` | Reads the domain from the first bytes of a TCP connection (TLS SNI, HTTP Host), so that later rules match it. |
| `Resolve` | Resolves the domain, so that later rules match its addresses; a domain that does not resolve fails the connection. |

## RejectMethod

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

How a `reject` rule closes a connection.

Serde: `serde (rename_all = "snake_case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `default` (default) | At once; dropped instead when the rule rejects more than 50 connections in 30 seconds, unless `no_drop`. |
| `drop` | Left unanswered. |
| `reply` | With an ICMP message, for ICMP; sail routes none. |

## Sniffer

[配置定义源码](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A protocol a `sniff` rule looks for, by sing-box's name. TLS, HTTP and QUIC name the domain too (QUIC's needs the `btls` crypto compiled in); DNS, STUN, BitTorrent and DTLS are only recognized.

Serde: `serde (rename_all = "snake_case")`

| 可选值 / 形态 | 源码说明 |
| --- | --- |
| `tls` | — |
| `http` | — |
| `quic` | — |
| `dns` | — |
| `stun` | — |
| `bittorrent` | — |
| `dtls` | — |

