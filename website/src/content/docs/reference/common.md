---
title: Common configuration
description: Fields, types and serialization rules extracted from Sail configuration source.
---

Generated from the Rust syntax tree. Update source comments and rebuild to change this page. `Option<T>` is optional; `Vec<T>` is an array. Comments retain their source language.

These declarations are not a complete runtime validation schema. Features and platform gates affect availability. Consult the [configuration guide](/sail/configuration/) and linked source for computed defaults, supported combinations and cross-field constraints; validate with `sail -c config.json -T`.

## Config

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `log` | `Log` | Default::default() | —<br/>`serde (default)` |
| `dns` | `Dns` | Default::default() | —<br/>`serde (default)` |
| `inbounds` | `Vec < Inbound >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `outbounds` | `Vec < Outbound >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `endpoints` | `Vec < Endpoint >` | Default::default() | Both an inbound and an outbound under one tag, as sing-box's endpoints: connections routed to the tag go out through it, and what comes in through it is routed with the tag as its inbound.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `route` | `Route` | Default::default() | —<br/>`serde (default)` |
| `api` | `Api` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Api::is_default")` |
| `experimental` | `Experimental` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Experimental::is_default")` |
| `certificate` | `Option < CertificateOptions >` | Default::default() | The root certificates servers are checked against; the system's when unset.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `http_clients` | `Vec < HttpClient >` | Default::default() | How sail fetches over HTTP, rule-sets for one, by tag.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `outbound_providers` | `Vec < OutboundProvider >` | Default::default() | A sail extension: outbounds given together, downloaded, read from a file or written in place, that groups take as members, as Mihomo's proxy groups take a proxy-provider's proxies.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `warnings` | `Vec < String >` | Required | What the configuration sets that sail ignores, one line each; the start logs them.<br/>`serde (skip)` |

## HttpClient

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

An HTTP client: the outbound it fetches through, or, with none, the dial fields it connects with itself.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `tag` | `String` | Default::default() | Of one in `http_clients`; none inline.<br/>`serde (default , skip_serializing_if = "String::is_empty")` |
| `detour` | `Option < String >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `bind_interface` | `Option < String >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `inet4_bind_address` | `Option < std :: net :: Ipv4Addr >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `inet6_bind_address` | `Option < std :: net :: Ipv6Addr >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `routing_mark` | `Option < u32 >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `connect_timeout` | `Option < std :: time :: Duration >` | Default::default() | —<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `domain_resolver` | `Option < DomainResolver >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `domain_strategy` | `Option < DnsStrategy >` | Default::default() | sing-box's deprecated field for the families names resolve to.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `headers` | `BTreeMap < String , HeaderValues >` | Default::default() | Sent with each request, over sail's own of the same name.<br/>`serde (default , skip_serializing_if = "BTreeMap::is_empty")` |

## HeaderValues

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

The values of a header: one, or a list.

Serde: `serde (transparent)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `` | `Vec < String >` | Required | —<br/>`serde (with = "listable")` |

## HttpClientRef

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

An HTTP client named by tag, or given in place; in place, its tag is no name, as in sing-box.

Serde: `serde (untagged)`

| Value / shape | Source notes |
| --- | --- |
| `(String)` | — |
| `(HttpClient)` | — |

## CertificateOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

sing-box's top-level `certificate`: a store of root certificates, and certificates of one's own besides.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `store` | `CertificateStore` | Default::default() | —<br/>`serde (default)` |
| `certificate` | `Vec < String >` | Default::default() | Inline PEM, its lines one to an entry or all in one.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `certificate_path` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `certificate_directory_path` | `Vec < String >` | Default::default() | Directories, every file of which holds certificates.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |

## CertificateStore

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Which roots: the system's, or Mozilla's or Chrome's included lists (without the certificate authorities of China, as sing-box's), or none.

Serde: `serde (rename_all = "snake_case")`

| Value / shape | Source notes |
| --- | --- |
| `system` (default) | — |
| `mozilla` | — |
| `chrome` | — |
| `none` | — |

## Experimental

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

sing-box's `experimental`: what sail takes of it.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `cache_file` | `Option < CacheFileOptions >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `clash_api` | `Option < ClashApi >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## CacheFileOptions

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

sing-box's `cache_file`: what is kept across restarts. The selections of selector groups and the Clash API's mode, and the fake IPs handed out with `store_fakeip`; nothing without it.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `enabled` | `bool` | Default::default() | —<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `path` | `Option < String >` | Default::default() | `cache.db` when unset. A relative path is in the host's cache directory, or the data directory.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `cache_id` | `Option < String >` | Default::default() | What this configuration keeps is kept apart, under this name, from what others sharing the file keep.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `store_fakeip` | `bool` | Default::default() | —<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |

## ClashApi

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Clash's API: the mode rules match, `Rule` when unset. The API itself is not served yet.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `default_mode` | `Option < String >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## Api

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

The control API; a sail extension.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `listen` | `Option < std :: net :: SocketAddr >` | Default::default() | Where the API listens; it is not served when unset.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## LogLevel

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (rename_all = "lowercase")`

| Value / shape | Source notes |
| --- | --- |
| `trace` | — |
| `debug` | — |
| `info` (default) | — |
| `warn` | — |
| `error` | — |
| `fatal` | As `error`: sail logs nothing more severe. |
| `panic` | As `error`. |

## LogFormat

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (rename_all = "lowercase")`

| Value / shape | Source notes |
| --- | --- |
| `full` (default) | — |
| `compact` | — |

## Log

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `disabled` | `bool` | Default::default() | Logs nothing.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `level` | `LogLevel` | Default::default() | —<br/>`serde (default)` |
| `output` | `Option < String >` | Default::default() | A file to append to. Logs go to the console when it is not set.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `timestamp` | `bool` | Default::default() | Starts each line with the time.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `format` | `LogFormat` | Default::default() | A sail extension: `compact` writes the message alone.<br/>`serde (default)` |

## Dns

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `servers` | `Vec < DnsServer >` | Default::default() | The servers, each by its tag. None is the system's resolver alone.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `rules` | `Vec < DnsRule >` | Default::default() | Which server a query goes to, matched in order.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `final` | `Option < String >` | Default::default() | The server of the queries no rule matches; the first one when unset.<br/>`serde (rename = "final" , default , skip_serializing_if = "Option::is_none")` |
| `strategy` | `DnsStrategy` | Default::default() | Which address families names resolve to, and in what order.<br/>`serde (default)` |
| `cache_capacity` | `Option < usize >` | Default::default() | Answers kept per address family; 512, or 64 on iOS, when unset.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `timeout` | `Option < std :: time :: Duration >` | Default::default() | How long one query to one server may take; 4s when unset.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `reverse_mapping` | `bool` | Default::default() | Remembers the domain of each address the DNS answers that pass through carry, so that connections to the address are routed by the domain.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `client_subnet` | `Option < Prefix >` | Default::default() | The EDNS Client Subnet each query carries, unless a rule says otherwise.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## DnsServer

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A DNS server. What it takes beyond its type and tag belongs to its type, and is read when the DNS client is built, as an outbound's options are.

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `type` | `String` | Required | `udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `local`, `hosts`, or sail's `smart_select`.<br/>`serde (rename = "type")` |
| `tag` | `String` | Default::default() | Defaults to the type.<br/>`serde (default)` |
| `options` | `Options` | Flattened into this object | —<br/>`serde (flatten)` |

## DnsRule

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A DNS rule, matched in order against each query. Its conditions are a routing rule's, matched as they are there, and `query_type` and `outbound` besides; a logical one (`type: logical`) combines others, which take no action of their own.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `type` | `RuleType` | Default::default() | `default`, or `logical`.<br/>`serde (rename = "type" , default , skip_serializing_if = "RuleType::is_default")` |
| `query_type` | `Vec < serde_json :: Value >` | Default::default() | Record types, by name (`A`, `AAAA`, `HTTPS`) or number.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `inbound` | `Vec < String >` | Default::default() | Tags of the inbounds the connection that needs the name came in through.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `clash_mode` | `Option < String >` | Default::default() | The mode of Clash's API, as in a routing rule.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `ip_version` | `Option < u8 >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `network` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `auth_user` | `Vec < String >` | Default::default() | Names of the users an inbound authenticated.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `protocol` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain_suffix` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain_keyword` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `domain_regex` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `geosite` | `Vec < String >` | Default::default() | A sail extension, as in a routing rule.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `external` | `Vec < String >` | Default::default() | A sail extension, as in a routing rule: `site:<file>:<code>`.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `source_ip_cidr` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `source_ip_is_private` | `bool` | Default::default() | —<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `source_port` | `Vec < u16 >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `source_port_range` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `port` | `Vec < u16 >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `port_range` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `process_name` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `process_path` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `process_path_regex` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `package_name` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `package_name_regex` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `user` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `user_id` | `Vec < i32 >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `outbound` | `Vec < String >` | Default::default() | Tags of the outbounds that dial the name; of the rule itself, not of a rule a logical one combines.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `rule_set` | `Vec < String >` | Default::default() | Tags of rule-sets, any of whose rules matching matches. Their `ip_cidr` rules match no query, which has no address yet.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `rule_set_ip_cidr_match_source` | `bool` | Default::default() | The rule-sets' `ip_cidr` match the source address.<br/>`serde (default , alias = "rule_set_ipcidr_match_source" , skip_serializing_if = "std::ops::Not::not")` |
| `match_response` | `Option < ResponseRef >` | Default::default() | The response of an `evaluate` rule before it, which the rule then matches: its addresses are what `ip_cidr`, `ip_is_private`, `ip_accept_any` and the rule-sets' `ip_cidr` match. With none, the rule matches only inverted.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `ip_cidr` | `Vec < String >` | Default::default() | —<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `ip_is_private` | `bool` | Default::default() | —<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `ip_accept_any` | `bool` | Default::default() | The response has an address.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `ip_match_all` | `bool` | Default::default() | A sail extension: the rule's conditions on the response's addresses hold for every one of them, rather than for any; a response without one they hold for none. Mihomo's fallback filter keeps an answer so.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `response_rcode` | `Option < Rcode >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `invert` | `bool` | Default::default() | —<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `mode` | `Option < LogicalMode >` | Default::default() | `logical`: `and` or `or`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `rules` | `Vec < DnsRule >` | Default::default() | `logical`: the rules combined.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `action` | `Option < DnsRuleAction >` | Default::default() | `route` when unset.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `server` | `Option < String >` | Default::default() | `route`: the server a matching query goes to.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `strategy` | `Option < DnsStrategy >` | Default::default() | `route`: the address families, instead of `dns.strategy`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `rcode` | `Option < Rcode >` | Default::default() | `predefined`: the code of the answer, NOERROR when unset.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `tag` | `Option < String >` | Default::default() | `evaluate`: the name of its response, which `match_response` gives.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `disable_cache` | `bool` | Default::default() | `route`, `evaluate` and `route-options`: the query neither comes from the cache nor goes into it.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `rewrite_ttl` | `Option < u32 >` | Default::default() | The TTL the answer's records carry, in seconds.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `timeout` | `Option < std :: time :: Duration >` | Default::default() | How long the query may take, instead of `dns.timeout`.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `client_subnet` | `Option < Prefix >` | Default::default() | The EDNS Client Subnet the query carries, instead of `dns.client_subnet`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `remove_client_subnet` | `bool` | Default::default() | The query carries no EDNS Client Subnet, whatever it or `dns.client_subnet` has.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |

## DnsRuleAction

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

What a matching DNS rule does.

Serde: `serde (rename_all = "kebab-case")`

| Value / shape | Source notes |
| --- | --- |
| `Route` (default) | Sends the query to `server`. |
| `Evaluate` | Sends the query to `server` and keeps the response for the rules after it to match, which goes on with the next rule. |
| `Respond` | Answers with the response kept. |
| `RouteOptions` | Sets how the query is sent, for the rule that sends it; matching goes on with the next rule. |
| `Reject` | Answers that the name does not resolve. |
| `Predefined` | Answers with `rcode` and no records, as sing-box's `predefined` without its records, which sail does not implement. |

## DnsStrategy

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Which address families names resolve to, as sing-box names them.

Serde: `serde (rename_all = "snake_case")`

| Value / shape | Source notes |
| --- | --- |
| `prefer_ipv4` (default) | Both, IPv4 first: sing-box's default. |
| `prefer_ipv6` | Both, IPv6 first. |
| `ipv4_only` | IPv4 addresses only. |
| `ipv6_only` | IPv6 addresses only. |

## Inbound

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `type` | `String` | Required | —<br/>`serde (rename = "type")` |
| `tag` | `String` | Default::default() | Defaults to the type.<br/>`serde (default)` |
| `listen` | `Option < String >` | Default::default() | The address to listen on; defaults to `127.0.0.1`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `listen_port` | `Option < u16 >` | Default::default() | The port to listen on. An inbound without one does not listen, and is only useful as a part of another inbound.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `udp_timeout` | `Option < std :: time :: Duration >` | Default::default() | How long a UDP session through this inbound lives without traffic; 5m when unset, as in sing-box.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `tcp_keep_alive` | `Option < std :: time :: Duration >` | Default::default() | How long an accepted TCP connection is idle before keepalive probes it; 5m when unset.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `tcp_keep_alive_interval` | `Option < std :: time :: Duration >` | Default::default() | Between keepalive probes; 75s when unset.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `disable_tcp_keep_alive` | `bool` | Default::default() | —<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |
| `options` | `Options` | Flattened into this object | —<br/>`serde (flatten)` |

## Outbound

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `type` | `String` | Required | —<br/>`serde (rename = "type")` |
| `tag` | `String` | Default::default() | Defaults to the type.<br/>`serde (default)` |
| `options` | `Options` | Flattened into this object | —<br/>`serde (flatten)` |

## Endpoint

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

An endpoint: an outbound, and an inbound, under one tag. Like an outbound's, its options belong to its protocol.

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `type` | `String` | Required | —<br/>`serde (rename = "type")` |
| `tag` | `String` | Default::default() | Defaults to the type.<br/>`serde (default)` |
| `udp_timeout` | `Option < std :: time :: Duration >` | Default::default() | How long a UDP session coming in through this endpoint lives without traffic; 5m when unset, as for an inbound.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `options` | `Options` | Flattened into this object | —<br/>`serde (flatten)` |

## OutboundProvider

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Outbounds given together, for groups to take as members (their `providers`): a sail extension, with the semantics of Mihomo's proxy-providers. A subscription or a file holds what Mihomo reads from one: Clash's YAML with its `proxies`, or share links, a line each and maybe in base64. It needs the outbound-provider feature.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `type` | `OutboundProviderKind` | Required | —<br/>`serde (rename = "type")` |
| `tag` | `String` | Required | Its members' keys name it, and groups' `providers`. |
| `url` | `Option < String >` | Default::default() | `remote`: where it is downloaded from.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `path` | `Option < String >` | Default::default() | `local`: the file, in the data directory unless absolute.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `update_interval` | `Option < std :: time :: Duration >` | Default::default() | `remote`: how often it is downloaded again, 1d when unset. `local`: how often the file is read again, never when unset.<br/>`serde (default , with = "duration" , skip_serializing_if = "Option::is_none")` |
| `download_detour` | `Option < String >` | Default::default() | `remote`: the outbound it is downloaded through, as a remote rule-set's.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `http_client` | `Option < HttpClientRef >` | Default::default() | `remote`: the HTTP client it is downloaded with, as a remote rule-set's.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `filter` | `Vec < String >` | Default::default() | `remote`, `local`: regular expressions, as Mihomo's `filter`; only the outbounds whose names match one are taken, those of the first first.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `exclude_filter` | `Vec < String >` | Default::default() | `remote`, `local`: regular expressions no name taken may match.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `exclude_type` | `Vec < String >` | Default::default() | `remote`, `local`: the Clash types (`ss`, `vmess`, ...) not taken, without case.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `override` | `Option < serde_json :: Map < String , serde_json :: Value > >` | Default::default() | `remote`, `local`: what is changed in every outbound taken, in the keys of Mihomo's `override` (`skip-cert-verify`, `additional-prefix`, `proxy-name`, ...).<br/>`serde (rename = "override" , default , skip_serializing_if = "Option::is_none")` |
| `detour` | `Option < String >` | Default::default() | `remote`, `local`: the outbound every outbound taken dials through, as Mihomo's `dialer-proxy`.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `outbounds` | `Vec < Outbound >` | Default::default() | `inline`: the outbounds, their tags their names as members.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |

## OutboundProviderKind

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (rename_all = "snake_case")`

| Value / shape | Source notes |
| --- | --- |
| `remote` | — |
| `local` | — |
| `inline` | — |

## GroupProviders

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

The members a group takes from outbound providers, after its own `outbounds`, and those it leaves out: a sail extension, as Mihomo's proxy groups take them (`use`, `filter`, `exclude-filter`, `exclude-type`, `empty-fallback`). Of `selector`, `urltest`, `fallback` and `load-balance`; it needs the outbound-provider feature.

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `providers` | `Vec < String >` | Default::default() | The outbound providers, by tag, whose outbounds join the group's own, in this order.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `filter` | `Vec < String >` | Default::default() | Regular expressions, as Mihomo's `filter`: of the providers' outbounds, only those whose names match one are members, those of the first first. The group's own outbounds are not filtered.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `exclude_filter` | `Vec < String >` | Default::default() | Regular expressions no member's name may match, the group's own outbounds' too.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `exclude_type` | `Vec < String >` | Default::default() | The types no member may be of, the group's own outbounds too, in Mihomo's names for them, without case: `Shadowsocks`, `Vmess`, `Socks5`, `Direct`, ...<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `empty_fallback` | `Option < String >` | Default::default() | An outbound, not a group, that is the member while there is none else. Without it such a group has none, and its connections fail.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## Route

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `rules` | `Vec < Rule >` | Default::default() | —<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `rule_set` | `Vec < super :: rule_set :: RuleSet >` | Default::default() | The rule-sets rules name, by tag.<br/>`serde (default , skip_serializing_if = "Vec::is_empty")` |
| `final` | `Option < String >` | Default::default() | The outbound for connections no rule matches; defaults to the first outbound.<br/>`serde (rename = "final" , default , skip_serializing_if = "Option::is_none")` |
| `default_interface` | `Option < String >` | Default::default() | The interface outbounds that name none of their own send through.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `default_mark` | `Option < u32 >` | Default::default() | The routing mark (`SO_MARK`, Linux) of outbounds that set none.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `auto_detect_interface` | `bool` | Default::default() | Sends outbounds that name no interface of their own through the system's default interface, found at start. Needed when a TUN inbound routes everything, or outbound traffic would loop back into it.<br/>`serde (default)` |
| `default_domain_resolver` | `Option < DomainResolver >` | Default::default() | The DNS server that resolves the names outbounds dial, for those that name no `domain_resolver` of their own. Unset, the DNS rules decide.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
| `default_http_client` | `Option < String >` | Default::default() | The HTTP client of what names none, by tag; the first of `http_clients` when unset, or with none, the default outbound.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |

## Rule

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A routing rule, matched in order, as sing-box has it. A default rule sets conditions on the things a connection is known by: of the conditions on one thing (the source's address, its port, the destination's address, its port) any matching will do, and the rule matches when each thing it has conditions on matches and every other condition does. A condition listing several values matches when any of them does. A logical rule (`type: logical`) combines the rules in `rules`, all of them (`mode: and`) or any (`mode: or`); `invert` turns either kind's result around.  `route`, `reject` and `hijack-dns` end the matching. `route-options`, `sniff` and `resolve` learn more about the connection or say how it is to be carried, and matching goes on with the next rule.

Serde: `serde (deny_unknown_fields)`

| Field | Type | Omission / flattening | Source notes |
| --- | --- | --- | --- |
| `type` | `RuleType` | Default::default() | `default`, or `logical`.<br/>`serde (rename = "type" , default , skip_serializing_if = "RuleType::is_default")` |
| `query_type` | `Vec < serde_json :: Value >` | Default::default() | Record types, by name (`A`, `AAAA`, `HTTPS`) or number: of a DNS query, and so never of a connection.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `clash_mode` | `Option < String >` | Default::default() | The mode of Clash's API: matches while it is that, whatever the case; never without an API.<br/>`serde (default , skip_serializing_if = "Option::is_none")` |
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
| `ip_accept_any` | `bool` | Required | A DNS rule's: the response it matches has an address.<br/>`serde (skip)` |
| `response_rcode` | `Option < u16 >` | Optional (None) | A DNS rule's: the response it matches has this code.<br/>`serde (skip)` |
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
| `skip_rule_set` | `Vec < String >` | Default::default() | `sniff`, a sail extension: a domain found that one of these rule-sets matches is not taken, neither matched nor connected to, as Mihomo's sniffer `skip-domain` has it.<br/>`serde (default , with = "listable" , skip_serializing_if = "Vec::is_empty")` |
| `ignore_failure` | `bool` | Default::default() | `resolve`, a sail extension: a domain that does not resolve, or not in time, has no addresses, and matching goes on, as Mihomo's IP rules have it; rather than the connection failing, as in sing-box.<br/>`serde (default , skip_serializing_if = "std::ops::Not::not")` |

## RuleType

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A rule's kind.

Serde: `serde (rename_all = "snake_case")`

| Value / shape | Source notes |
| --- | --- |
| `default` (default) | Conditions of its own. |
| `logical` | Other rules, combined. |

## LogicalMode

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

How a logical rule combines its rules.

Serde: `serde (rename_all = "snake_case")`

| Value / shape | Source notes |
| --- | --- |
| `and` | All of them match. |
| `or` | Any of them does. |

## RuleAction

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

What a matching rule does.

Serde: `serde (rename_all = "kebab-case")`

| Value / shape | Source notes |
| --- | --- |
| `Route` (default) | Sends the connection to `outbound`. |
| `RouteOptions` | Sets how the connection is carried, and lets the next rules decide where it goes. |
| `Reject` | Closes the connection. |
| `HijackDns` | Answers the DNS queries the connection carries. |
| `Sniff` | Reads the domain from the first bytes of a TCP connection (TLS SNI, HTTP Host), so that later rules match it. |
| `Resolve` | Resolves the domain, so that later rules match its addresses; a domain that does not resolve fails the connection. |
| `Bypass` | As sing-box 1.13: lets the kernel carry the connection past the proxy where TUN's auto_redirect matches it before it is set up. Elsewhere it routes to `outbound` like `route`, and without one the rule is skipped. |

## RejectMethod

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

How a `reject` rule closes a connection.

Serde: `serde (rename_all = "snake_case")`

| Value / shape | Source notes |
| --- | --- |
| `default` (default) | At once; dropped instead when the rule rejects more than 50 connections in 30 seconds, unless `no_drop`. |
| `drop` | Left unanswered. |
| `reply` | With an ICMP message, for ICMP; sail routes none. |

## Sniffer

[Configuration source](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

A protocol a `sniff` rule looks for, by sing-box's name. TLS, HTTP and QUIC name the domain too (QUIC's needs the `btls` crypto compiled in); DNS, STUN, BitTorrent and DTLS are only recognized.

Serde: `serde (rename_all = "snake_case")`

| Value / shape | Source notes |
| --- | --- |
| `tls` | — |
| `http` | — |
| `quic` | — |
| `dns` | — |
| `stun` | — |
| `bittorrent` | — |
| `dtls` | — |

