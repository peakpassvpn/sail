---
title: "路由"
description: "sail 原生配置格式（sing-box v1.14.2 JSON 与 sail 扩展）的逐字段参考。"
---

本页由 `website/scripts/build-config.mjs` 生成，请勿手改：它读取 sail 的配置类型（Rust 源码）、sing-box 字段注册表（`sail/src/config/singbox/fields.json`，sing-box v1.14.2）及注册表测试实测的分级（`fields.tiers.json`）。修改源码注释或上述文件后在 `website/` 下执行 `npm run docs:config`。

- **状态**：sing-box 的字段按注册表测试逐一实测：**支持**（读取并生效，不接受的取值仍报错）、**警告**（忽略并警告）、**报错**（拒绝该配置），并附理由；**sail 扩展** 为 sing-box 没有的字段与类型。
- **类型**：sing-box 字段取 sing-box 的 JSON 类型；扩展字段取自 sail 的 Rust 定义。
- **默认**：取自 sail 的 serde 声明；“未设置”表示可省略，省略时的行为见说明。只有 sail 读取的字段才列默认值。
- **说明**：sail 源码注释，保留原文；没有注释的扩展字段取注册表测试的说明。
- **构建条件**：Rust 源码中的 `cfg` 条件（Cargo feature 与平台）。

用 `sail -c config.json -T` 校验配置。编辑器可按 JSON schema 校验与补全：在配置顶层写 `"$schema": "https://peakpassvpn.github.io/sail/schema.json"`（由同一生成器产出；sail 报错的字段标为不允许，警告的标为弃用）。Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。

<a id="route"></a>

## `route`

Rust 定义：[`Route`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `rules` | array → [[]](#route-rules), [[action=bypass]](#route-rules-action-bypass), [[action=direct]](#route-rules-action-direct), [[action=reject]](#route-rules-action-reject), [[action=resolve]](#route-rules-action-resolve), [[action=route]](#route-rules-action-route), [[action=route-options]](#route-rules-action-route-options), [[action=sniff]](#route-rules-action-sniff), [[logical]](#route-rules-logical) | `[]` | 支持 | — |
| `rule_set` | array → [[]](#route-rule-set), [[inline]](#route-rule-set-inline), [[local]](#route-rule-set-local), [[remote]](#route-rule-set-remote) | `[]` | 支持 | The rule-sets rules name, by tag. |
| `final` | string | 未设置 | 支持 | The outbound for connections no rule matches; defaults to the first outbound. |
| `find_process` | bool | `false` | 支持 | Looks up who opened every connection (the program, the package, the user), for the connections list, though no rule asks; without it, only when a rule has conditions on it, as in sing-box. |
| `find_neighbor` | bool | `false` | 支持 | Looks up the LAN device of each connection's source even without a rule on it, for the logs (sing-box's, since 1.14). |
| `dhcp_lease_files` | listable-string | `[]` | 支持 | The DHCP lease files the LAN devices' names are read from; the usual ones of dnsmasq, odhcpd, ISC dhcpd and Kea when none. |
| `auto_detect_interface` | bool | `false` | 支持 | Sends outbounds that name no interface of their own through the system's default interface, found at start. Needed when a TUN inbound routes everything, or outbound traffic would loop back into it. |
| `override_android_vpn` | bool | — | 警告：Android's VPN is the host's to handle | — |
| `default_interface` | string | 未设置 | 支持 | The interface outbounds that name none of their own send through. |
| `default_mark` | number\|string | 未设置 | 支持 | The routing mark (`SO_MARK`, Linux) of outbounds that set none. |
| `default_domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names outbounds dial, for those that name no `domain_resolver` of their own. Unset, the DNS rules decide. |
| `default_network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | The `network_strategy`, `network_type`, `fallback_network_type` and `fallback_delay` of what sets none of the first three, or no delay; the strategy needs `auto_detect_interface`. |
| `default_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | — |
| `default_fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | — |
| `default_fallback_delay` | duration | 未设置 | 支持 | — |
| `default_http_client` | string | 未设置 | 支持 | The HTTP client of what names none, by tag; the first of `http_clients` when unset, or with none, the default outbound. |
| `geoip` | object | — | 警告：sing-box removed it in 1.12, and ignores it (sing-box 已弃用) | — |
| `geosite` | object | — | 警告：sing-box removed it in 1.12, and ignores it (sing-box 已弃用) | — |

<a id="route-rules"></a>

## `route.rules[]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `default`, `logical` | `default` | 支持 | `default`, or `logical`. |
| `inbound` | listable-string | `[]` | 支持 | Tags of the inbounds a connection came in through. |
| `ip_version` | number, 取值 `4`, `6` | 未设置 | 支持 | 4 or 6: the family of the destination address. |
| `network` | listable-string, 取值 `tcp`, `udp`, `icmp` | `[]` | 支持 | `tcp`, `udp`. |
| `auth_user` | listable-string | `[]` | 支持 | Names of the users an inbound authenticated. |
| `protocol` | listable-string, 取值 `tls`, `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`, `ssh`, `rdp`, `ntp` | `[]` | 支持 | The protocols a `sniff` rule found, by sing-box's names: `tls`, `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`. |
| `client` | listable-string | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `domain` | listable-string | `[]` | 支持 | — |
| `domain_suffix` | listable-string | `[]` | 支持 | — |
| `domain_keyword` | listable-string | `[]` | 支持 | — |
| `domain_regex` | listable-string | `[]` | 支持 | — |
| `source_ip_cidr` | listable-string | `[]` | 支持 | — |
| `source_ip_is_private` | bool | `false` | 支持 | The source address is not a public one. |
| `ip_cidr` | listable-string | `[]` | 支持 | — |
| `ip_is_private` | bool | `false` | 支持 | The destination address, or one the domain resolved to, is not a public one. |
| `source_port` | listable-number | `[]` | 支持 | — |
| `source_port_range` | listable-string | `[]` | 支持 | Inclusive port ranges, as `port_range` writes them. |
| `port` | listable-number | `[]` | 支持 | — |
| `port_range` | listable-string | `[]` | 支持 | Inclusive port ranges, as sing-box writes them: `1000:2000`, `:1024`, `8000:`. |
| `process_name` | listable-string | `[]` | 支持 | The name of the program a connection comes from, its path's last part. |
| `process_path` | listable-string | `[]` | 支持 | — |
| `process_path_regex` | listable-string | `[]` | 支持 | — |
| `package_name` | listable-string | `[]` | 支持 | Android packages: the app the host says opened the connection (`find_connection_owner`); an error without a host that tells. |
| `package_name_regex` | listable-string | `[]` | 支持 | — |
| `user` | listable-string | `[]` | 支持 | The user a connection's app runs as, by name and by id, as the host tells it; an error without a host that tells. |
| `user_id` | listable-number | `[]` | 支持 | — |
| `clash_mode` | string | 未设置 | 支持 | The mode of Clash's API: matches while it is that, whatever the case; never without an API. |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | The kind of network: `wifi`, `cellular`, `ethernet`, `other`. |
| `network_is_expensive` | bool | `false` | 支持 | The network is metered, as the system says. |
| `network_is_constrained` | bool | `false` | 支持 | The network is in a low data mode, as the system says. |
| `wifi_ssid` | listable-string | `[]` | 支持 | The name of the Wi-Fi network the host is on, whole and with case. This and the other conditions on the network match the network as the host tells it or sail detects it at the time; one on something not known of it does not match. |
| `wifi_bssid` | listable-string | `[]` | 支持 | The address of the Wi-Fi access point, `aa:bb:cc:dd:ee:ff`, in any case, with `:` or `-`, or as 12 hex digits. |
| `interface_address` | map | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `network_interface_address` | map | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `default_interface_address` | listable-string | — | 报错：A condition sail does not match: the rule would match otherwise | — |
| `source_mac_address` | listable-string | `[]` | 支持 | MAC addresses of the LAN device the connection comes from, as the neighbor table and DHCP leases know it (sing-box's, since 1.14). |
| `source_hostname` | listable-string | `[]` | 支持 | Host names of the LAN device the connection comes from, as its DHCP lease has it. |
| `preferred_by` | listable-string | — | 报错：A condition sail does not match: the rule would match otherwise | Tags of DNS servers, one of which prefers the name: of a DNS query, and so never of a connection. |
| `rule_set` | listable-string | `[]` | 支持 | Tags of rule-sets, any of whose rules matching matches. |
| `rule_set_ip_cidr_match_source` | bool | `false` | 支持 | The rule-sets' `ip_cidr` match the source address, not the destination. |
| `invert` | bool | `false` | 支持 | — |
| `action` | string, 取值 `route`, `route-options`, `direct`, `bypass`, `reject`, `hijack-dns`, `sniff`, `resolve` | 未设置 | 支持 | `route` when unset. |
| `geoip` | string 或 数组，元素为 string | `[]` | sail 扩展 | Country codes, looked up in `geo.mmdb` in the asset directory; a sail extension, as `geosite` is. |
| `geosite` | string 或 数组，元素为 string | `[]` | sail 扩展 | Site groups, looked up in `site.dat` in the asset directory. A sail extension: sing-box has dropped its GeoIP and GeoSite databases. |
| `external` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension: `mmdb:<file>:<code>` or `site:<file>:<code>`, for data files other than the default ones. |
| `http_user_agent` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `USER-AGENT`: patterns the User-Agent of a plain HTTP request a `sniff` rule read matches, whole and with case, `*` any run of characters and `?` any one. |
| `url_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `URL-REGEX`: regular expressions found in the URL of a plain HTTP request a `sniff` rule read, `http://host/path?query`. |
| `ip_asn` | number 或 数组，元素为 number | `[]` | sail 扩展 | A sail extension, for Surge's `IP-ASN`: the autonomous systems the destination address, or one the domain resolved to, belongs to, as `asn.mmdb` in the asset directory (GeoLite2-ASN's format, or ipinfo's) has them. |
| `process_name_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, as Mihomo's `PROCESS-NAME-REGEX`: regular expressions the program's name, its path's last part, matches. |
| `wifi_ssid_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `SSID:`: regular expressions found in the Wi-Fi network's name, with case. |
| `wifi_bssid_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `BSSID:`: regular expressions found in the access point's address as `aa:bb:cc:dd:ee:ff`, whatever the case. |
| `network_gateway` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `ROUTER:`: the address of the default gateway. |
| `network_mcc_mnc` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, for Surge's `MCCMNC:` and `CELLULAR-CARRIER`: the cellular carrier, its MCC and MNC as 5 or 6 digits; only off Wi-Fi. |
| `no_resolve` | bool | `false` | sail 扩展 | A sail extension, Surge's and Clash's `no-resolve`: the rule's conditions on the destination's addresses (`ip_cidr`, `ip_is_private`, `ip_asn`, `geoip`, those of its rule-sets and of the rules within) match only addresses already known, and never have an `on_demand` resolve resolve the domain for them. Only for a rule with such conditions. |

<a id="route-rules-action-bypass"></a>

## `route.rules[action=bypass]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `outbound` | string | 未设置 | 支持 | `route`: where a matching connection goes. |
| `override_address` | string | 未设置 | 支持 | `route`, `route-options`: connects to this address, an IP or a domain, instead of the one asked for, on the same port. |
| `override_port` | number | 未设置 | 支持 | `route`, `route-options`: connects to this port instead. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | `route`, `route-options`: how a direct outbound the connection goes out of chooses among the host's interfaces, instead of as its own says; not where it binds its sockets itself. A later rule's goes before. As in sing-box, only where the destination is an address (for UDP, a connected one) or a `resolve` rule resolved it; other outbounds, a group whose pick is a direct one among them, take no notice of it. `direct`: checked only. |
| `fallback_delay` | number | 未设置 | 支持 | `route`, `route-options`: how long a direct outbound the connection goes out of tries one family's addresses, and its first interfaces, before the others race them, instead of its own `fallback_delay`, where `network_strategy` would apply. A later rule's goes before. A duration string, as sing-box's documentation writes it, or a number of nanoseconds, as sing-box 1.14.1 reads it here. `direct`: checked only. |
| `udp_disable_domain_unmapping` | bool | `false` | 支持 | `route`, `route-options`: answers to UDP sent to a domain come back from the address it resolved to, not from the domain. |
| `udp_connect` | bool | `false` | 支持 | `route`, `route-options`: a direct outbound sends UDP from a connected socket. |
| `udp_timeout` | duration | 未设置 | 支持 | `route`, `route-options`: how long a UDP session lasts idle, instead of its inbound's `udp_timeout`. |
| `tls_fragment` | bool | `false` | 支持 | `route`, `route-options`: sends the TLS ClientHello in pieces, cut in the server name, each in a TCP segment of its own. |
| `tls_fragment_fallback_delay` | duration | 未设置 | 支持 | `route`, `route-options`: how long to wait between the pieces; 500ms when unset. |
| `tls_record_fragment` | bool | `false` | 支持 | `route`, `route-options`: sends the TLS ClientHello as several TLS records, cut in the server name. |
| `tls_spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `tls_spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |

<a id="route-rules-action-direct"></a>

## `route.rules[action=direct]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `bind_interface` | string | — | 警告：Accepted, no effect (as sing-box) | `direct`: the interface to send through, by name. |
| `inet4_bind_address` | string | — | 警告：Accepted, no effect (as sing-box) | `direct`: the local address for IPv4 destinations. |
| `inet6_bind_address` | string | — | 警告：Accepted, no effect (as sing-box) | `direct`: the local address for IPv6 destinations. |
| `bind_address_no_port` | bool | — | 警告：Accepted, no effect (as sing-box) | `direct`: `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address: Linux only. |
| `protect_path` | string | — | 警告：Accepted, no effect (as sing-box) | `direct`: the Unix socket each socket's descriptor is handed to, to be protected: Unix only. |
| `routing_mark` | number\|string | — | 警告：Accepted, no effect (as sing-box) | `direct`: `SO_MARK`, Linux only. |
| `reuse_addr` | bool | — | 警告：Accepted, no effect (as sing-box) | `direct`: `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | — |
| `connect_timeout` | duration | — | 警告：Accepted, no effect (as sing-box) | `direct`: how long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | — | 警告：Accepted, no effect (as sing-box) | `direct`: TCP Fast Open. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `disable_tcp_keep_alive` | bool | — | 警告：Accepted, no effect (as sing-box) | `direct`: no TCP keepalive at all. |
| `tcp_keep_alive` | duration | — | 警告：Accepted, no effect (as sing-box) | `direct`: how long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | — | 警告：Accepted, no effect (as sing-box) | `direct`: between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | — | 警告：Accepted, no effect (as sing-box) | `direct`: whether UDP datagrams may be fragmented on the way; not when unset, as sing-box's direct action has it. |
| `domain_resolver` | string\|object → [对象](#route-rules-action-direct-domain-resolver) | — | 警告：Accepted, no effect (as sing-box) | `direct`: the DNS server that resolves the names it dials. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 警告：Accepted, no effect (as sing-box) | `route`, `route-options`: how a direct outbound the connection goes out of chooses among the host's interfaces, instead of as its own says; not where it binds its sockets itself. A later rule's goes before. As in sing-box, only where the destination is an address (for UDP, a connected one) or a `resolve` rule resolved it; other outbounds, a group whose pick is a direct one among them, take no notice of it. `direct`: checked only. |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 警告：Accepted, no effect (as sing-box) | The kind of network: `wifi`, `cellular`, `ethernet`, `other`. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 警告：Accepted, no effect (as sing-box) | `direct`: the types of interface its `fallback` strategy falls back to. Its `network_type` is not one: a rule's `network_type` is its condition, as in sing-box. |
| `fallback_delay` | duration | — | 警告：Accepted, no effect (as sing-box) | `route`, `route-options`: how long a direct outbound the connection goes out of tries one family's addresses, and its first interfaces, before the others race them, instead of its own `fallback_delay`, where `network_strategy` would apply. A later rule's goes before. A duration string, as sing-box's documentation writes it, or a number of nanoseconds, as sing-box 1.14.1 reads it here. `direct`: checked only. |
| `domain_strategy` | string | — | 警告：Accepted, no effect (as sing-box) (sing-box 已弃用) | `direct`: sing-box's deprecated field for the families names resolve to. |

<a id="route-rules-action-direct-domain-resolver"></a>

### `route.rules[action=direct].domain_resolver`

Rust 定义：[`DomainResolver`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 必填 | 警告：Accepted, no effect (as sing-box) | — |
| `timeout` | duration | — | 警告：Accepted, no effect (as sing-box) | — |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | — | 警告：Accepted, no effect (as sing-box) | — |
| `disable_cache` | bool | — | 警告：Accepted, no effect (as sing-box) | — |
| `disable_optimistic_cache` | bool | — | 警告：Accepted, no effect (as sing-box) | — |
| `rewrite_ttl` | number | — | 警告：Accepted, no effect (as sing-box) | — |
| `client_subnet` | string | — | 警告：Accepted, no effect (as sing-box) | — |

<a id="route-rules-action-reject"></a>

## `route.rules[action=reject]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `method` | string, 取值 `default`, `drop`, `reply` | 未设置 | 支持 | `reject`: how. |
| `no_drop` | bool | `false` | 支持 | `reject`: never drops, however many connections the rule rejects. |

<a id="route-rules-action-resolve"></a>

## `route.rules[action=resolve]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `server` | string | 未设置 | 支持 | `resolve`: the DNS server to ask, rather than the one the DNS rules pick. |
| `timeout` | duration | 未设置 | 支持 | `sniff`: how long to wait for the first bytes; 300ms when unset. `resolve`: how long to wait for the answer; `dns.timeout` when unset. |
| `strategy` | string, 取值 `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | 未设置 | 支持 | `resolve`: the address families, instead of `dns.strategy`. |
| `disable_cache` | bool | `false` | 支持 | `resolve`: the answers neither come from the DNS cache nor go into it. |
| `disable_optimistic_cache` | bool | `false` | 支持 | `resolve`: an expired answer is not given while it is asked for again, though `dns.optimistic` is enabled. |
| `rewrite_ttl` | number | 未设置 | 支持 | `resolve`: the TTL the answers' records carry, in seconds. |
| `client_subnet` | string | 未设置 | 支持 | `resolve`: the EDNS Client Subnet the queries carry, instead of `dns.client_subnet`. |
| `ignore_failure` | bool | `false` | sail 扩展 | `resolve`, a sail extension: a domain that does not resolve, or not in time, has no addresses, and matching goes on, as Mihomo's IP rules have it; rather than the connection failing, as in sing-box. |
| `on_demand` | bool | `false` | sail 扩展 | `resolve`, `sniff`, a sail extension: the rule does not act where it stands but arms its action, with its options, and matching goes on. The action is taken the first time a later rule needs what it learns, just before that rule is matched: a resolve for a rule with conditions on the destination's addresses, while the destination is a domain; a sniff for one on the protocol, the plain HTTP request, or a domain while the destination is an address. A connection no later rule needs it for is never resolved or sniffed, as Surge and Mihomo have it. A later rule arming the same action replaces its options. |

<a id="route-rules-action-route"></a>

## `route.rules[action=route]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `outbound` | string | 未设置 | 支持 | `route`: where a matching connection goes. |
| `override_address` | string | 未设置 | 支持 | `route`, `route-options`: connects to this address, an IP or a domain, instead of the one asked for, on the same port. |
| `override_port` | number | 未设置 | 支持 | `route`, `route-options`: connects to this port instead. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | `route`, `route-options`: how a direct outbound the connection goes out of chooses among the host's interfaces, instead of as its own says; not where it binds its sockets itself. A later rule's goes before. As in sing-box, only where the destination is an address (for UDP, a connected one) or a `resolve` rule resolved it; other outbounds, a group whose pick is a direct one among them, take no notice of it. `direct`: checked only. |
| `fallback_delay` | number | 未设置 | 支持 | `route`, `route-options`: how long a direct outbound the connection goes out of tries one family's addresses, and its first interfaces, before the others race them, instead of its own `fallback_delay`, where `network_strategy` would apply. A later rule's goes before. A duration string, as sing-box's documentation writes it, or a number of nanoseconds, as sing-box 1.14.1 reads it here. `direct`: checked only. |
| `udp_disable_domain_unmapping` | bool | `false` | 支持 | `route`, `route-options`: answers to UDP sent to a domain come back from the address it resolved to, not from the domain. |
| `udp_connect` | bool | `false` | 支持 | `route`, `route-options`: a direct outbound sends UDP from a connected socket. |
| `udp_timeout` | duration | 未设置 | 支持 | `route`, `route-options`: how long a UDP session lasts idle, instead of its inbound's `udp_timeout`. |
| `tls_fragment` | bool | `false` | 支持 | `route`, `route-options`: sends the TLS ClientHello in pieces, cut in the server name, each in a TCP segment of its own. |
| `tls_fragment_fallback_delay` | duration | 未设置 | 支持 | `route`, `route-options`: how long to wait between the pieces; 500ms when unset. |
| `tls_record_fragment` | bool | `false` | 支持 | `route`, `route-options`: sends the TLS ClientHello as several TLS records, cut in the server name. |
| `tls_spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `tls_spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `override_destination` | bool 或 string, 取值 `proxy`, `proxy_and_direct`, `at_sniff` | 未设置 | sail 扩展 | `route`, `route-options`, `sniff`, a sail extension: a connection to an address is dialled by the name known for it, the sniffed domain or else the one `dns.reverse_mapping` keeps, where its last hop dials a proxy's server (`true` or `"proxy"`), or a direct dial too (`"proxy_and_direct"`). The rules still match the address. On a sniff rule, `"at_sniff"` instead makes the sniffed domain the destination there, for the rules after, as Mihomo's sniffer does. |

<a id="route-rules-action-route-options"></a>

## `route.rules[action=route-options]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `override_address` | string | 未设置 | 支持 | `route`, `route-options`: connects to this address, an IP or a domain, instead of the one asked for, on the same port. |
| `override_port` | number | 未设置 | 支持 | `route`, `route-options`: connects to this port instead. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | 未设置 | 支持 | `route`, `route-options`: how a direct outbound the connection goes out of chooses among the host's interfaces, instead of as its own says; not where it binds its sockets itself. A later rule's goes before. As in sing-box, only where the destination is an address (for UDP, a connected one) or a `resolve` rule resolved it; other outbounds, a group whose pick is a direct one among them, take no notice of it. `direct`: checked only. |
| `fallback_delay` | number | 未设置 | 支持 | `route`, `route-options`: how long a direct outbound the connection goes out of tries one family's addresses, and its first interfaces, before the others race them, instead of its own `fallback_delay`, where `network_strategy` would apply. A later rule's goes before. A duration string, as sing-box's documentation writes it, or a number of nanoseconds, as sing-box 1.14.1 reads it here. `direct`: checked only. |
| `udp_disable_domain_unmapping` | bool | `false` | 支持 | `route`, `route-options`: answers to UDP sent to a domain come back from the address it resolved to, not from the domain. |
| `udp_connect` | bool | `false` | 支持 | `route`, `route-options`: a direct outbound sends UDP from a connected socket. |
| `udp_timeout` | duration | 未设置 | 支持 | `route`, `route-options`: how long a UDP session lasts idle, instead of its inbound's `udp_timeout`. |
| `tls_fragment` | bool | `false` | 支持 | `route`, `route-options`: sends the TLS ClientHello in pieces, cut in the server name, each in a TCP segment of its own. |
| `tls_fragment_fallback_delay` | duration | 未设置 | 支持 | `route`, `route-options`: how long to wait between the pieces; 500ms when unset. |
| `tls_record_fragment` | bool | `false` | 支持 | `route`, `route-options`: sends the TLS ClientHello as several TLS records, cut in the server name. |
| `tls_spoof` | string | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `tls_spoof_method` | string, 取值 `wrong-sequence`, `wrong-checksum`, `wrong-ack`, `wrong-md5`, `wrong-timestamp` | — | 报错：Fragmenting or spoofing the TLS handshake against censorship | — |
| `override_destination` | bool 或 string, 取值 `proxy`, `proxy_and_direct`, `at_sniff` | 未设置 | sail 扩展 | `route`, `route-options`, `sniff`, a sail extension: a connection to an address is dialled by the name known for it, the sniffed domain or else the one `dns.reverse_mapping` keeps, where its last hop dials a proxy's server (`true` or `"proxy"`), or a direct dial too (`"proxy_and_direct"`). The rules still match the address. On a sniff rule, `"at_sniff"` instead makes the sniffed domain the destination there, for the rules after, as Mihomo's sniffer does. |

<a id="route-rules-action-sniff"></a>

## `route.rules[action=sniff]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `sniffer` | listable-string, 取值 `tls`, `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`, `ssh`, `rdp`, `ntp` | `[]` | 支持 | `sniff`: the protocols to look for; all of them when empty. |
| `timeout` | duration | 未设置 | 支持 | `sniff`: how long to wait for the first bytes; 300ms when unset. `resolve`: how long to wait for the answer; `dns.timeout` when unset. |
| `override_destination` | bool 或 string, 取值 `proxy`, `proxy_and_direct`, `at_sniff` | 未设置 | sail 扩展 | `route`, `route-options`, `sniff`, a sail extension: a connection to an address is dialled by the name known for it, the sniffed domain or else the one `dns.reverse_mapping` keeps, where its last hop dials a proxy's server (`true` or `"proxy"`), or a direct dial too (`"proxy_and_direct"`). The rules still match the address. On a sniff rule, `"at_sniff"` instead makes the sniffed domain the destination there, for the rules after, as Mihomo's sniffer does. |
| `skip_rule_set` | string 或 数组，元素为 string | `[]` | sail 扩展 | `sniff`, a sail extension: a domain found that one of these rule-sets matches is not taken, neither matched nor connected to, as Mihomo's sniffer `skip-domain` has it. |

<a id="route-rules-logical"></a>

## `route.rules[logical]`

Rust 定义：[`Rule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `mode` | string, 取值 `and`, `or` | 未设置 | 支持 | `logical`: `and` or `or`. |
| `rules` | array | `[]` | 支持 | `logical`: the rules combined. They take no action of their own. |
| `invert` | bool | `false` | 支持 | — |

<a id="route-rule-set"></a>

## `route.rule_set[]`

Rust 定义：[`RuleSet`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/rule_set.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `inline`, `local`, `remote` | `inline` | 支持 | — |

<a id="route-rule-set-inline"></a>

## `route.rule_set[inline]`

Rust 定义：[`RuleSet`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/rule_set.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | listable-string | 必填 | 支持 | One tag, or several, each put in place of `{tag}` in the path or URL. |
| `rules` | array → [[]](#route-rule-set-inline-rules), [[logical]](#route-rule-set-inline-rules-logical) | `[]` | 支持 | `inline`: the rules. |

<a id="route-rule-set-inline-rules"></a>

### `route.rule_set[inline].rules[]`

Rust 定义：[`HeadlessRule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/rule_set.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `default`, `logical` | 未设置 | 支持 | `default`, or `logical`. |
| `query_type` | listable-number\|string | `[]` | 支持 | — |
| `network` | listable-string, 取值 `tcp`, `udp`, `icmp` | `[]` | 支持 | — |
| `domain` | listable-string | `[]` | 支持 | — |
| `domain_suffix` | listable-string | `[]` | 支持 | — |
| `domain_keyword` | listable-string | `[]` | 支持 | — |
| `domain_regex` | listable-string | `[]` | 支持 | — |
| `source_ip_cidr` | listable-string | `[]` | 支持 | — |
| `ip_cidr` | listable-string | `[]` | 支持 | — |
| `source_port` | listable-number | `[]` | 支持 | — |
| `source_port_range` | listable-string | `[]` | 支持 | — |
| `port` | listable-number | `[]` | 支持 | — |
| `port_range` | listable-string | `[]` | 支持 | — |
| `process_name` | listable-string | `[]` | 支持 | — |
| `process_path` | listable-string | `[]` | 支持 | — |
| `process_path_regex` | listable-string | `[]` | 支持 | — |
| `package_name` | listable-string | `[]` | 支持 | As a routing rule's: the app the host says opened the connection, an error without a host that tells. |
| `package_name_regex` | listable-string | `[]` | 支持 | — |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | `[]` | 支持 | Conditions on the network the host is on, as a routing rule's: `wifi\|cellular\|ethernet\|other`. |
| `network_is_expensive` | bool | `false` | 支持 | — |
| `network_is_constrained` | bool | `false` | 支持 | — |
| `wifi_ssid` | listable-string | `[]` | 支持 | — |
| `wifi_bssid` | listable-string | `[]` | 支持 | — |
| `network_interface_address` | map | — | 报错：sail does not match it yet | Conditions sail does not match yet; a rule that sets one is refused when the rule-set is read. |
| `default_interface_address` | listable-string | — | 报错：sail does not match it yet | — |
| `invert` | bool | `false` | 支持 | — |
| `ip_asn` | number 或 数组，元素为 number | `[]` | sail 扩展 | A sail extension, as a routing rule's: autonomous systems, of `asn.mmdb` in the asset directory. |
| `http_user_agent` | string 或 数组，元素为 string | `[]` | sail 扩展 | Sail extensions, as a routing rule's: of a plain HTTP request. |
| `process_name_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | A sail extension, as Mihomo's `PROCESS-NAME-REGEX`: regular expressions the program's name, its path's last part, matches. |
| `wifi_ssid_regex` | string 或 数组，元素为 string | `[]` | sail 扩展 | Sail extensions, as a routing rule's: the Wi-Fi name and access point by pattern, the gateway, the cellular carrier. |
| `no_resolve` | bool | `false` | sail 扩展 | A sail extension, as a routing rule's, and Surge's and Clash's `no-resolve` on a line of a set: the rule's `ip_cidr` and `ip_asn`, and those of the rules within, match only addresses already known, and never have an `on_demand` resolve resolve the domain for them. Only for a rule with such conditions. |

<a id="route-rule-set-inline-rules-logical"></a>

### `route.rule_set[inline].rules[logical]`

Rust 定义：[`HeadlessRule`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/rule_set.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `mode` | string, 取值 `and`, `or` | 未设置 | 支持 | `logical`: `and` or `or`. |
| `rules` | array | `[]` | 支持 | `logical`: the rules combined. |
| `invert` | bool | `false` | 支持 | — |

<a id="route-rule-set-local"></a>

## `route.rule_set[local]`

Rust 定义：[`RuleSet`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/rule_set.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | listable-string | 必填 | 支持 | One tag, or several, each put in place of `{tag}` in the path or URL. |
| `format` | string, 取值 `source`, `binary` | 未设置 | 支持 | `source` (JSON) or `binary` (`.srs`); from the extension of the path or URL when unset. A sail extension, for Clash's rule-providers: `mrs` (Mihomo's binary), `clash-yaml` or `clash-text`, which take a `behavior`. |
| `path` | string | 未设置 | 支持 | `local`: the file. |

<a id="route-rule-set-remote"></a>

## `route.rule_set[remote]`

Rust 定义：[`RuleSet`](https://github.com/peakpassvpn/sail/blob/dev/sail/src/config/rule_set.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | listable-string | 必填 | 支持 | One tag, or several, each put in place of `{tag}` in the path or URL. |
| `format` | string, 取值 `source`, `binary` | 未设置 | 支持 | `source` (JSON) or `binary` (`.srs`); from the extension of the path or URL when unset. A sail extension, for Clash's rule-providers: `mrs` (Mihomo's binary), `clash-yaml` or `clash-text`, which take a `behavior`. |
| `url` | string | 未设置 | 支持 | `remote`: where it is downloaded from. |
| `initial_path` | string | 未设置 | 支持 | `remote`: a file to start from before the first download. |
| `http_client` | string\|object → [对象](#route-rule-set-remote-http-client) | 未设置 | 支持 | `remote`: the HTTP client it is downloaded with, by tag or in place. With neither this nor `download_detour`, the default one of `http_clients` (`route.default_http_client`, or else the first), or else the default outbound. |
| `update_interval` | duration | 未设置 | 支持 | `remote`: how often it is downloaded again; 1d when unset. |
| `download_detour` | string | 未设置 | 支持 (sing-box 已弃用) | `remote`: the outbound it is downloaded through; deprecated in sing-box for `http_client`. |
| `behavior` | string, 取值 `domain`, `ipcidr`, `classical` | 未设置 | sail 扩展 | A sail extension, for the Clash formats: what each line is, `domain`, `ipcidr` or `classical` (a Clash rule without its target). |
| `size_limit` | number | 未设置 | sail 扩展 | `remote`, a sail extension (Mihomo's `size-limit`): the most a download of it may be, in bytes; past it the download fails and the copy in use is kept. Unset, the download client's own cap. |

<a id="route-rule-set-remote-http-client"></a>

### `route.rule_set[remote].http_client`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `engine` | string, 取值 `go`, `apple` | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `version` | number, 取值 `0`, `1`, `2`, `3` | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `disable_version_fallback` | bool | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `headers` | map | — | 支持 | — |
| `tls` | object → [对象](/sail/zh/reference/shared/#tls-http-clients-route-rule-set) | — | 报错：TLS options of an HTTP client's own: its downloads would be checked otherwise | — |
| `detour` | string | — | 支持 | — |
| `bind_interface` | string | — | 支持 | — |
| `inet4_bind_address` | string | — | 支持 | — |
| `inet6_bind_address` | string | — | 支持 | — |
| `bind_address_no_port` | bool | — | 支持 | — |
| `protect_path` | string | — | 支持 | — |
| `routing_mark` | number\|string | — | 支持 | — |
| `reuse_addr` | bool | — | 支持 | — |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | — |
| `connect_timeout` | duration | — | 支持 | — |
| `tcp_fast_open` | bool | — | 支持 | — |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | — |
| `disable_tcp_keep_alive` | bool | — | 支持 | — |
| `tcp_keep_alive` | duration | — | 支持 | — |
| `tcp_keep_alive_interval` | duration | — | 支持 | — |
| `udp_fragment` | bool | — | 支持 | — |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-inbounds-route-rule-set) | — | 支持 | — |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 支持 | — |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 支持 | — |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 支持 | — |
| `fallback_delay` | duration | — | 支持 | — |
| `idle_timeout` | duration | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `keep_alive_period` | duration | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `stream_receive_window` | number\|string | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `connection_receive_window` | number\|string | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `max_concurrent_streams` | number | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `initial_packet_size` | number | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `disable_path_mtu_discovery` | bool | — | 警告：HTTP/2 and HTTP/3 tuning: a download over HTTP/1.1 is the same download | — |
| `domain_strategy` | string | — | 支持 (sing-box 已弃用) | — |

