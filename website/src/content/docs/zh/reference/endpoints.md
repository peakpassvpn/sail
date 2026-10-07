---
title: "端点"
description: "sail 原生配置格式（sing-box v1.14.2 JSON 与 sail 扩展）的逐字段参考。"
---

本页由 `website/scripts/build-config.mjs` 生成，请勿手改：它读取 sail 的配置类型（Rust 源码）、sing-box 字段注册表（`sail/src/config/singbox/fields.json`，sing-box v1.14.2）及注册表测试实测的分级（`fields.tiers.json`）。修改源码注释或上述文件后在 `website/` 下执行 `npm run docs:config`。

- **状态**：sing-box 的字段按注册表测试逐一实测：**支持**（读取并生效，不接受的取值仍报错）、**警告**（忽略并警告）、**报错**（拒绝该配置），并附理由；**sail 扩展** 为 sing-box 没有的字段与类型。
- **类型**：sing-box 字段取 sing-box 的 JSON 类型；扩展字段取自 sail 的 Rust 定义。
- **默认**：取自 sail 的 serde 声明；“未设置”表示可省略，省略时的行为见说明。只有 sail 读取的字段才列默认值。
- **说明**：sail 源码注释，保留原文；没有注释的扩展字段取注册表测试的说明。
- **构建条件**：Rust 源码中的 `cfg` 条件（Cargo feature 与平台）。

用 `sail -c config.json -T` 校验配置。编辑器可按 JSON schema 校验与补全：在配置顶层写 `"$schema": "https://peakpassvpn.github.io/sail/schema.json"`（由同一生成器产出；sail 报错的字段标为不允许，警告的标为弃用）。Clash 与 Surge 的支持表见[兼容性](/sail/zh/reference/compatibility/)。

<a id="endpoints"></a>

## `endpoints[]`

Rust 定义：[`Endpoint`](https://github.com/peakpassvpn/sail/blob/master/sail/src/config/model.rs)

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `type` | string, 取值 `openconnect`, `openvpn-client`, `openvpn-server`, `tailscale`, `wireguard` | 必填 | 支持 | — |

<a id="endpoints-wireguard"></a>

## `endpoints[wireguard]`

Rust 定义：[`WireGuardOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/wireguard/endpoint/options.rs) · 构建条件：`feature = "wireguard"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `tag` | string | `""` | 支持 | Defaults to the type. |
| `system` | bool | `false` | 支持 | A system interface instead of the userspace stack: not supported. |
| `name` | string | — | 报错：Names a system interface, which sail does not create | The system interface's name, for `system` only. |
| `mtu` | number | 未设置 | 支持 | — |
| `address` | listable-string | 必填 | 支持 | The endpoint's own addresses in the tunnel, as prefixes. |
| `private_key` | string | 必填 | 支持 | — |
| `listen_port` | number | 未设置 | 支持 | — |
| `peers` | array → [[]](#endpoints-wireguard-peers) | 必填 | 支持 | — |
| `udp_timeout` | duration | 未设置 | 支持 | How long a UDP session coming in through this endpoint lives without traffic; 5m when unset, as for an inbound. |
| `udp_mapping` | string, 取值 `endpoint_independent`, `address_dependent`, `address_and_port_dependent` | — | 警告：How UDP mappings are made and how many are kept: the same traffic | — |
| `udp_filtering` | string, 取值 `endpoint_independent`, `address_dependent`, `address_and_port_dependent` | — | 报错：Which remote addresses may answer through a UDP mapping: others would | — |
| `udp_nat_max` | number | — | 警告：How UDP mappings are made and how many are kept: the same traffic | — |
| `workers` | number | 未设置 | 支持 | sing-box's worker count; sail has no use for it. |
| `detour` | string | 未设置 | 支持 | The outbound to dial through, in place of a socket of its own. |
| `bind_interface` | string | 未设置 | 支持 | The interface to send through, by name. Loopback destinations still go over loopback, where sing-box applies the bind to them as well. |
| `inet4_bind_address` | string | 未设置 | 支持 | The local address for IPv4 destinations, loopback ones aside: as `bind_interface`. |
| `inet6_bind_address` | string | 未设置 | 支持 | The local address for IPv6 destinations, loopback ones aside: as `bind_interface`. |
| `bind_address_no_port` | bool | `false` | 支持 | `IP_BIND_ADDRESS_NO_PORT` on TCP sockets bound to an address, so that the port is picked at connect: Linux only. |
| `protect_path` | string | 未设置 | 支持 | A Unix socket each socket's descriptor is handed to, with `SCM_RIGHTS`, before it binds or connects, for the process there to protect it (from its VPN, say); it answers one byte. Besides what the host protects. Unix only. |
| `routing_mark` | number\|string | 未设置 | 支持 | `SO_MARK`, Linux only. |
| `reuse_addr` | bool | `false` | 支持 | `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on UDP sockets. |
| `netns` | string | — | 报错：Linux network namespaces: sockets would leave another way | Not implemented yet. |
| `connect_timeout` | duration | 未设置 | 支持 | How long a TCP connect to one address may take; 5s when unset. |
| `tcp_fast_open` | bool | `false` | 支持 | TCP Fast Open: the first data written goes with the SYN. Its addresses are then tried one by one, not raced. |
| `tcp_multi_path` | bool | — | 警告：Socket tuning: connections go the same way without it | Not implemented yet. |
| `disable_tcp_keep_alive` | bool | `false` | 支持 | No TCP keepalive at all. |
| `tcp_keep_alive` | duration | 未设置 | 支持 | How long a TCP connection is idle before keepalive probes it; 5m when unset. |
| `tcp_keep_alive_interval` | duration | 未设置 | 支持 | Between keepalive probes; 75s when unset. |
| `udp_fragment` | bool | 未设置 | 支持 | Whether UDP datagrams may be fragmented on the way; unset, as the place says, see `udp_fragment_default`. |
| `domain_resolver` | string\|object → [对象](/sail/zh/reference/shared/#domain-resolver-default-domain-resolver) | 未设置 | 支持 | The DNS server that resolves the names dialled. |
| `network_strategy` | string, 取值 `default`, `fallback`, `hybrid` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | Which of the host's interfaces a connection goes out of, and how they race; `default` where only types are given. Only where the host lists its interfaces (`NetworkState::interfaces`). |
| `network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types of interface the strategy goes out of first. |
| `fallback_network_type` | listable-string, 取值 `cellular`, `ethernet`, `other`, `wifi` | — | 报错：Choosing among the host's networks (Wi-Fi, cellular) here: it would go out as the route's defaults say | The types it falls back to, with `fallback`. |
| `fallback_delay` | duration | 未设置 | 支持 | How long the addresses of one family are tried before those of the other are raced against them (Happy Eyeballs), and the first interfaces before the fallback ones; 300ms when unset. |
| `domain_strategy` | string | 未设置 | 支持 (sing-box 已弃用) | sing-box's deprecated field for the families names resolve to, which a resolver's own `strategy` goes before. |
| `skip_default_domain_resolver` | bool | `false` | sail 扩展 | A sail extension: without a `domain_resolver` of its own, the names dialled resolve as the DNS rules say, not as `route.default_domain_resolver` does; as Mihomo's DIRECT resolves apart from the proxies' servers. |

<a id="endpoints-wireguard-peers"></a>

### `endpoints[wireguard].peers[]`

Rust 定义：[`PeerOptions`](https://github.com/peakpassvpn/sail/blob/master/sail/src/protocol/wireguard/endpoint/options.rs) · 构建条件：`feature = "wireguard"`

| 字段 | 类型 | 默认 | 状态 | 说明 |
| --- | --- | --- | --- | --- |
| `address` | string | 未设置 | 支持 | Where the peer is: an address or a domain. Without it, it is learnt from the peer's handshake, as a server's peers are. |
| `port` | number | 未设置 | 支持 | — |
| `public_key` | string | 必填 | 支持 | — |
| `pre_shared_key` | string | 未设置 | 支持 | — |
| `allowed_ips` | listable-string | 必填 | 支持 | — |
| `persistent_keepalive_interval` | number | 未设置 | 支持 | Seconds; 0 or unset is off. |
| `reserved` | string\|array | 未设置 | 支持 | Three bytes, or their base64: Cloudflare WARP's client identifier. |

<a id="endpoints-missing"></a>

## sail 未实现的类型：`endpoints`

| 类型 | 状态 | 字段数 |
| --- | --- | --: |
| `endpoints[openconnect]` | 报错：A protocol sail does not implement | 114 |
| `endpoints[openvpn-client]` | 报错：A protocol sail does not implement | 117 |
| `endpoints[openvpn-server]` | 报错：A protocol sail does not implement | 97 |
| `endpoints[tailscale]` | 报错：A protocol sail does not implement | 54 |

