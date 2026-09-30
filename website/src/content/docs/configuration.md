---
title: Configuration
description: Understand Sail's JSON model, defaults, validation and reusable protocol blocks.
---

Sail accepts JSON and its legacy section-based `.conf` format. New deployments should prefer JSON: it maps directly to the typed configuration model, rejects unknown top-level fields and makes nested transport settings explicit.

Sail's format has diverged from leaf. Treat leaf and Surge-style examples as migration input, not as interchangeable Sail configuration.

## Top-level model

For individual fields, see the generated reference: [top level and common](/sail/reference/common/), [DNS](/sail/reference/dns/), [inbounds](/sail/reference/inbounds/), [outbounds and groups](/sail/reference/outbounds/), [endpoints](/sail/reference/endpoints/), [route](/sail/reference/route/) and [shared objects](/sail/reference/shared/), with each field's status against sing-box; the Clash and Surge support tables are under [compatibility](/sail/reference/compatibility/).

| Field | Purpose | Default |
| --- | --- | --- |
| `log` | Log level, format and optional file output | `info`, full format, console |
| `dns` | Resolvers, static hosts, strategy and cache behavior | `1.1.1.1`, IPv4 only |
| `inbounds` | Listeners or packet sources that accept traffic | Empty |
| `outbounds` | Direct, proxy, group or tunnel destinations | Empty |
| `route` | Ordered rules and the final outbound | First outbound |
| `api` | Optional control API listener | Disabled |

Every inbound and outbound has a `type` and may have a `tag`. When `tag` is omitted it defaults to the protocol type. Explicit tags are recommended once a configuration has more than one item.

## Inbound fields

These fields are shared by network inbounds:

```json
{
  "type": "socks",
  "tag": "lan-socks",
  "listen": "127.0.0.1",
  "listen_port": 1080,
  "udp_timeout": "30s"
}
```

`listen` defaults to `127.0.0.1`. An inbound without `listen_port` does not open a listener and is only useful when composed by another inbound. Protocol-specific fields, such as SOCKS users or Shadowsocks credentials, live beside the shared fields.

## Outbound fields and blocks

An outbound starts with a protocol and its connection details:

```json
{
  "type": "trojan",
  "tag": "edge",
  "server": "edge.example.com",
  "server_port": 443,
  "password": "replace-me",
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com"
  }
}
```

Stream proxy protocols can use shared blocks around the protocol itself:

| Block | What it controls |
| --- | --- |
| `tls` | TLS, certificates, ALPN, ECH, REALITY and browser ClientHello |
| `transport` | WebSocket, HTTP Upgrade or gRPC framing |
| `multiplex` | Multiple logical streams over a shared connection |
| `detour` | Dial this outbound's server through another outbound |
| Dial fields | Interface, local address, Linux mark and connect timeout |

The supported blocks depend on the protocol. QUIC-native protocols such as TUIC and Hysteria2 own their TLS configuration and do not accept every stream transport block.

### Dial fields

```json
{
  "type": "socks",
  "tag": "upstream",
  "server": "192.0.2.10",
  "server_port": 1080,
  "bind_interface": "en0",
  "connect_timeout": "5s"
}
```

Available shared dial fields are `bind_interface`, `inet4_bind_address`, `inet6_bind_address`, `routing_mark` on Linux, and `connect_timeout`.

## DNS

```json
{
  "dns": {
    "servers": ["1.1.1.1", "8.8.8.8"],
    "hosts": {
      "internal.example": ["10.0.0.8"]
    },
    "strategy": "prefer_ipv4",
    "cache_capacity": 512,
    "timeout": "4s",
    "reverse_mapping": true
  }
}
```

`strategy` is one of `ipv4_only`, `ipv6_only`, `prefer_ipv4` or `prefer_ipv6`. Reverse mapping remembers the domain associated with DNS answers so later connections to those addresses can still match domain rules.

### Names on the local link (mDNS)

An `mdns` server (`{ "type": "mdns", "tag": "lan", "interface": ["en0"] }`, every multicast interface when `interface` is empty) resolves `.local` names and the link-local reverse zones by multicast DNS. Off Apple's systems a `local` server does the same for those names on its own; on Apple's the system resolver does. A DNS rule's `preferred_by` names servers and matches the names they answer for themselves: a `hosts` server its entries, `local` its hosts file and the mDNS names, `mdns` the mDNS names.

Unlike sing-box, sail's queries ask for a unicast reply (the QU bit of RFC 6762): Windows answers no other query, so sing-box cannot resolve a Windows machine's `.local` name, and sail can. sail also returns as soon as one interface answers instead of waiting out the whole second.

## Logging and control API

```json
{
  "log": {
    "level": "debug",
    "format": "compact",
    "output": "sail.log"
  },
  "api": {
    "listen": "127.0.0.1:9090"
  }
}
```

Log levels are `trace`, `debug`, `info`, `warn`, `error` and `none`. Leave `output` unset to log to the console. The API is not served unless `api.listen` is set; keep it on a trusted interface unless a host application provides its own access controls.

## Validation rules worth knowing

- Tags referenced by `route.final`, route rules, groups and detours must exist.
- A terminating `route` or `reject` rule needs at least one condition; use `route.final` for the catch-all path.
- `sniffer`, `timeout` and `override_destination` only belong to a `sniff` rule.
- `route.auto_detect_interface` and `route.default_interface` are mutually exclusive.
- An automatic TUN route needs one of those interface settings to keep Sail's own outbound traffic out of the tunnel.
- Durations such as DNS and UDP timeouts must be greater than zero.

Run `sail -c config.json -T` after every change. See [CLI reference](/sail/cli/) for connectivity testing and runtime settings.

## Legacy `.conf` files

The parser still supports sections such as `[General]`, `[Proxy]`, `[Proxy Group]`, `[Rule]` and `[Host]`. It translates them into the JSON model before validation. Keep existing files if they are already deployed, but use JSON for new fields and new documentation because it exposes the final model without translation rules.
