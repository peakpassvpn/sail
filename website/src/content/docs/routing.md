---
title: Routing
description: Build ordered routing rules with domain, IP, port, inbound, process and user conditions.
---

Sail evaluates route rules from top to bottom. `route` and `reject` stop evaluation. `sniff` and `resolve` enrich the connection, then matching continues with the next rule.

## Matching model

A rule can combine several condition families. Values inside one field are alternatives; different condition families must all match.

For example, this rule matches TCP connections from `local-socks` whose destination is either `example.com` or one of its subdomains:

```json
{
  "domain_suffix": ["example.com"],
  "network": ["tcp"],
  "inbound": ["local-socks"],
  "action": "route",
  "outbound": "secure"
}
```

Destination conditions—domain fields, GeoSite, IP CIDR, GeoIP and external sets—are alternatives to each other. They are still combined with every non-destination condition on the rule.

## Conditions

| Field | Example | Meaning |
| --- | --- | --- |
| `domain` | `api.example.com` | Exact domain |
| `domain_suffix` | `example.com` | Domain and its subdomains |
| `domain_keyword` | `cdn` | Domain containing a string |
| `ip_cidr` | `10.0.0.0/8` | Destination network |
| `geoip` | `private`, `cn` | Country or group from `geo.mmdb` |
| `geosite` | `category-ads-all` | Site group from `site.dat` |
| `external` | `site:custom.dat:work` | Group from another data file |
| `port_range` | `443`, `1000-2000` | Destination port or range |
| `network` | `tcp`, `udp` | Transport protocol |
| `inbound` | `tun-in` | Source inbound tag |
| `process_name` | `curl` | Originating process when available |
| `auth_user` | `alice` | User authenticated by the inbound |

GeoIP and GeoSite files are read from the data directory. Set it with `-D` or `--data-dir` when the files do not live beside the executable.

## Route, reject and final

```json
{
  "route": {
    "rules": [
      {
        "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "domain_suffix": ["ads.example"],
        "action": "reject"
      }
    ],
    "final": "secure"
  }
}
```

Use `final` for the catch-all path. A route or reject rule without conditions is rejected during validation because it would hide every later rule.

## Sniff a domain before routing

When an application connects to an IP address, Sail can inspect the beginning of a TCP stream for a TLS SNI or HTTP Host value:

```json
{
  "route": {
    "rules": [
      {
        "network": ["tcp"],
        "action": "sniff",
        "sniffer": ["tls", "http"],
        "timeout": "300ms",
        "override_destination": false
      },
      {
        "domain_suffix": ["example.com"],
        "action": "route",
        "outbound": "secure"
      }
    ],
    "final": "direct"
  }
}
```

Set `override_destination` only when Sail should connect to the sniffed domain instead of the original address. Sniffing learns metadata; it does not decrypt TLS.

## Resolve before IP matching

A `resolve` action resolves a domain so later IP, CIDR or GeoIP rules can evaluate its addresses:

```json
{
  "domain_suffix": ["example.net"],
  "action": "resolve"
}
```

Place this before the IP-based rules that need the result. DNS strategy and cache behavior come from the top-level [`dns`](/sail/configuration/#dns) section.

## TUN loop prevention

A TUN inbound with `auto_route` takes the system's traffic, and Sail's own outbound sockets would go back into it. Sail binds them to the physical interface: the one the destination's network is on, or the default one. It follows that interface as the network changes, and resets the TUN's connections when it moves. With `auto_route`, this is on even without `route.auto_detect_interface`; set `route.default_interface` instead when the egress interface must be fixed.

On Linux, `auto_route` never touches the main routing table. The TUN's routes live in table 2022 (`iproute2_table_index`), and ip rules from priority 9000 (`iproute2_rule_index`) send traffic there. The kernel removes the routes with the device, and the next start removes rules left by a crash. `route_address`, `route_exclude_address`, their rule-set forms, `include_interface`/`exclude_interface`, `include_uid`/`exclude_uid` and `strict_route` select what is taken, as in sing-box. With `route_address` or `route_exclude_address`, the listed prefixes win over the LAN's own routes, so exclude the LAN explicitly.

On macOS, `auto_route` adds routes through the utun that are more specific than the default route: 1.0.0.0/8, 2.0.0.0/7 … 128.0.0.0/1, and the same halves of IPv6. With `route_address`, it adds those prefixes instead. `route_exclude_address` and the rule-set forms carve holes in these routes. The default route itself is never changed, and the routes disappear with the utun. `strict_route`, the interface lists and the uid lists do nothing on macOS, as in sing-box.

## Bypass in the kernel (Linux `auto_redirect`)

With `auto_redirect`, a Linux TUN inbound leaves the main routing table alone. nftables sends the system's TCP to a local listener, and a mark sends UDP and ICMP into the TUN. Sail's own sockets carry the output mark and are never taken, so `auto_detect_interface` is not needed:

```json
{
  "inbounds": [
    {
      "type": "tun",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "auto_route": true,
      "auto_redirect": true
    }
  ]
}
```

The first packet of each connection is judged through NFQUEUE before the connection is redirected. A `bypass` rule that matches it lets the kernel carry the connection past Sail. A `reject` rule has the kernel reset or drop the connection:

```json
{
  "ip_cidr": ["192.0.2.0/24"],
  "action": "bypass"
}
```

Only what the first packet shows can match: addresses, ports and the network. A rule that needs sniffing ends the judgement, and the connection is redirected as usual. A `bypass` rule with an `outbound` routes to that outbound when the connection reaches Sail. Without auto_redirect, a `bypass` rule with no outbound is skipped.

`route_address_set` and `route_exclude_address_set` take only the destinations of rule-sets. They are refreshed when a rule-set is downloaded again. On OpenWrt, Sail also adds an fw4 drop-in that accepts the TUN's traffic.
