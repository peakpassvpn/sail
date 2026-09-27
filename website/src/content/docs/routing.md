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

When a TUN inbound installs the default route, Sail's own outbound sockets can otherwise re-enter that TUN. Prefer automatic detection:

```json
{
  "route": {
    "auto_detect_interface": true,
    "final": "secure"
  }
}
```

Use `default_interface` instead when the egress interface must be fixed. Do not set both.
