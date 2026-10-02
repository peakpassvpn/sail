---
title: Routing
description: Build ordered routing rules with domain, IP, port, inbound, process and user conditions.
---

Sail evaluates route rules from top to bottom. `route`, `reject` and `hijack-dns` stop evaluation. `sniff`, `resolve` and `route-options` enrich the connection, then matching continues with the next rule. A connection no rule stops goes to `route.final`.

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

As in sing-box, destination conditions—domain fields, GeoSite, IP CIDR, GeoIP and external sets—are alternatives to each other, as are the port conditions and the source address conditions. Each group is still combined with every other condition on the rule. `invert` negates the whole rule.

## Conditions

| Field | Example | Meaning |
| --- | --- | --- |
| `domain` | `api.example.com` | Exact domain |
| `domain_suffix` | `example.com` | Domain and its subdomains |
| `domain_keyword` | `cdn` | Domain containing a string |
| `domain_regex` | `^api\.` | Domain matching a regular expression |
| `ip_cidr` | `10.0.0.0/8` | Destination network |
| `ip_is_private` | `true` | Destination address is not public |
| `geoip` | `cn` | Country from `geo.mmdb` (Sail extension) |
| `geosite` | `category-ads-all` | Site group from `site.dat` (Sail extension) |
| `external` | `site:custom.dat:work` | Group from another data file (Sail extension) |
| `ip_asn` | `13335` | Autonomous system from `asn.mmdb` (Sail extension) |
| `rule_set` | `geosite-cn` | Any rule of the named rule-sets |
| `port`, `port_range` | `443`, `1000:2000` | Destination port, or an inclusive range; `:1024` and `8000:` are open ranges |
| `source_ip_cidr`, `source_port` | `192.168.0.0/16` | Where the connection comes from |
| `network` | `tcp`, `udp` | Transport protocol |
| `protocol` | `tls`, `quic` | Protocol found by a `sniff` rule |
| `inbound` | `tun-in` | Source inbound tag |
| `auth_user` | `alice` | User authenticated by the inbound |
| `process_name`, `process_path` | `curl` | Originating process when available |
| `package_name` | `com.example.app` | Android app, as the host reports it |
| `wifi_ssid`, `network_type` | `Home`, `cellular` | The network the host is on |
| `clash_mode` | `Global` | Current mode of the Clash API |

The [route reference](/sail/reference/route/) lists every condition. GeoIP, GeoSite and ASN files are read from the data directory. Set it with `-D` or `--data-dir` when the files do not live beside the executable.

## Rule actions

| Action | Effect |
| --- | --- |
| `route` (default) | Send the connection to `outbound` and stop |
| `reject` | Close the connection and stop; `method: drop` leaves it unanswered |
| `hijack-dns` | Answer the DNS queries the connection carries and stop |
| `route-options` | Set how the connection is carried, such as `override_address`, `udp_timeout` or `tls_fragment`, and continue |
| `sniff` | Read the protocol and domain from the first bytes, and continue |
| `resolve` | Resolve the domain so later rules can match its addresses, and continue |
| `bypass` | Let the kernel carry the connection past Sail under Linux `auto_redirect`; elsewhere route to its `outbound`, or skip the rule without one |
| `direct` | Accepted with a warning; it has no effect, as in sing-box 1.14.1 |

A `route` rule can carry the same options as `route-options`. sing-box's `evaluate`, `respond` and `predefined` route actions, and its `ssh`, `rdp` and `ntp` sniffers, are not implemented and are errors.

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

Use `final` for the catch-all path; without it, the first outbound takes what no rule matches. A route or reject rule without conditions is rejected during validation because it would hide every later rule.

## Logical rules

A rule with `"type": "logical"` combines other rules with `"mode": "and"` or `"or"`. The rules inside carry conditions only; the logical rule carries the action:

```json
{
  "type": "logical",
  "mode": "and",
  "rules": [
    { "network": ["udp"] },
    { "port": [443] }
  ],
  "action": "reject"
}
```

## Rule-sets

`route.rule_set` declares rule-sets that rules name in `rule_set`. A rule-set is `inline` (its `rules` in place), `local` (a `path`) or `remote` (a `url`, downloaded again every `update_interval`, one day by default, through `download_detour` or an `http_client`). The format is sing-box's `source` (JSON) or `binary` (`.srs`), taken from the file extension when `format` is unset.

As Sail extensions, a rule-set can also be a Clash rule-provider (`mrs`, `clash-yaml` or `clash-text`) or a Surge rule or domain set (`surge-text`), each with a `behavior` of `domain`, `ipcidr` or `classical`.

```json
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "geosite-cn",
        "url": "https://example.com/geosite-cn.srs"
      }
    ],
    "rules": [
      { "rule_set": ["geosite-cn"], "action": "route", "outbound": "direct" }
    ]
  }
}
```

## Pass a rule on (PASS)

A `pass` outbound, a Sail extension, is Mihomo's PASS: `{ "type": "pass", "tag": "PASS" }`. A rule that routes to it, or to a `selector`, `urltest`, `fallback` or `network` group whose current pick is PASS (followed down through nested groups), is skipped: its route options are not applied, and the next rules decide. Selecting PASS in a selector turns its rules off without editing them. When `final` comes to PASS through a group, the connection goes direct.

`final`, or the first outbound when `final` is not set, naming a pass outbound itself is a configuration error, as is PASS in a `load-balance` or `smart` group, even through a group nested in it. `urltest` and `fallback` never test PASS and count it as down, so they never pick it. Mihomo differs here: its groups can pick PASS before their first test, and fallback does when every member is down and PASS comes first. A connection that reaches PASS all the same (a selector switched to it after the connection was routed) fails with "routed to PASS".

## Sniff a domain before routing

When an application connects to an IP address, Sail can inspect the first bytes of a connection for its protocol and domain: a TLS or QUIC server name, or an HTTP Host. It also recognises DNS, STUN, BitTorrent and DTLS.

```json
{
  "route": {
    "rules": [
      {
        "action": "sniff",
        "sniffer": ["tls", "http", "quic"],
        "timeout": "300ms"
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

`sniffer` lists the protocols to look for; all of them when it is empty. `timeout` defaults to 300 ms. Sniffing learns metadata; it does not decrypt TLS.

Sail adds three fields. `override_destination` sets the option of the same name for the connection, described in the next section. `skip_rule_set` ignores sniffed domains that the named rule-sets match, as Mihomo's `skip-domain` does. `on_demand` arms the sniff instead of running it, so it runs only when a later rule needs its result.

## Dial a proxy by the domain (override_destination)

A TUN connection arrives with an IP address, and Sail often knows the domain behind it. `override_destination`, a Sail extension, sends that domain to the proxy server instead of the address, so the server resolves it itself. This helps when the local answer is poisoned, points to a far-away node, or is an address that only the local network can reach.

```json
{
  "inbound": ["tun"],
  "action": "route-options",
  "override_destination": true
}
```

- **Where it is set.** A `route` or `route-options` rule sets it, and so does a `sniff` rule's field of the same name. Rule conditions decide which connections it applies to. A later rule's value wins.
- **The rules still see the address.** The domain is used only when the connection is dialled, after routing. `ip_cidr`, `ip_is_private`, `ip_version` and rule-sets match the original address, so a rule that sends a LAN range direct still does.
- **Values.** `true` or `"proxy"` uses the domain only where the last hop dials a proxy server. This includes groups whose member is a proxy, and chains through a `detour`. A `direct` dial keeps the address. `"proxy_and_direct"` also gives the domain to a direct dial, which resolves it with its own `domain_resolver` and strategy. For example, a host with IPv6 enabled but no IPv6 route can dial IPv6 destinations it knows a name for over IPv4: `{"inbound": ["tun"], "ip_cidr": ["2000::/3"], "action": "route-options", "override_destination": "proxy_and_direct"}` with `"domain_resolver": {"server": "local", "strategy": "ipv4_only"}` on the direct outbound.
- **Where the domain comes from, in order.** First the sniffed domain (TLS or QUIC server name, HTTP Host). Otherwise the name Sail's own DNS answered with for that address, when [`dns.reverse_mapping`](/sail/configuration/#dns) is on, and only until the answer's TTL runs out. An IPv4-mapped IPv6 address is looked up as its IPv4 address. A sniffed "domain" that is an address, or an HTTP request without a Host, falls back to the mapping. With neither, the address is sent. When several names share an address, the latest answer wins. A destination that is already a domain is never changed.
- **UDP.** Datagrams go to the domain. Replies come back as if from the address the client sent to, or from the domain with `udp_disable_domain_unmapping`.
- **Logs and the connection list.** A debug line reads `dial <address> as <domain> (sniff)` or `(reverse mapping)`. If a dial by a reverse-mapped name fails, which may mean the mapping is stale, a debug line says so. The address is not retried. In the Clash API, `destinationIP` keeps the address, `host` shows the domain dialled, `sniffHost` the sniffed domain, and `dialDomainSource` is `sniff` or `reverse_mapping`.
- **With `resolve`.** When both apply, a proxy gets the domain, not the addresses `resolve` found. A direct dial still uses those addresses.

sing-box has no such option. Its sniff `override_destination` was deprecated and is now refused as an unknown field. Mihomo's sniffer `override-destination` works differently: it replaces the destination before the rules, so later IP rules resolve the sniffed domain. The Clash front-end keeps Mihomo's behaviour. It sets the sniff rule's `override_destination` to `"at_sniff"`, which is valid only on a `sniff` rule. The IP version that `ip_version` matches is still the original address's.

## Resolve before IP matching

A `resolve` action resolves a domain so later IP, CIDR or GeoIP rules can evaluate its addresses:

```json
{
  "domain_suffix": ["example.net"],
  "action": "resolve"
}
```

Place this before the IP-based rules that need the result. `server` and `strategy` override the DNS rules and `dns.strategy` for this lookup. As in sing-box, a domain that does not resolve fails the connection. Sail's `ignore_failure` lets matching continue with no addresses instead, and Sail's `on_demand` resolves only when a later rule needs the addresses. DNS strategy and cache behavior come from the top-level [`dns`](/sail/configuration/#dns) section.

What happens to the addresses afterwards differs between the two kinds of resolve, and it matters for privacy:

- A plain `resolve` action works as in sing-box: the addresses go to whatever outbound the connection takes. A proxy outbound sends its server the IP address, not the domain, so the local DNS decides where the connection goes and the proxy server never sees the name.
- An `on_demand` resolve, which Clash and Surge IP rules (`IP-CIDR`, `GEOIP` and the like, without `no-resolve`) turn into, works as in Mihomo: the addresses are only for matching and for a direct outbound. A proxy outbound still sends the domain, and the proxy server resolves it.
- With [`override_destination`](#dial-a-proxy-by-the-domain-override_destination) set as well, a proxy outbound sends the domain, not the addresses, after either kind.

## Choosing a network (network_strategy)

`network_strategy` chooses among the host's interfaces. It is a dial field of any outbound. On a `route` or `route-options` rule it applies when the connection goes out of a direct outbound.

- `default`: the default interface, or every interface of `network_type`.
- `hybrid`: every interface, or every one of `network_type`, at once.
- `fallback`: as `default`; then, after `fallback_delay` or when those fail, the interfaces of `fallback_network_type`, or all others.

Network types are `wifi`, `cellular`, `ethernet` and `other`. sing-box acts on these fields only in its Android and Apple clients. Sail also acts on them on Linux, macOS and Windows, from the interfaces it detects: a deliberate extension. There, interfaces of type `other`, such as other VPNs' tunnels and bridges, are candidates only when `network_type` or `fallback_network_type` names `other`. `route.default_network_strategy` sets the strategy for everything that sets none, and needs `route.auto_detect_interface`.

## Groups and providers

Group outbounds pick a member for each connection. sing-box's `selector` and `urltest` are joined by Sail's `fallback`, `load-balance`, `smart`, `network` and `tryall`; see [Protocols](/sail/protocols/#traffic-control-outbounds) for how each picks. Rules route to a group by its tag.

`outbound_providers`, a Sail extension, supplies members the way Mihomo's proxy-providers do. A provider is `remote` (a subscription URL), `local` (a file) or `inline`. A subscription holds Clash YAML with `proxies`, or share links. `filter`, `exclude_filter`, `exclude_type` and `override` shape what is taken.

```json
{
  "outbound_providers": [
    { "type": "remote", "tag": "sub", "url": "https://example.com/sub.yaml" }
  ],
  "outbounds": [
    { "type": "urltest", "tag": "auto", "providers": ["sub"] }
  ]
}
```

`selector`, `urltest`, `fallback`, `load-balance` and `smart` groups take `providers`, beside their own `outbounds`.

A `fallback` group switches on the first failed test and switches back on the first passing one. A member that flaps then sends traffic back and forth. `debounce`, a Sail extension, holds the switches back:

```json
{
  "type": "fallback",
  "tag": "auto",
  "outbounds": ["primary", "backup"],
  "interval": "10s",
  "debounce": { "fail_after": 1, "recover_after": 3, "min_dwell": "30s" }
}
```

- `fail_after`: failed rounds of tests in a row before the group leaves a member; 1.
- `recover_after`: passed rounds in a row before a member that was down is up again, and taken back if it comes first; 1.
- `min_dwell`: the least time on a member before the group goes back to an earlier one; 0s. The first round after it switches.

The defaults keep the behaviour without `debounce`. A connection that finds a member's server unreachable (refused, timed out or unreachable at dial) still has the group leave it at once, whatever `fail_after` and `min_dwell` say. The member then needs `recover_after` passed rounds before it is used again. Failed connections counted toward `max_failed_times` only bring the next round forward: they count toward neither. A member pinned by hand through the API is used while it is up or passed its last test, whatever the debounce. With `recover_after: 3` and `min_dwell: "30s"`, the group goes back to its first member at the first round at least 30 seconds after leaving it, once that member has passed three rounds in a row.

## TUN loop prevention

A TUN inbound with `auto_route` takes the system's traffic, and Sail's own outbound sockets would go back into it. Sail binds them to the physical interface: the one the destination's network is on, or the default one. It follows that interface as the network changes, and resets the TUN's connections when it moves. With `auto_route`, this is on even without `route.auto_detect_interface`; set `route.default_interface` instead when the egress interface must be fixed.

On Linux, `auto_route` never touches the main routing table. The TUN's routes live in table 2022 (`iproute2_table_index`), and ip rules from priority 9000 (`iproute2_rule_index`) send traffic there. The kernel removes the routes with the device, and the next start removes rules left by a crash. `route_address`, `route_exclude_address`, their rule-set forms, `include_interface`/`exclude_interface`, `include_uid`/`exclude_uid` and `strict_route` select what is taken, as in sing-box. With `route_address` or `route_exclude_address`, the listed prefixes win over the LAN's own routes, so exclude the LAN explicitly.

On macOS, `auto_route` adds routes through the utun that are more specific than the default route: 1.0.0.0/8, 2.0.0.0/7 … 128.0.0.0/1, and the same halves of IPv6. With `route_address`, it adds those prefixes instead. `route_exclude_address` and the rule-set forms carve holes in these routes. The default route itself is never changed, and the routes disappear with the utun. `strict_route`, the interface lists and the uid lists do nothing on macOS, as in sing-box.

On Windows, `auto_route` adds 0.0.0.0/0 and ::/0 through the wintun adapter at metric 0. They win over the default route by metric without replacing it. The adapter's DNS points at the address after the TUN's. `route_address`, `route_exclude_address` and their rule-set forms select the routes as on the other systems. `strict_route` adds firewall rules that keep DNS off every other interface.

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
