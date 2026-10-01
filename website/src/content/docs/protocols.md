---
title: Protocols
description: Protocol, transport, security and traffic-control support in the default Sail build.
---

Sail separates endpoint protocols from the layers that carry them. A VLESS, Trojan or VMess outbound can, for example, be wrapped in TLS and WebSocket without creating a separate protocol type for every combination.

The tables below describe the default build. Protocols are feature-gated, so a custom build may contain a smaller set.

## Clash, sing-box and Surge ecosystems

Sail reads all three formats directly, through one loader, into one runtime. sing-box's JSON is Sail's own format; Clash / Mihomo YAML and Surge profiles are read as they are, not converted by hand.

| Format | How it is recognised | Read as |
| --- | --- | --- |
| sing-box JSON (1.14) | A `.json` file, or text that is a JSON object | Native, with Sail's extensions |
| Clash / Mihomo YAML | A `.yaml` or `.yml` file, or any other text | Lowered into the same model |
| Surge profile | A `.conf` file, or text with a `[General]`, `[Proxy]` or `[Rule]` section | Lowered into the same model; included files are read too |

A field Sail does not implement is never guessed at. One whose absence changes no routing or security is dropped with a warning; one that would change where or how traffic goes is an error. Surge settings that mean nothing where Sail runs, such as its interface options, are passed over silently. The per-field support tables for each format are on the [compatibility](/sail/reference/compatibility/) page. See [Configuration](/sail/configuration/) for the native model.

## Proxy protocols

| Protocol | Inbound | Outbound | Notes |
| --- | :---: | :---: | --- |
| HTTP | Yes | Yes | Basic authentication supported |
| SOCKS | Yes | Yes | Inbound: SOCKS4, 4a and 5, TCP and UDP. Outbound: version 5 only; 4 and 4a are errors |
| Mixed | Yes | No | HTTP and SOCKS on one listener |
| Shadowsocks | Yes | Yes | Classic AEAD and 2022 methods; outbound `obfs-local` plugin |
| Trojan | Yes | Yes | TCP and UDP relay |
| VMess | Yes | Yes | AEAD only (`alter_id` 0); XUDP available |
| VLESS | Yes | Yes | Plain UDP or XUDP; Vision flow |
| AnyTLS | Yes | Yes | Shared authenticated TLS sessions |
| ShadowTLS | Yes | Yes | Version 3 only; carries another protocol, see below |
| Hysteria2 | Yes | Yes | QUIC, UDP, Salamander obfuscation, port hopping on the outbound, masquerade on the inbound |
| TUIC | Yes | Yes | QUIC streams and datagrams |
| MPTP | Yes | Yes | Multiple paths as one logical tunnel; a Sail protocol, see [MPTP](/sail/mptp/) |
| WireGuard | Endpoint | Endpoint | sing-box's `endpoints` entry: inbound and outbound under one tag, over Sail's userspace TCP/IP stack |

Other outbounds are `direct`, `block`, `pass` (Mihomo's PASS, see [Routing](/sail/routing/#pass-a-rule-on-pass)) and `redirect`, which sends every connection to one fixed address. Other inbounds include `direct`, `tun` and the transparent ones below.

sing-box's `hysteria`, `naive`, `snell`, `ssh`, `tor`, `cloudflared` and `tailscale` types, and the OpenVPN and OpenConnect endpoints, are configuration errors.

### UDP over TCP

Shadowsocks and SOCKS outbounds can carry UDP inside their TCP stream with `udp_over_tcp`, as sing-box and Mihomo do: version 2 by default, or version 1. AnyTLS always carries UDP this way. Every inbound serves a stream to either version's magic address as UDP.

### ShadowTLS

ShadowTLS v3 relays a real TLS handshake with a site the server imitates, and carries another protocol, usually Shadowsocks, after it. As in sing-box, the protocol's outbound names the ShadowTLS outbound as its `detour`, and may leave out `server` and `server_port`, which ShadowTLS dials in its place (a `server` given is not dialled); and the ShadowTLS inbound hands its connections to the inbound its `detour` names. Versions 1 and 2 are configuration errors.

```json
{
  "outbounds": [
    { "type": "shadowsocks", "tag": "ss",
      "method": "2022-blake3-aes-128-gcm", "password": "<psk>", "detour": "shadowtls" },
    { "type": "shadowtls", "tag": "shadowtls", "server": "203.0.113.1", "server_port": 443,
      "version": 3, "password": "<password>",
      "tls": { "enabled": true, "server_name": "www.example.com" } }
  ]
}
```

```json
{
  "inbounds": [
    { "type": "shadowtls", "listen": "::", "listen_port": 443, "version": 3,
      "users": [{ "name": "alice", "password": "<password>" }],
      "handshake": { "server": "www.example.com", "server_port": 443 },
      "strict_mode": true, "detour": "ss-in" },
    { "type": "shadowsocks", "tag": "ss-in",
      "method": "2022-blake3-aes-128-gcm", "password": "<psk>" }
  ]
}
```

The ClientHello carries a browser fingerprint (`tls.utls`, Chrome's by default) and the client's authentication in its session ID. The handshake server is dialled with its own dial fields over the instance's defaults; its `detour` is not implemented yet and is a configuration error. Clash's `ss` proxies with `plugin: shadow-tls` and Surge's `shadow-tls-password`, `shadow-tls-sni` and `shadow-tls-version` become such a pair, the ShadowTLS outbound named `<name> (shadow-tls)`.

### Streams on Hysteria2 and TUIC servers

sing-box's Hysteria2 and TUIC servers let a client open as many streams at once on its QUIC connection as it likes (1<<60). sail's QUIC library, quinn, sets aside room for every stream it allows, so a sail server lets a client hold 100 streams of each kind at once until it authenticates, then twice as many each time three quarters are open, up to 65536. A client multiplexing many connections onto one QUIC connection gets them as it opens them; one past the limit waits for a stream to close rather than failing. `user_limits.max_connections` bounds a user's streams. Making quinn allocate a stream's room only when the stream opens, as quic-go does, would remove the limit; sail does not do that yet.

### Hysteria2 masquerade

A Hysteria2 inbound serves anyone without a password, such as an active prober, what `masquerade` names: an `http://` or `https://` site behind it, or a fixed response. As in sing-box, the request goes to the site with the site's own name as SNI and Host (the client's Host with `rewrite_host: false` in the object form), over HTTP/2 where the site offers it and HTTP/1.1 otherwise, without the hop-by-hop and forwarding headers. Unlike sing-box, an `https://` site is trusted by the instance's certificate store (the system's unless `certificate` is set) and dialled with the instance's dial defaults.

Known gaps: request and response bodies are buffered (up to 1 MB and 8 MB) rather than streamed, `file://` and `type: file` sites are not supported, and chunked responses are not passed through as chunked.

## Transports and security

| Layer | Inbound | Outbound | Purpose |
| --- | :---: | :---: | --- |
| TLS | Yes | Yes | BoringSSL-based stream security; browser ClientHellos with `tls.utls` |
| REALITY | Yes | Yes | REALITY handshake over the TLS layer |
| ECH | No | Yes | Encrypted ClientHello; TLS 1.3 only |
| WebSocket | Yes | Yes | `transport` type `ws`, with early data |
| HTTP Upgrade | Yes | Yes | `transport` type `httpupgrade` |
| gRPC | Yes | Yes | `transport` type `grpc` |
| QUIC | Yes | Yes | `transport` type `quic` |
| sing-mux | Yes | Yes | `multiplex` with smux, yamux or h2mux (the default); padding and TCP Brutal |
| AMux | Yes | Yes | `multiplex` with `protocol: amux`, Sail's own; to be removed |
| Obfs | No | Yes | Shadowsocks `obfs-local` plugin: HTTP or TLS-shaped obfuscation |

sing-box's HTTP/2 transport (`transport` type `http`) is refused by design: use `grpc`, `ws` or `httpupgrade`. With `tls.ech`, a `min_version` or `max_version` below TLS 1.3 is a configuration error, because sing-box fails every such handshake. Browser fingerprints are `chrome` (the default), `firefox`, `edge`, `safari`, `ios`, `android` and `random`; see [TLS and fingerprints](/sail/tls-fingerprints/).

Not every endpoint accepts every layer. Sail validates shared fields against the protocol factory, so unsupported combinations fail with the tagged inbound or outbound in the error.

## Traffic-control outbounds

| Type | Selection behavior |
| --- | --- |
| `selector` | Manual member selection; kept across restarts with `experimental.cache_file` |
| `urltest` | Periodically selects the fastest member, switching only past `tolerance` |
| `fallback` | Uses the first member, in declared order, that passed its last URL test |
| `load-balance` | Consistent hashing, round-robin or sticky sessions |
| `smart` | Scores members by how real connections through them did, and keeps a site on one |
| `network` | Picks a member by the network the host is on (Wi-Fi name, network type and so on) |
| `tryall` | Races its members, starting each `delay_base` milliseconds after the last, and keeps the first that connects |

`selector` and `urltest` are sing-box's; the others are Sail extensions. These are regular outbounds with tags. Route rules can target them without knowing which concrete member ultimately carries the connection. Groups can also take members from [outbound providers](/sail/routing/#groups-and-providers).

To dial one outbound's server through another, set `detour` on it. There is no separate chain type; Clash's `relay` group is not implemented.

## Transparent and virtual networking

| Mechanism | Platform | Role |
| --- | --- | --- |
| TUN | Linux, macOS, Windows, iOS, Android | User-space IP data plane through `sail-netstack` |
| Redirect | Linux | Recover destinations redirected by iptables or nftables `REDIRECT` |
| TPROXY | Linux | Transparent listener with original destination |
| NF | Windows | NetFilter SDK integration; not in the default build (`inbound-nf` feature) |

TUN deployments need an egress interface policy to prevent routing loops. See [TUN loop prevention](/sail/routing/#tun-loop-prevention).

## Shared protocol fields

Protocol-specific options sit beside reusable blocks:

```json
{
  "type": "vless",
  "tag": "secure",
  "server": "edge.example.com",
  "server_port": 443,
  "uuid": "00000000-0000-0000-0000-000000000000",
  "flow": "xtls-rprx-vision",
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com",
    "utls": {
      "fingerprint": "chrome"
    }
  }
}
```

For the shape and validation of those shared blocks, see [Configuration](/sail/configuration/#outbound-fields-and-blocks). For browser ClientHello behavior, see [TLS and fingerprints](/sail/tls-fingerprints/).
