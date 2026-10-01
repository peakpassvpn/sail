---
title: Protocols
description: Protocol, transport, security and traffic-control support in the default Sail build.
---

Sail separates endpoint protocols from the layers that carry them. A VLESS, Trojan or VMess outbound can, for example, be wrapped in TLS and WebSocket without creating a separate protocol type for every combination.

The tables below describe the default build. Protocols are feature-gated, so a custom build may contain a smaller set.

## Clash, sing-box and Surge ecosystems

Sail's direction is one Rust runtime for the protocols, routing rules and policy groups familiar across mainstream proxy ecosystems. Compatibility currently means aligned concepts and a practical migration path—not that every third-party configuration file can be loaded unchanged.

| Ecosystem | Current relationship | Recommended path |
| --- | --- | --- |
| sing-box | Sail's JSON model uses familiar protocol names and nested transport concepts, but fields and coverage are not identical | Convert to Sail JSON, then validate with `sail -T` |
| Surge / leaf | The legacy parser accepts familiar `.conf` sections such as `[Proxy]`, `[Proxy Group]` and `[Rule]` | Use it as a migration input, then move new work to JSON |
| Clash / Mihomo | Protocol, policy-group and rule concepts overlap; arbitrary Clash YAML is not loaded natively today | Generate Sail JSON through a converter or host integration layer |

This boundary lets Sail unify runtime behavior without silently misinterpreting fields that share a name but differ in semantics. See [Configuration](/sail/configuration/) for the native model.

## Proxy protocols

| Protocol | Inbound | Outbound | Notes |
| --- | :---: | :---: | --- |
| HTTP | Yes | Yes | Basic authentication supported |
| SOCKS5 | Yes | Yes | TCP and UDP; optional users on inbound |
| Mixed | Yes | No | HTTP and SOCKS on one listener |
| Shadowsocks | Yes | Yes | Classic AEAD and 2022 variants |
| Trojan | Yes | Yes | TCP and UDP relay |
| VMess | Yes | Yes | AEAD mode; XUDP available |
| VLESS | Yes | Yes | Plain UDP or XUDP; Vision flow |
| AnyTLS | Yes | Yes | Shared authenticated TLS sessions |
| ShadowTLS | Yes | Yes | Version 3 only; carries another protocol, see below |
| Hysteria2 | Yes | Yes | QUIC, UDP and optional port hopping |
| TUIC | Yes | Yes | QUIC streams and datagrams |
| MPTP | Yes | Yes | Multiple paths as one logical tunnel |

Internal endpoints also include `direct`, `drop` and redirect-style handlers used by routing and platform integrations.

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

The ClientHello carries a browser fingerprint (`tls.utls`, Chrome's by default) and the client's authentication in its session ID. The handshake server is dialled directly: its dial fields, and `detour`, are not implemented yet. Clash's `ss` proxies with `plugin: shadow-tls` and Surge's `shadow-tls-password`, `shadow-tls-sni` and `shadow-tls-version` become such a pair, the ShadowTLS outbound named `<name> (shadow-tls)`.

### Streams on Hysteria2 and TUIC servers

sing-box's Hysteria2 and TUIC servers let a client open as many streams at once on its QUIC connection as it likes (1<<60). sail's QUIC library, quinn, sets aside room for every stream it allows, so a sail server lets a client hold 100 streams of each kind at once until it authenticates, then twice as many each time three quarters are open, up to 65536. A client multiplexing many connections onto one QUIC connection gets them as it opens them; one past the limit waits for a stream to close rather than failing. `user_limits.max_connections` bounds a user's streams. Making quinn allocate a stream's room only when the stream opens, as quic-go does, would remove the limit; sail does not do that yet.

### Hysteria2 masquerade

A Hysteria2 inbound serves anyone without a password, such as an active prober, what `masquerade` names: an `http://` or `https://` site behind it, or a fixed response. As in sing-box, the request goes to the site with the site's own name as SNI and Host (the client's Host with `rewrite_host: false` in the object form), over HTTP/2 where the site offers it and HTTP/1.1 otherwise, without the hop-by-hop and forwarding headers. Unlike sing-box, an `https://` site is trusted by the instance's certificate store (the system's unless `certificate` is set) and dialled with the instance's dial defaults.

Known gaps: request and response bodies are buffered (up to 1 MB and 8 MB) rather than streamed, `file://` and `type: file` sites are not supported, and chunked responses are not passed through as chunked.

## Transports and security

| Layer | Inbound | Outbound | Purpose |
| --- | :---: | :---: | --- |
| TLS | Yes | Yes | BoringSSL-based stream security |
| REALITY | Yes | Yes | REALITY handshake over the TLS layer |
| WebSocket | Yes | Yes | HTTP Upgrade compatible framing |
| HTTP Upgrade | Yes | Yes | Explicit HTTP/1.1 upgrade transport |
| gRPC | Yes | Yes | HTTP/2 streaming transport |
| QUIC | Yes | Yes | Reliable streams over UDP |
| AMux | Yes | Yes | leaf-compatible multiplexing |
| sing-mux | Yes | Yes | smux, yamux and h2mux modes |
| Obfs | No | Yes | Simple HTTP or TLS-shaped obfuscation |

Not every endpoint accepts every layer. Sail validates shared fields against the protocol factory, so unsupported combinations fail with the tagged inbound or outbound in the error.

## Traffic-control outbounds

| Type | Selection behavior |
| --- | --- |
| Selector | Manual member selection; kept across restarts with `experimental.cache_file` |
| URLTest | Periodically selects the fastest healthy member |
| Fallback | Uses the first healthy member in declared order |
| TryAll | Attempts members until one succeeds |
| Load balance | Consistent hashing, round-robin or sticky behavior |
| Detour | Dials one outbound's server through another outbound |

These are regular outbounds with tags. Route rules can target them without knowing which concrete member ultimately carries the connection.

## Transparent and virtual networking

| Mechanism | Platform | Role |
| --- | --- | --- |
| TUN | Linux, macOS, Windows, iOS, Android | User-space IP data plane through `sail-netstack` |
| NF | Windows | NetFilter SDK integration |
| Redirect | Platform dependent | Recover transparently redirected destinations |
| TPROXY | Linux | Transparent listener with original destination |

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
