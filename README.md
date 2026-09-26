<h1 align="center">Sail</h1>

<p align="center">
<img src="https://github.com/peakpassvpn/sail/actions/workflows/release.yml/badge.svg">
<img src="https://github.com/peakpassvpn/sail/actions/workflows/ci.yml/badge.svg">
</p>

<p align="center">
A proxy platform in Rust: one core for clients, servers and relays.
</p>

Sail started as a fork of [leaf](https://github.com/eycorsican/leaf) by eycorsican and is now maintained on its own. It no longer tracks upstream: the config format, the FFI and the TLS stack (BoringSSL only, browser ClientHellos) have diverged.

## Supported Protocols

### Proxy Protocols

| Protocol | Inbound | Outbound |
|---|---|---|
| HTTP | ✅ | ❌ |
| SOCKS5 | ✅ | ✅ |
| Shadowsocks | ✅ | ✅ |
| Trojan | ✅ | ✅ |
| VMess | ❌ | ✅ |
| Vless | ❌ | ✅ |

### Transports & Security

| Transport | Inbound | Outbound | Notes |
|---|---|---|---|
| WebSocket | ✅ | ✅ | |
| TLS | ✅ | ✅ | BoringSSL; the outbound sends a browser's ClientHello (`tls.utls`: chrome by default, firefox, safari) |
| QUIC | ✅ | ✅ | |
| AMux | ✅ | ✅ | Multiplexing from leaf; interoperates with leaf |
| Obfs | ❌ | ✅ | Simple obfuscation |
| Reality | ❌ | ✅ | Xray Reality, with a browser's ClientHello and X25519MLKEM768 |
| MPTP | ✅ | ✅ | Multi-path Transport Protocol (Aggregation) ([Architecture](docs/mptp_architecture.md), [Usage](docs/mptp_usage.md)) |

### Traffic Control

| Feature | Inbound | Outbound | Notes |
|---|---|---|---|
| Chain | ✅ | ✅ | Proxy chaining |
| Selector | ❌ | ✅ | Manual choice, kept across restarts |
| URLTest | ❌ | ✅ | Fastest member by URL test |
| Fallback | ❌ | ✅ | First healthy member, in order |
| Load balance | ❌ | ✅ | Consistent hashing, round-robin, sticky sessions |

### Transparent Proxying

| Mechanism | Inbound | Outbound | Notes |
|---|---|---|---|
| TUN | ✅ | ❌ | Linux, macOS, Windows, iOS, Android; lwip, smoltcp |
| NF | ✅ | ❌ | Windows, [NetFilter SDK](https://netfiltersdk.com/) |
| TPROXY | ❌ | ❌ | Linux; Coming soon |

## Building

TLS is BoringSSL, built from source: the build needs CMake and a C/C++ compiler (clang or gcc).

```sh
cargo build -p sail-cli --release
./target/release/sail --help
```

## License

Licensed under the [Apache License 2.0](LICENSE). Code from leaf keeps its original copyright.
