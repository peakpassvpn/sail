<h1 align="center">Sail</h1>

<p align="center">
<img src="https://github.com/peakpassvpn/sail/actions/workflows/ci.yml/badge.svg">
</p>

<p align="center">
用 Rust 写的代理平台：客户端、服务端和中转共用一个内核。
</p>

<p align="center">
<a href="README.md">English</a> · 简体中文 · <a href="https://peakpassvpn.github.io/sail/zh/">文档</a>
</p>

Sail 可以作为命令行客户端或服务端运行，可以通过 C 接口嵌进 App，也可以跑在路由器上。它的原生配置格式是 sing-box JSON，Clash/Mihomo 的 YAML 和 Surge 配置也能直接读取，不用转换。行为以 sing-box 1.14 和 Mihomo 为准；有意与它们不同的地方，文档里都有说明。

Sail 最初是 eycorsican 的 [leaf](https://github.com/eycorsican/leaf) 的分支，现在独立开发，不再跟随上游：配置、FFI、TCP/IP 协议栈和 TLS 实现都已重写。

> **状态：** 仍在积极开发中，还没有稳定版本，请从源码编译。

## 功能

- **协议**：SOCKS、HTTP、Mixed（仅入站）、Shadowsocks（AEAD 和 2022）、Trojan、VMess、VLESS（Vision、XUDP）、Hysteria2、TUIC、AnyTLS、ShadowTLS v3、MPTP（多路径冗余），以及作为 endpoint 的 WireGuard。大多数协议入站和出站都支持，详见[协议页](https://peakpassvpn.github.io/sail/zh/protocols/)。
- **传输层**：TLS、REALITY、WebSocket、HTTPUpgrade、gRPC、QUIC、多路复用（smux、yamux、h2mux）和 UDP over TCP。
- **TLS**：只用 BoringSSL。出站发送真实浏览器的 ClientHello（默认 Chrome，另有 Firefox、Safari、iOS 和 Android 指纹），支持 ECH 和证书锁定。
- **路由**：sing-box 的规则与规则动作、逻辑规则、源码和二进制规则集、协议嗅探、带独立规则的结构化 DNS，以及 Fake IP。
- **策略组**：手动选择、URL 测速、故障转移、负载均衡、智能分组和按网络分组，以及带过滤的订阅（provider）。
- **透明代理**：Linux、macOS、Windows、iOS 和 Android 上的 TUN，使用 Sail 自己的用户态 TCP/IP 协议栈，可自动配置路由；Linux 上另有 redirect 和 TPROXY。
- **网络变化**：跟随网卡和网络的变化，只关闭受影响的连接；每个出站可以指定或竞速使用多块网卡（`network_strategy`）。
- **服务端**：一个入站可以有多个用户，按用户统计流量，支持连接数上限、流量配额、到期时间和限速；提供 systemd 打包。
- **控制接口**：Clash API（现有面板可以直接使用），以及供 App 使用的 C 接口和 Swift、Kotlin 封装。

Sail 对每种配置格式支持哪些字段，完整的实测清单见[兼容性表](https://peakpassvpn.github.io/sail/zh/reference/compatibility/)。

## 快速开始

编译需要 Rust、CMake 和 C/C++ 编译器，因为 BoringSSL 要从源码编译。

```sh
cargo build -p sail-cli --release
```

把下面的配置保存为 `config.json`：

```json
{
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
```

先检查配置，再运行：

```sh
./target/release/sail -c config.json -T
./target/release/sail -c config.json
```

Clash/Mihomo 或 Surge 的配置同样用 `-c` 传入，按文件扩展名区分格式：`.json` 是 sing-box，`.yaml` 或 `.yml` 是 Clash，`.conf` 是 Surge。接下来可以看[快速上手](https://peakpassvpn.github.io/sail/zh/getting-started/)。

## 文档

- [文档站](https://peakpassvpn.github.io/sail/zh/)：快速上手、配置、协议、路由、命令行、平台集成，以及逐字段的配置参考。
- [与 sing-box、Clash、Surge 的兼容性](docs/compat/zh/)
- 面向 App 的 [FFI 接口说明](docs/ffi.md)（英文）
- [路线图](docs/roadmap.md)

## 许可证

采用 [Apache License 2.0](LICENSE) 许可。来自 leaf 的代码保留原有版权。第三方许可证见 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。
