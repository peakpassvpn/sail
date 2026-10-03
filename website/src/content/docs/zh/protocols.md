---
title: 协议与兼容性
description: Sail 的代理协议、传输层、安全能力，以及 Clash、sing-box、Surge 配置生态兼容范围。
---

Sail 将端点协议与承载它们的传输层分离。例如 VLESS、Trojan 或 VMess 出站可以组合 TLS 与 WebSocket，无需为每种组合单独定义协议类型。

下表描述默认构建。协议按 feature 编译，自定义构建可能只包含其中一部分。

## Clash、sing-box 与 Surge 配置生态

Sail 通过同一个加载器直接读取这三种格式，交给同一个运行时。sing-box 的 JSON 就是 Sail 自己的格式；Clash / Mihomo 的 YAML 和 Surge 配置按原样读取，无需手工转换。

| 格式 | 如何识别 | 读取方式 |
| --- | --- | --- |
| sing-box JSON（1.14） | `.json` 文件，或内容是 JSON 对象的文本 | 原生格式，含 Sail 扩展 |
| Clash / Mihomo YAML | `.yaml` 或 `.yml` 文件，或其他任何文本 | 转换为同一配置模型 |
| Surge 配置 | `.conf` 文件，或含 `[General]`、`[Proxy]` 或 `[Rule]` 分段的文本 | 转换为同一配置模型；被引用的文件也会读取 |

Sail 不实现的字段绝不靠猜。不影响路由和安全的字段会被丢弃并给出警告；会改变流量去向或承载方式的字段则报错。Surge 中在 Sail 运行环境下没有意义的设置（例如界面选项）会被静默跳过。各格式逐字段的支持表见[兼容性](/sail/zh/reference/compatibility/)页面；原生模型见[配置模型](/sail/zh/configuration/)。

## 代理协议

| 协议 | 入站 | 出站 | 说明 |
| --- | :---: | :---: | --- |
| HTTP | 是 | 是 | 支持基础认证 |
| SOCKS | 是 | 是 | 入站：SOCKS4、4a 与 5，TCP 和 UDP。出站：仅版本 5，4 和 4a 报错 |
| Mixed | 是 | 否 | 同一监听同时提供 HTTP 与 SOCKS |
| Shadowsocks | 是 | 是 | Classic AEAD 与 2022 方法；出站支持 `obfs-local` 插件 |
| Trojan | 是 | 是 | TCP 与 UDP 中继 |
| VMess | 是 | 是 | 仅 AEAD（`alter_id` 为 0），支持 XUDP |
| VLESS | 是 | 是 | 普通 UDP 或 XUDP；Vision flow |
| AnyTLS | 是 | 是 | 共享认证 TLS 会话 |
| ShadowTLS | 是 | 是 | 仅 v3；承载另一协议，见下文 |
| Hysteria2 | 是 | 是 | QUIC、UDP、Salamander 混淆；出站支持端口跳跃，入站支持伪装站 |
| TUIC | 是 | 是 | QUIC stream 与 datagram |
| MPTP | 是 | 是 | 多路径聚合为逻辑隧道；Sail 自有协议，见 [MPTP](/sail/zh/mptp/) |
| WireGuard | 端点 | 端点 | sing-box 的 `endpoints` 条目：同一标签下既是入站也是出站，运行在 Sail 的用户态 TCP/IP 协议栈上 |

其他出站有 `direct`、`block`、`pass`（Mihomo 的 PASS，见[路由规则](/sail/zh/routing/#跳过规则pass)）和 `redirect`（把所有连接发往一个固定地址）。其他入站包括 `direct`、`tun` 以及下文的透明代理入站。

sing-box 的 `hysteria`、`naive`、`snell`、`ssh`、`tor`、`cloudflared`、`tailscale` 类型，以及 OpenVPN 和 OpenConnect 端点，都是配置错误。

### UDP over TCP

Shadowsocks 和 SOCKS 出站可以用 `udp_over_tcp` 把 UDP 放进 TCP 流中承载，与 sing-box 和 Mihomo 一致：默认版本 2，也可用版本 1。AnyTLS 始终这样承载 UDP。任何入站收到发往这两个版本魔术地址的流，都会当作 UDP 处理。

### ShadowTLS

ShadowTLS v3 中继与服务端所模仿站点之间的真实 TLS 握手，握手之后承载另一协议，通常是 Shadowsocks。与 sing-box 相同：协议出站以 `detour` 指向 ShadowTLS 出站，可以省略 `server` 和 `server_port`，由 ShadowTLS 代为拨号（即使写了 `server` 也不会拨它）；ShadowTLS 入站把连接交给其 `detour` 所指的入站。v1、v2 为配置错误。

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

ClientHello 使用浏览器指纹（`tls.utls`，默认 Chrome），客户端认证放在其 session ID 中。握手服务器按其自身的拨号字段、在实例拨号默认值之上拨号；其 `detour` 尚未实现，属于配置错误。Clash 中 `plugin: shadow-tls` 的 `ss` 代理，以及 Surge 的 `shadow-tls-password`、`shadow-tls-sni`、`shadow-tls-version`，都转换为这样一对出站，ShadowTLS 出站名为 `<名称> (shadow-tls)`。

### Hysteria2 与 TUIC 服务端的流

sing-box 的 Hysteria2 和 TUIC 服务端允许客户端在一条 QUIC 连接上同时开任意多的流（1<<60）。sail 使用的 QUIC 库 quinn 会为允许的每一条流预留空间，因此 sail 服务端在客户端认证前每种流最多同时 100 条，认证后每当用到四分之三就翻倍，最多 65536 条。在一条 QUIC 连接上复用大量连接的客户端，开多少就得到多少；超出上限的会等待其他流关闭，而不是失败。用户的流数由 `user_limits.max_connections` 限制。如果让 quinn 像 quic-go 一样在流打开时才分配空间，就不再需要这个上限；sail 目前还没有这样做。

### QUIC 的拥塞控制

TUIC 和 `quic` 传输层用 `congestion_control` 选择拥塞控制（默认 `cubic`，也可用 `new_reno` 或 `bbr`）；Hysteria2 连接在两端的带宽设置协商出速率时用 Brutal，都没设置时用 BBR。sail 的 BBR 是 quinn 移植的 BBRv1：在丢包或缓冲很深的路径上，它估计的带宽比 sing-box（quic-go）的 BBR 低，因此在这类路径上发得更慢。在 sail 换用 BBRv3 之前，TUIC 建议用 `cubic`，Hysteria2 客户端建议设置 `up_mbps` 和 `down_mbps`，使用 Brutal。

### Hysteria2 伪装站

Hysteria2 入站对没有密码的访问者（例如主动探测）提供 `masquerade` 指定的内容：后面的 `http://` 或 `https://` 站点，或固定响应。与 sing-box 一致，请求以站点自己的名字作为 SNI 和 Host 发往站点（对象写法中 `rewrite_host: false` 时保留客户端的 Host），站点支持时用 HTTP/2，否则用 HTTP/1.1，并去掉逐跳头和转发头。与 sing-box 不同，`https://` 站点按实例的证书库校验（未设置 `certificate` 时即系统证书库），并按实例的拨号默认值连接。

已知缺口：请求体和响应体会先缓冲（上限分别为 1 MB 和 8 MB），不做流式转发；不支持 `file://` 和 `type: file`；chunked 响应不会按 chunked 原样转发。

### 探测与始终不认证的连接

入站怎样回应不是自己客户端的连接，以及这类连接最多消耗多少。与 sing-box 不同的地方会写明。

- **Shadowsocks**（2022 与 AEAD）：请求失败后继续读取并丢弃，直到对方关闭、读满 64 KiB 或到达握手超时，然后才关闭。sing-box 在失败处立即重置连接，探测者改变发送的长度就能得知协议头的长度，Shadowsocks 服务器正是这样被发现的（Frolov、Wampler、Wustrow，“How China Detects and Blocks Shadowsocks”，IMC 2020）。Outline 的 ss-server 和 Xray 与 sail 的做法相同。
- **Trojan、VLESS、AnyTLS**：配置了 `fallback`（或 `fallback_for_alpn`）时，认证失败的连接连同已读到的字节转给回落服务器，探测者面对的是那台服务器。没有配置时，第一个错误字节即关闭连接，与 sing-box 相同；服务端启动时会说明这一点。
- **REALITY、ShadowTLS**：不是自己客户端的连接转给握手服务器，与 sing-box 相同。**Hysteria2**：由 `masquerade` 回应，默认 404。**TUIC**：`auth_timeout`（3 秒）后关闭。
- **握手超时**：服务端（`--profile server`）给 TCP 入站的整个握手 15 秒（`inbound.handshake_timeout`），即 sing-box 对 TLS 与 REALITY 的取值；实测往返 300 ms、丢包 5% 的链路上最慢的建连为 4.7 秒。QUIC 握手 5 秒（`quic.server_handshake_timeout`），与 quic-go 相同：只发了 Initial 就沉默的客户端到时即被丢弃。
- **同时握手的连接数**，Sail 扩展（sing-box 没有限制）：每个入站同时处于握手中的连接至多 `inbound.max_handshakes` 个，正在被继续读取的也算在内：服务端 4096，路由器 256，其余 1024；0 为不限。超出的立即关闭。始终不认证的连接在超时前各占 9 至 20 KiB（实测）。`inbound.max_handshakes_per_source` 限制单个来源地址，默认关闭（0），因为运营商 NAT 后面许多客户端共用一个地址。一个连接在取得 `inbound.max_connections` 下的名额之前计在这里，不会同时计入两边。

以上是运行时选项：`--set inbound.max_handshakes=8192`。

## 传输层与安全

| 层 | 入站 | 出站 | 用途 |
| --- | :---: | :---: | --- |
| TLS | 是 | 是 | 基于 BoringSSL 的流安全；`tls.utls` 提供浏览器 ClientHello |
| REALITY | 是 | 是 | TLS 层上的 REALITY 握手 |
| ECH | 否 | 是 | 加密 ClientHello；仅 TLS 1.3 |
| WebSocket | 是 | 是 | `transport` 类型 `ws`，支持 early data |
| HTTP Upgrade | 是 | 是 | `transport` 类型 `httpupgrade` |
| gRPC | 是 | 是 | `transport` 类型 `grpc` |
| QUIC | 是 | 是 | `transport` 类型 `quic` |
| sing-mux | 是 | 是 | `multiplex` 使用 smux、yamux 或 h2mux（默认）；支持填充与 TCP Brutal |
| AMux | 是 | 是 | `multiplex` 设 `protocol: amux`，Sail 自有，计划移除 |
| Obfs | 否 | 是 | Shadowsocks `obfs-local` 插件：HTTP 或 TLS 形态混淆 |

sing-box 的 HTTP/2 传输（`transport` 类型 `http`）按设计拒绝，请改用 `grpc`、`ws` 或 `httpupgrade`。配置了 `tls.ech` 时，`min_version` 或 `max_version` 低于 TLS 1.3 属于配置错误，因为 sing-box 在这种情况下每次握手都会失败。浏览器指纹可选 `chrome`（默认）、`firefox`、`edge`、`safari`、`ios`、`android` 和 `random`，详见 [TLS 与指纹](/sail/zh/tls-fingerprints/)。

并非所有协议都接受所有层。Sail 会在端点工厂中验证组合，不支持的组合会携带对应入站或出站标签报错。

## 流量控制出站

| 类型 | 选择行为 |
| --- | --- |
| `selector` | 手动选择成员，开启 `experimental.cache_file` 后跨重启保留 |
| `urltest` | 周期性选择最快的成员，差距超过 `tolerance` 才切换 |
| `fallback` | 按声明顺序使用第一个最近一次 URL 测试通过的成员 |
| `load-balance` | 一致性哈希、轮询或粘性会话 |
| `smart` | 按真实连接的表现给成员打分，并让同一站点固定走一个成员 |
| `network` | 按主机当前所在网络（Wi-Fi 名称、网络类型等）选择成员 |
| `tryall` | 竞速尝试成员，每个比上一个晚 `delay_base` 毫秒启动，采用第一个连上的 |

`selector` 和 `urltest` 来自 sing-box，其余是 Sail 扩展。它们都是带标签的普通出站。路由规则只需指向组标签，不必知道最终由哪个成员承载连接。策略组还可以从[出站提供者](/sail/zh/routing/#策略组与提供者)获取成员。

要让一个出站经另一个出站连接其服务器，在它上面设置 `detour`。没有单独的链式类型；Clash 的 `relay` 组尚未实现。

## 透明代理与虚拟网络

| 机制 | 平台 | 作用 |
| --- | --- | --- |
| TUN | Linux、macOS、Windows、iOS、Android | 通过 `sail-netstack` 的用户态 IP 数据面 |
| Redirect | Linux | 取回被 iptables 或 nftables `REDIRECT` 重定向的原始目标 |
| TPROXY | Linux | 带原始目标的透明监听 |
| NF | Windows | NetFilter SDK 集成；不在默认构建中（`inbound-nf` feature） |

TUN 部署必须设置出口接口策略以防回环，详见[路由规则](/sail/zh/routing/#防止-tun-回环)。

## 通用协议字段

协议自身的选项与可复用模块并列：

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

这些通用模块的结构与验证见[配置模型](/sail/zh/configuration/#出站字段与模块)。浏览器 ClientHello 行为见 [TLS 与指纹](/sail/zh/tls-fingerprints/)。
