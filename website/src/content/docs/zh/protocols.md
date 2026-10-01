---
title: 协议与兼容性
description: Sail 的代理协议、传输层、安全能力，以及 Clash、sing-box、Surge 配置生态兼容范围。
---

Sail 将端点协议与承载它们的传输层分离。例如 VLESS、Trojan 或 VMess 出站可以组合 TLS 与 WebSocket，无需为每种组合单独定义协议类型。

## Clash、sing-box 与 Surge 配置生态

Sail 的目标是一套 Rust 核心承载主流代理配置生态中的协议、路由和策略组能力。当前“兼容”重点是语义对齐与可迁移性，而不是承诺任意第三方配置文件都能原样加载。

| 生态 | 当前关系 | 建议接入方式 |
| --- | --- | --- |
| sing-box | JSON 模型、协议命名和嵌套传输语义较接近，但字段与支持范围并非完全相同 | 转换后用 `sail -T` 验证 |
| Surge / leaf | Sail 保留 `[General]`、`[Proxy]`、`[Proxy Group]`、`[Rule]`、`[Host]` 等 `.conf` 分段解析路径 | 作为迁移入口，再逐步转为 JSON |
| Clash / Mihomo | 协议、策略组与规则概念高度重合；目前不原生加载任意 Clash YAML | 通过转换器或宿主集成层生成 Sail JSON |

这一边界让 Sail 可以持续统一运行时能力，同时避免把不同项目中同名但语义不同的字段静默解释错误。有关顶层模型见[配置模型](/sail/zh/configuration/)。

## 代理协议

| 协议 | 入站 | 出站 | 说明 |
| --- | :---: | :---: | --- |
| HTTP | 是 | 是 | 支持基础认证 |
| SOCKS5 | 是 | 是 | TCP、UDP；入站可选用户认证 |
| Mixed | 是 | 否 | 同一监听同时提供 HTTP 与 SOCKS |
| Shadowsocks | 是 | 是 | Classic AEAD 与 2022 |
| Trojan | 是 | 是 | TCP 与 UDP 中继 |
| VMess | 是 | 是 | AEAD，支持 XUDP |
| VLESS | 是 | 是 | 普通 UDP 或 XUDP；Vision flow |
| AnyTLS | 是 | 是 | 共享认证 TLS 会话 |
| ShadowTLS | 是 | 是 | 仅 v3；承载另一协议，见下文 |
| Hysteria2 | 是 | 是 | QUIC、UDP 与可选端口跳跃 |
| TUIC | 是 | 是 | QUIC stream 与 datagram |
| MPTP | 是 | 是 | 多路径聚合为逻辑隧道 |

内部端点还包括 `direct`、`drop` 与供路由或平台集成使用的重定向处理器。

### ShadowTLS

ShadowTLS v3 中继与服务端所模仿站点之间的真实 TLS 握手，握手之后承载另一协议，通常是 Shadowsocks。与 sing-box 相同：协议出站以 `detour` 指向 ShadowTLS 出站；ShadowTLS 入站把连接交给其 `detour` 所指的入站。v1、v2 为配置错误。

```json
{
  "outbounds": [
    { "type": "shadowsocks", "tag": "ss", "server": "203.0.113.1", "server_port": 443,
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

ClientHello 使用浏览器指纹（`tls.utls`，默认 Chrome），客户端认证放在其 session ID 中。握手服务器直接拨号，其拨号字段与 `detour` 暂未实现。Clash 中 `plugin: shadow-tls` 的 `ss` 代理，以及 Surge 的 `shadow-tls-password`、`shadow-tls-sni`、`shadow-tls-version`，都转换为这样一对出站，ShadowTLS 出站名为 `<名称> (shadow-tls)`。

### Hysteria2 与 TUIC 服务端的流

sing-box 的 Hysteria2 和 TUIC 服务端允许客户端在一条 QUIC 连接上同时开任意多的流（1<<60）。sail 使用的 QUIC 库 quinn 会为允许的每一条流预留空间，因此 sail 服务端在客户端认证前每种流最多同时 100 条，认证后每当用到四分之三就翻倍，最多 65536 条。在一条 QUIC 连接上复用大量连接的客户端，开多少就得到多少；超出上限的会等待其他流关闭，而不是失败。用户的流数由 `user_limits.max_connections` 限制。如果让 quinn 像 quic-go 一样在流打开时才分配空间，就不再需要这个上限；sail 目前还没有这样做。

## 传输层与安全

| 层 | 入站 | 出站 | 用途 |
| --- | :---: | :---: | --- |
| TLS | 是 | 是 | 基于 BoringSSL 的流安全 |
| REALITY | 是 | 是 | TLS 层上的 REALITY 握手 |
| WebSocket | 是 | 是 | HTTP Upgrade 兼容封装 |
| HTTP Upgrade | 是 | 是 | 显式 HTTP/1.1 Upgrade |
| gRPC | 是 | 是 | HTTP/2 流传输 |
| QUIC | 是 | 是 | UDP 上的可靠流 |
| AMux | 是 | 是 | leaf 兼容复用 |
| sing-mux | 是 | 是 | smux、yamux 与 h2mux |
| Obfs | 否 | 是 | HTTP 或 TLS 形态混淆 |

并非所有协议都接受所有层。Sail 会在端点工厂中验证组合，不支持的组合会携带对应入站或出站标签报错。

## 流量控制出站

| 类型 | 选择行为 |
| --- | --- |
| Selector | 手动选择成员，开启 `experimental.cache_file` 后跨重启保留 |
| URLTest | 周期性选择最快的健康成员 |
| Fallback | 按声明顺序使用第一个健康成员 |
| TryAll | 依次尝试直至成功 |
| Load balance | 一致性哈希、轮询或粘性策略 |
| Detour | 通过另一个出站连接当前出站服务器 |

它们都是带标签的普通出站。路由规则只需指向组标签，不必知道最终由哪个成员承载连接。

## 透明代理与虚拟网络

Sail 支持 Linux、macOS、Windows、iOS、Android 上的 TUN 数据面，Windows NF 集成、平台相关 Redirect，以及 Linux TPROXY。TUN 部署必须设置出口接口策略以防回环，详见[路由规则](/sail/zh/routing/#防止-tun-回环)。
