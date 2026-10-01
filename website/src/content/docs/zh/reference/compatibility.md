---
title: "兼容性"
description: "sail 对 sing-box、Clash / Mihomo 与 Surge 配置的支持表。"
---

sail 直接读取 sing-box、Clash / Mihomo 与 Surge 的配置。每种格式都有一张由注册表测试生成的支持表（`docs/compat/`），逐字段列出 sail 实测的处理方式。原生格式（sing-box v1.14.2 JSON 与 sail 扩展）的逐字段说明见本节其他页面，从[顶层与通用](/sail/zh/reference/common/)开始。

## sing-box

完整表格：[docs/compat/sing-box.md](https://github.com/peakpassvpn/sail/blob/dev/docs/compat/sing-box.md) · 中文版：[docs/compat/zh/sing-box.md](https://github.com/peakpassvpn/sail/blob/dev/docs/compat/zh/sing-box.md)

### 汇总

| 部分 | 字段数 | 支持 | 警告 | 报错 |
|---|--:|--:|--:|--:|
| `$schema` | 1 | 1 | 0 | 0 |
| `log` | 5 | 5 | 0 | 0 |
| `dns` | 578 | 356 | 66 | 156 |
| `ntp` | 35 | 0 | 35 | 0 |
| `certificate` | 5 | 5 | 0 | 0 |
| `certificate_providers` | 212 | 0 | 0 | 212 |
| `http_clients` | 80 | 29 | 11 | 40 |
| `network_namespaces` | 6 | 0 | 0 | 6 |
| `endpoints` | 433 | 56 | 13 | 364 |
| `inbounds` | 1367 | 585 | 151 | 631 |
| `outbounds` | 1228 | 678 | 76 | 474 |
| `route` | 268 | 171 | 36 | 61 |
| `services` | 751 | 1 | 166 | 584 |
| `experimental` | 34 | 16 | 17 | 1 |
| **全部** | **5003** | **1903** | **571** | **2529** |

## Clash / Mihomo

完整表格：[docs/compat/clash.md](https://github.com/peakpassvpn/sail/blob/dev/docs/compat/clash.md) · 中文版：[docs/compat/zh/clash.md](https://github.com/peakpassvpn/sail/blob/dev/docs/compat/zh/clash.md)

### 汇总

| 部分 | 字段 | 支持 | 警告 | 报错 |
|---|--:|--:|--:|--:|
| `clash-for-android` | 3 | 0 | 3 | 0 |
| `dns` | 33 | 28 | 5 | 0 |
| `experimental` | 5 | 0 | 5 | 0 |
| `external-controller-cors` | 3 | 3 | 0 | 0 |
| `general` | 48 | 25 | 21 | 2 |
| `geox-url` | 5 | 0 | 5 | 0 |
| `iptables` | 5 | 0 | 0 | 5 |
| `listeners[anytls]` | 45 | 0 | 0 | 45 |
| `listeners[http]` | 29 | 7 | 1 | 21 |
| `listeners[hysteria2]` | 49 | 0 | 0 | 49 |
| `listeners[mieru]` | 10 | 0 | 0 | 10 |
| `listeners[mixed]` | 30 | 8 | 1 | 21 |
| `listeners[redir]` | 6 | 4 | 1 | 1 |
| `listeners[shadowquic]` | 34 | 0 | 0 | 34 |
| `listeners[shadowsocks]` | 76 | 7 | 1 | 68 |
| `listeners[snell]` | 41 | 0 | 0 | 41 |
| `listeners[socks]` | 30 | 8 | 1 | 21 |
| `listeners[sudoku]` | 29 | 0 | 0 | 29 |
| `listeners[tproxy]` | 7 | 5 | 1 | 1 |
| `listeners[trojan]` | 73 | 0 | 0 | 73 |
| `listeners[trusttunnel]` | 18 | 0 | 0 | 18 |
| `listeners[tuic]` | 26 | 0 | 0 | 26 |
| `listeners[tun]` | 55 | 0 | 0 | 55 |
| `listeners[tunnel]` | 8 | 0 | 0 | 8 |
| `listeners[vless]` | 93 | 0 | 0 | 93 |
| `listeners[vmess]` | 116 | 0 | 0 | 116 |
| `ntp` | 7 | 0 | 7 | 0 |
| `profile` | 3 | 3 | 0 | 0 |
| `proxies[anytls]` | 38 | 22 | 4 | 12 |
| `proxies[direct]` | 7 | 5 | 2 | 0 |
| `proxies[dns]` | 7 | 1 | 6 | 0 |
| `proxies[easytier]` | 37 | 0 | 0 | 37 |
| `proxies[gost-relay]` | 22 | 0 | 0 | 22 |
| `proxies[http]` | 19 | 16 | 2 | 1 |
| `proxies[hysteria2]` | 50 | 24 | 10 | 16 |
| `proxies[hysteria]` | 35 | 0 | 0 | 35 |
| `proxies[masque]` | 29 | 0 | 0 | 29 |
| `proxies[mieru]` | 17 | 0 | 0 | 17 |
| `proxies[openvpn]` | 37 | 0 | 0 | 37 |
| `proxies[reject]` | 7 | 1 | 6 | 0 |
| `proxies[rematch]` | 9 | 0 | 0 | 9 |
| `proxies[shadowquic]` | 27 | 0 | 0 | 27 |
| `proxies[snell]` | 17 | 0 | 0 | 17 |
| `proxies[socks5]` | 18 | 15 | 2 | 1 |
| `proxies[ss]` | 93 | 24 | 3 | 66 |
| `proxies[ssh]` | 15 | 0 | 0 | 15 |
| `proxies[ssr]` | 16 | 0 | 0 | 16 |
| `proxies[sudoku]` | 31 | 0 | 0 | 31 |
| `proxies[tailscale]` | 16 | 0 | 0 | 16 |
| `proxies[trojan]` | 56 | 38 | 2 | 16 |
| `proxies[trusttunnel]` | 32 | 0 | 0 | 32 |
| `proxies[tuic]` | 41 | 26 | 12 | 3 |
| `proxies[vless]` | 137 | 45 | 2 | 90 |
| `proxies[vmess]` | 128 | 46 | 2 | 80 |
| `proxies[wireguard]` | 64 | 0 | 0 | 64 |
| `proxies[zerotier]` | 30 | 0 | 0 | 30 |
| `proxy-groups` | 23 | 18 | 5 | 0 |
| `proxy-providers` | 39 | 27 | 9 | 3 |
| `rule-providers` | 11 | 8 | 3 | 0 |
| `sniffer` | 12 | 12 | 0 | 0 |
| `tls` | 7 | 0 | 7 | 0 |
| `tuic-server` | 13 | 0 | 0 | 13 |
| `tun` | 50 | 33 | 10 | 7 |
| **All** | **2077** | **459** | **139** | **1479** |

## Surge

完整表格：[docs/compat/surge.md](https://github.com/peakpassvpn/sail/blob/dev/docs/compat/surge.md) · 中文版：[docs/compat/zh/surge.md](https://github.com/peakpassvpn/sail/blob/dev/docs/compat/zh/surge.md)

### 汇总

| 部分 | 字段 | 支持 | 静默忽略 | 警告 | 报错 |
|---|--:|--:|--:|--:|--:|
| `General` | 58 | 22 | 30 | 6 | 0 |
| `Keystore` | 3 | 3 | 0 | 0 | 0 |
| `Proxy Group[fallback]` | 16 | 11 | 4 | 1 | 0 |
| `Proxy Group[load-balance]` | 14 | 10 | 4 | 0 | 0 |
| `Proxy Group[select]` | 13 | 9 | 4 | 0 | 0 |
| `Proxy Group[smart]` | 14 | 10 | 4 | 0 | 0 |
| `Proxy Group[ssid]` | 6 | 3 | 3 | 0 | 0 |
| `Proxy Group[subnet]` | 6 | 3 | 3 | 0 | 0 |
| `Proxy Group[url-test]` | 17 | 11 | 4 | 2 | 0 |
| `Proxy[anytls]` | 28 | 16 | 4 | 7 | 1 |
| `Proxy[direct]` | 12 | 3 | 2 | 7 | 0 |
| `Proxy[external]` | 20 | 0 | 0 | 0 | 20 |
| `Proxy[h2-connect]` | 32 | 0 | 0 | 0 | 32 |
| `Proxy[http]` | 24 | 13 | 4 | 7 | 0 |
| `Proxy[https]` | 30 | 18 | 4 | 7 | 1 |
| `Proxy[hysteria2]` | 29 | 16 | 4 | 7 | 2 |
| `Proxy[masque]` | 27 | 0 | 0 | 0 | 27 |
| `Proxy[reject-drop]` | 12 | 1 | 4 | 7 | 0 |
| `Proxy[reject-no-drop]` | 12 | 1 | 4 | 7 | 0 |
| `Proxy[reject-tinygif]` | 12 | 1 | 4 | 7 | 0 |
| `Proxy[reject]` | 12 | 1 | 4 | 7 | 0 |
| `Proxy[snell]` | 28 | 0 | 0 | 0 | 28 |
| `Proxy[socks5-tls]` | 29 | 17 | 4 | 7 | 1 |
| `Proxy[socks5]` | 23 | 12 | 4 | 7 | 0 |
| `Proxy[ss]` | 27 | 15 | 4 | 7 | 1 |
| `Proxy[ssh]` | 25 | 0 | 0 | 0 | 25 |
| `Proxy[tailscale]` | 5 | 0 | 0 | 0 | 5 |
| `Proxy[trojan]` | 30 | 18 | 4 | 7 | 1 |
| `Proxy[trust-tunnel]` | 31 | 0 | 0 | 0 | 31 |
| `Proxy[tuic-v5]` | 27 | 13 | 5 | 7 | 2 |
| `Proxy[tuic]` | 26 | 0 | 0 | 0 | 26 |
| `Proxy[vmess]` | 33 | 21 | 4 | 7 | 1 |
| `Proxy[wireguard]` | 5 | 3 | 0 | 2 | 0 |
| `Rule` | 152 | 59 | 75 | 0 | 18 |
| `SSID Setting` | 6 | 0 | 0 | 6 | 0 |
| `Sections` | 17 | 3 | 3 | 11 | 0 |
| `WireGuard` | 13 | 11 | 0 | 2 | 0 |
| **All** | **874** | **324** | **193** | **135** | **222** |

