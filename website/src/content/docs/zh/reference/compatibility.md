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
| `log` | 5 | 5 | 0 | 0 |
| `dns` | 578 | 318 | 94 | 166 |
| `ntp` | 35 | 0 | 35 | 0 |
| `certificate` | 5 | 5 | 0 | 0 |
| `certificate_providers` | 212 | 0 | 0 | 212 |
| `http_clients` | 80 | 21 | 15 | 44 |
| `network_namespaces` | 6 | 0 | 0 | 6 |
| `endpoints` | 433 | 51 | 32 | 350 |
| `inbounds` | 1367 | 521 | 187 | 659 |
| `outbounds` | 1228 | 590 | 140 | 498 |
| `route` | 268 | 144 | 21 | 103 |
| `services` | 751 | 1 | 166 | 584 |
| `experimental` | 34 | 16 | 17 | 1 |
| **全部** | **5002** | **1672** | **707** | **2623** |

## Clash / Mihomo

本版本尚无。

## Surge

本版本尚无。

