---
title: 配置模型
description: 了解 Sail 的 JSON 模型、默认值、验证规则与主流配置生态迁移方式。
---

Sail 接受 JSON 和旧版分段式 `.conf`。新部署应优先使用 JSON：它直接映射到类型化配置模型，能拒绝未知顶层字段，并清晰表达嵌套传输层设置。

Sail 的格式已经与 leaf 分化。leaf、Surge、Clash 与 sing-box 配置适合作为迁移输入或转换来源，不应默认可以不经处理直接互换。

## 顶层结构

本指南讲解如何组织和验证配置。逐字段查阅请使用自动生成的[通用配置](/sail/zh/reference/common/)、[入站配置](/sail/zh/reference/inbounds/)、[出站与策略组](/sail/zh/reference/outbounds/)及[传输层配置](/sail/zh/reference/transport/)。参考页随源码重新生成，不包含内部 Rust API。

| 字段 | 用途 | 默认值 |
| --- | --- | --- |
| `log` | 日志级别、格式和文件输出 | `info`、完整格式、控制台 |
| `dns` | 解析器、静态 hosts、策略与缓存 | `1.1.1.1`、仅 IPv4 |
| `inbounds` | 接收流量的监听器或数据源 | 空 |
| `outbounds` | 直连、代理、策略组或隧道 | 空 |
| `route` | 有序规则与最终出站 | 第一个出站 |
| `api` | 可选控制 API | 关闭 |

每个入站和出站都有 `type`，并可设置 `tag`。省略标签时默认使用协议类型；配置中有多个端点后，建议显式命名。

## 入站与出站

```json
{
  "inbounds": [
    { "type": "socks", "tag": "lan-socks", "listen": "127.0.0.1", "listen_port": 1080 }
  ],
  "outbounds": [
    {
      "type": "trojan",
      "tag": "edge",
      "server": "edge.example.com",
      "server_port": 443,
      "password": "replace-me",
      "tls": { "enabled": true, "server_name": "edge.example.com" }
    }
  ]
}
```

流式代理协议可以组合通用模块：`tls` 控制证书、ALPN、ECH、REALITY 与浏览器 ClientHello；`transport` 表达 WebSocket、HTTP Upgrade 或 gRPC；`multiplex` 复用连接；`detour` 通过另一出站拨号。

## DNS

```json
{
  "dns": {
    "servers": ["1.1.1.1", "8.8.8.8"],
    "hosts": { "internal.example": ["10.0.0.8"] },
    "strategy": "prefer_ipv4",
    "cache_capacity": 512,
    "timeout": "4s",
    "reverse_mapping": true
  }
}
```

`strategy` 可取 `ipv4_only`、`ipv6_only`、`prefer_ipv4` 或 `prefer_ipv6`。反向映射让后续仅携带 IP 的连接仍有机会命中域名规则。

## 重要验证规则

- `route.final`、规则、策略组和 detour 引用的标签必须存在。
- 终止性的 `route` 或 `reject` 规则至少需要一个条件；全量兜底应使用 `route.final`。
- `sniffer`、`timeout`、`override_destination` 仅属于 `sniff` 规则。
- `route.auto_detect_interface` 与 `route.default_interface` 不能同时设置。
- 自动 TUN 路由必须配置出口接口策略，避免 Sail 自身流量回到隧道。
- DNS、UDP 等超时必须大于零。

每次修改后运行 `sail -c config.json -T`。

## 旧版 `.conf`

解析器支持 `[General]`、`[Proxy]`、`[Proxy Group]`、`[Rule]` 和 `[Host]` 等分段，并在验证前转换为 JSON 模型。已有部署可以继续使用；新字段与新文档建议采用 JSON，以免受隐式转换规则影响。
