---
title: 路由规则
description: 使用域名、IP、端口、入站、进程和用户条件构建有序路由。
---

Sail 从上到下评估路由规则。`route` 和 `reject` 会停止匹配；`sniff` 与 `resolve` 补充连接信息后继续处理下一条规则。

## 匹配模型

同一字段中的值为“或”，不同条件族之间为“与”。下面规则匹配来自 `local-socks`、目标为 `example.com` 或其子域名的 TCP 连接：

```json
{
  "domain_suffix": ["example.com"],
  "network": ["tcp"],
  "inbound": ["local-socks"],
  "action": "route",
  "outbound": "secure"
}
```

## 条件速查

| 字段 | 示例 | 含义 |
| --- | --- | --- |
| `domain` | `api.example.com` | 精确域名 |
| `domain_suffix` | `example.com` | 域名及其子域名 |
| `domain_keyword` | `cdn` | 包含字符串的域名 |
| `ip_cidr` | `10.0.0.0/8` | 目标网络 |
| `geoip` | `private`, `cn` | `geo.mmdb` 中的地区或分组 |
| `geosite` | `category-ads-all` | `site.dat` 中的网站组 |
| `port_range` | `443`, `1000-2000` | 目标端口或范围 |
| `network` | `tcp`, `udp` | 传输协议 |
| `inbound` | `tun-in` | 来源入站标签 |
| `process_name` | `curl` | 可用时的来源进程 |
| `auth_user` | `alice` | 入站认证用户 |

## 最终路由与拒绝

```json
{
  "route": {
    "rules": [
      { "ip_cidr": ["10.0.0.0/8"], "action": "route", "outbound": "direct" },
      { "domain_suffix": ["ads.example"], "action": "reject" }
    ],
    "final": "secure"
  }
}
```

兜底路径使用 `final`。没有条件的 route/reject 规则会在验证阶段被拒绝，因为它会遮蔽所有后续规则。

## 嗅探与解析

`sniff` 可从 TCP 流开头读取 TLS SNI 或 HTTP Host；它不会解密 TLS。`resolve` 会先解析域名，让后续 IP、CIDR 或 GeoIP 规则能够匹配。应用若本地解析域名，建议使用代理远程 DNS、DNS 反向映射或提前嗅探。

## 防止 TUN 回环

```json
{
  "route": {
    "auto_detect_interface": true,
    "final": "secure"
  }
}
```

TUN 安装默认路由时，Sail 的出站套接字可能重新进入 TUN。优先使用自动检测；出口必须固定时改用 `default_interface`，二者不要同时设置。
