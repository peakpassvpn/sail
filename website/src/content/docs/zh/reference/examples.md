---
title: "示例"
description: "sail 的完整配置示例，均经 sail 与 schema 校验。"
---

本页由 `website/scripts/build-config.mjs` 依据 `website/examples` 生成，请勿手改。每份配置都经 sail 读取并构建、没有警告（`sail/tests/it/test_examples.rs`），并符合 [JSON schema](/sail/schema.json)。其中的域名、密钥与密码均为占位。

## TUN 上的客户端

设备的全部连接经 TUN 进入：DNS 经代理走 HTTPS，局域网名字由系统解析；选择器下挂 URL 测速组，成员为 REALITY 与 Hysteria2 服务器；私有地址直连。所用字段均为 sing-box 原有。

`client-tun.json`

```json
{
  "$schema": "https://peakpassvpn.github.io/sail/schema.json",
  "log": { "level": "info" },
  "dns": {
    "servers": [
      { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },
      { "type": "local", "tag": "local" }
    ],
    "rules": [
      { "domain_suffix": ["lan", "local"], "server": "local" }
    ],
    "final": "remote"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "auto_route": true,
      "strict_route": true
    }
  ],
  "outbounds": [
    { "type": "selector", "tag": "proxy", "outbounds": ["auto", "reality", "hysteria2"] },
    { "type": "urltest", "tag": "auto", "outbounds": ["reality", "hysteria2"] },
    {
      "type": "vless",
      "tag": "reality",
      "server": "server.example.com",
      "server_port": 443,
      "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.example.com",
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": {
          "enabled": true,
          "public_key": "ERERERERERERERERERERERERERERERERERERERERERE",
          "short_id": "0123"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2",
      "server": "server.example.com",
      "server_port": 8443,
      "password": "a long random password",
      "tls": { "enabled": true, "server_name": "server.example.com" }
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "inbound": "tun", "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_is_private": true, "outbound": "direct" }
    ],
    "final": "proxy",
    "auto_detect_interface": true,
    "default_domain_resolver": "local"
  }
}
```

## 带用户限额的 REALITY 服务端

REALITY 上的 VLESS 入站，两个用户，加上 sail 的 `user_limits`：一个用户限连接数与速率，另一个限流量与到期时间。流量配额经缓存文件跨重启保留。

`server-reality.json`

```json
{
  "$schema": "https://peakpassvpn.github.io/sail/schema.json",
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "tag": "reality",
      "listen": "::",
      "listen_port": 443,
      "users": [
        { "name": "alice", "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b", "flow": "xtls-rprx-vision" },
        { "name": "bob", "uuid": "2c1f1b4f-2d3e-4f60-9bac-1d2e3f4a5b6c", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.example.com",
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.example.com", "server_port": 443 },
          "private_key": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
          "short_id": ["0123"]
        }
      }
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "user_limits": {
    "alice": { "max_connections": 64, "up_mbps": 50, "down_mbps": 200 },
    "bob": { "quota_bytes": 107374182400, "expire_at": "2027-01-01T00:00:00Z" }
  },
  "experimental": { "cache_file": { "enabled": true, "path": "cache.db" } }
}
```

## 取自订阅的策略组

sail 的 `outbound_providers`：每 12 小时下载一次订阅，其出站加入选择器，并按名称过滤后加入 URL 测速组；过滤后无成员时回落直连。

`providers.json`

```json
{
  "$schema": "https://peakpassvpn.github.io/sail/schema.json",
  "outbound_providers": [
    {
      "type": "remote",
      "tag": "subscription",
      "url": "https://provider.example.com/sub.yaml",
      "update_interval": "12h",
      "download_detour": "direct"
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy",
      "outbounds": ["fastest"],
      "providers": "subscription"
    },
    {
      "type": "urltest",
      "tag": "fastest",
      "providers": "subscription",
      "filter": "(?i)hong kong|singapore",
      "exclude_filter": "(?i)expire|traffic",
      "empty_fallback": "direct"
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": { "final": "proxy" }
}
```

## 按所在网络选择

sail 的 `network` 策略组：家中 Wi-Fi 直连，蜂窝网络走 Hysteria2，其他网络走 REALITY；另有一条按正则匹配 Wi-Fi 名称的规则（sail 扩展）。

`network-aware.json`

```json
{
  "$schema": "https://peakpassvpn.github.io/sail/schema.json",
  "outbounds": [
    {
      "type": "network",
      "tag": "by-network",
      "branches": [
        { "wifi_ssid": "Home", "outbound": "direct" },
        { "network_type": "cellular", "outbound": "hysteria2" }
      ],
      "default": "reality"
    },
    {
      "type": "vless",
      "tag": "reality",
      "server": "server.example.com",
      "server_port": 443,
      "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.example.com",
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": {
          "enabled": true,
          "public_key": "ERERERERERERERERERERERERERERERERERERERERERE",
          "short_id": "0123"
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2",
      "server": "server.example.com",
      "server_port": 8443,
      "password": "a long random password",
      "tls": { "enabled": true, "server_name": "server.example.com" }
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "wifi_ssid_regex": "^Office", "outbound": "direct" }
    ],
    "final": "by-network"
  }
}
```

