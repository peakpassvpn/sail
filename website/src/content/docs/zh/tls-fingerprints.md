---
title: TLS 与指纹
description: 配置 TLS、证书信任、ECH、REALITY 与浏览器 ClientHello 指纹。
---

Sail 使用 BoringSSL 处理 TCP 和 QUIC 上的 TLS。出站 TLS 默认发送浏览器形态的 ClientHello，而不是 BoringSSL 原生握手形态。

## 基础 TLS 出站

```json
{
  "type": "trojan",
  "tag": "edge",
  "server": "203.0.113.10",
  "server_port": 443,
  "password": "replace-me",
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com"
  }
}
```

`server_name` 同时影响证书校验和 SNI。省略时使用服务器地址。`insecure: true` 会关闭证书校验，只适合短时诊断，不应作为证书问题的长期解决方案。

## ClientHello 指纹

可用浏览器配置包括 Chrome、Firefox、Safari、iOS 和 Android；省略 `utls` 时默认使用 Chrome。

```json
{
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com",
    "utls": { "enabled": true, "fingerprint": "firefox" }
  }
}
```

若要使用 BoringSSL 原生 ClientHello，显式设置 `"utls": { "enabled": false }`。指纹只改变握手形态，不会改变 TLS 内承载的应用协议。

## 自定义信任、ALPN 与 ECH

可使用 `certificate` 内联 PEM，也可通过 `certificate_path` 读取证书。相对路径以 `-D` 指定的数据目录为基准，默认以可执行文件目录为基准。

```json
{
  "tls": {
    "enabled": true,
    "alpn": ["h2", "http/1.1"],
    "certificate_path": "certs/private-ca.pem",
    "ech": { "enabled": true }
  }
}
```

ECH 开启且未提供 `config` 时，可通过 DNS 发现 ECHConfigList；设置 `disable_dns_lookup` 可强制使用显式配置。

## REALITY

```json
{
  "tls": {
    "enabled": true,
    "server_name": "www.example.com",
    "reality": {
      "enabled": true,
      "public_key": "server-public-key",
      "short_id": "0123456789abcdef"
    }
  }
}
```

公钥和 short ID 必须与服务端一致。排查握手失败时，依次验证配置、单独测试出站、检查系统时间与证书链，再查看 DNS、连接和 TLS 阶段日志。
