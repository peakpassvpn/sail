---
title: TLS 与指纹
description: 配置 TLS、证书信任、客户端证书、SNI、ECH、REALITY 与浏览器 ClientHello 指纹。
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

ECH 只用于 TLS 1.3，因此开启 ECH 且 `min_version` 低于 `1.3` 属于配置错误。sing-box 会接受这样的配置，但之后每条连接都会失败（Go 的 TLS 要求开启 ECH 时最低版本为 1.3）；Sail 在读取配置时就报错。

### 证书固定

`certificate_sha256` 是 sail 的扩展字段，语义同 Mihomo 的 `fingerprint`：按整张证书（DER）的 SHA-256 接受服务器，十六进制，大小写均可，冒号可有可无，即 `openssl x509 -noout -fingerprint -sha256` 的输出。它取代 `certificate`、`certificate_path` 与 `insecure`，且不能与固定公钥的 sing-box 字段 `certificate_public_key_sha256` 同时使用。

```json
{
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com",
    "certificate_sha256": ["5A:1F:...:C3"]
  }
}
```

- 匹配服务器自身（叶子）证书：直接接受，不校验 CA、有效期和名称。**固定叶子证书即信任这张证书用于任意服务器名。**
- 匹配服务器链中的中间证书或根证书：以该证书为唯一 CA，叶子证书必须链到它且对 `server_name` 有效，无论 `insecure` 如何设置。
- 都不匹配：握手失败，错误信息给出服务器所发证书的哈希。

TCP 与 QUIC 均支持，DNS 服务器的 `tls` 也支持。REALITY 自行验证服务器，会忽略该字段并给出警告。

## 客户端证书

以证书认证客户端（双向 TLS）的服务器会在握手中索要证书。按 sing-box 的字段名给出证书与私钥，可内联 PEM，也可给路径：

```json
{
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com",
    "client_certificate_path": "certs/client.crt",
    "client_key_path": "certs/client.key"
  }
}
```

`client_certificate` 与 `client_key` 为内联 PEM，可写成一个字符串或每行一项。二者须同时设置或都不设置，内联与路径每对至多设一个。证书文件可在证书后附上证书链。私钥可为 RSA、ECDSA 或 Ed25519，PKCS#8、PKCS#1 或 SEC1 格式的 PEM，且须与证书匹配。TCP 与 QUIC（Hysteria2、TUIC、quic 传输层）均支持；不可与 REALITY 同用（其服务器不索要证书），DNS 服务器暂不支持。

Surge 的 `client-cert=<条目>` 读取 `[Keystore]` 中的 `p12` 条目；Mihomo 的 `certificate` 与 `private-key` 对应这两个字段。

## 不发送 SNI

`disable_sni: true` 使 ClientHello 不带服务器名，无论是否使用浏览器指纹。除非设置 `insecure`，证书仍按 `server_name`（未设置时为服务器地址）校验：

```json
{
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com",
    "disable_sni": true
  }
}
```

不可与 ECH 或 REALITY 同用（二者的 ClientHello 须带服务器名），QUIC 上暂不支持。Surge 的 `sni=off` 即此选项。

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
