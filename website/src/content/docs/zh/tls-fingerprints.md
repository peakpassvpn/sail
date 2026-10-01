---
title: TLS 与指纹
description: 配置 TLS、证书信任、客户端证书、SNI、ECH、REALITY 与浏览器 ClientHello 指纹。
---

Sail 通过 `btls` 绑定使用 BoringSSL，处理 TCP 和 QUIC 上的 TLS。TCP 上的出站 TLS 默认发送浏览器形态的 ClientHello，而不是 BoringSSL 原生的 ClientHello。

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

`server_name` 同时决定证书校验和 SNI。省略时使用服务器地址。

:::caution
`insecure: true` 会关闭证书校验。它只适合短时诊断，不能用来解决证书或主机名问题。
:::

## 选择 ClientHello 指纹

每个指纹对应一个实际抓取的浏览器或客户端的 ClientHello：

| `fingerprint` | 发送的 ClientHello |
| --- | --- |
| `chrome`（默认）、`edge` | macOS 上的 Chrome 154；Android 上的 Chrome 和 Edge 发送相同的 ClientHello |
| `firefox` | macOS 上的 Firefox 156 |
| `safari`、`ios` | macOS 上的 Safari 26.3，与 macOS 及 iOS 26.4 上的 URLSession 相同 |
| `android` | 基于系统 Conscrypt、使用 OkHttp 4.12 的 Android 应用 |
| `random` | 与 sing-box 一样，从 `chrome`、`firefox`、`edge`、`safari`、`ios` 中选一个；每个进程只选一次，之后所有连接都用它 |

省略 `utls`，或 `utls` 未指定 `fingerprint` 时，默认使用 Chrome。因此与 sing-box 不同，浏览器指纹默认开启，除非显式关闭。其他名称是配置错误。

```json
{
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "firefox"
    }
  }
}
```

若要发送 BoringSSL 自己的 ClientHello，显式关闭指纹：

```json
{
  "tls": {
    "enabled": true,
    "utls": {
      "enabled": false
    }
  }
}
```

指纹只改变握手形态，不改变 TLS 内承载的应用协议。与浏览器一样，每个指纹都提供 TLS 1.2 和 1.3：开启 `utls` 时，`min_version` 与 `max_version` 会被忽略并给出警告。没有 `utls` 块时，这两个字段设置的范围会生效，并有警告说明此时的 ClientHello 已不再是浏览器的。

在 QUIC 上（Hysteria2、TUIC 与 `quic` 传输层），ClientHello 是 BoringSSL 自己的：在那里开启 `utls`、`ech` 或 `reality` 是配置错误。

## 自定义信任

默认按系统根证书库校验服务器。顶层 `certificate` 块可选择其他证书库（`store`：`system`、`mozilla`、`chrome` 或 `none`），也可以加入自己的证书，与 sing-box 相同。

在出站的 `tls` 中，`certificate` 会替换上述根证书：服务器必须链到所给的 PEM 证书。可以内联：

```json
{
  "tls": {
    "enabled": true,
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
}
```

也可以从路径读取：

```json
{
  "tls": {
    "enabled": true,
    "certificate_path": "certs/private-ca.pem"
  }
}
```

相对证书路径以 `-D` 指定的数据目录为基准，默认以可执行文件所在目录为基准。

### 证书固定

`certificate_sha256` 是 sail 的扩展字段，语义同 Mihomo 的 `fingerprint`：按整张证书（DER）的 SHA-256 接受服务器，十六进制，大小写均可，冒号可有可无，即 `openssl x509 -noout -fingerprint -sha256` 的输出。它取代受信任的根证书与 `insecure`，二者都不再起作用。它不能与 `certificate` 或 `certificate_path` 同时使用，也不能与固定公钥的 sing-box 字段 `certificate_public_key_sha256` 同时使用。

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

## ALPN 与 ECH

服务器要求特定应用协议时使用 `alpn`。使用浏览器指纹且未设置 `alpn` 时，ClientHello 提供浏览器的 `h2` 与 `http/1.1`。

```json
{
  "tls": {
    "enabled": true,
    "alpn": ["h2", "http/1.1"],
    "ech": {
      "enabled": true
    }
  }
}
```

设置了 `config` 时，就使用它作为 ECHConfigList，不发任何 DNS 查询，与 sing-box 一致。未设置时，Sail 从服务器名的 HTTPS 记录（或 SVCB 记录）查找 ECHConfigList；查询失败或记录里没有 ECH 配置时，连接失败。设置 `disable_dns_lookup` 可强制要求显式的 base64 或 PEM `config`：缺少时配置被拒绝。

ECH 只用于 TLS 1.3，因此开启 ECH 且 `min_version` 或 `max_version` 低于 `1.3` 属于配置错误。sing-box 会接受这样的配置，但之后每条连接都会失败（Go 的 TLS 要求开启 ECH 时最低版本为 1.3）；Sail 在读取配置时就报错。

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

REALITY 在 TLS 块中配置：

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

使用服务端签发的公钥和 short ID。REALITY 的 ClientHello 总是浏览器的：与它同用时不能关闭 `utls`，且只能用于 TCP。REALITY 与普通证书 TLS 的认证前提不同；不要在未核对服务端的情况下从另一套部署复制字段。

## 排查握手失败

1. 运行 `sail -c config.json -T`，发现字段与组合错误。
2. 运行 `sail -c config.json -t edge -d 10`，单独测试该出站。
3. 确认 `server_name`、系统时间和证书链。
4. 只有确知服务器强制要求某种指纹时，才临时切换指纹。
5. 开启调试日志，查看失败发生在 DNS、TCP/UDP 连接还是 TLS 阶段。
