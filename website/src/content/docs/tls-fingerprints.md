---
title: TLS and fingerprints
description: Configure TLS, trust, client certificates, SNI, ECH, REALITY and browser ClientHello profiles.
---

Sail uses BoringSSL for TLS over TCP and QUIC. Outbound TLS sends a browser-shaped ClientHello by default instead of BoringSSL's native one.

## Basic TLS outbound

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

`server_name` controls certificate verification and SNI. When it is omitted, Sail uses the server address.

:::caution
`insecure: true` disables certificate verification. It is useful for a short diagnostic, not as a fix for a certificate or hostname problem.
:::

## Choose a ClientHello profile

The available browser profiles are Chrome, Firefox, Safari, iOS and Android. Chrome is the default when `utls` is omitted.

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

To send BoringSSL's own ClientHello instead, explicitly disable the profile:

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

The profile changes the handshake shape, not the application protocol carried inside TLS.

## Custom trust

Trust one additional PEM certificate inline:

```json
{
  "tls": {
    "enabled": true,
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
}
```

Or load it from a path:

```json
{
  "tls": {
    "enabled": true,
    "certificate_path": "certs/private-ca.pem"
  }
}
```

Relative certificate paths are resolved against the data directory configured with `-D` or the executable directory by default.

## ALPN and ECH

Use `alpn` when the server requires a specific application protocol:

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

When ECH is enabled and `config` is omitted, Sail can discover the ECHConfigList through DNS. Set `disable_dns_lookup` to require an explicit base64 or PEM configuration instead.

## Client certificates

A server that authenticates clients by certificate (mutual TLS) asks for one during the handshake. Give the certificate and its key, inline PEM or by path, as sing-box names them:

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

`client_certificate` and `client_key` take the PEM inline instead, as one string or one line per entry. Set both halves or neither, and at most one of each inline and path pair. The certificate file may hold its chain after it. The key may be RSA, ECDSA or Ed25519, in PKCS#8, PKCS#1 or SEC1 PEM, and must match the certificate. It works over TCP and over QUIC (Hysteria2, TUIC, the quic transport); not with REALITY, whose server asks for no certificate, and not on DNS servers yet.

Surge's `client-cert=<item>` reads a `p12` item of its `[Keystore]`, and Mihomo's `certificate` and `private-key` become these fields.

## ClientHello without SNI

`disable_sni: true` leaves the server name out of the ClientHello, with or without a browser profile. The certificate is still verified against `server_name`, or the server address, unless `insecure` is set:

```json
{
  "tls": {
    "enabled": true,
    "server_name": "edge.example.com",
    "disable_sni": true
  }
}
```

It cannot be combined with ECH or REALITY, whose ClientHello names a server, and it is not available over QUIC yet. Surge's `sni=off` sets it.

## REALITY

REALITY is configured inside the TLS block:

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

Use the public key and short ID issued by the server. REALITY and ordinary certificate-based TLS have different authentication assumptions; do not copy fields from one deployment without matching the server.

## Diagnose handshake failures

1. Run `sail -c config.json -T` to catch field and combination errors.
2. Run `sail -c config.json -t edge -d 10` to isolate the outbound.
3. Confirm `server_name`, system time and the certificate chain.
4. Temporarily switch the fingerprint only if the server is known to enforce one.
5. Enable debug logs and inspect whether the failure happens during DNS, TCP/UDP connect or TLS.
