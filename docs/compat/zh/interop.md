# 与 sing-box、Mihomo 互通

sail 分别作为客户端和服务端，与 sing-box、Mihomo 的发布版对接：sail 支持的每个协议，以及双方都支持的传输层、TLS、REALITY、ECH 与多路复用组合。测试脚本在 `scripts/interop/`（每格如何检查见其 README）。

- sail：提交 `b1b598458`（0.18.0），`sail-cli` release 构建
- sing-box：1.14.2
- Mihomo：Meta 1.19.32
- 运行：2026-10-08，Linux x86_64，单个网络命名空间，每格每个方向 64 MiB

每格都经客户端的 SOCKS 入站检查：TCP 回显（6 条消息，1 到 200000 字节），协议承载 UDP 时的 UDP 回显，以及上行、下行各一次 64 MiB 传输（SHA-256 校验）。方向写作 `客户端>服务端`：`sb` 为 sing-box，`mh` 为 Mihomo。

## 重跑

在 Linux 上以 root 运行，需要 `ip`、`openssl` 与 Python 3.9+：

```sh
python3 scripts/interop/run.py --work WORK --sail SAIL --sing-box SING_BOX --mihomo MIHOMO
python3 scripts/interop/run.py ... --only '^vmess/ws/off/-$' --dirs 'sail>mh' --repeat 3
```

## 结果

共 495 格，另有 21 格 skip。完整一轮中 490 格通过、5 格失败；每个失败格随后再跑 3 次，偶发失败所属的传输族（sail>sb 的全部 `httpupgrade` 行、sail>mh 的全部 `vmess` 行）也各再跑 3 次。

**P** 每次都通过。**flaky (n/m)** m 次（完整一轮加重跑）中通过 n 次。**F** 每次都失败。**skip** 是某一方没有的组合。

四个方向全部通过的行：

| 协议族 | 行 |
|---|---|
| Shadowsocks | aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305、2022-blake3-aes-128-gcm、2022-blake3-chacha20-poly1305、2022 加 UDP over TCP；aes-256-gcm 与 2022-blake3-aes-128-gcm 上的 smux、yamux、h2mux |
| VMess | tcp、ws、ws 早期数据、grpc、httpupgrade，各自明文与 TLS，各带 smux、yamux、h2mux；加密方式 chacha20-poly1305、none、zero；下表所列行除外 |
| VLESS | 同样的传输层、TLS 与多路复用；TLS 与 REALITY 上的 Vision；tcp（各种多路复用）与 grpc 上的 REALITY；下表所列行除外 |
| Trojan | TLS 上的 tcp、ws、grpc、httpupgrade，各带 smux、yamux、h2mux；REALITY |
| QUIC | Hysteria2（普通与 salamander）；TUIC（UDP native、UDP over QUIC、cubic） |
| 其他 | AnyTLS；ShadowTLS v3（配 Shadowsocks 2022 与 aes-256-gcm）；SOCKS；HTTP（明文与 TLS） |

其余各行：

| 行 | sail>sb | sb>sail | sail>mh | mh>sail |
|---|---|---|---|---|
| ss(aes-128-gcm+obfs-http)/tcp/off/- | skip¹ | skip² | F³ | skip¹ |
| ss(aes-128-gcm+obfs-tls)/tcp/off/- | skip¹ | skip² | F³ | skip¹ |
| vmess/tcp/off/- | P | P | flaky (3/4)⁴ | P |
| vmess/ws/off/- | P | P | flaky (6/7)⁴ | P |
| vmess/ws-ed/tls/- | P | P | flaky (3/4)⁴ | P |
| vmess/grpc/off/- | P | P | flaky (3/4)⁴ | P |
| vmess/httpupgrade/off/- | P | P | flaky (5/7)⁴ | P |
| vmess/httpupgrade/off/h2mux | flaky (3/4)⁵ | P | P | P |
| vless/httpupgrade/off/smux | flaky (3/4)⁵ | P | P | P |
| vless/httpupgrade/off/yamux | flaky (6/7)⁵ | P | P | P |
| vless/httpupgrade/tls/- | flaky (1/4)⁵ | P | P | P |
| vless/httpupgrade/tls/yamux | flaky (3/4)⁵ | P | P | P |
| trojan/httpupgrade/tls/yamux | flaky (6/7)⁵ | P | P | P |
| vmess/tcp/ech/- | P | skip⁶ | P | skip⁶ |
| vless/tcp/ech/- | P | skip⁶ | P | skip⁶ |
| trojan/tcp/ech/- | P | skip⁶ | P | skip⁶ |
| tuic/quic/ech/- | P | skip⁶ | P | skip⁶ |
| hysteria2/quic/ech/- | P | skip⁶ | P | skip⁶ |
| anytls/tcp/ech/- | P | skip⁶ | P | skip⁶ |
| mixed(socks)/tcp/off/- | P | P | P | skip⁷ |
| mixed(http)/tcp/off/- | P | P | P | skip⁷ |
| wireguard/udp/off/- | P | P | skip⁸ | P |

1. sail 与 sing-box 的 Shadowsocks 入站都没有 simple-obfs。
2. sing-box 以 `obfs-local` 插件进程运行 simple-obfs，测试脚本没有该程序。
3. sail 的限制：UDP 回显失败，因为 sail 的 simple-obfs 是流式层，不承载 UDP；TCP 与大块传输通过（obfs-http 的一次重跑也丢了一次 TCP 回显）。`docs/roadmap.md` 的传输层表把 simple-obfs 列为不支持（移除现有实现）。
4. Mihomo：其 VMess 入站（`listener/sing_vmess`）偶尔扣住上传最后的 10904 字节（目标每次都只收到 67097960 / 67108864 字节），校验和因此回不来。sing-box 客户端（sb>mh）也会遇到。只在不带多路复用的行上出现过，这些行都可能出现。
5. sing-box：其 httpupgrade 服务端丢弃了 `Hijack` 返回的 `bufio.ReadWriter`（`transport/v2rayhttpupgrade/server.go:110`）。Go 的 `net/http` 对没有 body 的请求已开始后台读，客户端在 101 之后立刻发出的字节因此丢失，sing-box 记录 `bad request` 或 `unknown version`。sail 读到 101 之后才发送。任何 httpupgrade 行都可能出现。
6. sail 的入站没有 ECH：入站上的 `tls.ech` 报错（见 [sing-box 兼容性](sing-box.md)）。
7. Mihomo 没有 `mixed` 代理类型，socks 与 http 两行已覆盖。
8. Mihomo 没有 WireGuard listener。
