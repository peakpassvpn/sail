# Interop with sing-box and Mihomo

sail against the release builds of sing-box and Mihomo, as client and as server: every protocol sail has, with each transport, TLS, REALITY, ECH and multiplex combination that both sides support. The harness is `scripts/interop/` (its README says how a cell is checked).

- sail: commit `b1b598458` (0.18.0), release build of `sail-cli`
- sing-box: 1.14.2
- Mihomo: Meta 1.19.32
- Run: 2026-10-08, Linux x86_64, one network namespace, 64 MiB each way per cell

Each cell is checked through the client's SOCKS inbound: a TCP echo (6 messages, 1 to 200000 bytes), a UDP echo where the protocol carries UDP, and a 64 MiB transfer each way with a SHA-256 check. A direction is written client>server: `sb` is sing-box, `mh` Mihomo.

## Rerun

As root, on Linux with `ip`, `openssl` and Python 3.9+:

```sh
python3 scripts/interop/run.py --work WORK --sail SAIL --sing-box SING_BOX --mihomo MIHOMO
python3 scripts/interop/run.py ... --only '^vmess/ws/off/-$' --dirs 'sail>mh' --repeat 3
```

## Result

495 cells and 21 skips. In the full run 490 passed and 5 failed; every failure was then run 3 more times, and the transport families the intermittent ones belong to (all `httpupgrade` rows sail>sb, all `vmess` rows sail>mh) 3 more times each.

**P** passed every attempt. **flaky (n/m)** passed n of m attempts (the full run and the reruns). **F** failed every attempt. **skip** is a combination one side does not have.

Rows that passed in all four directions:

| Family | Rows |
|---|---|
| Shadowsocks | aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-chacha20-poly1305, 2022 with UDP over TCP; smux, yamux and h2mux over aes-256-gcm and 2022-blake3-aes-128-gcm |
| VMess | tcp, ws, ws early data, grpc, httpupgrade, each plain and with TLS, with smux, yamux and h2mux; security chacha20-poly1305, none and zero; except the rows below |
| VLESS | the same transports, TLS and multiplex; Vision over TLS and REALITY; REALITY over tcp (with each multiplex) and grpc; except the rows below |
| Trojan | tcp, ws, grpc, httpupgrade over TLS, with smux, yamux and h2mux; REALITY |
| QUIC | Hysteria2 (plain and salamander); TUIC (UDP native, UDP over QUIC, cubic) |
| Others | AnyTLS; ShadowTLS v3 (with Shadowsocks 2022 and aes-256-gcm); SOCKS; HTTP (plain and TLS) |

Every other row:

| Row | sail>sb | sb>sail | sail>mh | mh>sail |
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

1. Neither sail's nor sing-box's Shadowsocks inbound has simple-obfs.
2. sing-box runs simple-obfs as the `obfs-local` plugin process, which the harness does not have.
3. sail limit: the UDP echo fails, as sail's simple-obfs is a stream layer and carries no UDP; TCP and the transfers pass (one obfs-http rerun also lost a TCP echo). simple-obfs is listed as not supported, its implementation to be removed, in the transport table of `docs/roadmap.md`.
4. Mihomo: its VMess inbound (`listener/sing_vmess`) at times keeps the last 10904 bytes of an upload (the target receives 67097960 of 67108864 bytes, every time), so the checksum never comes back. A sing-box client hits it too (sb>mh). Seen only on rows without multiplex; any of them may show it.
5. sing-box: its httpupgrade server drops the `bufio.ReadWriter` that `Hijack` returns (`transport/v2rayhttpupgrade/server.go:110`). Go's `net/http` has started a background read on a request without a body, so bytes the client sends right after the 101 are lost, and sing-box logs `bad request` or `unknown version`. sail sends only after reading the 101. Any httpupgrade row may show it.
6. sail has no ECH on inbounds: `tls.ech` on an inbound is an error ([sing-box compatibility](sing-box.md)).
7. Mihomo has no `mixed` proxy type; the socks and http rows cover it.
8. Mihomo has no WireGuard listener.
