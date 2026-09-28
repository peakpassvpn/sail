//! A 60 KB UDP payload, near the largest UDP carries, echoed through a SOCKS
//! inbound and each UDP-capable outbound:
//!
//!   app(socks) -> sail(socks -> X) [-> sail(X -> direct)] -> echo
//!
//! for X in direct, Shadowsocks 2022, Hysteria2, TUIC and a WireGuard
//! endpoint pair. Hysteria2 and TUIC fragment it into QUIC datagrams, each
//! bound by the path MTU; the WireGuard tunnel carries it as IP fragments.
//! UDP may lose a packet, and losing one fragment loses the whole payload,
//! so each echo is tried a few times, as a UDP application would.

#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

const SIZE: usize = 60_000;

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed ^ (i >> 8) as u8)
        })
        .collect()
}

/// A self-signed certificate for `localhost`: the PEM and its key.
#[allow(dead_code)]
fn cert() -> (String, String) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

/// Runs the instances `configs` gives for an echo server's address, and
/// echoes [`SIZE`] bytes to `target` through the SOCKS inbound on
/// `socks_port`; with no `target`, to the echo server.
fn echo_large(
    socks_port: u16,
    target: Option<SocketAddr>,
    configs: impl FnOnce(SocketAddr) -> Vec<String>,
) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (echo_addr, echo) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
    let echo = rt.spawn(echo);
    let target = target.unwrap_or(echo_addr);
    let ids = match common::run_sail_instances(&rt, configs(echo_addr)) {
        Ok(ids) => ids,
        Err(e) => {
            echo.abort();
            return Err(e);
        }
    };
    let result = rt.block_on(async {
        let sess = Session {
            destination: SocksAddr::Ip(target),
            ..Default::default()
        };
        let dgram = common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None).await?;
        let (mut r, mut s) = dgram.split();
        let mut buf = vec![0u8; 65536];
        // A small one first, then the large one.
        for (i, size) in [100, SIZE].into_iter().enumerate() {
            let msg = pattern(size, i as u8);
            let mut answered = false;
            for _ in 0..5 {
                s.send_to(&msg, &sess.destination).await?;
                if let Ok(got) = timeout(Duration::from_secs(2), r.recv_from(&mut buf)).await {
                    let (n, from) = got?;
                    anyhow::ensure!(n == size, "a UDP echo of {} bytes for {}", n, size);
                    anyhow::ensure!(
                        buf[..n] == msg[..],
                        "the UDP echo of {} bytes differs",
                        size
                    );
                    anyhow::ensure!(from == sess.destination, "UDP echo from {}", from);
                    answered = true;
                    break;
                }
            }
            anyhow::ensure!(answered, "no UDP echo of {} bytes", size);
        }
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    echo.abort();
    result
}

fn socks_in(port: u16) -> serde_json::Value {
    json!({ "type": "socks", "listen": "127.0.0.1", "listen_port": port })
}

#[test]
fn test_udp_large_direct() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port] = common::free_ports();
        let config = json!({
            "inbounds": [socks_in(socks_port)],
            "outbounds": [{ "type": "direct" }],
        });
        echo_large(socks_port, None, |_| vec![config.to_string()])
    })
}

#[cfg(all(feature = "inbound-shadowsocks", feature = "outbound-shadowsocks"))]
#[test]
fn test_udp_large_ss2022() -> anyhow::Result<()> {
    const METHOD: &str = "2022-blake3-aes-128-gcm";
    const KEY: &str = "a8C5QncIl9HvTmenrEb7aw==";
    common::retry_port_clash(|| {
        let [socks_port, ss_port] = common::free_ports();
        let server = json!({
            "inbounds": [{
                "type": "shadowsocks",
                "listen": "127.0.0.1",
                "listen_port": ss_port,
                "method": METHOD,
                "password": KEY,
            }],
            "outbounds": [{ "type": "direct" }],
        });
        let client = json!({
            "inbounds": [socks_in(socks_port)],
            "outbounds": [{
                "type": "shadowsocks",
                "server": "127.0.0.1",
                "server_port": ss_port,
                "method": METHOD,
                "password": KEY,
            }],
        });
        echo_large(socks_port, None, |_| {
            vec![server.to_string(), client.to_string()]
        })
    })
}

#[cfg(all(feature = "inbound-hysteria2", feature = "outbound-hysteria2"))]
#[test]
fn test_udp_large_hysteria2() -> anyhow::Result<()> {
    let (pem, key) = cert();
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let server = json!({
            "inbounds": [{
                "type": "hysteria2",
                "listen": "127.0.0.1",
                "listen_port": server_port,
                "users": [{ "name": "alice", "password": "large" }],
                "tls": { "enabled": true, "certificate": pem, "key": key },
            }],
            "outbounds": [{ "type": "direct" }],
        });
        let client = json!({
            "inbounds": [socks_in(socks_port)],
            "outbounds": [{
                "type": "hysteria2",
                "server": "127.0.0.1",
                "server_port": server_port,
                "password": "large",
                "tls": { "enabled": true, "server_name": "localhost", "certificate": pem },
            }],
        });
        echo_large(socks_port, None, |_| {
            vec![server.to_string(), client.to_string()]
        })
    })
}

#[cfg(all(feature = "inbound-tuic", feature = "outbound-tuic"))]
#[test]
fn test_udp_large_tuic() -> anyhow::Result<()> {
    const UUID: &str = "2dd61d93-75d8-4da4-ac0e-6aece7eac365";
    let (pem, key) = cert();
    // Both relay modes: QUIC datagrams, fragmented, and a stream a packet.
    for mode in ["native", "quic"] {
        common::retry_port_clash(|| {
            let [socks_port, server_port] = common::free_ports();
            let server = json!({
                "inbounds": [{
                    "type": "tuic",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "users": [{ "uuid": UUID, "password": "large" }],
                    "tls": { "enabled": true, "alpn": ["h3"], "certificate": pem, "key": key },
                }],
                "outbounds": [{ "type": "direct" }],
            });
            let client = json!({
                "inbounds": [socks_in(socks_port)],
                "outbounds": [{
                    "type": "tuic",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                    "uuid": UUID,
                    "password": "large",
                    "udp_relay_mode": mode,
                    "tls": {
                        "enabled": true,
                        "server_name": "localhost",
                        "alpn": ["h3"],
                        "certificate": pem,
                    },
                }],
            });
            echo_large(socks_port, None, |_| {
                vec![server.to_string(), client.to_string()]
            })
        })
        .map_err(|e| e.context(format!("udp_relay_mode {}", mode)))?;
    }
    Ok(())
}

#[cfg(all(feature = "wireguard", feature = "outbound-redirect"))]
#[test]
fn test_udp_large_wireguard() -> anyhow::Result<()> {
    use sail::protocol::wireguard::crypto;

    fn base64(key: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in key.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            for i in 0..=chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        while !out.len().is_multiple_of(4) {
            out.push('=');
        }
        out
    }
    let keys = || {
        let private = crypto::generate_private_key();
        (base64(&private), base64(&crypto::public_key(&private)))
    };
    let (client_private, client_public) = keys();
    let (server_private, server_public) = keys();

    // Inside the tunnel, the client sends here; the server redirects it
    // to the echo server.
    let target: SocketAddr = "198.18.0.1:7".parse()?;
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let server = |echo: SocketAddr| {
            json!({
                "endpoints": [{
                    "type": "wireguard",
                    "tag": "wg-in",
                    "address": ["10.77.0.1/24"],
                    "private_key": server_private,
                    "listen_port": server_port,
                    "peers": [{
                        "public_key": client_public,
                        "allowed_ips": ["10.77.0.2/32"],
                    }],
                }],
                "outbounds": [
                    { "type": "direct" },
                    { "type": "redirect", "tag": "udp-echo", "server": "127.0.0.1", "server_port": echo.port() },
                ],
                "route": { "rules": [
                    { "auth_user": [client_public], "network": ["udp"], "outbound": "udp-echo" },
                ] },
            })
        };
        let client = json!({
            "inbounds": [socks_in(socks_port)],
            "endpoints": [{
                "type": "wireguard",
                "tag": "wg",
                "address": ["10.77.0.2/32"],
                "private_key": client_private,
                "peers": [{
                    "address": "127.0.0.1",
                    "port": server_port,
                    "public_key": server_public,
                    "allowed_ips": ["0.0.0.0/0"],
                }],
            }],
            "outbounds": [{ "type": "direct" }],
            "route": { "final": "wg" },
        });
        echo_large(socks_port, Some(target), |echo| {
            vec![server(echo).to_string(), client.to_string()]
        })
    })
}
