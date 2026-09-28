//! The WireGuard endpoint against sing-box's, in both directions, on
//! loopback: TCP and UDP echo over IPv4 and IPv6 inside the tunnel.
//!
//! Needs `sing-box` (1.11 or later) on the PATH, in /opt/homebrew/bin, or
//! in `$SING_BOX`; ignored unless asked for:
//! `cargo test -p sail --features wireguard --test it test_wireguard_sing_box:: -- --ignored`.

#![cfg(all(
    feature = "wireguard",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-redirect",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use sail::protocol::wireguard::crypto;
use sail::session::{Session, SocksAddr};

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

struct Keys {
    private: String,
    public: String,
}

impl Keys {
    fn new() -> Self {
        let private = crypto::generate_private_key();
        Keys {
            private: base64(&private),
            public: base64(&crypto::public_key(&private)),
        }
    }
}

const TARGET_V4: &str = "198.18.0.1:7";
const TARGET_V6: &str = "[2001:db8::1]:7";

/// The client's endpoint, as both sail and sing-box write it.
fn client_endpoint(keys: &Keys, server: &Keys, server_port: u16) -> serde_json::Value {
    json!({
        "type": "wireguard",
        "tag": "wg",
        "address": ["10.77.0.2/32", "fd77::2/128"],
        "private_key": keys.private,
        "mtu": 1408,
        "peers": [{
            "address": "127.0.0.1",
            "port": server_port,
            "public_key": server.public,
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "reserved": [1, 2, 3],
        }],
    })
}

fn server_endpoint(keys: &Keys, client: &Keys, port: u16) -> serde_json::Value {
    json!({
        "type": "wireguard",
        "tag": "wg-in",
        "address": ["10.77.0.1/24", "fd77::1/64"],
        "private_key": keys.private,
        "listen_port": port,
        "peers": [{
            "public_key": client.public,
            "allowed_ips": ["10.77.0.2/32", "fd77::2/128"],
            "reserved": [1, 2, 3],
        }],
    })
}

fn socks_client(endpoint: serde_json::Value, socks_port: u16) -> serde_json::Value {
    json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "endpoints": [endpoint],
        "outbounds": [{ "type": "direct" }],
        "route": { "final": "wg" },
    })
}

fn sail_server(endpoint: serde_json::Value, tcp_echo: u16, udp_echo: u16) -> String {
    json!({
        "endpoints": [endpoint],
        "outbounds": [
            { "type": "direct" },
            { "type": "redirect", "tag": "tcp-echo", "server": "127.0.0.1", "server_port": tcp_echo },
            { "type": "redirect", "tag": "udp-echo", "server": "127.0.0.1", "server_port": udp_echo },
        ],
        "route": { "rules": [
            { "inbound": ["wg-in"], "network": ["tcp"], "outbound": "tcp-echo" },
            { "inbound": ["wg-in"], "network": ["udp"], "outbound": "udp-echo" },
        ] },
    })
    .to_string()
}

fn sing_box_server(endpoint: serde_json::Value, tcp_echo: u16, udp_echo: u16) -> serde_json::Value {
    json!({
        "endpoints": [endpoint],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "rules": [
            {
                "inbound": ["wg-in"], "network": ["tcp"], "action": "route", "outbound": "direct",
                "override_address": "127.0.0.1", "override_port": tcp_echo,
            },
            {
                "inbound": ["wg-in"], "network": ["udp"], "action": "route", "outbound": "direct",
                "override_address": "127.0.0.1", "override_port": udp_echo,
            },
        ] },
    })
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

async fn tcp_echo(socks_port: u16, target: &str, data: &[u8]) -> anyhow::Result<()> {
    let sess = Session {
        destination: SocksAddr::Ip(target.parse()?),
        ..Default::default()
    };
    let stream = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None).await?;
    let (mut r, mut w) = tokio::io::split(stream);
    let expected = data.to_vec();
    let data = data.to_vec();
    timeout(Duration::from_secs(60), async {
        tokio::try_join!(
            async {
                w.write_all(&data).await?;
                anyhow::Ok(())
            },
            async {
                let mut got = vec![0u8; expected.len()];
                r.read_exact(&mut got).await?;
                anyhow::ensure!(got == expected, "the echo differs");
                anyhow::Ok(())
            }
        )
    })
    .await??;
    Ok(())
}

async fn udp_echo(socks_port: u16, target: &str) -> anyhow::Result<()> {
    let target: SocketAddr = target.parse()?;
    let sess = Session {
        destination: SocksAddr::Ip(target),
        ..Default::default()
    };
    let datagram = common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None).await?;
    let (mut r, mut s) = datagram.split();
    for i in 0..10u8 {
        let msg = pattern(64 + i as usize * 100, i);
        let mut buf = vec![0u8; 4096];
        let mut answered = false;
        for _ in 0..5 {
            s.send_to(&msg, &SocksAddr::Ip(target)).await?;
            if let Ok(r) = timeout(Duration::from_secs(2), r.recv_from(&mut buf)).await {
                let (n, _) = r?;
                anyhow::ensure!(buf[..n] == msg[..], "the UDP echo differs");
                answered = true;
                break;
            }
        }
        anyhow::ensure!(answered, "no UDP echo from {}", target);
    }
    Ok(())
}

async fn exchange(socks_port: u16) -> anyhow::Result<()> {
    for target in [TARGET_V4, TARGET_V6] {
        tcp_echo(socks_port, target, &pattern(2 << 20, 5)).await?;
        udp_echo(socks_port, target).await?;
    }
    Ok(())
}

fn echo_servers(rt: &tokio::runtime::Runtime) -> anyhow::Result<(u16, u16)> {
    let (tcp, tcp_fut) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    let (udp, udp_fut) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
    rt.spawn(tcp_fut);
    rt.spawn(udp_fut);
    Ok((tcp.port(), udp.port()))
}

/// sail's endpoint dials sing-box's.
#[test]
#[ignore]
fn test_wireguard_sail_to_sing_box() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let (tcp_echo_port, udp_echo_port) = echo_servers(&rt)?;
    let dir = common::TempDir::new("wg-sing-box-server")?;
    let (client, server) = (Keys::new(), Keys::new());
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let _sing_box = common::Daemon::sing_box(
            dir.path(),
            "server",
            sing_box_server(
                server_endpoint(&server, &client, server_port),
                tcp_echo_port,
                udp_echo_port,
            ),
        )?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                socks_client(client_endpoint(&client, &server, server_port), socks_port)
                    .to_string(),
            ],
        )?;
        let result = rt.block_on(exchange(socks_port));
        common::shutdown_instances(&rt, ids);
        result
    })
}

/// sing-box's endpoint dials sail's.
#[test]
#[ignore]
fn test_wireguard_sing_box_to_sail() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let (tcp_echo_port, udp_echo_port) = echo_servers(&rt)?;
    let dir = common::TempDir::new("wg-sing-box-client")?;
    let (client, server) = (Keys::new(), Keys::new());
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let ids = common::run_sail_instances(
            &rt,
            vec![sail_server(
                server_endpoint(&server, &client, server_port),
                tcp_echo_port,
                udp_echo_port,
            )],
        )?;
        let result = common::Daemon::sing_box(
            dir.path(),
            "client",
            socks_client(client_endpoint(&client, &server, server_port), socks_port),
        )
        .and_then(|_sing_box| rt.block_on(exchange(socks_port)));
        common::shutdown_instances(&rt, ids);
        result
    })
}
