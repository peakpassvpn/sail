//! The WireGuard endpoint, sail to sail on loopback: a client instance
//! routes a SOCKS inbound into its endpoint, whose peer is the endpoint of
//! a server instance, which routes what comes out of the tunnel to echo
//! servers. TCP and UDP, over IPv4 and IPv6 inside the tunnel.
//!
//! The throughput test is ignored by default:
//! `cargo test -p sail --release --test it test_wireguard_endpoint:: -- --ignored --nocapture`.

#![cfg(all(
    feature = "wireguard",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-redirect",
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

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

/// A key pair, base64 as configurations write them.
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

/// Inside the tunnel, the client connects to these; the server sends
/// everything to the echo servers.
const TARGET_V4: &str = "198.18.0.1:7";
const TARGET_V6: &str = "[2001:db8::1]:7";

fn client_json(keys: &Keys, server: &Keys, socks_port: u16, server_port: u16) -> serde_json::Value {
    json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "endpoints": [{
            "type": "wireguard",
            "tag": "wg",
            "address": ["10.77.0.2/32", "fd77::2/128"],
            "private_key": keys.private,
            "peers": [{
                "address": "127.0.0.1",
                "port": server_port,
                "public_key": server.public,
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "persistent_keepalive_interval": 25,
            }],
        }],
        "outbounds": [{ "type": "direct" }],
        "route": { "final": "wg" },
    })
}

fn server(keys: &Keys, client: &Keys, port: u16, tcp_echo: u16, udp_echo: u16) -> String {
    json!({
        "endpoints": [{
            "type": "wireguard",
            "tag": "wg-in",
            "address": ["10.77.0.1/24", "fd77::1/64"],
            "private_key": keys.private,
            "listen_port": port,
            "udp_timeout": "1m",
            "peers": [{
                "public_key": client.public,
                "allowed_ips": ["10.77.0.2/32", "fd77::2/128"],
            }],
        }],
        "outbounds": [
            { "type": "direct" },
            { "type": "redirect", "tag": "tcp-echo", "server": "127.0.0.1", "server_port": tcp_echo },
            { "type": "redirect", "tag": "udp-echo", "server": "127.0.0.1", "server_port": udp_echo },
        ],
        "route": { "rules": [
            { "inbound": ["wg-in"], "network": ["tcp"], "outbound": "tcp-echo" },
            // The peer is named by its public key.
            { "auth_user": [client.public], "network": ["udp"], "outbound": "udp-echo" },
        ] },
    })
    .to_string()
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
    let writer = async move {
        w.write_all(&data).await?;
        w.flush().await?;
        anyhow::Ok(w)
    };
    let reader = async move {
        let mut got = vec![0u8; expected.len()];
        r.read_exact(&mut got).await?;
        anyhow::ensure!(got == expected, "the echo differs");
        anyhow::Ok(())
    };
    let (w, ()) = timeout(Duration::from_secs(60), async {
        tokio::try_join!(writer, reader)
    })
    .await??;
    drop(w);
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
    for i in 0..20u32 {
        // Past the tunnel's MTU, fragmented; `test_udp_large` takes one up
        // to 60 KB.
        let msg = pattern(1 + i as usize * 100, i as u8);
        let mut buf = vec![0u8; 4096];
        // UDP may be lost before the handshake completes: try a few times.
        let mut answered = false;
        for _ in 0..5 {
            s.send_to(&msg, &SocksAddr::Ip(target)).await?;
            if let Ok(r) = timeout(Duration::from_secs(2), r.recv_from(&mut buf)).await {
                let (n, from) = r?;
                anyhow::ensure!(buf[..n] == msg[..], "the UDP echo differs");
                anyhow::ensure!(from == SocksAddr::Ip(target), "from {}", from);
                answered = true;
                break;
            }
        }
        anyhow::ensure!(answered, "no UDP echo from {}", target);
    }
    Ok(())
}

/// How the client's WireGuard datagrams reach the server.
#[derive(Clone, Copy)]
enum Path {
    Direct,
    /// Through a SOCKS outbound, to a relay instance.
    Socks,
    /// Through a Hysteria2 outbound, to a relay instance.
    Hysteria2,
}

/// The relay's configuration, and the client's outbound to it.
fn relay(path: Path, relay_port: u16) -> Option<(String, serde_json::Value)> {
    match path {
        Path::Direct => None,
        Path::Socks => Some((
            json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": relay_port }],
                "outbounds": [{ "type": "direct" }],
            })
            .to_string(),
            json!({ "type": "socks", "tag": "relay", "server": "127.0.0.1", "server_port": relay_port }),
        )),
        Path::Hysteria2 => {
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            Some((
                json!({
                    "inbounds": [{
                        "type": "hysteria2",
                        "listen": "127.0.0.1",
                        "listen_port": relay_port,
                        "users": [{ "name": "wg", "password": "relay" }],
                        "tls": { "enabled": true, "certificate": cert.pem(), "key": key_pair.serialize_pem() },
                    }],
                    "outbounds": [{ "type": "direct" }],
                })
                .to_string(),
                json!({
                    "type": "hysteria2",
                    "tag": "relay",
                    "server": "127.0.0.1",
                    "server_port": relay_port,
                    "password": "relay",
                    "tls": { "enabled": true, "server_name": "localhost", "certificate": cert.pem() },
                }),
            ))
        }
    }
}

/// Runs a client and a server with echo servers behind, and `f` against
/// the client's SOCKS port.
fn with_tunnel(
    f: impl Fn(&tokio::runtime::Runtime, u16) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    with_tunnel_over(Path::Direct, f)
}

fn with_tunnel_over(
    path: Path,
    f: impl Fn(&tokio::runtime::Runtime, u16) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (tcp_addr, tcp_fut) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    let (udp_addr, udp_fut) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
    let echo_tcp = rt.spawn(tcp_fut);
    let echo_udp = rt.spawn(udp_fut);
    let (client_keys, server_keys) = (Keys::new(), Keys::new());
    let result = common::retry_port_clash(|| {
        let [socks_port, server_port, relay_port] = common::free_ports();
        let mut configs = vec![server(
            &server_keys,
            &client_keys,
            server_port,
            tcp_addr.port(),
            udp_addr.port(),
        )];
        let mut client = client_json(&client_keys, &server_keys, socks_port, server_port);
        if let Some((relay, outbound)) = relay(path, relay_port) {
            configs.push(relay);
            client["outbounds"].as_array_mut().unwrap().push(outbound);
            client["endpoints"][0]["detour"] = "relay".into();
        }
        configs.push(client.to_string());
        let ids = common::run_sail_instances(&rt, configs)?;
        let result = f(&rt, socks_port);
        common::shutdown_instances(&rt, ids);
        result
    });
    echo_tcp.abort();
    echo_udp.abort();
    result
}

#[test]
fn test_wireguard_endpoint_sail_to_sail() -> anyhow::Result<()> {
    with_tunnel(|rt, socks_port| {
        rt.block_on(async {
            for target in [TARGET_V4, TARGET_V6] {
                tcp_echo(socks_port, target, b"hello through the tunnel").await?;
                udp_echo(socks_port, target).await?;
            }
            // More than a window, both ways at once, and several at a time.
            let big = pattern(4 << 20, 7);
            tcp_echo(socks_port, TARGET_V4, &big).await?;
            let many = (0..16u8).map(|i| {
                let data = pattern(256 << 10, i);
                let target = if i % 2 == 0 { TARGET_V4 } else { TARGET_V6 };
                async move { tcp_echo(socks_port, target, &data).await }
            });
            futures::future::try_join_all(many).await?;
            anyhow::Ok(())
        })
    })
}

/// WireGuard's own datagrams through another outbound.
#[test]
fn test_wireguard_endpoint_detour() -> anyhow::Result<()> {
    for path in [Path::Socks, Path::Hysteria2] {
        with_tunnel_over(path, |rt, socks_port| {
            rt.block_on(async {
                tcp_echo(socks_port, TARGET_V4, &pattern(1 << 20, 1)).await?;
                udp_echo(socks_port, TARGET_V6).await
            })
        })?;
    }
    Ok(())
}

/// Throughput of one TCP connection through the tunnel, both instances in
/// this process, 256 MiB up and echoed back down at once.
#[test]
#[ignore]
fn test_wireguard_endpoint_throughput() -> anyhow::Result<()> {
    with_tunnel(|rt, socks_port| {
        rt.block_on(async {
            tcp_echo(socks_port, TARGET_V4, b"warm up").await?;
            let size = 256usize << 20;
            let data = pattern(size, 3);
            let cpu = cpu_seconds();
            let started = Instant::now();
            tcp_echo(socks_port, TARGET_V4, &data).await?;
            let elapsed = started.elapsed().as_secs_f64();
            let cpu = cpu_seconds() - cpu;
            println!(
                "sail<->sail: 256 MiB each way in {:.2}s: {:.1} Mbit/s each way, \
                 process CPU {:.2}s ({:.0}% of one core)",
                elapsed,
                size as f64 * 8.0 / elapsed / 1e6,
                cpu,
                cpu / elapsed * 100.0
            );
            anyhow::Ok(())
        })
    })
}

/// User and system CPU time of this process.
fn cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc_rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given.
    unsafe { getrusage(0, usage.as_mut_ptr()) };
    let usage = unsafe { usage.assume_init() };
    let t = |tv: [i64; 2]| tv[0] as f64 + tv[1] as f64 / 1e6;
    t(usage.utime) + t(usage.stime)
}

/// The start of `struct rusage`: two `struct timeval`s, which are two
/// 64-bit fields on the 64-bit targets tests run on (`suseconds_t` is 32
/// bits on macOS, but padded to 64).
#[repr(C)]
struct libc_rusage {
    utime: [i64; 2],
    stime: [i64; 2],
    rest: [i64; 14],
}

extern "C" {
    fn getrusage(who: i32, usage: *mut libc_rusage) -> i32;
}
