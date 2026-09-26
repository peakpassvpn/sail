//! UDP over TCP (version 2) from Shadowsocks 2022 and SOCKS outbounds with
//! `udp_over_tcp`, served by those inbounds: between sail instances, and
//! against sing-box both ways.
//!
//! Each client reaches its server through a TCP-only forwarder, so that
//! UDP gets through only over TCP. The sing-box tests need
//! `/opt/homebrew/bin/sing-box` (or `SING_BOX`) and are ignored by default:
//!
//! ```text
//! cargo test -p sail --test test_uot -- --ignored
//! ```

#![cfg(all(
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-chain",
))]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

const SS_METHOD: &str = "2022-blake3-aes-128-gcm";
const SS_KEY: &str = "a8C5QncIl9HvTmenrEb7aw==";

/// The ports of one direction: the clients' SOCKS ports in front of the
/// Shadowsocks and the SOCKS outbound, then the servers'.
struct Ports {
    client_ss: u16,
    client_socks: u16,
    server_ss: u16,
    server_socks: u16,
}

impl Ports {
    fn new() -> Self {
        let [client_ss, client_socks, server_ss, server_socks] = common::free_ports();
        Ports {
            client_ss,
            client_socks,
            server_ss,
            server_socks,
        }
    }
}

/// A TCP forwarder to `target` on a port of the system's choosing, and the
/// count of its connections.
async fn counting_forwarder(target: u16) -> anyhow::Result<(u16, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", target)).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Ok((port, count))
}

/// Echoes a few packets through each of two UDP associations, and checks
/// that they went over the forwarder.
async fn echo_datagrams(socks_port: u16, connections: &AtomicUsize) -> anyhow::Result<()> {
    let (echo, server) = common::run_udp_echo_server("127.0.0.1:0").await?;
    let server = tokio::spawn(server);
    let result = async {
        let sess = Session {
            destination: SocksAddr::from(echo),
            ..Default::default()
        };
        for round in 0..2u8 {
            let dgram = timeout(
                Duration::from_secs(5),
                common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None),
            )
            .await??;
            let (mut r, mut s) = dgram.split();
            for i in 0..3u8 {
                let msg = vec![round * 16 + i; 100 + i as usize * 500];
                s.send_to(&msg, &sess.destination).await?;
                let mut buf = vec![0u8; 4096];
                let (n, from) = timeout(Duration::from_secs(5), r.recv_from(&mut buf))
                    .await
                    .map_err(|_| anyhow::anyhow!("udp round {} packet {}: no echo", round, i))??;
                anyhow::ensure!(buf[..n] == msg[..], "udp echo mismatch");
                anyhow::ensure!(from == sess.destination, "udp echo from {}", from);
            }
        }
        anyhow::ensure!(
            connections.load(Ordering::SeqCst) >= 1,
            "nothing went over TCP"
        );
        anyhow::Ok(())
    }
    .await;
    server.abort();
    result
}

/// Forwarders to the servers, the clients' configuration for them, and
/// the exercise.
fn run(
    rt: &tokio::runtime::Runtime,
    ports: &Ports,
    client: impl FnOnce(u16, u16) -> anyhow::Result<Box<dyn std::any::Any>>,
) -> anyhow::Result<()> {
    let ((ss_forwarder, ss_count), (socks_forwarder, socks_count)) = rt.block_on(async {
        anyhow::Ok((
            counting_forwarder(ports.server_ss).await?,
            counting_forwarder(ports.server_socks).await?,
        ))
    })?;
    let _client = client(ss_forwarder, socks_forwarder)?;
    rt.block_on(async {
        echo_datagrams(ports.client_ss, &ss_count)
            .await
            .map_err(|e| anyhow::anyhow!("shadowsocks: {}", e))?;
        echo_datagrams(ports.client_socks, &socks_count)
            .await
            .map_err(|e| anyhow::anyhow!("socks: {}", e))
    })
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn sail_server(ports: &Ports) -> String {
    json!({
        "inbounds": [
            {
                "type": "shadowsocks",
                "listen": "127.0.0.1",
                "listen_port": ports.server_ss,
                "method": SS_METHOD,
                "password": SS_KEY,
            },
            { "type": "socks", "listen": "127.0.0.1", "listen_port": ports.server_socks },
        ],
        "outbounds": [{ "type": "direct" }],
    })
    .to_string()
}

fn sail_client(ports: &Ports, ss_forwarder: u16, socks_forwarder: u16) -> String {
    json!({
        "inbounds": [
            { "type": "socks", "tag": "in-ss", "listen": "127.0.0.1", "listen_port": ports.client_ss },
            { "type": "socks", "tag": "in-socks", "listen": "127.0.0.1", "listen_port": ports.client_socks },
        ],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss",
                "server": "127.0.0.1",
                "server_port": ss_forwarder,
                "method": SS_METHOD,
                "password": SS_KEY,
                "udp_over_tcp": { "enabled": true, "version": 2 },
            },
            {
                "type": "socks",
                "tag": "socks",
                "server": "127.0.0.1",
                "server_port": socks_forwarder,
                "udp_over_tcp": true,
            },
        ],
        "route": {
            "rules": [
                { "inbound": ["in-ss"], "outbound": "ss" },
                { "inbound": ["in-socks"], "outbound": "socks" },
            ],
        },
    })
    .to_string()
}

/// Shuts sail instances down when dropped.
struct Instances(Vec<sail::RuntimeId>);

impl Drop for Instances {
    fn drop(&mut self) {
        for id in &self.0 {
            sail::shutdown(*id);
        }
    }
}

// app(socks) -> sail(ss|socks, udp_over_tcp) -> forwarder -> sail -> echo
#[test]
fn test_uot_sail_to_sail() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let ports = Ports::new();
        let rt = runtime()?;
        let _server = Instances(common::run_sail_instances(&rt, vec![sail_server(&ports)])?);
        run(&rt, &ports, |ss, socks| {
            let ids = common::run_sail_instances(&rt, vec![sail_client(&ports, ss, socks)])?;
            Ok(Box::new(Instances(ids)))
        })
    })
}

// app(socks) -> sail(ss|socks, udp_over_tcp) -> forwarder -> sing-box -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_uot_sail_to_sing_box() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let ports = Ports::new();
        let dir = common::TempDir::new("uot")?;
        let server = json!({
            "inbounds": [
                {
                    "type": "shadowsocks",
                    "listen": "127.0.0.1",
                    "listen_port": ports.server_ss,
                    "method": SS_METHOD,
                    "password": SS_KEY,
                },
                { "type": "socks", "listen": "127.0.0.1", "listen_port": ports.server_socks },
            ],
            "outbounds": [{ "type": "direct" }],
        });
        let _sing_box = common::Daemon::sing_box(dir.path(), "server", server)?;
        let rt = runtime()?;
        run(&rt, &ports, |ss, socks| {
            let ids = common::run_sail_instances(&rt, vec![sail_client(&ports, ss, socks)])?;
            Ok(Box::new(Instances(ids)))
        })
    })
}

// app(socks) -> sing-box(ss|socks, udp_over_tcp) -> forwarder -> sail -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_uot_sing_box_to_sail() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let ports = Ports::new();
        let dir = common::TempDir::new("uot")?;
        let rt = runtime()?;
        let _server = Instances(common::run_sail_instances(&rt, vec![sail_server(&ports)])?);
        run(&rt, &ports, |ss, socks| {
            let client = json!({
                "inbounds": [
                    { "type": "mixed", "tag": "in-ss", "listen": "127.0.0.1", "listen_port": ports.client_ss },
                    { "type": "mixed", "tag": "in-socks", "listen": "127.0.0.1", "listen_port": ports.client_socks },
                ],
                "outbounds": [
                    {
                        "type": "shadowsocks",
                        "tag": "ss",
                        "server": "127.0.0.1",
                        "server_port": ss,
                        "method": SS_METHOD,
                        "password": SS_KEY,
                        "udp_over_tcp": { "enabled": true, "version": 2 },
                    },
                    {
                        "type": "socks",
                        "tag": "socks",
                        "server": "127.0.0.1",
                        "server_port": socks,
                        "udp_over_tcp": { "enabled": true, "version": 2 },
                    },
                ],
                "route": {
                    "rules": [
                        { "inbound": ["in-ss"], "outbound": "ss" },
                        { "inbound": ["in-socks"], "outbound": "socks" },
                    ],
                },
            });
            Ok(Box::new(common::Daemon::sing_box(
                dir.path(),
                "client",
                client,
            )?))
        })
    })
}
