//! Multiplex (sing-mux) over the gRPC transport, under VLESS: smux, yamux
//! and h2mux, plain and with TLS, sail to sail and sail to sing-box.
//!
//! Each case runs concurrent streams and a UDP association through one
//! client. The same client against a server with no `multiplex` block,
//! which refuses mux connections, fails: its streams were multiplexed. The
//! sing-box tests need `/opt/homebrew/bin/sing-box` (or `SING_BOX`) and are
//! ignored by default:
//!
//! ```text
//! cargo test -p sail --test it test_grpc_mux:: -- --ignored
//! ```

#![cfg(all(
    feature = "mux",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "inbound-vless",
    feature = "outbound-vless",
    feature = "inbound-tls",
    feature = "outbound-tls",
    feature = "inbound-grpc",
    feature = "outbound-grpc",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

const UUID: &str = "6e0c4a1f-3b2d-4c5e-9f8a-7b6c5d4e3f2a";
const PROTOCOLS: [&str; 3] = ["smux", "yamux", "h2mux"];

/// A certificate for `localhost`, written where both sail and sing-box can
/// read it.
struct Cert {
    dir: common::TempDir,
}

impl Cert {
    fn new(name: &str) -> anyhow::Result<Self> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let dir = common::TempDir::new(&format!("grpc-mux-{}", name))?;
        std::fs::write(dir.join("cert.pem"), cert.pem())?;
        std::fs::write(dir.join("key.pem"), key_pair.serialize_pem())?;
        Ok(Cert { dir })
    }

    fn cert_path(&self) -> String {
        common::json_path(&self.dir.join("cert.pem"))
    }

    fn key_path(&self) -> String {
        common::json_path(&self.dir.join("key.pem"))
    }
}

fn grpc() -> Value {
    json!({ "type": "grpc", "service_name": "MuxService" })
}

/// sail: socks on `socks_port`, out through VLESS over gRPC to
/// `server_port`, multiplexed with `protocol`.
fn sail_client(
    cert: &Cert,
    tls: bool,
    protocol: &str,
    socks_port: u16,
    server_port: u16,
) -> String {
    let mut outbound = json!({
        "type": "vless",
        "server": "127.0.0.1",
        "server_port": server_port,
        "uuid": UUID,
        "transport": grpc(),
        "multiplex": { "enabled": true, "protocol": protocol },
    });
    if tls {
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": "localhost",
            "certificate_path": cert.cert_path(),
        });
    }
    json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [outbound],
    })
    .to_string()
}

/// The same for sail and sing-box: VLESS over gRPC on `served`, serving
/// sing-mux, and on `refused` with no `multiplex` block; out direct.
fn server(cert: &Cert, tls: bool, served: u16, refused: u16) -> Value {
    let inbound = |tag: &str, port: u16, multiplex: bool| {
        let mut inbound = json!({
            "type": "vless",
            "tag": tag,
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "name": "alice", "uuid": UUID }],
            "transport": grpc(),
        });
        if tls {
            inbound["tls"] = json!({
                "enabled": true,
                "certificate_path": cert.cert_path(),
                "key_path": cert.key_path(),
            });
        }
        if multiplex {
            inbound["multiplex"] = json!({ "enabled": true });
        }
        inbound
    };
    json!({
        "inbounds": [inbound("served", served, true), inbound("refused", refused, false)],
        "outbounds": [{ "type": "direct" }],
    })
}

/// The sail instances a test started, stopped when dropped.
#[derive(Default)]
struct Instances(Vec<sail::RuntimeId>);

impl Instances {
    fn start(&mut self, cert: &Cert, config: &str) -> anyhow::Result<()> {
        let rt_id = common::next_rt_id();
        let host = sail::runtime::Host {
            cache_dir: Some(cert.dir.join(format!("cache-{}", rt_id))),
            ..Default::default()
        };
        let config = sail::config::from_string_for(config, &host)?;
        common::start_instance(
            rt_id,
            sail::StartOptions {
                signals: false,
                config: sail::Config::Internal(Box::new(config)),
                #[cfg(feature = "auto-reload")]
                auto_reload: false,
                runtime_opt: sail::RuntimeOption::SingleThread,
                runtime: common::runtime_options(),
                host,
            },
        )?;
        self.0.push(rt_id);
        Ok(())
    }
}

impl Drop for Instances {
    fn drop(&mut self) {
        for rt_id in self.0.drain(..) {
            common::stop_instance(rt_id);
        }
    }
}

fn session_to(addr: SocketAddr) -> Session {
    Session {
        destination: SocksAddr::from(addr),
        ..Default::default()
    }
}

/// Echoes `len` bytes through a new stream from the SOCKS server at
/// `socks_port`.
async fn echo_stream(
    socks_port: u16,
    echo: SocketAddr,
    seed: u8,
    len: usize,
) -> anyhow::Result<()> {
    let mut stream = timeout(
        Duration::from_secs(5),
        common::new_socks_stream("127.0.0.1", socks_port, &session_to(echo), None, None),
    )
    .await??;
    let data: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect();
    let (mut r, mut w) = tokio::io::split(&mut stream);
    let write = async {
        w.write_all(&data).await?;
        anyhow::Ok(())
    };
    let read = async {
        let mut back = vec![0u8; len];
        r.read_exact(&mut back).await?;
        anyhow::Ok(back)
    };
    let (written, back) =
        timeout(Duration::from_secs(10), async { tokio::join!(write, read) }).await?;
    written?;
    anyhow::ensure!(back? == data, "stream {} echoed something else", seed);
    Ok(())
}

/// Echoes a few packets through a UDP association.
async fn echo_datagrams(socks_port: u16, echo: SocketAddr) -> anyhow::Result<()> {
    let sess = session_to(echo);
    let dgram = timeout(
        Duration::from_secs(5),
        common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None),
    )
    .await??;
    let (mut r, mut s) = dgram.split();
    for i in 0..3u8 {
        let msg = vec![i; 100 + i as usize * 500];
        s.send_to(&msg, &sess.destination).await?;
        let mut buf = vec![0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(5), r.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("udp packet {}: no echo", i))??;
        anyhow::ensure!(buf[..n] == msg[..], "udp echo mismatch");
    }
    Ok(())
}

/// Concurrent streams and a UDP association through the client on
/// `served`, which reach the server; a stream through the client on
/// `refused`, whose server takes no mux connection, which does not.
async fn exercise(served: u16, refused: u16) -> anyhow::Result<()> {
    let (tcp_echo, tcp) = common::run_tcp_echo_server("127.0.0.1:0").await?;
    let (udp_echo, udp) = common::run_udp_echo_server("127.0.0.1:0").await?;
    let tcp = tokio::spawn(tcp);
    let udp = tokio::spawn(udp);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = async {
        let streams: Vec<_> = (0..8u8)
            .map(|i| tokio::spawn(echo_stream(served, tcp_echo, i, 100_000)))
            .collect();
        for stream in streams {
            stream.await??;
        }
        echo_datagrams(served, udp_echo).await?;
        anyhow::ensure!(
            echo_stream(refused, tcp_echo, 100, 1000).await.is_err(),
            "a server with no multiplex block served the stream: it was not multiplexed"
        );
        anyhow::Ok(())
    }
    .await;
    tcp.abort();
    udp.abort();
    result
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

/// For each protocol, a client to the served port and one to the refused
/// port of the server at `served` and `refused`, exercised.
fn run_clients(cert: &Cert, tls: bool, served: u16, refused: u16) -> anyhow::Result<()> {
    let mut instances = Instances::default();
    let socks: [u16; 6] = common::free_ports();
    for (i, protocol) in PROTOCOLS.iter().enumerate() {
        instances.start(
            cert,
            &sail_client(cert, tls, protocol, socks[2 * i], served),
        )?;
        instances.start(
            cert,
            &sail_client(cert, tls, protocol, socks[2 * i + 1], refused),
        )?;
    }
    let rt = runtime()?;
    for (i, protocol) in PROTOCOLS.iter().enumerate() {
        rt.block_on(common::scoped(exercise(socks[2 * i], socks[2 * i + 1])))
            .map_err(|e| anyhow::anyhow!("{} (tls: {}): {}", protocol, tls, e))?;
    }
    Ok(())
}

// app(socks) -> sail(vless/grpc/mux) -> sail(vless/grpc, multiplex or none)
fn sail_to_sail(name: &str, tls: bool) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    common::retry_port_clash(|| {
        let [served, refused] = common::free_ports();
        let mut server_instance = Instances::default();
        server_instance.start(&cert, &server(&cert, tls, served, refused).to_string())?;
        run_clients(&cert, tls, served, refused)
    })
}

#[test]
fn test_grpc_mux_sail_to_sail() -> anyhow::Result<()> {
    sail_to_sail("sail", false)
}

#[test]
fn test_grpc_mux_sail_to_sail_tls() -> anyhow::Result<()> {
    sail_to_sail("sail-tls", true)
}

// app(socks) -> sail(vless/grpc/mux) -> sing-box(vless/grpc, multiplex or none)
fn sail_to_sing_box(name: &str, tls: bool) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    common::retry_port_clash(|| {
        let [served, refused] = common::free_ports();
        let _server = common::Daemon::sing_box(
            cert.dir.path(),
            "server",
            server(&cert, tls, served, refused),
        )?;
        run_clients(&cert, tls, served, refused)
    })
}

#[test]
#[ignore = "needs sing-box"]
fn test_grpc_mux_sail_to_sing_box() -> anyhow::Result<()> {
    sail_to_sing_box("sing-box", false)
}

#[test]
#[ignore = "needs sing-box"]
fn test_grpc_mux_sail_to_sing_box_tls() -> anyhow::Result<()> {
    sail_to_sing_box("sing-box-tls", true)
}
