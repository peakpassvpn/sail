//! The gRPC transport's outbound connection pool: gun streams to one server
//! share an HTTP/2 connection, between sail instances and to sing-box.
//!
//! Each test puts a counting TCP forwarder in front of the server, so that
//! reuse shows as the number of connections the client made. The sing-box
//! tests need `/opt/homebrew/bin/sing-box` (or `SING_BOX`) and are ignored
//! by default:
//!
//! ```text
//! cargo test -p sail --test it test_grpc_pool:: -- --ignored
//! ```

#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "inbound-trojan",
    feature = "outbound-trojan",
    feature = "inbound-tls",
    feature = "outbound-tls",
    feature = "inbound-grpc",
    feature = "outbound-grpc",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

const PASSWORD: &str = "grpc-pool-password";

/// A certificate for `localhost`, as PEM and as files for sing-box.
struct Cert {
    pem: String,
    key_pem: String,
    dir: common::TempDir,
}

impl Cert {
    fn new(name: &str) -> anyhow::Result<Self> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let dir = common::TempDir::new(&format!("grpc-pool-{}", name))?;
        let cert = Cert {
            pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            dir,
        };
        std::fs::write(cert.dir.join("cert.pem"), &cert.pem)?;
        std::fs::write(cert.dir.join("key.pem"), &cert.key_pem)?;
        Ok(cert)
    }
}

/// A TCP forwarder to `target`: the count of the connections it took, and
/// a switch that cuts every one of them.
struct Forwarder {
    port: u16,
    connections: Arc<AtomicUsize>,
    live: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Forwarder {
    async fn start(target: u16) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let connections = Arc::new(AtomicUsize::new(0));
        let live: Arc<Mutex<Vec<AbortHandle>>> = Arc::default();
        let (counted, tasks) = (connections.clone(), live.clone());
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let task = tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", target)).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                tasks.lock().unwrap().push(task.abort_handle());
            }
        });
        Ok(Forwarder {
            port,
            connections,
            live,
        })
    }

    fn count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Closes every connection it carries, both ways.
    fn cut(&self) {
        for task in self.live.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

fn grpc() -> Value {
    json!({
        "type": "grpc",
        "service_name": "PoolService",
        "idle_timeout": "15s",
        "ping_timeout": "15s",
    })
}

/// sail: socks on `socks_port`, out through Trojan over gRPC to
/// `server_port`, or through the SOCKS proxy at `detour` to it.
fn sail_client(
    cert: &Cert,
    tls: bool,
    socks_port: u16,
    server_port: u16,
    detour: Option<u16>,
) -> String {
    let mut outbound = json!({
        "type": "trojan",
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": server_port,
        "password": PASSWORD,
        "transport": grpc(),
    });
    if tls {
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": "localhost",
            "certificate": cert.pem,
        });
    }
    let mut outbounds = vec![outbound];
    if let Some(port) = detour {
        outbounds[0]["detour"] = json!("hop");
        outbounds.push(json!({
            "type": "socks",
            "tag": "hop",
            "server": "127.0.0.1",
            "server_port": port,
        }));
    }
    json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": outbounds,
    })
    .to_string()
}

/// sail or sing-box: Trojan over gRPC on `port`, out direct.
fn server(sing_box: bool, cert: &Cert, tls: bool, port: u16) -> Value {
    let mut inbound = json!({
        "type": "trojan",
        "tag": "in",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "name": "alice", "password": PASSWORD }],
        "transport": grpc(),
    });
    if tls {
        inbound["tls"] = if sing_box {
            json!({
                "enabled": true,
                "certificate_path": cert.dir.join("cert.pem"),
                "key_path": cert.dir.join("key.pem"),
            })
        } else {
            json!({ "enabled": true, "certificate": cert.pem, "key": cert.key_pem })
        };
    }
    json!({
        "inbounds": [inbound],
        "outbounds": [{ "type": "direct" }],
    })
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

/// Sequential streams, then concurrent ones, then UDP, all of which have
/// to share one connection; then, with that connection cut, a stream on a
/// new one. Returns the connection counts after the sequential and the
/// concurrent streams.
async fn exercise(socks_port: u16, forwarder: &Forwarder) -> anyhow::Result<(usize, usize)> {
    let (tcp_echo, tcp) = common::run_tcp_echo_server("127.0.0.1:0").await?;
    let (udp_echo, udp) = common::run_udp_echo_server("127.0.0.1:0").await?;
    let tcp = tokio::spawn(tcp);
    let udp = tokio::spawn(udp);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = async {
        for i in 0..5u8 {
            echo_stream(socks_port, tcp_echo, i, 1000 + 40_000 * i as usize).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let sequential = forwarder.count();

        let concurrent: Vec<_> = (0..16u8)
            .map(|i| tokio::spawn(echo_stream(socks_port, tcp_echo, 100 + i, 150_000)))
            .collect();
        for task in concurrent {
            task.await??;
        }
        echo_datagrams(socks_port, udp_echo).await?;
        let concurrent = forwarder.count();
        eprintln!(
            "grpc pool: 5 sequential streams took {} connection(s); \
             16 concurrent streams and a UDP association, {} in all",
            sequential, concurrent
        );

        // A dead connection is replaced.
        forwarder.cut();
        tokio::time::sleep(Duration::from_millis(300)).await;
        echo_stream(socks_port, tcp_echo, 200, 5000).await?;
        echo_stream(socks_port, tcp_echo, 201, 5000).await?;
        anyhow::ensure!(
            forwarder.count() == concurrent + 1,
            "after the cut, two streams made {} connections",
            forwarder.count() - concurrent
        );
        anyhow::Ok((sequential, concurrent))
    }
    .await;
    tcp.abort();
    udp.abort();
    result
}

fn ensure_one_connection((sequential, concurrent): (usize, usize)) -> anyhow::Result<()> {
    anyhow::ensure!(
        sequential == 1,
        "5 sequential streams took {} connections, not 1",
        sequential
    );
    anyhow::ensure!(
        concurrent == 1,
        "16 concurrent streams made {} connections in all, not 1",
        concurrent
    );
    Ok(())
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

// app(socks) -> sail(trojan/grpc) -> forwarder -> sail(trojan/grpc) -> echo
fn sail_to_sail(name: &str, tls: bool) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    common::retry_port_clash(|| {
        let [server_port, socks, via_detour, detour] = common::free_ports();
        let rt = runtime()?;
        let forwarder = rt.block_on(Forwarder::start(server_port))?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                server(false, &cert, tls, server_port).to_string(),
                sail_client(&cert, tls, socks, forwarder.port, None),
                sail_client(&cert, tls, via_detour, server_port, Some(detour)),
                json!({
                    "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": detour }],
                    "outbounds": [{ "type": "direct" }],
                })
                .to_string(),
            ],
        )?;
        let result = rt.block_on(async {
            ensure_one_connection(exercise(socks, &forwarder).await?)?;
            // Through a detour: the pool's connections are dialled through it.
            let (echo, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_server = tokio::spawn(echo_server);
            for i in 0..3 {
                echo_stream(via_detour, echo, i, 20_000).await?;
            }
            echo_server.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

#[test]
fn test_grpc_pool_sail_to_sail() -> anyhow::Result<()> {
    sail_to_sail("sail", false)
}

#[test]
fn test_grpc_pool_sail_to_sail_tls() -> anyhow::Result<()> {
    sail_to_sail("sail-tls", true)
}

// app(socks) -> sail(trojan/grpc) -> forwarder -> sing-box(trojan/grpc) -> echo
fn sail_to_sing_box(name: &str, tls: bool) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    common::retry_port_clash(|| {
        let [server_port, socks] = common::free_ports();
        let _sing_box = common::Daemon::sing_box(
            cert.dir.path(),
            "server",
            server(true, &cert, tls, server_port),
        )?;
        let rt = runtime()?;
        let forwarder = rt.block_on(Forwarder::start(server_port))?;
        let ids = common::run_sail_instances(
            &rt,
            vec![sail_client(&cert, tls, socks, forwarder.port, None)],
        )?;
        let result = rt.block_on(exercise(socks, &forwarder));
        common::shutdown_instances(&rt, ids);
        ensure_one_connection(result?)
    })
}

#[test]
#[ignore = "needs sing-box"]
fn test_grpc_pool_sail_to_sing_box() -> anyhow::Result<()> {
    sail_to_sing_box("to-sing-box", false)
}

#[test]
#[ignore = "needs sing-box"]
fn test_grpc_pool_sail_to_sing_box_tls() -> anyhow::Result<()> {
    sail_to_sing_box("to-sing-box-tls", true)
}
