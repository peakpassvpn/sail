//! AnyTLS, between sail instances and against sing-box in both directions.
//!
//! Each test puts a counting TCP forwarder in front of the AnyTLS server, so
//! that session reuse shows as the number of TLS connections the client
//! made. The sing-box tests need `/opt/homebrew/bin/sing-box` (or
//! `SING_BOX`) and are ignored by default:
//!
//! ```text
//! cargo test -p sail --test test_anytls -- --ignored
//! ```

#![cfg(all(
    feature = "inbound-anytls",
    feature = "outbound-anytls",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-tls",
    feature = "inbound-tls",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

const PASSWORD: &str = "anytls-password";

/// A certificate for `localhost`, written where both sail and sing-box can
/// read it.
struct Certs {
    cert: String,
    key: String,
    _dir: common::TempDir,
}

fn certs(name: &str) -> anyhow::Result<Certs> {
    let dir = common::TempDir::new(&format!("anytls-{}", name))?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    Ok(Certs {
        cert: cert_path.to_string_lossy().into_owned(),
        key: key_path.to_string_lossy().into_owned(),
        _dir: dir,
    })
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

/// Echoes a few packets through each of two UDP associations.
async fn echo_datagrams(socks_port: u16, echo: SocketAddr) -> anyhow::Result<()> {
    let sess = session_to(echo);
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
    Ok(())
}

/// Sequential streams, which have to share one connection, then
/// concurrent ones, then UDP. `connections` counts the client's
/// connections to the server.
async fn exercise(socks_port: u16, connections: &AtomicUsize) -> anyhow::Result<()> {
    let (tcp_echo, tcp) = common::run_tcp_echo_server("127.0.0.1:0").await?;
    let (udp_echo, udp) = common::run_udp_echo_server("127.0.0.1:0").await?;
    let tcp = tokio::spawn(tcp);
    let udp = tokio::spawn(udp);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = async {
        for i in 0..5u8 {
            echo_stream(socks_port, tcp_echo, i, 1000 + 40_000 * i as usize).await?;
            // For the relay to finish and the session to go back.
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let sequential = connections.load(Ordering::SeqCst);
        anyhow::ensure!(
            sequential == 1,
            "5 sequential streams took {} connections, not 1",
            sequential
        );

        let concurrent: Vec<_> = (0..8u8)
            .map(|i| tokio::spawn(echo_stream(socks_port, tcp_echo, 100 + i, 150_000)))
            .collect();
        for task in concurrent {
            task.await??;
        }
        let after = connections.load(Ordering::SeqCst);
        anyhow::ensure!(
            (2..=8).contains(&after),
            "8 concurrent streams made {} connections in all",
            after
        );

        // Idle sessions from the concurrent streams are reused.
        tokio::time::sleep(Duration::from_millis(300)).await;
        echo_stream(socks_port, tcp_echo, 200, 5000).await?;
        anyhow::ensure!(
            connections.load(Ordering::SeqCst) == after,
            "a stream after the concurrent ones did not reuse a session"
        );

        echo_datagrams(socks_port, udp_echo).await?;
        anyhow::Ok(())
    }
    .await;
    tcp.abort();
    udp.abort();
    result
}

fn socks_to_anytls(socks_port: u16, server_port: u16, password: &str, certs: &Certs) -> String {
    format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {socks_port} }}],
            "outbounds": [{{
                "type": "anytls",
                "server": "127.0.0.1",
                "server_port": {server_port},
                "password": "{password}",
                "idle_session_check_interval": "30s",
                "idle_session_timeout": "60s",
                "min_idle_session": 1,
                "tls": {{
                    "enabled": true,
                    "server_name": "localhost",
                    "certificate_path": "{cert}"
                }}
            }}]
        }}"#,
        cert = certs.cert,
    )
}

/// Like `socks_to_anytls`, with the connections to the server made through
/// a SOCKS proxy at `detour_port`.
fn detoured(socks_port: u16, server_port: u16, detour_port: u16, certs: &Certs) -> String {
    format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {socks_port} }}],
            "outbounds": [
                {{
                    "type": "anytls",
                    "server": "127.0.0.1",
                    "server_port": {server_port},
                    "password": "{PASSWORD}",
                    "detour": "hop",
                    "tls": {{
                        "enabled": true,
                        "server_name": "localhost",
                        "certificate_path": "{cert}"
                    }}
                }},
                {{
                    "type": "socks",
                    "tag": "hop",
                    "server": "127.0.0.1",
                    "server_port": {detour_port}
                }}
            ]
        }}"#,
        cert = certs.cert,
    )
}

/// An AnyTLS server that only lets `alice` through: the user's name has to
/// reach routing for anything to work.
fn anytls_server(port: u16, padding_scheme: Option<&str>, certs: &Certs) -> String {
    let padding = padding_scheme
        .map(|s| format!(r#""padding_scheme": {},"#, s))
        .unwrap_or_default();
    format!(
        r#"{{
            "inbounds": [{{
                "type": "anytls",
                "listen": "127.0.0.1",
                "listen_port": {port},
                "users": [
                    {{ "name": "alice", "password": "{PASSWORD}" }},
                    {{ "name": "bob", "password": "bob-password" }}
                ],
                {padding}
                "tls": {{
                    "enabled": true,
                    "certificate_path": "{cert}",
                    "key_path": "{key}"
                }}
            }}],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "block" }}
            ],
            "route": {{
                "rules": [{{ "auth_user": ["alice"], "outbound": "direct" }}],
                "final": "block"
            }}
        }}"#,
        cert = certs.cert,
        key = certs.key,
    )
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

// app(socks) -> sail(anytls) -> forwarder -> sail(anytls, alice only) -> echo
#[test]
fn test_anytls_sail_to_sail() -> anyhow::Result<()> {
    let certs = certs("sail")?;
    common::retry_port_clash(|| {
        let [server, socks, wrong, bob, via_detour, detour] = common::free_ports();
        let rt = runtime()?;
        // The forwarder runs on `rt`, for as long as it does.
        let (forwarder, connections) = rt.block_on(counting_forwarder(server))?;
        // A scheme of the server's own, which it pushes to the client.
        let scheme = r#"["stop=4", "0=10-20", "1=200-300", "2=100-200,c,300-400", "3=50-60"]"#;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                anytls_server(server, Some(scheme), &certs),
                socks_to_anytls(socks, forwarder, PASSWORD, &certs),
                socks_to_anytls(wrong, server, "wrong", &certs),
                socks_to_anytls(bob, server, "bob-password", &certs),
                detoured(via_detour, server, detour, &certs),
                serde_json::json!({
                    "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": detour }],
                    "outbounds": [{ "type": "direct" }]
                })
                .to_string(),
            ],
        )?;
        let result = rt.block_on(async {
            exercise(socks, &connections).await?;

            let (echo, server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let server = tokio::spawn(server);
            // Through a detour: the sessions' connections are dialled through it.
            for i in 0..3 {
                echo_stream(via_detour, echo, i, 20_000).await?;
            }
            // A wrong password, and a user routing does not let through.
            for port in [wrong, bob] {
                let result = echo_stream(port, echo, 1, 10).await;
                anyhow::ensure!(result.is_err(), "port {}: expected a failure", port);
            }
            server.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sail(anytls) -> forwarder -> sing-box(anytls) -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_anytls_sail_to_sing_box() -> anyhow::Result<()> {
    let certs = certs("to-sing-box")?;
    common::retry_port_clash(|| {
        let [server, socks] = common::free_ports();
        let dir = common::TempDir::new("anytls")?;
        let sing_box_config = serde_json::json!({
            "inbounds": [{
                "type": "anytls",
                "listen": "127.0.0.1",
                "listen_port": server,
                "users": [{ "name": "alice", "password": PASSWORD }],
                "padding_scheme": ["stop=3", "0=5-10", "1=300-400", "2=100-200,c,50-60"],
                "tls": {
                    "enabled": true,
                    "certificate_path": certs.cert,
                    "key_path": certs.key
                }
            }],
            "outbounds": [{ "type": "direct" }]
        });
        let _sing_box = common::Daemon::sing_box(dir.path(), "server", sing_box_config)?;
        let rt = runtime()?;
        let (forwarder, connections) = rt.block_on(counting_forwarder(server))?;
        let ids = common::run_sail_instances(
            &rt,
            vec![socks_to_anytls(socks, forwarder, PASSWORD, &certs)],
        )?;
        let result = rt.block_on(exercise(socks, &connections));
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sing-box(anytls) -> forwarder -> sail(anytls, alice only) -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_anytls_sing_box_to_sail() -> anyhow::Result<()> {
    let certs = certs("from-sing-box")?;
    common::retry_port_clash(|| {
        let [server, socks] = common::free_ports();
        let dir = common::TempDir::new("anytls")?;
        let rt = runtime()?;
        let ids = common::run_sail_instances(&rt, vec![anytls_server(server, None, &certs)])?;
        let result = (|| {
            let (forwarder, connections) = rt.block_on(counting_forwarder(server))?;
            let sing_box_config = serde_json::json!({
                "inbounds": [{ "type": "mixed", "listen": "127.0.0.1", "listen_port": socks }],
                "outbounds": [{
                    "type": "anytls",
                    "server": "127.0.0.1",
                    "server_port": forwarder,
                    "password": PASSWORD,
                    "idle_session_check_interval": "30s",
                    "idle_session_timeout": "60s",
                    "tls": {
                        "enabled": true,
                        "server_name": "localhost",
                        "certificate_path": certs.cert
                    }
                }]
            });
            let sing_box = common::Daemon::sing_box(dir.path(), "client", sing_box_config)?;
            let result = rt.block_on(exercise(socks, &connections));
            drop(sing_box);
            result
        })();
        common::shutdown_instances(&rt, ids);
        result
    })
}
