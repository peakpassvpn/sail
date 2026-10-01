//! ShadowTLS v3, Shadowsocks going through it, between sail instances and
//! against sing-box in both directions.
//!
//! The handshake server is a TLS 1.3 echo server of the test's own, which
//! also sends session tickets after the handshake, as real sites do. The
//! sing-box tests need `/opt/homebrew/bin/sing-box` (or `SING_BOX`) and are
//! ignored by default:
//!
//! ```text
//! cargo test -p sail --test it test_shadowtls:: -- --ignored
//! ```
//!
//! So are the tests against the reference implementation, ihciah's
//! shadow-tls, at `SHADOW_TLS`: its client checks the certificate against
//! the public roots, so the handshake server is a real site,
//! `SHADOWTLS_SITE` (www.apple.com by default), and they need the network.

#![cfg(all(
    feature = "inbound-shadowtls",
    feature = "outbound-shadowtls",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-chain",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use btls::pkey::PKey;
use btls::ssl::{SslAcceptor, SslConnector, SslMethod, SslVersion};
use btls::x509::X509;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

const PASSWORD: &str = "shadowtls-password";
const SS_PASSWORD: &str = "ss-password";
const METHOD: &str = "aes-128-gcm";

/// A certificate for `localhost`, and where it is.
struct Certs {
    cert: String,
    cert_pem: String,
    key_pem: String,
    _dir: common::TempDir,
}

fn certs(name: &str) -> anyhow::Result<Certs> {
    let dir = common::TempDir::new(&format!("shadowtls-{}", name))?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = dir.join("cert.pem");
    std::fs::write(&cert_path, cert.pem())?;
    Ok(Certs {
        cert: cert_path.to_string_lossy().into_owned(),
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        _dir: dir,
    })
}

/// A TLS 1.3 server that echoes, on a port of the system's choosing: the
/// site ShadowTLS servers imitate. Its threads live as long as the test.
fn handshake_server(certs: &Certs) -> anyhow::Result<u16> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let cert = X509::from_pem(certs.cert_pem.as_bytes())?;
    let key = PKey::private_key_from_pem(certs.key_pem.as_bytes())?;
    builder.set_certificate(&cert)?;
    builder.set_private_key(&key)?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    let acceptor = builder.build();
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let acceptor = acceptor.clone();
            std::thread::spawn(move || {
                let Ok(mut tls) = acceptor.accept(tcp) else {
                    return;
                };
                let mut buf = [0u8; 4096];
                while let Ok(n) = tls.read(&mut buf) {
                    if n == 0 || tls.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    Ok(port)
}

/// A TLS client, as a prober is: it must get the handshake server's
/// certificate and echo through `port`.
async fn probe(port: u16, certs: &Certs) -> anyhow::Result<()> {
    let cert = certs.cert.clone();
    tokio::task::spawn_blocking(move || {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_ca_file(&cert)?;
        let connector = builder.build();
        let tcp = std::net::TcpStream::connect(("127.0.0.1", port))?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut tls = connector
            .connect("localhost", tcp)
            .map_err(|e| anyhow::anyhow!("probe handshake: {}", e))?;
        tls.write_all(b"are you a web server?")?;
        let mut back = [0u8; 21];
        tls.read_exact(&mut back)?;
        anyhow::ensure!(&back == b"are you a web server?", "probe echo mismatch");
        anyhow::Ok(())
    })
    .await?
}

fn session_to(addr: SocketAddr) -> Session {
    Session {
        destination: SocksAddr::from(addr),
        ..Default::default()
    }
}

/// Echoes `len` bytes through a new stream from the SOCKS server at
/// `socks_port`, both ways at once.
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

/// A SOCKS inbound, and Shadowsocks through ShadowTLS to `server_port`:
/// the Shadowsocks outbound has no server, as in sing-box's documented
/// pair, for its detour dials one.
fn client(socks_port: u16, server_port: u16, password: &str, certs: &Certs) -> serde_json::Value {
    serde_json::json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss",
                "method": METHOD,
                "password": SS_PASSWORD,
                "detour": "shadowtls"
            },
            {
                "type": "shadowtls",
                "tag": "shadowtls",
                "server": "127.0.0.1",
                "server_port": server_port,
                "version": 3,
                "password": password,
                "tls": {
                    "enabled": true,
                    "server_name": "localhost",
                    "certificate_path": certs.cert
                }
            }
        ]
    })
}

/// A ShadowTLS server handing to Shadowsocks, which only lets `alice`
/// through: the user's name has to reach routing for anything to work.
fn server(port: u16, handshake_port: u16) -> String {
    serde_json::json!({
        "inbounds": [
            {
                "type": "shadowtls",
                "listen": "127.0.0.1",
                "listen_port": port,
                "version": 3,
                "users": [
                    { "name": "alice", "password": PASSWORD },
                    { "name": "bob", "password": "bob-password" }
                ],
                "handshake": { "server": "127.0.0.1", "server_port": handshake_port },
                "strict_mode": true,
                "detour": "ss-in"
            },
            {
                "type": "shadowsocks",
                "tag": "ss-in",
                "method": METHOD,
                "password": SS_PASSWORD
            }
        ],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" }
        ],
        "route": {
            "rules": [{ "auth_user": ["alice"], "inbound": ["ss-in"], "outbound": "direct" }],
            "final": "block"
        }
    })
    .to_string()
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

/// Streams one after another and at once, through `socks_port`.
async fn exercise(socks_port: u16) -> anyhow::Result<()> {
    let (echo, server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
    let server = tokio::spawn(server);
    let result = async {
        for i in 0..3u8 {
            echo_stream(socks_port, echo, i, 1000 + 70_000 * i as usize).await?;
        }
        let concurrent: Vec<_> = (0..6u8)
            .map(|i| tokio::spawn(echo_stream(socks_port, echo, 100 + i, 100_000)))
            .collect();
        for task in concurrent {
            task.await??;
        }
        anyhow::Ok(())
    }
    .await;
    server.abort();
    result
}

// app(socks) -> sail(ss, shadowtls) -> sail(shadowtls, ss; alice only) -> echo
#[test]
fn test_shadowtls_sail_to_sail() -> anyhow::Result<()> {
    let certs = certs("sail")?;
    let handshake = handshake_server(&certs)?;
    common::retry_port_clash(|| {
        let [server_port, socks, wrong, bob] = common::free_ports();
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                server(server_port, handshake),
                client(socks, server_port, PASSWORD, &certs).to_string(),
                client(wrong, server_port, "wrong", &certs).to_string(),
                client(bob, server_port, "bob-password", &certs).to_string(),
            ],
        )?;
        let result = rt.block_on(async {
            exercise(socks).await?;
            let (echo, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_server = tokio::spawn(echo_server);
            // A wrong password is relayed to the handshake server, which the
            // client finds out; a user routing does not let through.
            for port in [wrong, bob] {
                let result = echo_stream(port, echo, 1, 10).await;
                anyhow::ensure!(result.is_err(), "port {}: expected a failure", port);
            }
            echo_server.abort();
            // A prober meets the handshake server.
            probe(server_port, &certs).await
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sail(ss, shadowtls) -> sing-box(shadowtls, ss) -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_shadowtls_sail_to_sing_box() -> anyhow::Result<()> {
    let certs = certs("to-sing-box")?;
    let handshake = handshake_server(&certs)?;
    common::retry_port_clash(|| {
        let [server_port, socks] = common::free_ports();
        let dir = common::TempDir::new("shadowtls")?;
        let sing_box_config = serde_json::json!({
            "inbounds": [
                {
                    "type": "shadowtls",
                    "listen": "127.0.0.1",
                    "listen_port": server_port,
                    "version": 3,
                    "users": [{ "name": "alice", "password": PASSWORD }],
                    "handshake": { "server": "127.0.0.1", "server_port": handshake },
                    "strict_mode": true,
                    "detour": "ss-in"
                },
                {
                    "type": "shadowsocks",
                    "tag": "ss-in",
                    "listen": "127.0.0.1",
                    "method": METHOD,
                    "password": SS_PASSWORD
                }
            ],
            "outbounds": [{ "type": "direct" }]
        });
        let _sing_box = common::Daemon::sing_box(dir.path(), "server", sing_box_config)?;
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![client(socks, server_port, PASSWORD, &certs).to_string()],
        )?;
        let result = rt.block_on(async {
            exercise(socks).await?;
            probe(server_port, &certs).await
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sing-box(ss, shadowtls) -> sail(shadowtls, ss; alice only) -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_shadowtls_sing_box_to_sail() -> anyhow::Result<()> {
    let certs = certs("from-sing-box")?;
    let handshake = handshake_server(&certs)?;
    common::retry_port_clash(|| {
        let [server_port, socks] = common::free_ports();
        let dir = common::TempDir::new("shadowtls")?;
        let rt = runtime()?;
        let ids = common::run_sail_instances(&rt, vec![server(server_port, handshake)])?;
        let result = (|| {
            let mut config = client(socks, server_port, PASSWORD, &certs);
            config["inbounds"][0]["type"] = "mixed".into();
            config["outbounds"][1]["tls"]["utls"] =
                serde_json::json!({ "enabled": true, "fingerprint": "chrome" });
            let sing_box = common::Daemon::sing_box(dir.path(), "client", config)?;
            let result = rt.block_on(exercise(socks));
            drop(sing_box);
            result
        })();
        common::shutdown_instances(&rt, ids);
        result
    })
}

/// The reference implementation, at `SHADOW_TLS`, with `args` after `--v3`.
fn reference(name: &str, args: &[&str]) -> anyhow::Result<common::Daemon> {
    let path = std::env::var_os("SHADOW_TLS")
        .ok_or_else(|| anyhow::anyhow!("SHADOW_TLS: the shadow-tls binary"))?;
    let mut command = std::process::Command::new(path);
    command.env("RUST_LOG", "info").arg("--v3").args(args);
    common::Daemon::spawn(command, name, |line| line.contains("Start "))
}

fn site() -> String {
    std::env::var("SHADOWTLS_SITE").unwrap_or_else(|_| "www.apple.com".into())
}

// app(socks) -> sail(ss, shadowtls) -> shadow-tls server -> sail(ss) -> echo
#[test]
#[ignore = "needs shadow-tls and the network"]
fn test_shadowtls_sail_to_reference() -> anyhow::Result<()> {
    let certs = certs("to-reference")?;
    common::retry_port_clash(|| {
        let [server_port, ss_port, socks] = common::free_ports();
        let site = site();
        let listen = format!("127.0.0.1:{}", server_port);
        let data = format!("127.0.0.1:{}", ss_port);
        let tls = format!("{}:443", site);
        let _server = reference(
            "shadow-tls server",
            &[
                "--strict",
                "server",
                "--listen",
                &listen,
                "--server",
                &data,
                "--tls",
                &tls,
                "--password",
                PASSWORD,
            ],
        )?;
        let rt = runtime()?;
        let mut config = client(socks, server_port, PASSWORD, &certs);
        let tls = &mut config["outbounds"][1]["tls"];
        tls["server_name"] = site.clone().into();
        tls.as_object_mut().unwrap().remove("certificate_path");
        let ss_server = serde_json::json!({
            "inbounds": [{
                "type": "shadowsocks",
                "listen": "127.0.0.1",
                "listen_port": ss_port,
                "method": METHOD,
                "password": SS_PASSWORD
            }],
            "outbounds": [{ "type": "direct" }]
        });
        let ids = common::run_sail_instances(&rt, vec![ss_server.to_string(), config.to_string()])?;
        let result = rt.block_on(exercise(socks));
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sail(ss) -> shadow-tls client -> sail(shadowtls, ss) -> echo
#[test]
#[ignore = "needs shadow-tls and the network"]
fn test_shadowtls_reference_to_sail() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [server_port, client_port, socks] = common::free_ports();
        let site = site();
        let rt = runtime()?;
        let mut server = serde_json::from_str::<serde_json::Value>(&server(server_port, 443))?;
        server["inbounds"][0]["handshake"]["server"] = site.clone().into();
        let ss_client = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": [{
                "type": "shadowsocks",
                "server": "127.0.0.1",
                "server_port": client_port,
                "method": METHOD,
                "password": SS_PASSWORD
            }]
        });
        let ids = common::run_sail_instances(&rt, vec![server.to_string(), ss_client.to_string()])?;
        let result = (|| {
            let listen = format!("127.0.0.1:{}", client_port);
            let upstream = format!("127.0.0.1:{}", server_port);
            let _client = reference(
                "shadow-tls client",
                &[
                    "client",
                    "--listen",
                    &listen,
                    "--server",
                    &upstream,
                    "--sni",
                    &site,
                    "--password",
                    PASSWORD,
                ],
            )?;
            rt.block_on(exercise(socks))
        })();
        common::shutdown_instances(&rt, ids);
        result
    })
}
