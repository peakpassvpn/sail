//! VMess both ways: sail to sail, and against sing-box in either role;
//! each security, TCP and UDP, the latter as VMess's own UDP or as XUDP.
//!
//! The sing-box tests need `sing-box` on the PATH or in
//! /opt/homebrew/bin, and are ignored unless asked for:
//! `cargo test -p sail --test test_vmess -- --ignored`.
//!
//! Ports 33040-33069 only.

#![cfg(all(
    feature = "inbound-vmess",
    feature = "outbound-vmess",
    feature = "inbound-tls",
    feature = "outbound-tls",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// A self-signed certificate for localhost, as files.
struct Cert {
    cert_pem: String,
    key_pem: String,
    dir: PathBuf,
}

impl Cert {
    fn new(name: &str) -> anyhow::Result<Self> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let dir = std::env::temp_dir().join(format!("sail-vmess-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let cert = Cert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            dir,
        };
        std::fs::write(cert.cert_path(), &cert.cert_pem)?;
        std::fs::write(cert.key_path(), &cert.key_pem)?;
        Ok(cert)
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join("cert.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("key.pem")
    }
}

impl Drop for Cert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// How a test connects.

/// How a test connects.
#[derive(Clone, Copy)]
struct Setup {
    security: &'static str,
    tls: bool,
    xudp: bool,
    global_padding: bool,
}

const fn setup(security: &'static str, tls: bool, xudp: bool, global_padding: bool) -> Setup {
    Setup {
        security,
        tls,
        xudp,
        global_padding,
    }
}

fn server_tls(cert: &Cert, setup: Setup) -> serde_json::Value {
    if setup.tls {
        json!({
            "enabled": true,
            "certificate_path": cert.cert_path(),
            "key_path": cert.key_path(),
        })
    } else {
        json!(null)
    }
}

fn client_tls(cert: &Cert, setup: Setup) -> serde_json::Value {
    if setup.tls {
        json!({
            "enabled": true,
            "server_name": "localhost",
            "certificate_path": cert.cert_path(),
        })
    } else {
        json!(null)
    }
}

/// Drops nulls, which neither sail nor sing-box take for "unset".
fn prune(mut value: serde_json::Value) -> serde_json::Value {
    fn walk(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                map.retain(|_, v| !v.is_null());
                map.values_mut().for_each(walk);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut value);
    value
}

fn vmess_outbound(cert: &Cert, setup: Setup, server_port: u16, uuid: &str) -> serde_json::Value {
    json!({
        "type": "vmess",
        "server": "127.0.0.1",
        "server_port": server_port,
        "uuid": uuid,
        "security": setup.security,
        "global_padding": setup.global_padding,
        "packet_encoding": if setup.xudp { "xudp" } else { "" },
        "tls": client_tls(cert, setup),
    })
}

fn vmess_inbound(cert: &Cert, setup: Setup, port: u16) -> serde_json::Value {
    json!({
        "type": "vmess",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "name": "alice", "uuid": UUID, "alterId": 0 }],
        "tls": server_tls(cert, setup),
    })
}

fn sail_client(cert: &Cert, setup: Setup, socks_port: u16, server_port: u16, uuid: &str) -> String {
    prune(json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [vmess_outbound(cert, setup, server_port, uuid)],
    }))
    .to_string()
}

fn sail_server(cert: &Cert, setup: Setup, port: u16) -> String {
    prune(json!({
        "inbounds": [vmess_inbound(cert, setup, port)],
        "outbounds": [{ "type": "direct" }],
    }))
    .to_string()
}

fn sail_to_sail(name: &str, setup: Setup, socks_port: u16, server_port: u16) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    let configs = vec![
        sail_client(&cert, setup, socks_port, server_port, UUID),
        sail_server(&cert, setup, server_port),
    ];
    common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
    transfer(configs, socks_port, true)
}

#[test]
fn test_vmess_sail_to_sail_aes_128_gcm() -> anyhow::Result<()> {
    sail_to_sail(
        "aes",
        setup("aes-128-gcm", false, false, true),
        33040,
        33041,
    )
}

#[test]
fn test_vmess_sail_to_sail_chacha20_xudp() -> anyhow::Result<()> {
    sail_to_sail(
        "chacha",
        setup("chacha20-poly1305", false, true, false),
        33042,
        33043,
    )
}

#[test]
fn test_vmess_sail_to_sail_none_tls() -> anyhow::Result<()> {
    sail_to_sail("none", setup("none", true, false, true), 33044, 33045)
}

#[test]
fn test_vmess_sail_to_sail_zero_xudp() -> anyhow::Result<()> {
    sail_to_sail("zero", setup("zero", false, true, false), 33046, 33047)
}

#[test]
fn test_vmess_sail_to_sail_zero_udp_auto() -> anyhow::Result<()> {
    sail_to_sail("zero-udp", setup("zero", false, false, false), 33048, 33049)?;
    sail_to_sail("auto", setup("auto", true, true, false), 33048, 33049)
}

#[test]
fn test_vmess_refuses_unknown_user() -> anyhow::Result<()> {
    let cert = Cert::new("refuse")?;
    let setup = setup("aes-128-gcm", false, false, false);
    let configs = vec![
        sail_client(
            &cert,
            setup,
            33050,
            33051,
            "00000000-0000-0000-0000-000000000001",
        ),
        sail_server(&cert, setup, 33051),
    ];
    assert!(common::test_configs(configs, "127.0.0.1", 33050).is_err());
    Ok(())
}

#[test]
fn test_vmess_refuses_legacy_alter_id() -> anyhow::Result<()> {
    let cert = Cert::new("alter")?;
    let setup = setup("aes-128-gcm", false, false, false);
    let mut server = vmess_inbound(&cert, setup, 33052);
    server["users"][0]["alterId"] = json!(4);
    let config = prune(json!({ "inbounds": [server], "outbounds": [{ "type": "direct" }] }));
    let config = sail::config::from_string(&config.to_string())?;
    let err = sail::check_config(&config, &Default::default()).unwrap_err();
    assert!(err.to_string().contains("alterId"), "{}", err);
    Ok(())
}

// ---------------------------------------------------------------------------
// Traffic
// ---------------------------------------------------------------------------

/// Runs `configs` and, through the socks server on `socks_port`, echoes
/// megabytes over TCP and UDP packets of a few sizes. With `inner_tls`, it
/// also runs TLS 1.3 through the proxy, which is what Vision switches to
/// direct copy for.
fn transfer(configs: Vec<String>, socks_port: u16, inner_tls: bool) -> anyhow::Result<()> {
    use rand::RngCore;
    use sail::session::{Session, SocksAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = rt.block_on(async {
        let (tcp_addr, tcp_echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        let tcp_echo = tokio::spawn(tcp_echo);
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let udp_addr = udp.local_addr()?;
        let udp_echo = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = udp.recv_from(&mut buf).await {
                let _ = udp.send_to(&buf[..n], from).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut sess = Session {
            destination: SocksAddr::Ip(tcp_addr),
            ..Default::default()
        };
        let stream = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None).await?;
        let (mut r, mut w) = tokio::io::split(stream);
        let mut data = vec![0u8; 4 * 1024 * 1024];
        rand::thread_rng().fill_bytes(&mut data);
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&sent).await?;
            Ok::<_, std::io::Error>(w)
        });
        let mut echoed = vec![0u8; data.len()];
        timeout(Duration::from_secs(60), r.read_exact(&mut echoed))
            .await
            .map_err(|_| anyhow::anyhow!("TCP echo timed out"))??;
        let _w = writer.await??;
        anyhow::ensure!(echoed == data, "TCP echo differs");

        sess.destination = SocksAddr::Ip(udp_addr);
        let dgram = common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None).await?;
        let (mut r, mut w) = dgram.split();
        for size in [1usize, 100, 1500, 2000] {
            let mut packet = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut packet);
            w.send_to(&packet, &sess.destination).await?;
            let mut buf = vec![0u8; 4096];
            let (n, from) = timeout(Duration::from_secs(2), r.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("UDP echo of {} bytes timed out", size))??;
            anyhow::ensure!(buf[..n] == packet[..], "UDP echo of {} bytes differs", size);
            anyhow::ensure!(from == sess.destination, "UDP echo from {}", from);
        }
        tcp_echo.abort();
        udp_echo.abort();
        Ok::<(), anyhow::Error>(())
    });
    let result = result.and_then(|_| {
        if inner_tls {
            tls_through_socks(socks_port)
        } else {
            Ok(())
        }
    });
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// A TLS 1.3 echo server on a thread, and a TLS client that reaches it
/// through the socks server on `socks_port`: several megabytes each way.
fn tls_through_socks(socks_port: u16) -> anyhow::Result<()> {
    use btls::pkey::PKey;
    use btls::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};
    use btls::x509::X509;

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let x509 = X509::from_pem(cert.pem().as_bytes())?;
    let key = PKey::private_key_from_pem(key_pair.serialize_pem().as_bytes())?;
    acceptor.set_certificate(&x509)?;
    acceptor.set_private_key(&key)?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let echo_addr = listener.local_addr()?;
    let server = std::thread::spawn(move || -> anyhow::Result<()> {
        let (tcp, _) = listener.accept()?;
        let mut tls = acceptor
            .accept(tcp)
            .map_err(|e| anyhow::anyhow!("inner TLS accept: {}", e))?;
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match tls.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            tls.write_all(&buf[..n])?;
        }
    });

    let tcp = socks_connect(socks_port, echo_addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);
    let mut tls = connector
        .build()
        .connect("localhost", tcp)
        .map_err(|e| anyhow::anyhow!("inner TLS connect: {}", e))?;
    let mut data = vec![0u8; 3 * 1024 * 1024];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
    // Write and read in turns, so neither side's buffers fill up.
    let mut echoed = vec![0u8; data.len()];
    for (chunk, out) in data.chunks(64 * 1024).zip(echoed.chunks_mut(64 * 1024)) {
        tls.write_all(chunk)?;
        tls.read_exact(out)?;
    }
    anyhow::ensure!(echoed == data, "inner TLS echo differs");
    let _ = tls.shutdown();
    drop(tls);
    server
        .join()
        .map_err(|_| anyhow::anyhow!("TLS echo server panicked"))??;
    Ok(())
}

/// A blocking SOCKS5 CONNECT to `target`.
fn socks_connect(socks_port: u16, target: SocketAddr) -> anyhow::Result<TcpStream> {
    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, socks_port))?;
    tcp.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply)?;
    anyhow::ensure!(reply == [5, 0], "socks method {:?}", reply);
    let SocketAddr::V4(target) = target else {
        anyhow::bail!("IPv4 only");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    tcp.write_all(&request)?;
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply)?;
    anyhow::ensure!(reply[1] == 0, "socks connect failed: {}", reply[1]);
    Ok(tcp)
}

// ---------------------------------------------------------------------------
// sing-box
// ---------------------------------------------------------------------------

fn sing_box_path() -> PathBuf {
    let homebrew = Path::new("/opt/homebrew/bin/sing-box");
    if homebrew.exists() {
        homebrew.to_path_buf()
    } else {
        PathBuf::from("sing-box")
    }
}

/// A sing-box process, killed when dropped.
struct SingBox(Child);

impl SingBox {
    /// Runs sing-box with `config` and waits for it to listen on TCP `port`.
    fn run(cert: &Cert, name: &str, config: serde_json::Value, port: u16) -> anyhow::Result<Self> {
        let path = cert.dir.join(format!("{}.json", name));
        std::fs::write(&path, prune(config).to_string())?;
        let child = Command::new(sing_box_path())
            .arg("run")
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow::anyhow!("run sing-box: {}", e))?;
        let sing_box = SingBox(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            if Instant::now() > deadline {
                return Err(anyhow::anyhow!("sing-box did not listen on {}", port));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(sing_box)
    }
}

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sing_box_server(cert: &Cert, setup: Setup, port: u16) -> serde_json::Value {
    json!({
        "log": { "level": "warn" },
        "inbounds": [vmess_inbound(cert, setup, port)],
        "outbounds": [{ "type": "direct" }],
    })
}

fn sing_box_client(
    cert: &Cert,
    setup: Setup,
    socks_port: u16,
    server_port: u16,
) -> serde_json::Value {
    let mut outbound = vmess_outbound(cert, setup, server_port, UUID);
    outbound["alter_id"] = json!(0);
    json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [outbound],
    })
}

/// sail outbound -> sing-box inbound.
fn sail_to_sing_box(
    name: &str,
    setup: Setup,
    socks_port: u16,
    server_port: u16,
) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    let _server = SingBox::run(
        &cert,
        "server",
        sing_box_server(&cert, setup, server_port),
        server_port,
    )?;
    let configs = vec![sail_client(&cert, setup, socks_port, server_port, UUID)];
    common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
    transfer(configs, socks_port, true)
}

/// sing-box outbound -> sail inbound.
fn sing_box_to_sail(
    name: &str,
    setup: Setup,
    socks_port: u16,
    server_port: u16,
) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    let configs = vec![sail_server(&cert, setup, server_port)];
    let _client = SingBox::run(
        &cert,
        "client",
        sing_box_client(&cert, setup, socks_port, server_port),
        socks_port,
    )?;
    common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
    transfer(configs, socks_port, true)
}

/// Each security, both UDP encodings between them, one over TLS.
const INTEROP: [(&str, Setup); 5] = [
    ("aes", setup("aes-128-gcm", false, false, true)),
    ("chacha", setup("chacha20-poly1305", false, true, false)),
    ("none", setup("none", false, true, true)),
    ("zero", setup("zero", false, false, false)),
    ("auto", setup("auto", true, true, false)),
];

/// Runs each setup in turn on the same two ports.
fn interop(to_sing_box: bool, port: u16) -> anyhow::Result<()> {
    for (name, setup) in INTEROP.iter() {
        let result = if to_sing_box {
            sail_to_sing_box(&format!("out-{}", name), *setup, port, port + 1)
        } else {
            sing_box_to_sail(&format!("in-{}", name), *setup, port, port + 1)
        };
        result.map_err(|e| anyhow::anyhow!("{}: {}", name, e))?;
    }
    Ok(())
}

#[test]
#[ignore = "needs sing-box"]
fn test_vmess_sail_to_sing_box() -> anyhow::Result<()> {
    interop(true, 33054)
}

#[test]
#[ignore = "needs sing-box"]
fn test_vmess_sing_box_to_sail() -> anyhow::Result<()> {
    interop(false, 33056)
}
