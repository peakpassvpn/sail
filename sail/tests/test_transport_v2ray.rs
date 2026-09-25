//! The V2Ray transports -- WebSocket with early data, HTTPUpgrade, gRPC --
//! under Trojan: sail to sail, and against sing-box in either role.
//!
//! Not under VLESS. sail has no VLESS inbound, and its VLESS outbound always
//! asks for the `xtls-rprx-vision` flow, which sing-box serves over TLS
//! directly and nothing else: over any of these transports it refuses the
//! connection ("vision: not a valid supported TLS connection").
//!
//! The sing-box tests need `sing-box` on the PATH or in /opt/homebrew/bin,
//! and are ignored unless asked for:
//! `cargo test -p sail --test test_transport_v2ray -- --ignored`.
//!
//! Ports 32800-32899 only.

#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "inbound-trojan",
    feature = "outbound-trojan",
    feature = "inbound-tls",
    feature = "outbound-tls",
    feature = "inbound-ws",
    feature = "outbound-ws",
    feature = "inbound-httpupgrade",
    feature = "outbound-httpupgrade",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const PASSWORD: &str = "transport-password";

/// A self-signed certificate for localhost, as PEM, and as files for
/// sing-box.
struct Cert {
    cert_pem: String,
    key_pem: String,
    dir: PathBuf,
}

impl Cert {
    fn new(name: &str) -> anyhow::Result<Self> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let dir =
            std::env::temp_dir().join(format!("sail-transport-{}-{}", name, std::process::id()));
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

/// How a case is carried: the transport block, the same for both ends and
/// both implementations, and whether under TLS.
#[derive(Clone)]
struct Carriage {
    transport: Value,
    tls: bool,
}

fn ws_early_data_in_path() -> Value {
    json!({ "type": "ws", "path": "/sail-ws", "max_early_data": 2048 })
}

fn ws_early_data_in_header() -> Value {
    json!({
        "type": "ws",
        "path": "/sail-ws",
        "max_early_data": 2048,
        "early_data_header_name": "Sec-WebSocket-Protocol",
    })
}

fn trojan_outbound(server_port: u16) -> Value {
    json!({
        "type": "trojan",
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": server_port,
        "password": PASSWORD,
    })
}

fn trojan_inbound(port: u16) -> Value {
    json!({
        "type": "trojan",
        "tag": "in",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "name": "alice", "password": PASSWORD }],
    })
}

/// sail or sing-box: socks on `socks_port`, out through Trojan over
/// `carriage` to `server_port`.
fn client(
    sing_box: bool,
    cert: &Cert,
    carriage: &Carriage,
    socks_port: u16,
    server_port: u16,
) -> Value {
    let mut outbound = trojan_outbound(server_port);
    outbound["transport"] = carriage.transport.clone();
    if carriage.tls {
        outbound["tls"] = if sing_box {
            json!({
                "enabled": true,
                "server_name": "localhost",
                "certificate_path": cert.cert_path(),
            })
        } else {
            json!({
                "enabled": true,
                "server_name": "localhost",
                "certificate": cert.cert_pem,
            })
        };
    }
    json!({
        "log": { "level": if sing_box { "warn" } else { "info" } },
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
        }],
        "outbounds": [outbound],
    })
}

/// sail or sing-box: Trojan over `carriage` on `port`, out direct.
fn server(sing_box: bool, cert: &Cert, carriage: &Carriage, port: u16) -> Value {
    let mut inbound = trojan_inbound(port);
    inbound["transport"] = carriage.transport.clone();
    if carriage.tls {
        inbound["tls"] = if sing_box {
            json!({
                "enabled": true,
                "certificate_path": cert.cert_path(),
                "key_path": cert.key_path(),
            })
        } else {
            json!({
                "enabled": true,
                "certificate": cert.cert_pem,
                "key": cert.key_pem,
            })
        };
    }
    json!({
        "log": { "level": if sing_box { "warn" } else { "info" } },
        "inbounds": [inbound],
        "outbounds": [{ "type": "direct" }],
    })
}

/// sail to sail, with the common echo test, a transfer, and
/// the half-close one for a transport that carries a half close. WebSocket
/// does only when `ws.half_close` is set, which it is not here.
fn sail_to_sail(
    name: &str,
    carriage: Carriage,
    half_close: bool,
    socks_port: u16,
    server_port: u16,
) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    let configs = vec![
        client(false, &cert, &carriage, socks_port, server_port).to_string(),
        server(false, &cert, &carriage, server_port).to_string(),
    ];
    common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
    if half_close {
        common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", socks_port)?;
    }
    transfer(configs, socks_port)
}

/// Runs `configs` and, through the socks server on `socks_port`, echoes
/// megabytes over TCP, and UDP packets up to 2000 bytes.
///
/// Not the common reliability test, whose files have fixed names and so
/// cannot run alongside another in the same binary.
fn transfer(configs: Vec<String>, socks_port: u16) -> anyhow::Result<()> {
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
        for size in [100usize, 1500, 2000] {
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
    for id in ids {
        sail::shutdown(id);
    }
    result
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
    /// Runs sing-box with `config` and waits for it to listen on `port`.
    fn run(cert: &Cert, name: &str, config: Value, port: u16) -> anyhow::Result<Self> {
        let path = cert.dir.join(format!("{}.json", name));
        std::fs::write(&path, config.to_string())?;
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
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(sing_box);
            }
            if Instant::now() > deadline {
                return Err(anyhow::anyhow!("sing-box did not listen on {}", port));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// sail outbound -> sing-box inbound.
fn sail_to_sing_box(
    name: &str,
    carriage: Carriage,
    socks_port: u16,
    server_port: u16,
) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    let _server = SingBox::run(
        &cert,
        "server",
        server(true, &cert, &carriage, server_port),
        server_port,
    )?;
    let configs = vec![client(false, &cert, &carriage, socks_port, server_port).to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
    transfer(configs, socks_port)
}

/// sing-box outbound -> sail inbound.
fn sing_box_to_sail(
    name: &str,
    carriage: Carriage,
    socks_port: u16,
    server_port: u16,
) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    let configs = vec![server(false, &cert, &carriage, server_port).to_string()];
    // A sing-box client may keep its connection to the sail it saw last,
    // and each common test runs sail anew: a fresh client each.
    let client = || {
        SingBox::run(
            &cert,
            "client",
            client(true, &cert, &carriage, socks_port, server_port),
            socks_port,
        )
    };
    let sing_box = client()?;
    common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
    drop(sing_box);
    let _sing_box = client()?;
    transfer(configs, socks_port)
}

/// Both ways against sing-box, on the four ports from `port` on.
fn against_sing_box(name: &str, carriage: Carriage, port: u16) -> anyhow::Result<()> {
    sail_to_sing_box(&format!("{}-out", name), carriage.clone(), port, port + 1)?;
    sing_box_to_sail(&format!("{}-in", name), carriage, port + 2, port + 3)
}

// ---------------------------------------------------------------------------
// WebSocket, early data
// ---------------------------------------------------------------------------

#[test]
fn test_ws_early_data_in_path_sail_to_sail() -> anyhow::Result<()> {
    let carriage = Carriage {
        transport: ws_early_data_in_path(),
        tls: false,
    };
    sail_to_sail("ws-path", carriage, false, 32800, 32801)
}

#[test]
fn test_ws_early_data_in_header_sail_to_sail_tls() -> anyhow::Result<()> {
    let carriage = Carriage {
        transport: ws_early_data_in_header(),
        tls: true,
    };
    sail_to_sail("ws-header", carriage, false, 32802, 32803)
}

/// A client with no early data at a server that takes it, and one with
/// early data in the path at a server that expects none, which refuses it.
#[test]
fn test_ws_early_data_mismatch() -> anyhow::Result<()> {
    let cert = Cert::new("ws-mismatch")?;
    let plain = Carriage {
        transport: json!({ "type": "ws", "path": "/sail-ws" }),
        tls: false,
    };
    let early = Carriage {
        transport: ws_early_data_in_header(),
        tls: false,
    };
    let configs = vec![
        client(false, &cert, &plain, 32804, 32805).to_string(),
        server(false, &cert, &early, 32805).to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 32804)?;

    let in_path = Carriage {
        transport: ws_early_data_in_path(),
        tls: false,
    };
    let configs = vec![
        client(false, &cert, &in_path, 32806, 32807).to_string(),
        server(false, &cert, &plain, 32807).to_string(),
    ];
    assert!(common::test_configs(configs, "127.0.0.1", 32806).is_err());
    Ok(())
}

#[test]
#[ignore = "needs sing-box"]
fn test_ws_early_data_in_path_sing_box() -> anyhow::Result<()> {
    let carriage = Carriage {
        transport: ws_early_data_in_path(),
        tls: false,
    };
    against_sing_box("ws-path", carriage, 32810)
}

#[test]
#[ignore = "needs sing-box"]
fn test_ws_early_data_in_header_sing_box_tls() -> anyhow::Result<()> {
    let carriage = Carriage {
        transport: ws_early_data_in_header(),
        tls: true,
    };
    against_sing_box("ws-header", carriage, 32820)
}

// ---------------------------------------------------------------------------
// HTTPUpgrade
// ---------------------------------------------------------------------------

fn httpupgrade() -> Value {
    json!({
        "type": "httpupgrade",
        "host": "upgrade.example",
        "path": "/sail-up",
        "headers": { "X-Sail": "1" },
    })
}

#[test]
fn test_httpupgrade_sail_to_sail() -> anyhow::Result<()> {
    let carriage = Carriage {
        transport: httpupgrade(),
        tls: false,
    };
    sail_to_sail("up", carriage, true, 32830, 32831)
}

#[test]
fn test_httpupgrade_sail_to_sail_tls() -> anyhow::Result<()> {
    let carriage = Carriage {
        transport: httpupgrade(),
        tls: true,
    };
    sail_to_sail("up-tls", carriage, true, 32832, 32833)
}

/// A client asking for another host or path is turned away.
#[test]
fn test_httpupgrade_wrong_host_or_path() -> anyhow::Result<()> {
    let cert = Cert::new("up-wrong")?;
    let server_side = Carriage {
        transport: httpupgrade(),
        tls: false,
    };
    for (i, transport) in [
        json!({ "type": "httpupgrade", "host": "other.example", "path": "/sail-up" }),
        json!({ "type": "httpupgrade", "host": "upgrade.example", "path": "/other" }),
    ]
    .into_iter()
    .enumerate()
    {
        let port = 32834 + 2 * i as u16;
        let client_side = Carriage {
            transport,
            tls: false,
        };
        let configs = vec![
            client(false, &cert, &client_side, port, port + 1).to_string(),
            server(false, &cert, &server_side, port + 1).to_string(),
        ];
        assert!(common::test_configs(configs, "127.0.0.1", port).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "needs sing-box"]
fn test_httpupgrade_sing_box() -> anyhow::Result<()> {
    let carriage = Carriage {
        transport: httpupgrade(),
        tls: false,
    };
    against_sing_box("up", carriage, 32840)
}

#[test]
#[ignore = "needs sing-box"]
fn test_httpupgrade_sing_box_tls() -> anyhow::Result<()> {
    let carriage = Carriage {
        transport: httpupgrade(),
        tls: true,
    };
    against_sing_box("up-tls", carriage, 32844)
}
