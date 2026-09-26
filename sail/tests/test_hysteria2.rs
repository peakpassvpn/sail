//! Hysteria2 both ways: sail to sail, and against sing-box in either role.
//!
//! The sing-box tests need `sing-box` on the PATH or in
//! /opt/homebrew/bin, and are ignored unless asked for:
//! `cargo test -p sail --test test_hysteria2 -- --ignored`.

#![cfg(all(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

mod common;

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

const PASSWORD: &str = "hy2-password";
const OBFS_PASSWORD: &str = "salamander-password";

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
            std::env::temp_dir().join(format!("sail-hysteria2-{}-{}", name, std::process::id()));
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

fn obfs(salamander: bool) -> serde_json::Value {
    if salamander {
        json!({ "type": "salamander", "password": OBFS_PASSWORD })
    } else {
        serde_json::Value::Null
    }
}

/// Drops the null fields of `value`'s objects, so that options left out
/// are left out of the configuration.
fn prune(mut value: serde_json::Value) -> serde_json::Value {
    fn walk(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                map.retain(|_, v| !v.is_null());
                map.values_mut().for_each(walk);
            }
            serde_json::Value::Array(list) => list.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut value);
    value
}

/// sail: socks on `socks_port`, out through hysteria2 to `server_port`.
fn sail_client(
    cert: &Cert,
    socks_port: u16,
    server_port: u16,
    salamander: bool,
    bandwidth: bool,
) -> String {
    prune(json!({
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
        }],
        "outbounds": [{
            "type": "hysteria2",
            "tag": "hy2",
            "server": "127.0.0.1",
            "server_port": server_port,
            "password": PASSWORD,
            "up_mbps": if bandwidth { json!(100) } else { json!(null) },
            "down_mbps": if bandwidth { json!(100) } else { json!(null) },
            "obfs": obfs(salamander),
            "tls": {
                "enabled": true,
                "server_name": "localhost",
                "certificate": cert.cert_pem,
            },
        }],
    }))
    .to_string()
}

/// sail: hysteria2 on `port`, out direct.
fn sail_server(cert: &Cert, port: u16, salamander: bool, bandwidth: bool) -> String {
    prune(json!({
        "inbounds": [{
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "name": "alice", "password": PASSWORD }],
            "up_mbps": if bandwidth { json!(100) } else { json!(null) },
            "down_mbps": if bandwidth { json!(100) } else { json!(null) },
            "obfs": obfs(salamander),
            "tls": {
                "enabled": true,
                "certificate": cert.cert_pem,
                "key": cert.key_pem,
            },
        }],
        "outbounds": [{ "type": "direct" }],
    }))
    .to_string()
}

#[test]
fn test_hysteria2_sail_to_sail() -> anyhow::Result<()> {
    let cert = Cert::new("sail")?;
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let configs = vec![
            sail_client(&cert, socks_port, server_port, false, false),
            sail_server(&cert, server_port, false, false),
        ];
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", socks_port)?;
        common::test_data_transfering_reliability_on_configs(
            configs.clone(),
            "127.0.0.1",
            socks_port,
        )?;
        transfer(configs, socks_port)
    })
}

#[test]
fn test_hysteria2_sail_to_sail_salamander_brutal() -> anyhow::Result<()> {
    let cert = Cert::new("sail-obfs")?;
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let configs = vec![
            sail_client(&cert, socks_port, server_port, true, true),
            sail_server(&cert, server_port, true, true),
        ];
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        transfer(configs, socks_port)
    })
}

/// A client with the wrong password, or without the obfuscation the
/// server has, gets nowhere.
#[test]
fn test_hysteria2_refuses_the_wrong_credentials() -> anyhow::Result<()> {
    let cert = Cert::new("refuse")?;
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let wrong_password =
            sail_client(&cert, socks_port, server_port, false, false).replace(PASSWORD, "nope");
        let configs = vec![
            wrong_password,
            sail_server(&cert, server_port, false, false),
        ];
        assert!(common::test_configs(configs, "127.0.0.1", socks_port).is_err());

        let [socks_port, server_port] = common::free_ports();
        let no_obfs = sail_client(&cert, socks_port, server_port, false, false);
        let configs = vec![no_obfs, sail_server(&cert, server_port, true, false)];
        assert!(common::test_configs(configs, "127.0.0.1", socks_port).is_err());
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// sing-box
// ---------------------------------------------------------------------------

fn sing_box_server(cert: &Cert, port: u16, salamander: bool, bandwidth: bool) -> serde_json::Value {
    json!({
        "inbounds": [{
            "type": "hysteria2",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "name": "alice", "password": PASSWORD }],
            "up_mbps": if bandwidth { json!(100) } else { json!(null) },
            "down_mbps": if bandwidth { json!(100) } else { json!(null) },
            "obfs": obfs(salamander),
            "tls": {
                "enabled": true,
                "certificate_path": cert.cert_path(),
                "key_path": cert.key_path(),
            },
        }],
        "outbounds": [{ "type": "direct" }],
    })
}

fn sing_box_client(
    cert: &Cert,
    socks_port: u16,
    server_port: u16,
    salamander: bool,
    bandwidth: bool,
) -> serde_json::Value {
    json!({
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
        }],
        "outbounds": [{
            "type": "hysteria2",
            "server": "127.0.0.1",
            "server_port": server_port,
            "password": PASSWORD,
            "up_mbps": if bandwidth { json!(100) } else { json!(null) },
            "down_mbps": if bandwidth { json!(100) } else { json!(null) },
            "obfs": obfs(salamander),
            "tls": {
                "enabled": true,
                "server_name": "localhost",
                "certificate_path": cert.cert_path(),
            },
        }],
    })
}

/// sail outbound -> sing-box inbound.
fn sail_to_sing_box(name: &str, salamander: bool, bandwidth: bool) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let _server = common::Daemon::sing_box(
            &cert.dir,
            "server",
            prune(sing_box_server(&cert, server_port, salamander, bandwidth)),
        )?;
        let configs = vec![sail_client(
            &cert,
            socks_port,
            server_port,
            salamander,
            bandwidth,
        )];
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        transfer(configs, socks_port)
    })
}

/// sing-box outbound -> sail inbound.
fn sing_box_to_sail(name: &str, salamander: bool, bandwidth: bool) -> anyhow::Result<()> {
    let cert = Cert::new(name)?;
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let configs = vec![sail_server(&cert, server_port, salamander, bandwidth)];
        // A sing-box client keeps its connection to the sail it saw last
        // until that times out, and each test runs sail anew: a fresh
        // client each.
        let client = || {
            common::Daemon::sing_box(
                &cert.dir,
                "client",
                prune(sing_box_client(
                    &cert,
                    socks_port,
                    server_port,
                    salamander,
                    bandwidth,
                )),
            )
        };
        let sing_box = client()?;
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        drop(sing_box);
        let _sing_box = client()?;
        transfer(configs, socks_port)
    })
}

/// Runs `configs` and, through the socks server on `socks_port`, echoes
/// megabytes over TCP and UDP packets large enough to be fragmented.
///
/// Not the common reliability test, which runs sail anew for each
/// direction; see `sing_box_to_sail`.
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
        // Echoes packets of any size, unlike the common one.
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
        // Above a QUIC datagram, below sail's 2 KiB datagram buffer.
        for size in [100usize, 1500, 2000] {
            let mut packet = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut packet);
            w.send_to(&packet, &sess.destination).await?;
            let mut buf = vec![0u8; 4096];
            let (n, from) = timeout(Duration::from_secs(10), r.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("UDP echo of {} bytes timed out", size))??;
            anyhow::ensure!(buf[..n] == packet[..], "UDP echo of {} bytes differs", size);
            anyhow::ensure!(from == sess.destination, "UDP echo from {}", from);
        }
        tcp_echo.abort();
        udp_echo.abort();
        Ok::<(), anyhow::Error>(())
    });
    common::shutdown_instances(&rt, ids);
    result
}

#[test]
#[ignore = "needs sing-box"]
fn test_hysteria2_sail_to_sing_box() -> anyhow::Result<()> {
    sail_to_sing_box("out-plain", false, false)
}

#[test]
#[ignore = "needs sing-box"]
fn test_hysteria2_sail_to_sing_box_salamander_brutal() -> anyhow::Result<()> {
    sail_to_sing_box("out-obfs", true, true)
}

#[test]
#[ignore = "needs sing-box"]
fn test_hysteria2_sing_box_to_sail() -> anyhow::Result<()> {
    sing_box_to_sail("in-plain", false, false)
}

#[test]
#[ignore = "needs sing-box"]
fn test_hysteria2_sing_box_to_sail_salamander_brutal() -> anyhow::Result<()> {
    sing_box_to_sail("in-obfs", true, true)
}
