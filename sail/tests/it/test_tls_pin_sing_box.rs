//! `certificate_public_key_sha256` and the TLS versions, against sing-box
//! both ways: a pin one writes, the other takes. The tests need
//! `/opt/homebrew/bin/sing-box` (or `SING_BOX`), 1.13 or later, and are
//! ignored by default:
//!
//! ```text
//! cargo test -p sail --test it test_tls_pin_sing_box:: -- --ignored
//! ```

#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-tls",
    feature = "inbound-tls",
    feature = "outbound-trojan",
    feature = "inbound-trojan",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

const PASSWORD: &str = "pin-password";

/// A certificate for `localhost` in files, and the pin of its key: the
/// SHA-256 of the SubjectPublicKeyInfo rcgen writes, base64.
struct Certs {
    cert: String,
    key: String,
    pin: String,
    _dir: common::TempDir,
}

fn certs(name: &str) -> anyhow::Result<Certs> {
    let dir = common::TempDir::new(&format!("tls-pin-{}", name))?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    Ok(Certs {
        cert: cert_path.to_string_lossy().into_owned(),
        key: key_path.to_string_lossy().into_owned(),
        pin: btls::base64::encode_block(&btls::sha::sha256(&key_pair.public_key_der())),
        _dir: dir,
    })
}

/// A pin of no key.
fn other_pin() -> String {
    btls::base64::encode_block(&[9; 32])
}

/// A SOCKS inbound on `socks_port` to a trojan server at `server_port`,
/// with the `tls` block `tls`.
fn socks_to_trojan(socks_port: u16, server_port: u16, tls: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [{
            "type": "trojan",
            "server": "127.0.0.1",
            "server_port": server_port,
            "password": PASSWORD,
            "tls": tls,
        }]
    })
}

/// A trojan server on `port`, with `tls` added to its certificate.
fn trojan_server(port: u16, certs: &Certs, tls: serde_json::Value) -> serde_json::Value {
    let mut block = serde_json::json!({
        "enabled": true,
        "certificate_path": certs.cert,
        "key_path": certs.key,
    });
    block
        .as_object_mut()
        .unwrap()
        .extend(tls.as_object().unwrap().clone());
    serde_json::json!({
        "inbounds": [{
            "type": "trojan",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "password": PASSWORD }],
            "tls": block,
        }],
        "outbounds": [{ "type": "direct" }]
    })
}

/// Echoes a few bytes through the SOCKS server at `socks_port`.
async fn echo(socks_port: u16, echo: SocketAddr) -> anyhow::Result<()> {
    let sess = Session {
        destination: SocksAddr::from(echo),
        ..Default::default()
    };
    let mut stream = timeout(
        Duration::from_secs(5),
        common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None),
    )
    .await??;
    timeout(Duration::from_secs(5), async {
        stream.write_all(b"pinned").await?;
        let mut back = [0; 6];
        stream.read_exact(&mut back).await?;
        anyhow::ensure!(&back == b"pinned", "echoed something else");
        anyhow::Ok(())
    })
    .await?
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

// app(socks) -> sail(trojan, pinning) -> sing-box(trojan) -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_sail_pins_sing_box() -> anyhow::Result<()> {
    let certs = certs("to-sing-box")?;
    common::retry_port_clash(|| {
        let [server, tls12_server, pinned, insecure, unpinned, tls13, tls12] = common::free_ports();
        let dir = common::TempDir::new("tls-pin")?;
        let mut config = trojan_server(server, &certs, serde_json::json!({}));
        let tls12_inbound = trojan_server(
            tls12_server,
            &certs,
            serde_json::json!({
                "max_version": "1.2"
            }),
        )["inbounds"][0]
            .clone();
        config["inbounds"]
            .as_array_mut()
            .unwrap()
            .push(tls12_inbound);
        let _sing_box = common::Daemon::sing_box(dir.path(), "server", config)?;
        // The certificate is for localhost: a pin takes it for any name.
        let pin = |port, pins: &[&str], insecure: bool| {
            socks_to_trojan(
                port,
                server,
                serde_json::json!({
                    "enabled": true, "server_name": "example.com", "insecure": insecure,
                    "certificate_public_key_sha256": pins,
                }),
            )
            .to_string()
        };
        let other = other_pin();
        let tls = |port, versions: serde_json::Value| {
            let mut tls = serde_json::json!({
                "enabled": true, "server_name": "localhost",
                "certificate_public_key_sha256": certs.pin,
            });
            tls.as_object_mut()
                .unwrap()
                .extend(versions.as_object().unwrap().clone());
            socks_to_trojan(port, tls12_server, tls).to_string()
        };
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                pin(pinned, &[&other, &certs.pin], false),
                pin(insecure, &[&certs.pin], true),
                pin(unpinned, &[&other], true),
                tls(tls13, serde_json::json!({ "min_version": "1.3" })),
                tls(tls12, serde_json::json!({ "max_version": "1.2" })),
            ],
        )?;
        let result = rt.block_on(async {
            let (echo_addr, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_server = tokio::spawn(echo_server);
            echo(pinned, echo_addr).await?;
            echo(insecure, echo_addr).await?;
            anyhow::ensure!(
                echo(unpinned, echo_addr).await.is_err(),
                "a key not pinned is taken"
            );
            // A server of TLS 1.2 only: kept to by a client of 1.3 only,
            // reached by one of 1.2.
            anyhow::ensure!(
                echo(tls13, echo_addr).await.is_err(),
                "min_version 1.3 took TLS 1.2"
            );
            echo(tls12, echo_addr).await?;
            echo_server.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sing-box(trojan, pinning) -> sail(trojan) -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_sing_box_pins_sail() -> anyhow::Result<()> {
    let certs = certs("from-sing-box")?;
    common::retry_port_clash(|| {
        let [server, pinned, unpinned] = common::free_ports();
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![trojan_server(server, &certs, serde_json::json!({})).to_string()],
        )?;
        let dir = common::TempDir::new("tls-pin")?;
        let client = |port, pin: &str| {
            socks_to_trojan(
                port,
                server,
                serde_json::json!({
                    "enabled": true, "server_name": "localhost",
                    "certificate_public_key_sha256": [pin],
                }),
            )
        };
        let mut config = client(pinned, &certs.pin);
        let unpinned_client = client(unpinned, &other_pin());
        for key in ["inbounds", "outbounds"] {
            let mut entry = unpinned_client[key][0].clone();
            entry["tag"] = serde_json::json!("unpinned");
            config[key][0]["tag"] = serde_json::json!("pinned");
            config[key].as_array_mut().unwrap().push(entry);
        }
        config["route"] = serde_json::json!({
            "rules": [{ "inbound": "unpinned", "outbound": "unpinned" }],
            "final": "pinned",
        });
        let result = common::Daemon::sing_box(dir.path(), "client", config).and_then(|_sing_box| {
            rt.block_on(async {
                let (echo_addr, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
                let echo_server = tokio::spawn(echo_server);
                echo(pinned, echo_addr).await?;
                anyhow::ensure!(
                    echo(unpinned, echo_addr).await.is_err(),
                    "sing-box took a key not pinned"
                );
                echo_server.abort();
                anyhow::Ok(())
            })
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}
