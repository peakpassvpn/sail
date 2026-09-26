//! VLESS both ways: sail to sail, and against sing-box in either role; with
//! and without XTLS Vision, TCP and UDP, the latter as VLESS's own UDP or as
//! XUDP.
//!
//! The sing-box tests need `sing-box` on the PATH or in
//! /opt/homebrew/bin, and are ignored unless asked for:
//! `cargo test -p sail --test test_vless -- --ignored`.

#![cfg(all(
    feature = "inbound-vless",
    feature = "outbound-vless",
    feature = "inbound-tls",
    feature = "outbound-tls",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const VISION: &str = "xtls-rprx-vision";

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
        let dir = std::env::temp_dir().join(format!("sail-vless-{}-{}", name, std::process::id()));
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
#[derive(Clone, Copy)]
struct Setup {
    tls: bool,
    flow: &'static str,
    /// `packet_encoding` of the client.
    xudp: bool,
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

fn sail_client(cert: &Cert, setup: Setup, socks_port: u16, server_port: u16, uuid: &str) -> String {
    prune(json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [{
            "type": "vless",
            "server": "127.0.0.1",
            "server_port": server_port,
            "uuid": uuid,
            "flow": setup.flow,
            "packet_encoding": if setup.xudp { "xudp" } else { "" },
            "tls": client_tls(cert, setup),
        }],
    }))
    .to_string()
}

fn sail_server(cert: &Cert, setup: Setup, port: u16) -> String {
    prune(json!({
        "inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "name": "alice", "uuid": UUID, "flow": setup.flow }],
            "tls": server_tls(cert, setup),
        }],
        "outbounds": [{ "type": "direct" }],
    }))
    .to_string()
}

fn sail_to_sail(name: &str, setup: Setup) -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let cert = Cert::new(name)?;
        let configs = vec![
            sail_client(&cert, setup, socks_port, server_port, UUID),
            sail_server(&cert, setup, server_port),
        ];
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        transfer(configs, socks_port, setup.flow == VISION)
    })
}

#[test]
fn test_vless_sail_to_sail_plain_udp() -> anyhow::Result<()> {
    let setup = Setup {
        tls: false,
        flow: "",
        xudp: false,
    };
    sail_to_sail("plain", setup)
}

#[test]
fn test_vless_sail_to_sail_xudp() -> anyhow::Result<()> {
    let setup = Setup {
        tls: false,
        flow: "",
        xudp: true,
    };
    sail_to_sail("xudp", setup)
}

#[test]
fn test_vless_sail_to_sail_tls() -> anyhow::Result<()> {
    let setup = Setup {
        tls: true,
        flow: "",
        xudp: true,
    };
    sail_to_sail("tls", setup)
}

#[test]
fn test_vless_sail_to_sail_tls_vision() -> anyhow::Result<()> {
    let setup = Setup {
        tls: true,
        flow: VISION,
        xudp: true,
    };
    sail_to_sail("vision", setup)
}

#[test]
fn test_vless_refuses_unknown_user_and_wrong_flow() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, server_port, socks_port2, server_port2] = common::free_ports();
        let cert = Cert::new("refuse")?;
        let setup = Setup {
            tls: true,
            flow: "",
            xudp: true,
        };
        let configs = vec![
            sail_client(
                &cert,
                setup,
                socks_port,
                server_port,
                "00000000-0000-0000-0000-000000000001",
            ),
            sail_server(&cert, setup, server_port),
        ];
        assert!(common::test_configs(configs, "127.0.0.1", socks_port).is_err());
        // A Vision user cannot go without Vision over TCP.
        let vision = Setup {
            flow: VISION,
            ..setup
        };
        let configs = vec![
            sail_client(&cert, setup, socks_port2, server_port2, UUID),
            sail_server(&cert, vision, server_port2),
        ];
        assert!(common::test_configs(configs, "127.0.0.1", socks_port2).is_err());
        Ok(())
    })
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

fn sing_box_server(cert: &Cert, setup: Setup, port: u16) -> serde_json::Value {
    json!({
        "inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "name": "alice", "uuid": UUID, "flow": setup.flow }],
            "tls": server_tls(cert, setup),
        }],
        "outbounds": [{ "type": "direct" }],
    })
}

fn sing_box_client(
    cert: &Cert,
    setup: Setup,
    socks_port: u16,
    server_port: u16,
) -> serde_json::Value {
    json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [{
            "type": "vless",
            "server": "127.0.0.1",
            "server_port": server_port,
            "uuid": UUID,
            "flow": setup.flow,
            "packet_encoding": if setup.xudp { "xudp" } else { "" },
            "tls": client_tls(cert, setup),
        }],
    })
}

/// sail outbound -> sing-box inbound.
fn sail_to_sing_box(name: &str, setup: Setup) -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let cert = Cert::new(name)?;
        let _server = common::Daemon::sing_box(
            &cert.dir,
            "server",
            prune(sing_box_server(&cert, setup, server_port)),
        )?;
        let configs = vec![sail_client(&cert, setup, socks_port, server_port, UUID)];
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        transfer(configs, socks_port, setup.flow == VISION)
    })
}

/// sing-box outbound -> sail inbound.
fn sing_box_to_sail(name: &str, setup: Setup) -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let cert = Cert::new(name)?;
        let configs = vec![sail_server(&cert, setup, server_port)];
        let _client = common::Daemon::sing_box(
            &cert.dir,
            "client",
            prune(sing_box_client(&cert, setup, socks_port, server_port)),
        )?;
        common::test_configs(configs.clone(), "127.0.0.1", socks_port)?;
        transfer(configs, socks_port, setup.flow == VISION)
    })
}

const TLS_PLAIN_UDP: Setup = Setup {
    tls: true,
    flow: "",
    xudp: false,
};
const TLS_XUDP: Setup = Setup {
    tls: true,
    flow: "",
    xudp: true,
};
const TLS_VISION: Setup = Setup {
    tls: true,
    flow: VISION,
    xudp: true,
};

#[test]
#[ignore = "needs sing-box"]
fn test_vless_sail_to_sing_box_tls() -> anyhow::Result<()> {
    sail_to_sing_box("out-tls", TLS_PLAIN_UDP)
}

#[test]
#[ignore = "needs sing-box"]
fn test_vless_sail_to_sing_box_tls_xudp() -> anyhow::Result<()> {
    sail_to_sing_box("out-xudp", TLS_XUDP)
}

#[test]
#[ignore = "needs sing-box"]
fn test_vless_sail_to_sing_box_vision() -> anyhow::Result<()> {
    sail_to_sing_box("out-vision", TLS_VISION)
}

#[test]
#[ignore = "needs sing-box"]
fn test_vless_sing_box_to_sail_tls() -> anyhow::Result<()> {
    sing_box_to_sail("in-tls", TLS_PLAIN_UDP)
}

#[test]
#[ignore = "needs sing-box"]
fn test_vless_sing_box_to_sail_tls_xudp() -> anyhow::Result<()> {
    sing_box_to_sail("in-xudp", TLS_XUDP)
}

#[test]
#[ignore = "needs sing-box"]
fn test_vless_sing_box_to_sail_vision() -> anyhow::Result<()> {
    sing_box_to_sail("in-vision", TLS_VISION)
}
/// The ALPN a plain TLS client offering `offered` gets from a VLESS
/// inbound, with the TLS block `inbound_tls` and `transport` inside it.
fn negotiated_alpn(
    inbound_tls: serde_json::Value,
    transport: serde_json::Value,
    offered: &[&str],
) -> anyhow::Result<Option<String>> {
    use btls::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let port = common::free_port();
    let config = prune(json!({
        "inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{ "uuid": UUID }],
            "tls": inbound_tls,
            "transport": transport,
        }],
        "outbounds": [{ "type": "direct" }],
    }));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
    let mut wire = Vec::new();
    for p in offered {
        wire.push(p.len() as u8);
        wire.extend_from_slice(p.as_bytes());
    }
    // The listener runs on `rt`, which must be polled while the blocking
    // handshake runs on a thread of its own.
    let handshake = std::thread::spawn(move || -> anyhow::Result<Option<String>> {
        let tcp = TcpStream::connect(("127.0.0.1", port))?;
        let mut connector = SslConnector::builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::NONE);
        connector.set_alpn_protos(&wire)?;
        let stream = connector
            .build()
            .connect("localhost", tcp)
            .map_err(|e| anyhow::anyhow!("TLS connect: {}", e))?;
        Ok(stream
            .ssl()
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()))
    });
    rt.block_on(async {
        while !handshake.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    for id in ids {
        sail::shutdown(id);
    }
    handshake
        .join()
        .map_err(|_| anyhow::anyhow!("handshake thread panicked"))?
}

#[test]
fn test_vless_inbound_tls_alpn() -> anyhow::Result<()> {
    let cert = Cert::new("alpn")?;
    let mut tls = server_tls(&cert, TLS_XUDP);
    // Unset, bare TLS offers none.
    let alpn = common::retry_port_clash(|| {
        negotiated_alpn(tls.clone(), json!(null), &["h2", "http/1.1"])
    })?;
    assert_eq!(alpn, None);
    // Set, the server's preference wins among what the client offers, and
    // a client offering none of it gets none rather than an alert.
    tls["alpn"] = json!(["h2", "http/1.1"]);
    let alpn = common::retry_port_clash(|| {
        negotiated_alpn(tls.clone(), json!(null), &["http/1.1", "h2"])
    })?;
    assert_eq!(alpn.as_deref(), Some("h2"));
    let alpn = common::retry_port_clash(|| negotiated_alpn(tls.clone(), json!(null), &["h3"]))?;
    assert_eq!(alpn, None);
    Ok(())
}

#[cfg(feature = "inbound-ws")]
#[test]
fn test_vless_inbound_tls_alpn_defaults_from_ws() -> anyhow::Result<()> {
    let cert = Cert::new("alpn-ws")?;
    let alpn = common::retry_port_clash(|| {
        negotiated_alpn(
            server_tls(&cert, TLS_XUDP),
            json!({ "type": "ws" }),
            &["h2", "http/1.1"],
        )
    })?;
    assert_eq!(alpn.as_deref(), Some("http/1.1"));
    Ok(())
}

/// Full cone, which XUDP is for: a packet to one address, and replies
/// from it and from another address the destination hands ours to, each
/// with the address it came from.
fn full_cone(configs: Vec<String>, socks_port: u16) -> anyhow::Result<()> {
    use sail::session::{Session, SocksAddr};
    use tokio::time::timeout;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = rt.block_on(async {
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let (a_addr, b_addr) = (a.local_addr()?, b.local_addr()?);
        let servers = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, from) = a.recv_from(&mut buf).await?;
            a.send_to(&buf[..n], from).await?;
            b.send_to(b"from b", from).await?;
            Ok::<_, std::io::Error>(())
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sess = Session {
            destination: SocksAddr::Ip(a_addr),
            ..Default::default()
        };
        let dgram = common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None).await?;
        let (mut r, mut w) = dgram.split();
        w.send_to(b"to a", &sess.destination).await?;
        let mut got = Vec::new();
        for _ in 0..2 {
            let mut buf = [0u8; 64];
            let (n, from) = timeout(Duration::from_secs(2), r.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("full cone reply timed out"))??;
            got.push((buf[..n].to_vec(), from));
        }
        got.sort_by_key(|(data, _)| data.clone());
        anyhow::ensure!(
            got == vec![
                (b"from b".to_vec(), SocksAddr::Ip(b_addr)),
                (b"to a".to_vec(), SocksAddr::Ip(a_addr)),
            ],
            "replies {:?}",
            got
        );
        servers.await??;
        Ok::<(), anyhow::Error>(())
    });
    for id in ids {
        sail::shutdown(id);
    }
    result
}

#[test]
fn test_vless_xudp_full_cone() -> anyhow::Result<()> {
    let cert = Cert::new("cone")?;
    let setup = Setup {
        tls: false,
        flow: "",
        xudp: true,
    };
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        full_cone(
            vec![
                sail_client(&cert, setup, socks_port, server_port, UUID),
                sail_server(&cert, setup, server_port),
            ],
            socks_port,
        )
    })
}

#[test]
#[ignore = "needs sing-box"]
fn test_vless_xudp_full_cone_sing_box() -> anyhow::Result<()> {
    let cert = Cert::new("cone-sb")?;
    // sail to sing-box.
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let _server = common::Daemon::sing_box(
            &cert.dir,
            "server",
            prune(sing_box_server(&cert, TLS_VISION, server_port)),
        )?;
        full_cone(
            vec![sail_client(
                &cert,
                TLS_VISION,
                socks_port,
                server_port,
                UUID,
            )],
            socks_port,
        )
    })?;
    // sing-box to sail.
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let _client = common::Daemon::sing_box(
            &cert.dir,
            "client",
            prune(sing_box_client(&cert, TLS_XUDP, socks_port, server_port)),
        )?;
        full_cone(vec![sail_server(&cert, TLS_XUDP, server_port)], socks_port)
    })
}
