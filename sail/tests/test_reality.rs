//! REALITY both ways, carrying VLESS with Vision: sail to sail, against
//! sing-box in either role, and what a prober that is not a REALITY
//! client sees -- the handshake server, here a local TLS site.
//!
//! The sing-box tests need `sing-box` on the PATH or in
//! /opt/homebrew/bin, and are ignored unless asked for:
//! `cargo test -p sail --test test_reality -- --ignored`.
//!
//! Ports 33070-33099 only.

#![cfg(all(
    feature = "inbound-reality",
    feature = "outbound-reality",
    feature = "inbound-vless",
    feature = "outbound-vless",
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

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const VISION: &str = "xtls-rprx-vision";
const SHORT_ID: &str = "0123456789abcdef";
const SERVER_NAME: &str = "localhost";
/// What the local site says to whoever it serves.
const SITE_GREETING: &[u8] = b"the real site\n";

/// A self-signed certificate for localhost, as files.
struct Cert {
    cert_pem: String,
    key_pem: String,
    dir: PathBuf,
}

impl Cert {
    fn new(name: &str) -> anyhow::Result<Self> {
        // Names enough to make the site's certificate the size of a real
        // one: a REALITY server takes a first encrypted record of 512 bytes
        // or less for EncryptedExtensions alone, and waits for the
        // certificate in a record of its own.
        let mut names = vec!["localhost".to_string()];
        names.extend((0..16).map(|i| format!("host-{}.sail.example", i)));
        let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(names)?;
        let dir =
            std::env::temp_dir().join(format!("sail-reality-{}-{}", name, std::process::id()));
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

/// An X25519 key pair, base64url as Xray and sing-box write it.
struct Keys {
    private: String,
    public: String,
}

impl Keys {
    fn new() -> Self {
        let mut private = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut private);
        let mut public = [0u8; 32];
        // SAFETY: both are 32 bytes.
        unsafe { btls_sys::X25519_public_from_private(public.as_mut_ptr(), private.as_ptr()) };
        Keys {
            private: URL_SAFE_NO_PAD.encode(private),
            public: URL_SAFE_NO_PAD.encode(public),
        }
    }
}

/// A TLS site on a thread, the handshake server REALITY imitates: it
/// greets each client and then reads until it goes away.
struct Site {
    port: u16,
    certificate_der: Vec<u8>,
}

impl Site {
    fn run(cert: &Cert) -> anyhow::Result<Self> {
        use btls::pkey::PKey;
        use btls::ssl::{SslAcceptor, SslMethod};
        use btls::x509::X509;

        let x509 = X509::from_pem(cert.cert_pem.as_bytes())?;
        let key = PKey::private_key_from_pem(cert.key_pem.as_bytes())?;
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        acceptor.set_certificate(&x509)?;
        acceptor.set_private_key(&key)?;
        let acceptor = std::sync::Arc::new(acceptor.build());
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { return };
                let acceptor = acceptor.clone();
                std::thread::spawn(move || {
                    if let Ok(mut tls) = acceptor.accept(tcp) {
                        let _ = tls.write_all(SITE_GREETING);
                        let mut buf = [0u8; 1024];
                        while matches!(tls.read(&mut buf), Ok(n) if n > 0) {}
                    }
                });
            }
        });
        Ok(Site {
            port,
            certificate_der: x509.to_der()?,
        })
    }
}

fn reality_server_tls(keys: &Keys, site: &Site) -> serde_json::Value {
    json!({
        "enabled": true,
        "server_name": SERVER_NAME,
        "reality": {
            "enabled": true,
            "handshake": { "server": "127.0.0.1", "server_port": site.port },
            "private_key": keys.private,
            "short_id": [SHORT_ID, "ab"],
            "max_time_difference": "1m",
        },
    })
}

fn reality_client_tls(keys: &Keys, short_id: &str) -> serde_json::Value {
    json!({
        "enabled": true,
        "server_name": SERVER_NAME,
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": { "enabled": true, "public_key": keys.public, "short_id": short_id },
    })
}

fn vless_inbound(keys: &Keys, site: &Site, port: u16) -> serde_json::Value {
    json!({
        "type": "vless",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "name": "alice", "uuid": UUID, "flow": VISION }],
        "tls": reality_server_tls(keys, site),
    })
}

fn vless_outbound(keys: &Keys, server_port: u16, short_id: &str) -> serde_json::Value {
    json!({
        "type": "vless",
        "server": "127.0.0.1",
        "server_port": server_port,
        "uuid": UUID,
        "flow": VISION,
        "packet_encoding": "xudp",
        "tls": reality_client_tls(keys, short_id),
    })
}

fn sail_client(keys: &Keys, socks_port: u16, server_port: u16, short_id: &str) -> String {
    prune(json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [vless_outbound(keys, server_port, short_id)],
    }))
    .to_string()
}

fn sail_server(keys: &Keys, site: &Site, port: u16) -> String {
    prune(json!({
        "inbounds": [vless_inbound(keys, site, port)],
        "outbounds": [{ "type": "direct" }],
    }))
    .to_string()
}

#[test]
fn test_reality_sail_to_sail() -> anyhow::Result<()> {
    let cert = Cert::new("sail")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let configs = vec![
        sail_client(&keys, 33070, 33071, SHORT_ID),
        sail_server(&keys, &site, 33071),
    ];
    common::test_configs(configs.clone(), "127.0.0.1", 33070)?;
    transfer(configs, 33070, true)?;
    // A short ID the server lists, given short.
    let configs = vec![
        sail_client(&keys, 33070, 33071, "ab"),
        sail_server(&keys, &site, 33071),
    ];
    common::test_configs(configs, "127.0.0.1", 33070)
}

#[test]
fn test_reality_refuses_unknown_short_id_and_key() -> anyhow::Result<()> {
    let cert = Cert::new("refuse")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let configs = vec![
        sail_client(&keys, 33072, 33073, "cd"),
        sail_server(&keys, &site, 33073),
    ];
    assert!(common::test_configs(configs, "127.0.0.1", 33072).is_err());
    let configs = vec![
        sail_client(&Keys::new(), 33072, 33073, SHORT_ID),
        sail_server(&keys, &site, 33073),
    ];
    assert!(common::test_configs(configs, "127.0.0.1", 33072).is_err());
    Ok(())
}

/// What a TLS client that is not a REALITY client sees at `port`: the
/// certificate it is shown and the first line it reads.
fn probe(port: u16, server_name: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use btls::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let tcp = TcpStream::connect(("127.0.0.1", port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);
    let mut tls = connector
        .build()
        .connect(server_name, tcp)
        .map_err(|e| anyhow::anyhow!("probe TLS connect: {}", e))?;
    let certificate = tls
        .ssl()
        .peer_certificate()
        .ok_or_else(|| anyhow::anyhow!("no certificate"))?
        .to_der()?;
    let mut greeting = vec![0u8; SITE_GREETING.len()];
    tls.read_exact(&mut greeting)?;
    Ok((certificate, greeting))
}

#[test]
fn test_reality_probes_see_the_handshake_server() -> anyhow::Result<()> {
    let cert = Cert::new("probe")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, vec![sail_server(&keys, &site, 33074)])?;
    // The prober blocks; the sail instance runs on `rt`, polled meanwhile.
    let prober = std::thread::spawn(|| -> anyhow::Result<()> {
        for server_name in [SERVER_NAME, "other.example"] {
            let (certificate, greeting) = probe(33074, server_name)
                .map_err(|e| anyhow::anyhow!("probe {}: {}", server_name, e))?;
            anyhow::ensure!(greeting == SITE_GREETING, "greeting {:?}", greeting);
            let _ = certificate;
        }
        // Not TLS at all: relayed all the same, and the site's TLS stack
        // hangs up rather than anyone waiting for more.
        let mut tcp = TcpStream::connect(("127.0.0.1", 33074))?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        tcp.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        let mut reply = Vec::new();
        tcp.read_to_end(&mut reply)
            .map_err(|e| anyhow::anyhow!("plain probe: {}", e))?;
        Ok(())
    });
    let site_certificate = site.certificate_der.clone();
    let result = rt.block_on(async {
        while !prober.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        prober
            .join()
            .map_err(|_| anyhow::anyhow!("prober panicked"))?
    });
    for id in ids {
        sail::shutdown(id);
    }
    result?;
    // And the certificate was the site's, not a REALITY one.
    let (certificate, _) = {
        let ids = common::run_sail_instances(&rt, vec![sail_server(&keys, &site, 33075)])?;
        let prober = std::thread::spawn(|| probe(33075, SERVER_NAME));
        rt.block_on(async {
            while !prober.is_finished() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        for id in ids {
            sail::shutdown(id);
        }
        prober
            .join()
            .map_err(|_| anyhow::anyhow!("prober panicked"))??
    };
    anyhow::ensure!(
        certificate == site_certificate,
        "not the site's certificate"
    );
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

fn sing_box_server(keys: &Keys, site: &Site, port: u16) -> serde_json::Value {
    json!({
        "log": { "level": "warn" },
        "inbounds": [vless_inbound(keys, site, port)],
        "outbounds": [{ "type": "direct" }],
    })
}

fn sing_box_client(keys: &Keys, socks_port: u16, server_port: u16) -> serde_json::Value {
    json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [vless_outbound(keys, server_port, SHORT_ID)],
    })
}

#[test]
#[ignore = "needs sing-box"]
fn test_reality_sail_to_sing_box() -> anyhow::Result<()> {
    let cert = Cert::new("out")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let _server = SingBox::run(&cert, "server", sing_box_server(&keys, &site, 33081), 33081)?;
    let configs = vec![sail_client(&keys, 33080, 33081, SHORT_ID)];
    common::test_configs(configs.clone(), "127.0.0.1", 33080)?;
    transfer(configs, 33080, true)
}

#[test]
#[ignore = "needs sing-box"]
fn test_reality_sing_box_to_sail() -> anyhow::Result<()> {
    let cert = Cert::new("in")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let configs = vec![sail_server(&keys, &site, 33083)];
    let _client = SingBox::run(&cert, "client", sing_box_client(&keys, 33082, 33083), 33082)?;
    common::test_configs(configs.clone(), "127.0.0.1", 33082)?;
    transfer(configs, 33082, true)
}

#[test]
fn test_reality_config_mistakes_are_errors() -> anyhow::Result<()> {
    let cert = Cert::new("config")?;
    let site = Site {
        port: 1,
        certificate_der: Vec::new(),
    };
    let keys = Keys::new();
    let check = |inbound: serde_json::Value| -> anyhow::Result<()> {
        let config = json!({ "inbounds": [inbound], "outbounds": [{ "type": "direct" }] });
        let config = sail::config::from_string(&config.to_string())?;
        sail::check_config(&config, &Default::default())
    };
    assert!(check(vless_inbound(&keys, &site, 33090)).is_ok());
    let mut with_certificate = vless_inbound(&keys, &site, 33090);
    with_certificate["tls"]["certificate_path"] = json!(cert.cert_path());
    assert!(check(with_certificate).is_err());
    let mut without_name = vless_inbound(&keys, &site, 33090);
    without_name["tls"]["server_name"] = json!(null);
    assert!(check(prune(without_name)).is_err());
    let mut bad_short_id = vless_inbound(&keys, &site, 33090);
    bad_short_id["tls"]["reality"]["short_id"] = json!(["xyz"]);
    assert!(check(bad_short_id).is_err());
    let mut plain_with_name = vless_inbound(&keys, &site, 33090);
    plain_with_name["tls"]["reality"]["enabled"] = json!(false);
    plain_with_name["tls"]["certificate_path"] = json!(cert.cert_path());
    plain_with_name["tls"]["key_path"] = json!(cert.key_path());
    assert!(check(plain_with_name).is_err());
    Ok(())
}
