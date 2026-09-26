//! REALITY both ways, carrying VLESS with Vision: sail to sail, against
//! sing-box in either role, and what a prober that is not a REALITY
//! client sees -- the handshake server, here a local TLS site.
//!
//! The sing-box tests need `sing-box` on the PATH or in
//! /opt/homebrew/bin, the Xray tests `xray` on the PATH or in `XRAY`; both
//! are ignored unless asked for:
//! `cargo test -p sail --test test_reality -- --ignored`.
//!
//! Ports 33500-33549 only.

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
        sail_client(&keys, 33500, 33501, SHORT_ID),
        sail_server(&keys, &site, 33501),
    ];
    common::test_configs(configs.clone(), "127.0.0.1", 33500)?;
    transfer(configs, 33500, true)?;
    // A short ID the server lists, given short.
    let configs = vec![
        sail_client(&keys, 33500, 33501, "ab"),
        sail_server(&keys, &site, 33501),
    ];
    common::test_configs(configs, "127.0.0.1", 33500)
}

#[test]
fn test_reality_refuses_unknown_short_id_and_key() -> anyhow::Result<()> {
    let cert = Cert::new("refuse")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let configs = vec![
        sail_client(&keys, 33502, 33503, "cd"),
        sail_server(&keys, &site, 33503),
    ];
    assert!(common::test_configs(configs, "127.0.0.1", 33502).is_err());
    let configs = vec![
        sail_client(&Keys::new(), 33502, 33503, SHORT_ID),
        sail_server(&keys, &site, 33503),
    ];
    assert!(common::test_configs(configs, "127.0.0.1", 33502).is_err());
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
    let ids = common::run_sail_instances(&rt, vec![sail_server(&keys, &site, 33504)])?;
    // The prober blocks; the sail instance runs on `rt`, polled meanwhile.
    let prober = std::thread::spawn(|| -> anyhow::Result<()> {
        for server_name in [SERVER_NAME, "other.example"] {
            let (certificate, greeting) = probe(33504, server_name)
                .map_err(|e| anyhow::anyhow!("probe {}: {}", server_name, e))?;
            anyhow::ensure!(greeting == SITE_GREETING, "greeting {:?}", greeting);
            let _ = certificate;
        }
        // Not TLS at all: relayed all the same, and the site's TLS stack
        // hangs up rather than anyone waiting for more.
        let mut tcp = TcpStream::connect(("127.0.0.1", 33504))?;
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
        let ids = common::run_sail_instances(&rt, vec![sail_server(&keys, &site, 33505)])?;
        let prober = std::thread::spawn(|| probe(33505, SERVER_NAME));
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

/// A TCP forwarder on threads from `listen` to `to`: for each connection,
/// what came back from `to`, in the order connections were accepted.
fn tap(listen: u16, to: u16) -> anyhow::Result<std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>> {
    use std::sync::{Arc, Mutex};
    let listener = TcpListener::bind(("127.0.0.1", listen))?;
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let all = seen.clone();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(mut client) = client else { return };
            let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", to)) else {
                continue;
            };
            let index = {
                let mut all = all.lock().unwrap();
                all.push(Vec::new());
                all.len() - 1
            };
            let (Ok(mut client_w), Ok(mut upstream_r)) = (client.try_clone(), upstream.try_clone())
            else {
                continue;
            };
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut client, &mut upstream);
                let _ = upstream.shutdown(std::net::Shutdown::Write);
            });
            let all = all.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 16384];
                while let Ok(n) = upstream_r.read(&mut buf) {
                    if n == 0 || client_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    all.lock().unwrap()[index].extend_from_slice(&buf[..n]);
                }
                let _ = client_w.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    Ok(seen)
}

/// The lengths of the first `n` records in `wire`, headers included.
fn record_lengths(wire: &[u8], n: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 5 <= wire.len() && out.len() < n {
        let len = 5 + u16::from_be_bytes([wire[pos + 3], wire[pos + 4]]) as usize;
        out.push(len);
        pos += len;
    }
    out
}

/// A client of ours gets a server flight of the site's shape: its
/// ServerHello, ChangeCipherSpec and encrypted records are as long as those
/// the site answered the same ClientHello with.
#[test]
fn test_reality_flight_has_the_sites_shape() -> anyhow::Result<()> {
    let cert = Cert::new("shape")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    // client 33530 -> tap 33533 -> server 33532 -> tap 33531 -> site
    let from_site = tap(33531, site.port)?;
    let from_server = tap(33533, 33532)?;
    let proxied_site = Site {
        port: 33531,
        certificate_der: Vec::new(),
    };
    let configs = vec![
        sail_client(&keys, 33530, 33533, SHORT_ID),
        sail_server(&keys, &proxied_site, 33532),
    ];
    common::test_configs(configs, "127.0.0.1", 33530)?;
    let from_site = from_site.lock().unwrap().clone();
    let from_server = from_server.lock().unwrap().clone();
    anyhow::ensure!(!from_server.is_empty(), "no connection");
    anyhow::ensure!(
        from_site.len() == from_server.len(),
        "a connection not mirrored"
    );
    // Connections run side by side, so their order may differ; the
    // shapes, taken together, may not.
    let mut site: Vec<Vec<usize>> = from_site.iter().map(|w| record_lengths(w, 3)).collect();
    let mut ours: Vec<Vec<usize>> = from_server.iter().map(|w| record_lengths(w, 3)).collect();
    for shape in &site {
        // The site's BoringSSL answers in one encrypted record.
        anyhow::ensure!(shape.len() == 3 && shape[1] == 6, "site {:?}", shape);
    }
    site.sort();
    ours.sort();
    anyhow::ensure!(ours == site, "ours {:?}, the site's {:?}", ours, site);
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
    let _server = SingBox::run(&cert, "server", sing_box_server(&keys, &site, 33511), 33511)?;
    let configs = vec![sail_client(&keys, 33510, 33511, SHORT_ID)];
    common::test_configs(configs.clone(), "127.0.0.1", 33510)?;
    transfer(configs, 33510, true)
}

#[test]
#[ignore = "needs sing-box"]
fn test_reality_sing_box_to_sail() -> anyhow::Result<()> {
    let cert = Cert::new("in")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let configs = vec![sail_server(&keys, &site, 33513)];
    let _client = SingBox::run(&cert, "client", sing_box_client(&keys, 33512, 33513), 33512)?;
    common::test_configs(configs.clone(), "127.0.0.1", 33512)?;
    transfer(configs, 33512, true)
}

// ---------------------------------------------------------------------------
// Xray
// ---------------------------------------------------------------------------

/// An Xray process, killed when dropped.
struct Xray(Child);

impl Xray {
    /// Runs Xray with `config` and waits for it to listen on TCP `port`.
    fn run(cert: &Cert, name: &str, config: serde_json::Value, port: u16) -> anyhow::Result<Self> {
        let path = cert.dir.join(format!("xray-{}.json", name));
        std::fs::write(&path, config.to_string())?;
        let xray = std::env::var_os("XRAY").map_or_else(|| PathBuf::from("xray"), PathBuf::from);
        let child = Command::new(xray)
            .arg("run")
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow::anyhow!("run xray: {}", e))?;
        let xray = Xray(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            if Instant::now() > deadline {
                return Err(anyhow::anyhow!("xray did not listen on {}", port));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(xray)
    }
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "needs xray"]
fn test_reality_xray_to_sail() -> anyhow::Result<()> {
    let cert = Cert::new("xray-in")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let configs = vec![sail_server(&keys, &site, 33541)];
    let client = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1", "port": 33540, "protocol": "socks",
            "settings": { "udp": true },
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": { "vnext": [{
                "address": "127.0.0.1", "port": 33541,
                "users": [{ "id": UUID, "flow": VISION, "encryption": "none" }],
            }] },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": SERVER_NAME,
                    "fingerprint": "chrome",
                    "publicKey": keys.public,
                    "shortId": SHORT_ID,
                },
            },
        }],
    });
    let _client = Xray::run(&cert, "client", client, 33540)?;
    common::test_configs(configs.clone(), "127.0.0.1", 33540)?;
    transfer(configs, 33540, true)
}

/// Xray's server and ours, each in front of the site, answer sail's client
/// with flights of the site's shape, connection by connection. (The site's
/// own flights differ by a byte or two, with its ECDSA signature.)
#[test]
#[ignore = "needs xray"]
fn test_reality_flight_shape_as_xray() -> anyhow::Result<()> {
    let cert = Cert::new("xray-shape")?;
    let site = Site::run(&cert)?;
    let keys = Keys::new();
    let shapes = |taps: &std::sync::Mutex<Vec<Vec<u8>>>| -> Vec<Vec<usize>> {
        let mut out: Vec<Vec<usize>> = taps
            .lock()
            .unwrap()
            .iter()
            .map(|w| record_lengths(w, 3))
            .collect();
        out.sort();
        out
    };

    // sail client 33544 -> tap 33543 -> Xray 33542 -> tap 33548 -> site
    let xray_site = tap(33548, site.port)?;
    let from_xray = tap(33543, 33542)?;
    let server = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1", "port": 33542, "protocol": "vless",
            "settings": {
                "clients": [{ "id": UUID, "flow": VISION }],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "target": "127.0.0.1:33548",
                    "serverNames": [SERVER_NAME],
                    "privateKey": keys.private,
                    "shortIds": [SHORT_ID],
                },
            },
        }],
        "outbounds": [{ "protocol": "freedom" }],
    });
    let _server = Xray::run(&cert, "server", server, 33542)?;
    // Connections Xray may make to the site by itself, as it learns what
    // the site sends after a handshake, have no counterpart.
    std::thread::sleep(Duration::from_millis(500));
    let before = xray_site.lock().unwrap().len();
    xray_site.lock().unwrap().drain(..before);
    let configs = vec![sail_client(&keys, 33544, 33543, SHORT_ID)];
    common::test_configs(configs, "127.0.0.1", 33544)?;
    let (xray, xray_site) = (shapes(&from_xray), shapes(&xray_site));
    anyhow::ensure!(!xray.is_empty(), "no connection");
    anyhow::ensure!(
        xray == xray_site,
        "Xray's {:?}, the site's {:?}",
        xray,
        xray_site
    );

    // sail client 33547 -> tap 33546 -> sail 33545 -> tap 33549 -> site
    let our_site = tap(33549, site.port)?;
    let from_ours = tap(33546, 33545)?;
    let proxied_site = Site {
        port: 33549,
        certificate_der: Vec::new(),
    };
    let configs = vec![
        sail_client(&keys, 33547, 33546, SHORT_ID),
        sail_server(&keys, &proxied_site, 33545),
    ];
    common::test_configs(configs, "127.0.0.1", 33547)?;
    let (ours, our_site) = (shapes(&from_ours), shapes(&our_site));
    anyhow::ensure!(
        ours == our_site,
        "ours {:?}, the site's {:?}",
        ours,
        our_site
    );
    anyhow::ensure!(
        ours.len() == xray.len(),
        "ours {:?}, Xray's {:?}",
        ours,
        xray
    );
    Ok(())
}

/// A handshake server that answers every ClientHello with a TLS 1.3
/// ServerHello (AES-128-GCM, X25519), a ChangeCipherSpec and encrypted-
/// looking records of `lengths`, one per message as Go and OpenSSL send
/// them, and then only reads. Returns its port.
fn run_record_site(lengths: &'static [usize]) -> anyhow::Result<u16> {
    fn record(typ: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![typ, 3, 3];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(mut tcp) = tcp else { return };
            std::thread::spawn(move || {
                let mut header = [0u8; 5];
                if tcp.read_exact(&mut header).is_err() {
                    return;
                }
                let mut hello = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
                if tcp.read_exact(&mut hello).is_err() || hello.len() < 71 {
                    return;
                }
                let mut ext = vec![0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 0x1d, 0, 32];
                ext.extend_from_slice(&[7; 32]);
                let mut body = vec![3, 3];
                body.extend_from_slice(&[9; 32]);
                body.push(32);
                body.extend_from_slice(&hello[39..71]);
                body.extend_from_slice(&[0x13, 0x01, 0]);
                body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
                body.extend_from_slice(&ext);
                let mut message = vec![2, 0];
                message.extend_from_slice(&(body.len() as u16).to_be_bytes());
                message.extend_from_slice(&body);
                let mut reply = record(0x16, &message);
                reply.extend_from_slice(&record(0x14, &[1]));
                for &len in lengths {
                    reply.extend_from_slice(&record(0x17, &vec![0x5a; len - 5]));
                }
                let _ = tcp.write_all(&reply);
                let mut buf = [0u8; 1024];
                while matches!(tcp.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    Ok(port)
}

/// sing-box's client takes a flight re-framed into four records, padded.
#[test]
#[ignore = "needs sing-box"]
fn test_reality_sing_box_to_sail_four_records() -> anyhow::Result<()> {
    let cert = Cert::new("in-four")?;
    let site = Site {
        port: run_record_site(&[40, 2500, 300, 74])?,
        certificate_der: Vec::new(),
    };
    let keys = Keys::new();
    let configs = vec![sail_server(&keys, &site, 33515)];
    let _client = SingBox::run(&cert, "client", sing_box_client(&keys, 33514, 33515), 33514)?;
    common::test_configs(configs.clone(), "127.0.0.1", 33514)?;
    transfer(configs, 33514, true)
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
    assert!(check(vless_inbound(&keys, &site, 33520)).is_ok());
    let mut with_certificate = vless_inbound(&keys, &site, 33520);
    with_certificate["tls"]["certificate_path"] = json!(cert.cert_path());
    assert!(check(with_certificate).is_err());
    let mut without_name = vless_inbound(&keys, &site, 33520);
    without_name["tls"]["server_name"] = json!(null);
    assert!(check(prune(without_name)).is_err());
    let mut bad_short_id = vless_inbound(&keys, &site, 33520);
    bad_short_id["tls"]["reality"]["short_id"] = json!(["xyz"]);
    assert!(check(bad_short_id).is_err());
    // The handshake server is dialed with sing-box's dial fields, as this
    // platform allows them; a detour is not one of them.
    let mut dialed = vless_inbound(&keys, &site, 33520);
    dialed["tls"]["reality"]["handshake"]["connect_timeout"] = json!("3s");
    assert!(check(dialed).is_ok());
    let mut marked = vless_inbound(&keys, &site, 33520);
    marked["tls"]["reality"]["handshake"]["routing_mark"] = json!(1);
    assert_eq!(check(marked).is_ok(), cfg!(target_os = "linux"));
    let mut detour = vless_inbound(&keys, &site, 33520);
    detour["tls"]["reality"]["handshake"]["detour"] = json!("direct");
    assert!(check(detour).is_err());
    let mut plain_with_name = vless_inbound(&keys, &site, 33520);
    plain_with_name["tls"]["reality"]["enabled"] = json!(false);
    plain_with_name["tls"]["certificate_path"] = json!(cert.cert_path());
    plain_with_name["tls"]["key_path"] = json!(cert.key_path());
    assert!(check(plain_with_name).is_err());
    Ok(())
}
