//! Fallback on the Trojan and VLESS inbounds: what fails to authenticate is
//! relayed, byte for byte, to a fallback server chosen by the TLS ALPN, and
//! clients that do authenticate are not affected.
//!
//! The sing-box tests need `sing-box` on the PATH or in /opt/homebrew/bin,
//! and are ignored unless asked for:
//! `cargo test -p sail --test test_fallback -- --ignored`.
//!
//! Ports 33400-33499 only.

#![cfg(all(
    feature = "inbound-trojan",
    feature = "outbound-trojan",
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
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use sha2::Digest;

const PASSWORD: &str = "password";
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
/// What the partial-header tests are waited on for: the inbound's
/// `HEADER_TIMEOUT`, which is 2s.
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);

/// A self-signed certificate for localhost, as files.
struct Cert {
    dir: PathBuf,
}

impl Cert {
    fn new(name: &str) -> anyhow::Result<Self> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let dir =
            std::env::temp_dir().join(format!("sail-fallback-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let cert_files = Cert { dir };
        std::fs::write(cert_files.cert_path(), cert.pem())?;
        std::fs::write(cert_files.key_path(), key_pair.serialize_pem())?;
        Ok(cert_files)
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

/// A stand-in for a web server, on a thread: for each connection it reads
/// until the peer has been quiet for a moment, then answers with its name, a
/// newline and every byte it received, and closes.
fn run_web_server(name: &'static str, port: u16) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            std::thread::spawn(move || {
                let mut received = Vec::new();
                let mut buf = [0u8; 4096];
                // Until the first bytes: long; after them: until a pause.
                let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            received.extend_from_slice(&buf[..n]);
                            let _ = conn.set_read_timeout(Some(Duration::from_millis(300)));
                        }
                    }
                }
                let mut answer = format!("{}\n", name).into_bytes();
                answer.extend_from_slice(&received);
                let _ = conn.write_all(&answer);
            });
        }
    });
    Ok(())
}

/// What `run_web_server` named `name` answers to `sent`.
fn answer(name: &str, sent: &[u8]) -> Vec<u8> {
    let mut answer = format!("{}\n", name).into_bytes();
    answer.extend_from_slice(sent);
    answer
}

/// A TLS connection to `port` offering `alpn`, in wire format.
fn tls_connect(port: u16, alpn: &[u8]) -> anyhow::Result<btls::ssl::SslStream<TcpStream>> {
    use btls::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let tcp = TcpStream::connect(("127.0.0.1", port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);
    if !alpn.is_empty() {
        connector.set_alpn_protos(alpn)?;
    }
    connector
        .build()
        .connect("localhost", tcp)
        .map_err(|e| anyhow::anyhow!("TLS connect: {}", e))
}

/// Sends `sent` over TLS to `port` offering `alpn`, and checks that the
/// web server `name` got exactly that; returns how long the answer took.
fn probe(port: u16, alpn: &[u8], sent: &[u8], name: &str) -> anyhow::Result<Duration> {
    let mut tls = tls_connect(port, alpn)?;
    let start = Instant::now();
    tls.write_all(sent)?;
    let expected = answer(name, sent);
    let mut got = vec![0u8; expected.len()];
    tls.read_exact(&mut got)
        .map_err(|e| anyhow::anyhow!("no answer from the fallback: {}", e))?;
    anyhow::ensure!(
        got == expected,
        "the fallback answered {:?}, not {:?}",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&expected)
    );
    Ok(start.elapsed())
}

fn server_tls(cert: &Cert) -> serde_json::Value {
    json!({
        "enabled": true,
        "certificate_path": cert.cert_path(),
        "key_path": cert.key_path(),
        "alpn": ["h2", "http/1.1"],
    })
}

/// The fallbacks every server here has: `http1` by default, `h2` for h2.
fn fallbacks(inbound: &mut serde_json::Value, http1: u16, h2: u16) {
    inbound["fallback"] = json!({ "server": "127.0.0.1", "server_port": http1 });
    inbound["fallback_for_alpn"] = json!({ "h2": { "server": "127.0.0.1", "server_port": h2 } });
}

fn trojan_server(cert: &Cert, port: u16, fallback: Option<(u16, u16)>) -> String {
    let mut inbound = json!({
        "type": "trojan",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "password": PASSWORD }],
        "tls": server_tls(cert),
    });
    if let Some((http1, h2)) = fallback {
        fallbacks(&mut inbound, http1, h2);
    }
    json!({ "inbounds": [inbound], "outbounds": [{ "type": "direct" }] }).to_string()
}

fn vless_server(cert: &Cert, port: u16, fallback: Option<(u16, u16)>) -> String {
    let mut inbound = json!({
        "type": "vless",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "uuid": UUID }],
        "tls": server_tls(cert),
    });
    if let Some((http1, h2)) = fallback {
        fallbacks(&mut inbound, http1, h2);
    }
    json!({ "inbounds": [inbound], "outbounds": [{ "type": "direct" }] }).to_string()
}

fn client_tls(cert: &Cert, alpn: &str) -> serde_json::Value {
    json!({
        "enabled": true,
        "server_name": "localhost",
        "certificate_path": cert.cert_path(),
        "alpn": [alpn],
    })
}

fn sail_client(outbound: serde_json::Value, socks_port: u16) -> String {
    json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [outbound],
    })
    .to_string()
}

fn trojan_outbound(cert: &Cert, server_port: u16, alpn: &str) -> serde_json::Value {
    json!({
        "type": "trojan",
        "server": "127.0.0.1",
        "server_port": server_port,
        "password": PASSWORD,
        "tls": client_tls(cert, alpn),
    })
}

fn vless_outbound(cert: &Cert, server_port: u16, alpn: &str) -> serde_json::Value {
    json!({
        "type": "vless",
        "server": "127.0.0.1",
        "server_port": server_port,
        "uuid": UUID,
        "tls": client_tls(cert, alpn),
    })
}

/// Runs `configs`, then `check` on a thread of its own.
fn with_sail<F>(configs: Vec<String>, check: F) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()> + Send + 'static,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = std::thread::spawn(check)
        .join()
        .map_err(|_| anyhow::anyhow!("the check panicked"))
        .and_then(|r| r);
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// Echoes a few kilobytes through the socks server on `socks_port`, to an
/// echo server on `echo_port`.
fn echo_through_socks(socks_port: u16, echo_port: u16) -> anyhow::Result<()> {
    let echo = TcpListener::bind(("127.0.0.1", echo_port))?;
    std::thread::spawn(move || {
        if let Ok((mut conn, _)) = echo.accept() {
            let mut buf = [0u8; 4096];
            while let Ok(n) = conn.read(&mut buf) {
                if n == 0 || conn.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    });
    let mut tcp = TcpStream::connect(("127.0.0.1", socks_port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply)?;
    anyhow::ensure!(reply == [5, 0], "socks method {:?}", reply);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo_port.to_be_bytes());
    tcp.write_all(&request)?;
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply)?;
    anyhow::ensure!(reply[1] == 0, "socks connect failed: {}", reply[1]);
    let data: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
    tcp.write_all(&data)?;
    let mut echoed = vec![0u8; data.len()];
    tcp.read_exact(&mut echoed)
        .map_err(|e| anyhow::anyhow!("no echo through the proxy: {}", e))?;
    anyhow::ensure!(echoed == data, "the echo differs");
    Ok(())
}

const HTTP1_REQUEST: &[u8] =
    b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe\r\nAccept: */*\r\n\r\n";
/// The HTTP/2 connection preface and an empty SETTINGS frame.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// A VLESS request header for `uuid`: TCP to 127.0.0.1:80.
fn vless_header(uuid: &str) -> Vec<u8> {
    let mut header = vec![0u8];
    header.extend_from_slice(uuid::Uuid::parse_str(uuid).unwrap().as_bytes());
    header.extend_from_slice(&[0, 1, 0, 80, 1, 127, 0, 0, 1]);
    header
}

// ---------------------------------------------------------------------------
// Trojan
// ---------------------------------------------------------------------------

#[test]
fn test_trojan_fallback() -> anyhow::Result<()> {
    let cert = Cert::new("trojan")?;
    run_web_server("http1", 33400)?;
    run_web_server("h2", 33401)?;
    let configs = vec![
        trojan_server(&cert, 33402, Some((33400, 33401))),
        sail_client(trojan_outbound(&cert, 33402, "h2"), 33403),
        sail_client(trojan_outbound(&cert, 33402, "http/1.1"), 33404),
    ];
    with_sail(configs, || {
        // A web client gets the web server, whichever ALPN it speaks.
        probe(33402, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
        probe(33402, b"", HTTP1_REQUEST, "http1")?;
        probe(33402, b"\x02h2", H2_PREFACE, "h2")?;
        // A well-formed header with a wrong password.
        let mut wrong = hex::encode(sha2::Sha224::digest(b"wrong")).into_bytes();
        wrong.extend_from_slice(b"\r\n\x01\x01\x7f\x00\x00\x01\x00\x50\r\nGET / HTTP/1.1\r\n\r\n");
        probe(33402, b"\x08http/1.1", &wrong, "http1")?;
        // Trojan clients still get through, on either ALPN.
        echo_through_socks(33403, 33405)?;
        echo_through_socks(33404, 33406)?;
        Ok(())
    })
}

#[test]
fn test_trojan_fallback_after_partial_header() -> anyhow::Result<()> {
    let cert = Cert::new("trojan-partial")?;
    run_web_server("http1", 33410)?;
    run_web_server("h2", 33411)?;
    let configs = vec![trojan_server(&cert, 33412, Some((33410, 33411)))];
    with_sail(configs, || {
        // Hex, as a key starts: the inbound waits for the rest, then gives up.
        let took = probe(33412, b"\x08http/1.1", b"0123456789abcdef", "http1")?;
        anyhow::ensure!(
            took >= HEADER_TIMEOUT - Duration::from_millis(100),
            "fell back after {:?}, before the header timeout",
            took
        );
        // Not hex: no waiting.
        let took = probe(33412, b"\x08http/1.1", b"GET /", "http1")?;
        anyhow::ensure!(took < HEADER_TIMEOUT, "waited {:?} for a non-key", took);
        Ok(())
    })
}

#[test]
fn test_trojan_without_fallback_closes() -> anyhow::Result<()> {
    let cert = Cert::new("trojan-none")?;
    let configs = vec![trojan_server(&cert, 33415, None)];
    with_sail(configs, || {
        let mut tls = tls_connect(33415, b"\x08http/1.1")?;
        tls.write_all(HTTP1_REQUEST)?;
        let mut buf = [0u8; 64];
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => Ok(()),
            Ok(n) => Err(anyhow::anyhow!("got {} bytes without a fallback", n)),
        }
    })
}

// ---------------------------------------------------------------------------
// VLESS
// ---------------------------------------------------------------------------

#[test]
fn test_vless_fallback() -> anyhow::Result<()> {
    let cert = Cert::new("vless")?;
    run_web_server("http1", 33420)?;
    run_web_server("h2", 33421)?;
    let configs = vec![
        vless_server(&cert, 33422, Some((33420, 33421))),
        sail_client(vless_outbound(&cert, 33422, "h2"), 33423),
        sail_client(vless_outbound(&cert, 33422, "http/1.1"), 33424),
    ];
    with_sail(configs, || {
        probe(33422, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
        probe(33422, b"\x02h2", H2_PREFACE, "h2")?;
        // A wrong UUID: the header, then whatever follows it.
        let mut wrong = vless_header("00000000-0000-0000-0000-000000000001");
        wrong.extend_from_slice(HTTP1_REQUEST);
        probe(33422, b"\x02h2", &wrong, "h2")?;
        // A bad version.
        let mut bad_version = vless_header(UUID);
        bad_version[0] = 1;
        probe(33422, b"\x08http/1.1", &bad_version, "http1")?;
        // A flow the user does not have.
        let mut vision = vec![0u8];
        vision.extend_from_slice(uuid::Uuid::parse_str(UUID)?.as_bytes());
        vision.extend_from_slice(b"\x12\x0a\x10xtls-rprx-vision");
        vision.extend_from_slice(&[1, 0, 80, 1, 127, 0, 0, 1]);
        probe(33422, b"\x08http/1.1", &vision, "http1")?;
        // VLESS clients still get through, on either ALPN.
        echo_through_socks(33423, 33425)?;
        echo_through_socks(33424, 33426)?;
        Ok(())
    })
}

#[test]
fn test_vless_fallback_after_partial_header() -> anyhow::Result<()> {
    let cert = Cert::new("vless-partial")?;
    run_web_server("http1", 33430)?;
    run_web_server("h2", 33431)?;
    let configs = vec![vless_server(&cert, 33432, Some((33430, 33431)))];
    with_sail(configs, || {
        let header = vless_header(UUID);
        let took = probe(33432, b"\x08http/1.1", &header[..10], "http1")?;
        anyhow::ensure!(
            took >= HEADER_TIMEOUT - Duration::from_millis(100),
            "fell back after {:?}, before the header timeout",
            took
        );
        Ok(())
    })
}

#[test]
fn test_fallback_config_mistakes() -> anyhow::Result<()> {
    let cert = Cert::new("config")?;
    let bad = |inbound: fn(&Cert, u16, Option<(u16, u16)>) -> String,
               patch: &dyn Fn(&mut serde_json::Value)| {
        let mut config: serde_json::Value =
            serde_json::from_str(&inbound(&cert, 33440, Some((33441, 33442)))).unwrap();
        patch(&mut config["inbounds"][0]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        match common::run_sail_instances(&rt, vec![config.to_string()]) {
            Ok(ids) => {
                for id in ids {
                    sail::shutdown(id);
                }
                false
            }
            Err(_) => true,
        }
    };
    for inbound in [trojan_server, vless_server] {
        anyhow::ensure!(bad(inbound, &|i| i["fallback_for_alpn"] =
            json!({ "": { "server": "127.0.0.1", "server_port": 80 } })));
        anyhow::ensure!(bad(inbound, &|i| i["fallback"]["port"] = json!(80)));
        anyhow::ensure!(bad(inbound, &|i| i["fallback"]["server_port"] = json!(0)));
        anyhow::ensure!(bad(inbound, &|i| i["fallback"]["server"] = json!("")));
    }
    Ok(())
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

fn sing_box_client(outbound: serde_json::Value, socks_port: u16) -> serde_json::Value {
    json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [outbound],
    })
}

#[test]
#[ignore]
fn test_trojan_fallback_sing_box_client() -> anyhow::Result<()> {
    let cert = Cert::new("sb-trojan")?;
    run_web_server("http1", 33450)?;
    run_web_server("h2", 33451)?;
    let configs = vec![trojan_server(&cert, 33452, Some((33450, 33451)))];
    let mut sing_box = Vec::new();
    for (alpn, socks) in [("h2", 33453), ("http/1.1", 33454)] {
        let config = sing_box_client(trojan_outbound(&cert, 33452, alpn), socks);
        sing_box.push(SingBox::run(
            &cert,
            &format!("client-{}", socks),
            config,
            socks,
        )?);
    }
    with_sail(configs, || {
        echo_through_socks(33453, 33455)?;
        echo_through_socks(33454, 33456)?;
        probe(33452, b"\x02h2", H2_PREFACE, "h2")?;
        Ok(())
    })
}

#[test]
#[ignore]
fn test_vless_fallback_sing_box_client() -> anyhow::Result<()> {
    let cert = Cert::new("sb-vless")?;
    run_web_server("http1", 33460)?;
    run_web_server("h2", 33461)?;
    let configs = vec![vless_server(&cert, 33462, Some((33460, 33461)))];
    let mut sing_box = Vec::new();
    for (alpn, socks) in [("h2", 33463), ("http/1.1", 33464)] {
        let config = sing_box_client(vless_outbound(&cert, 33462, alpn), socks);
        sing_box.push(SingBox::run(
            &cert,
            &format!("client-{}", socks),
            config,
            socks,
        )?);
    }
    with_sail(configs, || {
        echo_through_socks(33463, 33465)?;
        echo_through_socks(33464, 33466)?;
        probe(33462, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
        Ok(())
    })
}
