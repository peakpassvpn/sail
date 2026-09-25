//! The HTTP outbound against the HTTP inbound, with and without TLS, and
//! against sing-box in both directions.
//!
//! The sing-box tests need `/opt/homebrew/bin/sing-box` (or `SING_BOX`) and
//! are ignored by default:
//!
//! ```text
//! cargo test -p sail --test test_http_proxy -- --ignored
//! ```
//!
//! Ports: 32500-32519.

#![cfg(all(
    feature = "inbound-http",
    feature = "outbound-http",
    feature = "inbound-socks",
    feature = "inbound-mixed",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-tls",
    feature = "inbound-tls",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

/// A certificate for `localhost`, written where both sail and sing-box can
/// read it.
struct Certs {
    cert: String,
    key: String,
}

fn certs(name: &str) -> anyhow::Result<Certs> {
    let dir = std::env::temp_dir().join(format!("sail-http-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    Ok(Certs {
        cert: cert_path.to_string_lossy().into_owned(),
        key: key_path.to_string_lossy().into_owned(),
    })
}

/// sing-box, killed when dropped.
struct SingBox(Child);

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sing_box_path() -> PathBuf {
    std::env::var_os("SING_BOX")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/homebrew/bin/sing-box"))
}

/// Runs sing-box with `config` and waits for it to listen on `port`.
fn run_sing_box(name: &str, config: &str, port: u16) -> anyhow::Result<SingBox> {
    let path = std::env::temp_dir().join(format!("sail-http-{}-{}.json", name, std::process::id()));
    std::fs::write(&path, config)?;
    let child = Command::new(sing_box_path())
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("run sing-box failed: {}", e))?;
    let sing_box = SingBox(child);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("sing-box did not listen on {} within 10s", port);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(sing_box)
}

/// Echoes a few kilobytes over TCP through the SOCKS server at
/// `socks_port`.
async fn echo_through(socks_port: u16, echo: SocketAddr) -> anyhow::Result<()> {
    let sess = Session {
        destination: SocksAddr::from(echo),
        ..Default::default()
    };
    let mut stream = timeout(
        Duration::from_secs(5),
        common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None),
    )
    .await??;
    let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7) as u8).collect();
    let (mut r, mut w) = tokio::io::split(&mut stream);
    let write = async {
        w.write_all(&data).await?;
        anyhow::Ok(())
    };
    let read = async {
        let mut back = vec![0u8; data.len()];
        r.read_exact(&mut back).await?;
        anyhow::Ok(back)
    };
    let (written, back) =
        timeout(Duration::from_secs(5), async { tokio::join!(write, read) }).await?;
    written?;
    anyhow::ensure!(back? == data, "echo mismatch");
    Ok(())
}

/// Runs `configs`, then `check` against a TCP echo server, and shuts the
/// instances down.
fn with_instances<F, Fut>(configs: Vec<String>, check: F) -> anyhow::Result<()>
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (echo, echo_fut) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    let echo_task = rt.spawn(echo_fut);
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        check(echo).await
    });
    echo_task.abort();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// An HTTP proxy that knows alice and bob and lets only bob through, so
/// that the user's name has to reach routing.
fn http_server(port: u16, tls: Option<&Certs>) -> String {
    let tls = tls
        .map(|c| {
            format!(
                r#", "tls": {{ "enabled": true, "certificate_path": "{}", "key_path": "{}" }}"#,
                c.cert, c.key
            )
        })
        .unwrap_or_default();
    format!(
        r#"{{
            "inbounds": [{{
                "type": "http",
                "listen": "127.0.0.1",
                "listen_port": {port},
                "users": [
                    {{ "username": "alice", "password": "alice-pass" }},
                    {{ "username": "bob", "password": "bob-pass" }}
                ]
                {tls}
            }}],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "block" }}
            ],
            "route": {{
                "rules": [{{ "auth_user": ["bob"], "outbound": "direct" }}],
                "final": "block"
            }}
        }}"#
    )
}

/// A SOCKS inbound at `socks_port` whose traffic goes to the HTTP proxy at
/// `server_port` as `credentials`.
fn http_client(
    socks_port: u16,
    server_port: u16,
    credentials: Option<(&str, &str)>,
    tls: Option<&Certs>,
) -> String {
    let credentials = credentials
        .map(|(u, p)| format!(r#", "username": "{}", "password": "{}""#, u, p))
        .unwrap_or_default();
    let tls = tls
        .map(|c| {
            format!(
                r#", "tls": {{ "enabled": true, "server_name": "localhost", "certificate_path": "{}" }}"#,
                c.cert
            )
        })
        .unwrap_or_default();
    format!(
        r#"{{
            "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {socks_port} }}],
            "outbounds": [{{
                "type": "http",
                "server": "127.0.0.1",
                "server_port": {server_port},
                "headers": {{ "X-Sail-Test": "1" }}
                {credentials}
                {tls}
            }}]
        }}"#
    )
}

// app(socks) -> sail(http, bob / wrong / none) -> sail(http, users) -> echo
#[test]
fn test_http_outbound_through_http_inbound_with_auth() -> anyhow::Result<()> {
    let configs = vec![
        http_server(32500, None),
        http_client(32501, 32500, Some(("bob", "bob-pass")), None),
        http_client(32502, 32500, Some(("bob", "alice-pass")), None),
        http_client(32503, 32500, None, None),
    ];
    with_instances(configs, |echo| async move {
        echo_through(32501, echo).await?;
        anyhow::ensure!(
            echo_through(32502, echo).await.is_err(),
            "a wrong password got through"
        );
        anyhow::ensure!(
            echo_through(32503, echo).await.is_err(),
            "no credentials got through"
        );
        Ok(())
    })
}

// The server answers without credentials 407, which the client names.
#[test]
fn test_http_inbound_answers_407() -> anyhow::Result<()> {
    with_instances(vec![http_server(32506, None)], |echo| async move {
        let mut stream = tokio::net::TcpStream::connect("127.0.0.1:32506").await?;
        stream
            .write_all(format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", echo, echo).as_bytes())
            .await?;
        let mut answer = Vec::new();
        timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await??;
        let answer = String::from_utf8_lossy(&answer);
        anyhow::ensure!(
            answer.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n")
                && answer.contains("Proxy-Authenticate: Basic realm="),
            "answered {:?}",
            answer
        );
        Ok(())
    })
}

// app(socks) -> sail(http + tls) -> sail(https, users) -> echo
#[test]
fn test_http_outbound_over_tls() -> anyhow::Result<()> {
    let certs = certs("tls")?;
    let configs = vec![
        http_server(32504, Some(&certs)),
        http_client(32505, 32504, Some(("bob", "bob-pass")), Some(&certs)),
    ];
    with_instances(configs, |echo| echo_through(32505, echo))
}

// UDP has no way through an HTTP proxy: the outbound takes none, and the
// session fails rather than going anywhere else.
#[test]
fn test_http_outbound_refuses_udp() -> anyhow::Result<()> {
    let configs = vec![
        http_server(32507, None),
        http_client(32508, 32507, Some(("bob", "bob-pass")), None),
    ];
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (echo, echo_fut) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
    let echo_task = rt.spawn(echo_fut);
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sess = Session {
            destination: SocksAddr::from(echo),
            ..Default::default()
        };
        let dgram = common::new_socks_datagram("127.0.0.1", 32508, &sess, None, None).await?;
        let (mut r, mut s) = dgram.split();
        s.send_to(b"udp", &sess.destination).await?;
        let mut buf = [0u8; 64];
        anyhow::ensure!(
            timeout(Duration::from_secs(1), r.recv_from(&mut buf))
                .await
                .is_err(),
            "a datagram came back through an HTTP proxy"
        );
        Ok(())
    });
    echo_task.abort();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

// app(socks) -> sing-box(http) -> sail(http | mixed, users) -> echo
#[test]
#[ignore]
fn test_sing_box_http_outbound_to_sail() -> anyhow::Result<()> {
    let mixed_server = http_server(32511, None).replace(r#""type": "http""#, r#""type": "mixed""#);
    let sing_box_client = |socks_port: u16, server_port: u16| {
        format!(
            r#"{{
                "log": {{ "level": "warn" }},
                "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {socks_port} }}],
                "outbounds": [{{
                    "type": "http",
                    "server": "127.0.0.1",
                    "server_port": {server_port},
                    "username": "bob",
                    "password": "bob-pass"
                }}]
            }}"#
        )
    };
    let _http = run_sing_box("sb-http-out-1", &sing_box_client(32512, 32510), 32512)?;
    let _mixed = run_sing_box("sb-http-out-2", &sing_box_client(32513, 32511), 32513)?;
    with_instances(
        vec![http_server(32510, None), mixed_server],
        |echo| async move {
            echo_through(32512, echo).await?;
            echo_through(32513, echo).await
        },
    )
}

// app(socks) -> sail(http, plain | tls) -> sing-box(mixed | http + tls) -> echo
#[test]
#[ignore]
fn test_sail_http_outbound_to_sing_box() -> anyhow::Result<()> {
    let certs = certs("sing-box")?;
    let sing_box_server = format!(
        r#"{{
            "log": {{ "level": "warn" }},
            "inbounds": [
                {{
                    "type": "mixed",
                    "listen": "127.0.0.1",
                    "listen_port": 32514,
                    "users": [
                        {{ "username": "alice", "password": "alice-pass" }},
                        {{ "username": "bob", "password": "bob-pass" }}
                    ]
                }},
                {{
                    "type": "http",
                    "listen": "127.0.0.1",
                    "listen_port": 32515,
                    "users": [{{ "username": "bob", "password": "bob-pass" }}],
                    "tls": {{
                        "enabled": true,
                        "certificate_path": "{cert}",
                        "key_path": "{key}"
                    }}
                }}
            ],
            "outbounds": [{{ "type": "direct" }}]
        }}"#,
        cert = certs.cert,
        key = certs.key,
    );
    let _server = run_sing_box("sb-mixed-in", &sing_box_server, 32514)?;
    let configs = vec![
        http_client(32516, 32514, Some(("bob", "bob-pass")), None),
        http_client(32517, 32514, Some(("bob", "wrong")), None),
        http_client(32518, 32515, Some(("bob", "bob-pass")), Some(&certs)),
    ];
    with_instances(configs, |echo| async move {
        echo_through(32516, echo).await?;
        anyhow::ensure!(
            echo_through(32517, echo).await.is_err(),
            "sing-box let a wrong password through"
        );
        echo_through(32518, echo).await
    })
}
