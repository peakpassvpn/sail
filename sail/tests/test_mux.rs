//! sing-box's multiplex (sing-mux): smux, yamux and h2mux, with and without
//! padding, over Trojan (with TLS) and Shadowsocks 2022, TCP and UDP.
//!
//! Every case runs between sail instances, and against sing-box both ways.
//! A counting TCP forwarder in front of each server shows how many mux
//! connections a client made. The sing-box tests need
//! `/opt/homebrew/bin/sing-box` (or `SING_BOX`) and are ignored by default:
//!
//! ```text
//! cargo test -p sail --test test_mux -- --ignored
//! ```
//!
//! Ports: 32900-32987.

#![cfg(all(
    feature = "mux",
    feature = "inbound-trojan",
    feature = "outbound-trojan",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-tls",
    feature = "inbound-tls",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

const PASSWORD: &str = "mux-password";
const SS_METHOD: &str = "2022-blake3-aes-128-gcm";
const SS_KEY: &str = "a8C5QncIl9HvTmenrEb7aw==";

#[derive(Clone, Copy, Debug)]
enum Carrier {
    Trojan,
    Shadowsocks,
}

#[derive(Clone, Copy, Debug)]
struct Case {
    carrier: Carrier,
    protocol: &'static str,
    padding: bool,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for carrier in [Carrier::Trojan, Carrier::Shadowsocks] {
        for protocol in ["smux", "yamux", "h2mux"] {
            for padding in [false, true] {
                cases.push(Case {
                    carrier,
                    protocol,
                    padding,
                });
            }
        }
    }
    cases
}

/// The ports one direction uses from `base`: the Trojan and Shadowsocks
/// servers, then per case the client's SOCKS port and its forwarder's,
/// then the servers again for padded connections, which sing-box's refuse
/// any other.
struct Ports {
    base: u16,
}

impl Ports {
    fn trojan(&self) -> u16 {
        self.base
    }
    fn shadowsocks(&self) -> u16 {
        self.base + 1
    }
    fn padded(&self) -> u16 {
        self.base + 2 + 2 * cases().len() as u16
    }
    fn server(&self, case: &Case) -> u16 {
        let padded = if case.padding {
            self.padded() - self.base
        } else {
            0
        };
        padded
            + match case.carrier {
                Carrier::Trojan => self.trojan(),
                Carrier::Shadowsocks => self.shadowsocks(),
            }
    }
    fn socks(&self, i: usize) -> u16 {
        self.base + 2 + 2 * i as u16
    }
    fn forwarder(&self, i: usize) -> u16 {
        self.base + 3 + 2 * i as u16
    }
}

/// A certificate for `localhost`, written where both sail and sing-box can
/// read it.
struct Certs {
    cert: String,
    key: String,
}

fn certs(name: &str) -> anyhow::Result<Certs> {
    let dir = std::env::temp_dir().join(format!("sail-mux-{}-{}", name, std::process::id()));
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

/// Forwards `listen` to `target`, counting the connections.
async fn counting_forwarder(listen: u16, target: u16) -> anyhow::Result<Arc<AtomicUsize>> {
    let listener = TcpListener::bind(("127.0.0.1", listen)).await?;
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", target)).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Ok(count)
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
fn run_sing_box(name: &str, config: &Value, port: u16) -> anyhow::Result<SingBox> {
    let path = std::env::temp_dir().join(format!("sail-mux-{}-{}.json", name, std::process::id()));
    std::fs::write(&path, serde_json::to_vec_pretty(config)?)?;
    let child = Command::new(sing_box_path())
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("run sing-box failed: {}", e))?;
    let mut sing_box = SingBox(child);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        if let Some(status) = sing_box.0.try_wait()? {
            anyhow::bail!("sing-box exited: {}", status);
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("sing-box did not listen on {} within 10s", port);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(sing_box)
}

fn session_to(addr: SocketAddr) -> Session {
    Session {
        destination: SocksAddr::from(addr),
        ..Default::default()
    }
}

/// Echoes `len` bytes through a new stream from the SOCKS server at
/// `socks_port`.
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

/// Echoes a few packets through each of two UDP associations.
async fn echo_datagrams(socks_port: u16, echo: SocketAddr) -> anyhow::Result<()> {
    let sess = session_to(echo);
    for round in 0..2u8 {
        let dgram = timeout(
            Duration::from_secs(5),
            common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None),
        )
        .await??;
        let (mut r, mut s) = dgram.split();
        for i in 0..3u8 {
            let msg = vec![round * 16 + i; 100 + i as usize * 500];
            s.send_to(&msg, &sess.destination).await?;
            let mut buf = vec![0u8; 4096];
            let (n, from) = timeout(Duration::from_secs(5), r.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("udp round {} packet {}: no echo", round, i))??;
            anyhow::ensure!(buf[..n] == msg[..], "udp echo mismatch");
            anyhow::ensure!(from == sess.destination, "udp echo from {}", from);
        }
    }
    Ok(())
}

/// Sequential streams, which share one connection, then concurrent ones,
/// which take at most `max_connections`, then UDP.
async fn exercise(
    socks_port: u16,
    connections: &AtomicUsize,
    max_connections: usize,
) -> anyhow::Result<()> {
    let (tcp_echo, tcp) = common::run_tcp_echo_server("127.0.0.1:0").await?;
    let (udp_echo, udp) = common::run_udp_echo_server("127.0.0.1:0").await?;
    let tcp = tokio::spawn(tcp);
    let udp = tokio::spawn(udp);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = async {
        for i in 0..3u8 {
            echo_stream(socks_port, tcp_echo, i, 1000 + 100_000 * i as usize).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let sequential = connections.load(Ordering::SeqCst);
        anyhow::ensure!(
            sequential == 1,
            "3 sequential streams took {} connections, not 1",
            sequential
        );

        let concurrent: Vec<_> = (0..12u8)
            .map(|i| tokio::spawn(echo_stream(socks_port, tcp_echo, 100 + i, 400_000)))
            .collect();
        for task in concurrent {
            task.await??;
        }
        let after = connections.load(Ordering::SeqCst);
        anyhow::ensure!(
            (1..=max_connections).contains(&after),
            "12 concurrent streams made {} connections in all",
            after
        );

        echo_datagrams(socks_port, udp_echo).await?;
        anyhow::Ok(())
    }
    .await;
    tcp.abort();
    udp.abort();
    result
}

/// Runs every case against the servers in `ports`, from the SOCKS ports
/// in front of each case's client.
fn run_cases(
    rt: &tokio::runtime::Runtime,
    ports: &Ports,
    max_connections: usize,
) -> anyhow::Result<()> {
    rt.block_on(async {
        let mut counters = Vec::new();
        for (i, case) in cases().iter().enumerate() {
            counters.push(counting_forwarder(ports.forwarder(i), ports.server(case)).await?);
        }
        for (i, case) in cases().iter().enumerate() {
            exercise(ports.socks(i), &counters[i], max_connections)
                .await
                .map_err(|e| anyhow::anyhow!("{:?}: {}", case, e))?;
        }
        anyhow::Ok(())
    })
}

// ---------------------------------------------------------------------------
// sail
// ---------------------------------------------------------------------------

/// A client with a SOCKS inbound and an outbound for each case, each to
/// its forwarder.
fn sail_client(ports: &Ports, certs: &Certs) -> String {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    for (i, case) in cases().iter().enumerate() {
        inbounds.push(json!({
            "type": "socks",
            "tag": format!("in-{}", i),
            "listen": "127.0.0.1",
            "listen_port": ports.socks(i),
        }));
        let multiplex = json!({
            "enabled": true,
            "protocol": case.protocol,
            "padding": case.padding,
        });
        let outbound = match case.carrier {
            Carrier::Trojan => json!({
                "type": "trojan",
                "tag": format!("out-{}", i),
                "server": "127.0.0.1",
                "server_port": ports.forwarder(i),
                "password": PASSWORD,
                "tls": {
                    "enabled": true,
                    "server_name": "localhost",
                    "certificate_path": certs.cert,
                },
                "multiplex": multiplex,
            }),
            Carrier::Shadowsocks => json!({
                "type": "shadowsocks",
                "tag": format!("out-{}", i),
                "server": "127.0.0.1",
                "server_port": ports.forwarder(i),
                "method": SS_METHOD,
                "password": SS_KEY,
                "multiplex": multiplex,
            }),
        };
        outbounds.push(outbound);
        rules.push(json!({ "inbound": [format!("in-{}", i)], "outbound": format!("out-{}", i) }));
    }
    json!({
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": { "rules": rules },
    })
    .to_string()
}

/// Trojan and Shadowsocks servers, which serve sing-mux like any other
/// inbound does.
fn sail_server(ports: &Ports, certs: &Certs) -> String {
    let inbounds: Vec<Value> = [0, ports.padded() - ports.base]
        .into_iter()
        .flat_map(|offset| sail_server_inbounds(ports, certs, offset))
        .collect();
    let ss: Vec<String> = [0, ports.padded() - ports.base]
        .into_iter()
        .map(|offset| format!("ss-{}", offset))
        .collect();
    // Trojan's streams only get through as alice: the user of a mux
    // connection has to reach routing with each of its streams.
    json!({
        "inbounds": inbounds,
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" },
        ],
        "route": {
            "rules": [
                { "auth_user": ["alice"], "outbound": "direct" },
                { "inbound": ss, "outbound": "direct" },
            ],
            "final": "block",
        },
    })
    .to_string()
}

fn sail_server_inbounds(ports: &Ports, certs: &Certs, offset: u16) -> Vec<Value> {
    serde_json::from_value(json!(
        [
            {
                "type": "trojan",
                "tag": format!("trojan-{}", offset),
                "listen": "127.0.0.1",
                "listen_port": ports.trojan() + offset,
                "users": [
                    { "name": "alice", "password": PASSWORD },
                    { "name": "bob", "password": "bob-password" },
                ],
                "tls": {
                    "enabled": true,
                    "certificate_path": certs.cert,
                    "key_path": certs.key,
                },
            },
            {
                "type": "shadowsocks",
                "tag": format!("ss-{}", offset),
                "listen": "127.0.0.1",
                "listen_port": ports.shadowsocks() + offset,
                "method": SS_METHOD,
                "password": SS_KEY,
            },
        ]
    ))
    .unwrap_or_default()
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

// ---------------------------------------------------------------------------
// sing-box
// ---------------------------------------------------------------------------

fn sing_box_server(ports: &Ports, certs: &Certs) -> Value {
    let inbounds: Vec<Value> = [false, true]
        .into_iter()
        .flat_map(|padding| sing_box_server_inbounds(ports, certs, padding))
        .collect();
    json!({
        "log": { "level": "warn" },
        "inbounds": inbounds,
        "outbounds": [{ "type": "direct" }],
    })
}

/// With `padding`, on the padded ports, refusing connections that are not.
fn sing_box_server_inbounds(ports: &Ports, certs: &Certs, padding: bool) -> Vec<Value> {
    let offset = if padding {
        ports.padded() - ports.base
    } else {
        0
    };
    serde_json::from_value(json!(
        [
            {
                "type": "trojan",
                "tag": format!("trojan-{}", padding),
                "listen": "127.0.0.1",
                "listen_port": ports.trojan() + offset,
                "users": [{ "name": "a", "password": PASSWORD }],
                "tls": {
                    "enabled": true,
                    "certificate_path": certs.cert,
                    "key_path": certs.key,
                },
                "multiplex": { "enabled": true, "padding": padding },
            },
            {
                "type": "shadowsocks",
                "tag": format!("ss-{}", padding),
                "listen": "127.0.0.1",
                "listen_port": ports.shadowsocks() + offset,
                "method": SS_METHOD,
                "password": SS_KEY,
                "multiplex": { "enabled": true, "padding": padding },
            },
        ]
    ))
    .unwrap_or_default()
}

/// sing-box's client, limited as sail's is by default: up to 4
/// connections, a new one while the least busy carries 4 streams.
fn sing_box_client(ports: &Ports, certs: &Certs) -> Value {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    for (i, case) in cases().iter().enumerate() {
        inbounds.push(json!({
            "type": "mixed",
            "tag": format!("in-{}", i),
            "listen": "127.0.0.1",
            "listen_port": ports.socks(i),
        }));
        let multiplex = json!({
            "enabled": true,
            "protocol": case.protocol,
            "padding": case.padding,
            "max_connections": 4,
            "min_streams": 4,
        });
        outbounds.push(match case.carrier {
            Carrier::Trojan => json!({
                "type": "trojan",
                "tag": format!("out-{}", i),
                "server": "127.0.0.1",
                "server_port": ports.forwarder(i),
                "password": PASSWORD,
                "tls": {
                    "enabled": true,
                    "server_name": "localhost",
                    "certificate_path": certs.cert,
                },
                "multiplex": multiplex,
            }),
            Carrier::Shadowsocks => json!({
                "type": "shadowsocks",
                "tag": format!("out-{}", i),
                "server": "127.0.0.1",
                "server_port": ports.forwarder(i),
                "method": SS_METHOD,
                "password": SS_KEY,
                "multiplex": multiplex,
            }),
        });
        rules.push(json!({ "inbound": [format!("in-{}", i)], "outbound": format!("out-{}", i) }));
    }
    json!({
        "log": { "level": "warn" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": { "rules": rules },
    })
}

// app(socks) -> sail(trojan|ss + mux) -> forwarder -> sing-box -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_mux_sail_to_sing_box() -> anyhow::Result<()> {
    let ports = Ports { base: 32900 };
    let certs = certs("to-sing-box")?;
    let _sing_box = run_sing_box(
        "server",
        &sing_box_server(&ports, &certs),
        ports.padded() + 1,
    )?;
    let rt = runtime()?;
    let ids = common::run_sail_instances(&rt, vec![sail_client(&ports, &certs)])?;
    let result = run_cases(&rt, &ports, 4);
    for id in ids {
        sail::shutdown(id);
    }
    result
}

// app(socks) -> sail(trojan|ss + mux) -> forwarder -> sail -> echo
#[test]
fn test_mux_sail_to_sail() -> anyhow::Result<()> {
    let ports = Ports { base: 32960 };
    let certs = certs("sail")?;
    let rt = runtime()?;
    let ids = common::run_sail_instances(
        &rt,
        vec![sail_server(&ports, &certs), sail_client(&ports, &certs)],
    )?;
    let result = run_cases(&rt, &ports, 4);
    for id in ids {
        sail::shutdown(id);
    }
    result
}

// app(socks) -> sing-box(trojan|ss + mux) -> forwarder -> sail -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_mux_sing_box_to_sail() -> anyhow::Result<()> {
    let ports = Ports { base: 32930 };
    let certs = certs("from-sing-box")?;
    let rt = runtime()?;
    let ids = common::run_sail_instances(&rt, vec![sail_server(&ports, &certs)])?;
    let result = (|| {
        let last = ports.socks(cases().len() - 1);
        let _sing_box = run_sing_box("client", &sing_box_client(&ports, &certs), last)?;
        run_cases(&rt, &ports, 4)
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}
