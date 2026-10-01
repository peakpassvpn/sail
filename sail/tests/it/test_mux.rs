//! sing-box's multiplex (sing-mux): smux, yamux and h2mux, with and without
//! padding, over Trojan (with TLS) and Shadowsocks 2022, TCP and UDP.
//!
//! Every case runs between sail instances, and against sing-box both ways.
//! So do the connections an inbound's `multiplex` block refuses: all of
//! them with no block, the unpadded ones with `padding`.
//! A counting TCP forwarder in front of each server shows how many mux
//! connections a client made. The sing-box tests need
//! `/opt/homebrew/bin/sing-box` (or `SING_BOX`) and are ignored by default:
//!
//! ```text
//! cargo test -p sail --test it test_mux:: -- --ignored
//! ```

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
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
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

/// The ports of one direction: the Trojan and Shadowsocks servers, the
/// same again for padded connections, which sing-box's refuse any other,
/// and per case the client's SOCKS port and its forwarder's.
struct Ports {
    trojan: u16,
    shadowsocks: u16,
    padded_trojan: u16,
    padded_shadowsocks: u16,
    socks: Vec<u16>,
    forwarders: Vec<u16>,
}

impl Ports {
    fn new() -> Self {
        let [trojan, shadowsocks, padded_trojan, padded_shadowsocks] = common::free_ports();
        let n = cases().len();
        Ports {
            trojan,
            shadowsocks,
            padded_trojan,
            padded_shadowsocks,
            socks: (0..n).map(|_| common::free_port()).collect(),
            forwarders: (0..n).map(|_| common::free_port()).collect(),
        }
    }
    fn server(&self, case: &Case) -> u16 {
        match (case.carrier, case.padding) {
            (Carrier::Trojan, false) => self.trojan,
            (Carrier::Trojan, true) => self.padded_trojan,
            (Carrier::Shadowsocks, false) => self.shadowsocks,
            (Carrier::Shadowsocks, true) => self.padded_shadowsocks,
        }
    }
    fn socks(&self, i: usize) -> u16 {
        self.socks[i]
    }
    fn forwarder(&self, i: usize) -> u16 {
        self.forwarders[i]
    }
}

/// A certificate for `localhost`, written where both sail and sing-box can
/// read it.
struct Certs {
    cert: String,
    key: String,
    _dir: common::TempDir,
}

fn certs(name: &str) -> anyhow::Result<Certs> {
    let dir = common::TempDir::new(&format!("mux-{}", name))?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    Ok(Certs {
        cert: cert_path.to_string_lossy().into_owned(),
        key: key_path.to_string_lossy().into_owned(),
        _dir: dir,
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

/// Trojan and Shadowsocks servers, which serve sing-mux as sing-box's do:
/// with `multiplex` enabled, and on the padded ports only padded.
fn sail_server(ports: &Ports, certs: &Certs) -> String {
    let inbounds: Vec<Value> = [false, true]
        .into_iter()
        .flat_map(|padding| sail_server_inbounds(ports, certs, padding))
        .collect();
    let ss: Vec<String> = [false, true]
        .into_iter()
        .map(|padding| format!("ss-{}", padding))
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

fn sail_server_inbounds(ports: &Ports, certs: &Certs, padding: bool) -> Vec<Value> {
    let (trojan, shadowsocks) = server_ports(ports, padding);
    serde_json::from_value(json!(
        [
            {
                "type": "trojan",
                "tag": format!("trojan-{}", padding),
                "listen": "127.0.0.1",
                "listen_port": trojan,
                "users": [
                    { "name": "alice", "password": PASSWORD },
                    { "name": "bob", "password": "bob-password" },
                ],
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
                "listen_port": shadowsocks,
                "method": SS_METHOD,
                "password": SS_KEY,
                "multiplex": { "enabled": true, "padding": padding },
            },
        ]
    ))
    .unwrap_or_default()
}

/// The Trojan and Shadowsocks servers' ports, padded or not.
fn server_ports(ports: &Ports, padding: bool) -> (u16, u16) {
    if padding {
        (ports.padded_trojan, ports.padded_shadowsocks)
    } else {
        (ports.trojan, ports.shadowsocks)
    }
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
        "inbounds": inbounds,
        "outbounds": [{ "type": "direct" }],
    })
}

/// With `padding`, on the padded ports, refusing connections that are not.
fn sing_box_server_inbounds(ports: &Ports, certs: &Certs, padding: bool) -> Vec<Value> {
    let (trojan, shadowsocks) = server_ports(ports, padding);
    serde_json::from_value(json!(
        [
            {
                "type": "trojan",
                "tag": format!("trojan-{}", padding),
                "listen": "127.0.0.1",
                "listen_port": trojan,
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
                "listen_port": shadowsocks,
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
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": { "rules": rules },
    })
}

// app(socks) -> sail(trojan|ss + mux) -> forwarder -> sing-box -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_mux_sail_to_sing_box() -> anyhow::Result<()> {
    let certs = certs("to-sing-box")?;
    common::retry_port_clash(|| {
        let ports = Ports::new();
        let dir = common::TempDir::new("mux")?;
        let _sing_box =
            common::Daemon::sing_box(dir.path(), "server", sing_box_server(&ports, &certs))?;
        let rt = runtime()?;
        let ids = common::run_sail_instances(&rt, vec![sail_client(&ports, &certs)])?;
        let result = run_cases(&rt, &ports, 4);
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sail(trojan|ss + mux) -> forwarder -> sail -> echo
#[test]
fn test_mux_sail_to_sail() -> anyhow::Result<()> {
    let certs = certs("sail")?;
    common::retry_port_clash(|| {
        let ports = Ports::new();
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![sail_server(&ports, &certs), sail_client(&ports, &certs)],
        )?;
        let result = run_cases(&rt, &ports, 4);
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sing-box(trojan|ss + mux) -> forwarder -> sail -> echo
#[test]
#[ignore = "needs sing-box"]
fn test_mux_sing_box_to_sail() -> anyhow::Result<()> {
    let certs = certs("from-sing-box")?;
    common::retry_port_clash(|| {
        let ports = Ports::new();
        let dir = common::TempDir::new("mux")?;
        let rt = runtime()?;
        let ids = common::run_sail_instances(&rt, vec![sail_server(&ports, &certs)])?;
        let result = (|| {
            let _sing_box =
                common::Daemon::sing_box(dir.path(), "client", sing_box_client(&ports, &certs))?;
            run_cases(&rt, &ports, 4)
        })();
        common::shutdown_instances(&rt, ids);
        result
    })
}

// ---------------------------------------------------------------------------
// What an inbound's multiplex block refuses
// ---------------------------------------------------------------------------

/// How a server inbound of the refusal tests serves sing-mux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerMux {
    /// No `multiplex` block: no sing-mux at all.
    NoBlock,
    /// `enabled`, but `padding` too: padded connections only.
    Padded,
}

#[derive(Clone, Copy, Debug)]
struct Refusal {
    client: Case,
    server: ServerMux,
    served: bool,
}

fn refusals() -> Vec<Refusal> {
    let case = |carrier, protocol, padding| Case {
        carrier,
        protocol,
        padding,
    };
    let refused = |client, server| Refusal {
        client,
        server,
        served: false,
    };
    vec![
        refused(case(Carrier::Trojan, "smux", false), ServerMux::NoBlock),
        refused(case(Carrier::Trojan, "h2mux", true), ServerMux::NoBlock),
        refused(
            case(Carrier::Shadowsocks, "yamux", false),
            ServerMux::NoBlock,
        ),
        refused(case(Carrier::Trojan, "smux", false), ServerMux::Padded),
        refused(
            case(Carrier::Shadowsocks, "h2mux", false),
            ServerMux::Padded,
        ),
        Refusal {
            client: case(Carrier::Trojan, "yamux", true),
            server: ServerMux::Padded,
            served: true,
        },
        Refusal {
            client: case(Carrier::Shadowsocks, "smux", true),
            server: ServerMux::Padded,
            served: true,
        },
    ]
}

/// The servers' ports, by carrier and `ServerMux`, and a SOCKS port per
/// refusal case.
struct RefusalPorts {
    servers: [u16; 4],
    socks: Vec<u16>,
}

impl RefusalPorts {
    fn new() -> Self {
        RefusalPorts {
            servers: common::free_ports(),
            socks: (0..refusals().len()).map(|_| common::free_port()).collect(),
        }
    }

    fn server(&self, carrier: Carrier, mux: ServerMux) -> u16 {
        let i = match carrier {
            Carrier::Trojan => 0,
            Carrier::Shadowsocks => 2,
        };
        self.servers[i + (mux == ServerMux::Padded) as usize]
    }
}

/// The same config for sail and sing-box: a Trojan and a Shadowsocks
/// inbound for each `ServerMux`.
fn refusal_server(ports: &RefusalPorts, certs: &Certs) -> Value {
    let mut inbounds = Vec::new();
    for mux in [ServerMux::NoBlock, ServerMux::Padded] {
        let mut trojan = json!({
            "type": "trojan",
            "tag": format!("trojan-{:?}", mux),
            "listen": "127.0.0.1",
            "listen_port": ports.server(Carrier::Trojan, mux),
            "users": [{ "name": "a", "password": PASSWORD }],
            "tls": {
                "enabled": true,
                "certificate_path": certs.cert,
                "key_path": certs.key,
            },
        });
        let mut shadowsocks = json!({
            "type": "shadowsocks",
            "tag": format!("ss-{:?}", mux),
            "listen": "127.0.0.1",
            "listen_port": ports.server(Carrier::Shadowsocks, mux),
            "method": SS_METHOD,
            "password": SS_KEY,
        });
        if mux == ServerMux::Padded {
            let multiplex = json!({ "enabled": true, "padding": true });
            trojan["multiplex"] = multiplex.clone();
            shadowsocks["multiplex"] = multiplex;
        }
        inbounds.push(trojan);
        inbounds.push(shadowsocks);
    }
    json!({ "inbounds": inbounds, "outbounds": [{ "type": "direct" }] })
}

/// A client with a SOCKS (sail) or mixed (sing-box) inbound for each
/// refusal case, and its mux outbound.
fn refusal_client(ports: &RefusalPorts, certs: &Certs, sing_box: bool) -> Value {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    for (i, refusal) in refusals().iter().enumerate() {
        let case = refusal.client;
        inbounds.push(json!({
            "type": if sing_box { "mixed" } else { "socks" },
            "tag": format!("in-{}", i),
            "listen": "127.0.0.1",
            "listen_port": ports.socks[i],
        }));
        let multiplex = json!({
            "enabled": true,
            "protocol": case.protocol,
            "padding": case.padding,
        });
        let server_port = ports.server(case.carrier, refusal.server);
        outbounds.push(match case.carrier {
            Carrier::Trojan => json!({
                "type": "trojan",
                "tag": format!("out-{}", i),
                "server": "127.0.0.1",
                "server_port": server_port,
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
                "server_port": server_port,
                "method": SS_METHOD,
                "password": SS_KEY,
                "multiplex": multiplex,
            }),
        });
        rules.push(json!({ "inbound": [format!("in-{}", i)], "outbound": format!("out-{}", i) }));
    }
    json!({
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": { "rules": rules },
    })
}

/// Echoes through every refusal case at once, and checks that the ones
/// served echo and the others do not.
fn run_refusals(rt: &tokio::runtime::Runtime, ports: &RefusalPorts) -> anyhow::Result<()> {
    rt.block_on(async {
        let (echo, server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        let server = tokio::spawn(server);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let tasks: Vec<_> = refusals()
            .into_iter()
            .enumerate()
            .map(|(i, refusal)| {
                let socks = ports.socks[i];
                tokio::spawn(
                    async move { (refusal, echo_stream(socks, echo, i as u8, 10_000).await) },
                )
            })
            .collect();
        let mut result = Ok(());
        for task in tasks {
            let (refusal, echoed) = task.await?;
            match (refusal.served, echoed) {
                (true, Err(e)) => {
                    result = Err(anyhow::anyhow!("{:?}: not served: {}", refusal, e));
                }
                (false, Ok(())) => {
                    result = Err(anyhow::anyhow!("{:?}: served", refusal));
                }
                _ => {}
            }
        }
        server.abort();
        result
    })
}

// app(socks) -> sail(mux) -> sail(multiplex: none, or padding)
#[test]
fn test_mux_refused_sail_to_sail() -> anyhow::Result<()> {
    let certs = certs("refused")?;
    common::retry_port_clash(|| {
        let ports = RefusalPorts::new();
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                refusal_server(&ports, &certs).to_string(),
                refusal_client(&ports, &certs, false).to_string(),
            ],
        )?;
        let result = run_refusals(&rt, &ports);
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(mixed) -> sing-box(mux) -> sail(multiplex: none, or padding)
#[test]
#[ignore = "needs sing-box"]
fn test_mux_refused_sing_box_to_sail() -> anyhow::Result<()> {
    let certs = certs("refused-from-sing-box")?;
    common::retry_port_clash(|| {
        let ports = RefusalPorts::new();
        let dir = common::TempDir::new("mux-refused")?;
        let rt = runtime()?;
        let ids =
            common::run_sail_instances(&rt, vec![refusal_server(&ports, &certs).to_string()])?;
        let result = (|| {
            let _sing_box = common::Daemon::sing_box(
                dir.path(),
                "client",
                refusal_client(&ports, &certs, true),
            )?;
            run_refusals(&rt, &ports)
        })();
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sail(mux) -> sing-box(multiplex: none, or padding): the
// same server config refuses the same connections there.
#[test]
#[ignore = "needs sing-box"]
fn test_mux_refused_sail_to_sing_box() -> anyhow::Result<()> {
    let certs = certs("refused-to-sing-box")?;
    common::retry_port_clash(|| {
        let ports = RefusalPorts::new();
        let dir = common::TempDir::new("mux-refused")?;
        let _sing_box =
            common::Daemon::sing_box(dir.path(), "server", refusal_server(&ports, &certs))?;
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![refusal_client(&ports, &certs, false).to_string()],
        )?;
        let result = run_refusals(&rt, &ports);
        common::shutdown_instances(&rt, ids);
        result
    })
}

/// The inbound `multiplex` block's mistakes are errors.
#[test]
fn test_mux_inbound_config_mistakes() -> anyhow::Result<()> {
    let certs = certs("config")?;
    let rt = runtime()?;
    let starts = |multiplex: Value| -> bool {
        let ports = RefusalPorts::new();
        let mut config = refusal_server(&ports, &certs);
        config["inbounds"][0]["multiplex"] = multiplex;
        match common::run_sail_instances(&rt, vec![config.to_string()]) {
            Ok(ids) => {
                common::shutdown_instances(&rt, ids);
                true
            }
            Err(_) => false,
        }
    };
    // TCP Brutal is served on Linux only, as by sing-box, at rates of at
    // least 1 Mbps either way, and not with amux.
    let brutal = json!({ "enabled": true, "up_mbps": 100, "down_mbps": 100 });
    anyhow::ensure!(
        starts(json!({ "enabled": true, "brutal": brutal })) == cfg!(target_os = "linux")
    );
    anyhow::ensure!(!starts(json!({
        "enabled": true,
        "brutal": { "enabled": true, "up_mbps": 0, "down_mbps": 100 },
    })));
    anyhow::ensure!(!starts(json!({
        "enabled": true,
        "brutal": { "enabled": true, "up_mbps": 100 },
    })));
    anyhow::ensure!(!starts(
        json!({ "enabled": true, "protocol": "amux", "brutal": brutal })
    ));
    anyhow::ensure!(!starts(
        json!({ "enabled": true, "protocol": "amux", "padding": true })
    ));
    anyhow::ensure!(!starts(json!({ "enabled": true, "protocol": "smux" })));
    anyhow::ensure!(!starts(json!({ "enabled": true, "max_connections": 4 })));
    // A disabled Brutal is no mistake, nor is a disabled block.
    anyhow::ensure!(starts(
        json!({ "enabled": true, "brutal": { "enabled": false } })
    ));
    anyhow::ensure!(starts(json!({ "enabled": false, "padding": true })));
    Ok(())
}

// ---------------------------------------------------------------------------
// TCP Brutal
// ---------------------------------------------------------------------------

/// The rates both ends ask for.
fn brutal() -> Value {
    json!({ "enabled": true, "up_mbps": 100, "down_mbps": 100 })
}

/// The mux protocols the Brutal cases run over: framed and HTTP/2.
const BRUTAL_PROTOCOLS: [&str; 2] = ["smux", "h2mux"];

/// A Shadowsocks server, per protocol a SOCKS (sail) or mixed (sing-box)
/// port and a counting forwarder in front of the server.
struct BrutalPorts {
    server: u16,
    socks: [u16; 2],
    forwarders: [u16; 2],
}

impl BrutalPorts {
    fn new() -> Self {
        let [server, a, b, c] = common::free_ports();
        BrutalPorts {
            server,
            socks: [a, b],
            forwarders: [c, common::free_port()],
        }
    }
}

/// Whether this host can set TCP Brutal on a socket: Linux, with the
/// tcp-brutal module loaded.
fn brutal_loaded() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
        .is_ok_and(|s| s.split_whitespace().any(|c| c == "brutal"))
}

/// Whether the sing-box run is a build with `-tags debug`, whose server
/// negotiates Brutal even when it cannot set it on its socket.
fn sing_box_debug() -> bool {
    std::env::var_os("SING_BOX_DEBUG").is_some()
}

/// The same config for sail and sing-box: a Shadowsocks server with
/// `multiplex`, with Brutal or not.
fn brutal_server(ports: &BrutalPorts, with_brutal: bool) -> Value {
    let mut multiplex = json!({ "enabled": true });
    if with_brutal {
        multiplex["brutal"] = brutal();
    }
    json!({
        "inbounds": [{
            "type": "shadowsocks",
            "tag": "ss",
            "listen": "127.0.0.1",
            "listen_port": ports.server,
            "method": SS_METHOD,
            "password": SS_KEY,
            "multiplex": multiplex,
        }],
        "outbounds": [{ "type": "direct" }],
    })
}

/// A client asking for Brutal, per protocol through its forwarder.
fn brutal_client(ports: &BrutalPorts, sing_box: bool) -> Value {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    for (i, protocol) in BRUTAL_PROTOCOLS.iter().enumerate() {
        inbounds.push(json!({
            "type": if sing_box { "mixed" } else { "socks" },
            "tag": format!("in-{}", i),
            "listen": "127.0.0.1",
            "listen_port": ports.socks[i],
        }));
        outbounds.push(json!({
            "type": "shadowsocks",
            "tag": format!("out-{}", i),
            "server": "127.0.0.1",
            "server_port": ports.forwarders[i],
            "method": SS_METHOD,
            "password": SS_KEY,
            "multiplex": {
                "enabled": true,
                "protocol": protocol,
                "brutal": brutal(),
            },
        }));
        rules.push(json!({ "inbound": [format!("in-{}", i)], "outbound": format!("out-{}", i) }));
    }
    json!({
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": { "rules": rules },
    })
}

/// Echoes through every protocol: when `served`, concurrent streams that
/// all go over one connection, as with Brutal they do; else a stream that
/// fails, since a refused negotiation fails the connection.
fn run_brutal(
    rt: &tokio::runtime::Runtime,
    ports: &BrutalPorts,
    served: bool,
) -> anyhow::Result<()> {
    rt.block_on(async {
        let (echo, server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        let server = tokio::spawn(server);
        let result = async {
            for (i, protocol) in BRUTAL_PROTOCOLS.iter().enumerate() {
                let count = counting_forwarder(ports.forwarders[i], ports.server).await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                if !served {
                    anyhow::ensure!(
                        echo_stream(ports.socks[i], echo, 0, 10_000).await.is_err(),
                        "{}: served without Brutal",
                        protocol
                    );
                    continue;
                }
                echo_stream(ports.socks[i], echo, 0, 10_000).await?;
                let concurrent: Vec<_> = (0..8u8)
                    .map(|n| tokio::spawn(echo_stream(ports.socks[i], echo, n, 200_000)))
                    .collect();
                for task in concurrent {
                    task.await??;
                }
                let connections = count.load(Ordering::SeqCst);
                anyhow::ensure!(
                    connections == 1,
                    "{}: 9 streams with Brutal took {} connections, not 1",
                    protocol,
                    connections
                );
            }
            anyhow::Ok(())
        }
        .await;
        server.abort();
        result
    })
}

// app(socks) -> sail(ss + mux + brutal) -> sail(ss + mux): a server
// without Brutal refuses it, and the connection fails.
#[test]
fn test_mux_brutal_refused_sail_to_sail() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let ports = BrutalPorts::new();
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                brutal_server(&ports, false).to_string(),
                brutal_client(&ports, false).to_string(),
            ],
        )?;
        let result = run_brutal(&rt, &ports, false);
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sail(ss + mux + brutal) -> sail(ss + mux + brutal): served
// where the module is loaded; elsewhere the server cannot set Brutal and
// refuses it.
#[cfg(target_os = "linux")]
#[test]
fn test_mux_brutal_sail_to_sail() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let ports = BrutalPorts::new();
        let rt = runtime()?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                brutal_server(&ports, true).to_string(),
                brutal_client(&ports, false).to_string(),
            ],
        )?;
        let result = run_brutal(&rt, &ports, brutal_loaded());
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> sail(ss + mux + brutal) -> sing-box(ss + mux), then
// sing-box(ss + mux + brutal). sing-box's release builds serve Brutal on
// Linux only, and there, where the module is loaded; a build with
// `-tags debug` (`SING_BOX_DEBUG`) serves it anywhere.
#[test]
#[ignore = "needs sing-box"]
fn test_mux_brutal_sail_to_sing_box() -> anyhow::Result<()> {
    let dir = common::TempDir::new("mux-brutal")?;
    for with_brutal in [false, true] {
        if with_brutal && !cfg!(target_os = "linux") && !sing_box_debug() {
            continue;
        }
        common::retry_port_clash(|| {
            let ports = BrutalPorts::new();
            let _sing_box =
                common::Daemon::sing_box(dir.path(), "server", brutal_server(&ports, with_brutal))?;
            let rt = runtime()?;
            let ids =
                common::run_sail_instances(&rt, vec![brutal_client(&ports, false).to_string()])?;
            let served = with_brutal && (brutal_loaded() || sing_box_debug());
            let result = run_brutal(&rt, &ports, served)
                .map_err(|e| anyhow::anyhow!("server brutal {}: {}", with_brutal, e));
            common::shutdown_instances(&rt, ids);
            result
        })?;
    }
    Ok(())
}

// app(mixed) -> sing-box(ss + mux + brutal) -> sail(ss + mux), then
// sail(ss + mux + brutal) where sail serves Brutal, on Linux.
#[test]
#[ignore = "needs sing-box"]
fn test_mux_brutal_sing_box_to_sail() -> anyhow::Result<()> {
    let dir = common::TempDir::new("mux-brutal")?;
    for with_brutal in [false, true] {
        if with_brutal && !cfg!(target_os = "linux") {
            continue;
        }
        common::retry_port_clash(|| {
            let ports = BrutalPorts::new();
            let rt = runtime()?;
            let ids = common::run_sail_instances(
                &rt,
                vec![brutal_server(&ports, with_brutal).to_string()],
            )?;
            let result = (|| {
                let _sing_box =
                    common::Daemon::sing_box(dir.path(), "client", brutal_client(&ports, true))?;
                run_brutal(&rt, &ports, with_brutal && brutal_loaded())
            })()
            .map_err(|e| anyhow::anyhow!("server brutal {}: {}", with_brutal, e));
            common::shutdown_instances(&rt, ids);
            result
        })?;
    }
    Ok(())
}
