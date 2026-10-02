//! A reload that changes only `dns.servers` keeps connections held over
//! multiplexed sessions: an AnyTLS outbound's, and a sing-mux one's. A host
//! pushes new DNS servers by reload after each change of network; were the
//! sessions torn down, every connection would drop with it. And once those
//! connections end, the replaced outbound's sessions close: were they left
//! open, each reload would leave idle sessions to the server behind.
#![cfg(all(
    feature = "inbound-anytls",
    feature = "outbound-anytls",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks",
    feature = "mux",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "inbound-tls",
    feature = "outbound-tls",
))]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sail::embed::{Config, Instance, Options, Threads};
use sail::session::Session;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::common;

const PASSWORD: &str = "anytls-password";
const SS_METHOD: &str = "2022-blake3-aes-128-gcm";
const SS_KEY: &str = "a8C5QncIl9HvTmenrEb7aw==";
/// How long an AnyTLS session may stay idle, and how often that is looked
/// at: the shortest AnyTLS takes, so that the test waits seconds.
const IDLE: &str = "6s";
const IDLE_CHECK: &str = "6s";
/// How long the replaced outbound's sessions may take to close once
/// their connections have: the idle timeout and a check, with room.
const CLOSED_WITHIN: Duration = Duration::from_secs(30);

struct Ports {
    anytls: u16,
    shadowsocks: u16,
    socks_anytls: u16,
    socks_mux: u16,
}

/// The connections a forwarder in front of a server has open, by number.
#[derive(Clone, Default)]
struct Open(Arc<Mutex<BTreeSet<usize>>>);

impl Open {
    fn now(&self) -> BTreeSet<usize> {
        self.0.lock().unwrap().clone()
    }
}

/// A TCP forwarder to `target`: its port, and the connections open
/// through it, each a session the client's outbound holds.
async fn forwarder(target: u16) -> (u16, Open) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let open = Open::default();
    let tracked = open.clone();
    tokio::spawn(async move {
        let mut next = 0usize;
        while let Ok((mut inbound, _)) = listener.accept().await {
            next += 1;
            let n = next;
            tracked.0.lock().unwrap().insert(n);
            let tracked = tracked.clone();
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", target)).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
                tracked.0.lock().unwrap().remove(&n);
            });
        }
    });
    (port, open)
}

fn server(ports: &Ports, cert: &str, key: &str) -> String {
    json!({
        "inbounds": [
            {
                "type": "anytls", "tag": "anytls-in",
                "listen": "127.0.0.1", "listen_port": ports.anytls,
                "users": [{ "name": "alice", "password": PASSWORD }],
                "tls": { "enabled": true, "certificate_path": cert, "key_path": key },
            },
            {
                "type": "shadowsocks", "tag": "ss-in",
                "listen": "127.0.0.1", "listen_port": ports.shadowsocks,
                "method": SS_METHOD, "password": SS_KEY,
                "multiplex": { "enabled": true },
            },
        ],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    })
    .to_string()
}

/// The client, its outbounds reaching the servers through the forwarders
/// at `anytls` and `shadowsocks`.
fn client(ports: &Ports, anytls: u16, shadowsocks: u16, cert: &str, dns_port: u16) -> String {
    json!({
        "dns": {
            "servers": [{ "tag": "upstream", "type": "udp", "server": "127.0.0.1", "server_port": dns_port }],
        },
        "inbounds": [
            { "type": "socks", "tag": "in-anytls", "listen": "127.0.0.1", "listen_port": ports.socks_anytls },
            { "type": "socks", "tag": "in-mux", "listen": "127.0.0.1", "listen_port": ports.socks_mux },
        ],
        "outbounds": [
            {
                "type": "anytls", "tag": "anytls",
                "server": "127.0.0.1", "server_port": anytls,
                "password": PASSWORD,
                "idle_session_check_interval": IDLE_CHECK,
                "idle_session_timeout": IDLE,
                "tls": { "enabled": true, "server_name": "localhost", "certificate_path": cert },
            },
            {
                "type": "shadowsocks", "tag": "mux",
                "server": "127.0.0.1", "server_port": shadowsocks,
                "method": SS_METHOD, "password": SS_KEY,
                "multiplex": { "enabled": true, "protocol": "smux" },
            },
        ],
        "route": {
            "rules": [
                { "inbound": ["in-anytls"], "outbound": "anytls" },
                { "inbound": ["in-mux"], "outbound": "mux" },
            ],
        },
    })
    .to_string()
}

async fn round_trip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    s: &mut S,
    what: &[u8],
) -> std::io::Result<()> {
    s.write_all(what).await?;
    let mut back = vec![0u8; what.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    assert_eq!(back, what);
    Ok(())
}

/// Waits until none of `sessions` is open through `open`, up to `within`:
/// those still open then.
async fn closed(open: &Open, sessions: &BTreeSet<usize>, within: Duration) -> BTreeSet<usize> {
    let until = tokio::time::Instant::now() + within;
    loop {
        let left: BTreeSet<usize> = open.now().intersection(sessions).copied().collect();
        if left.is_empty() || tokio::time::Instant::now() >= until {
            return left;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_over_multiplexed_sessions_outlive_a_reload_of_the_dns_servers() {
    let dir = common::TempDir::new("reload-sessions").unwrap();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    let (cert, key) = (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    );
    let [anytls, shadowsocks, socks_anytls, socks_mux] = common::free_ports::<4>();
    let ports = Ports {
        anytls,
        shadowsocks,
        socks_anytls,
        socks_mux,
    };
    let (anytls_via, anytls_open) = forwarder(ports.anytls).await;
    let (mux_via, mux_open) = forwarder(ports.shadowsocks).await;
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);

    let options = || Options::new().threads(Threads::One).log_lines(0);
    let server_instance = Instance::new(options()).unwrap();
    server_instance
        .start(Config::Json(server(&ports, &cert, &key)))
        .await
        .unwrap();
    let client_instance = Instance::new(options()).unwrap();
    client_instance
        .start(Config::Json(client(&ports, anytls_via, mux_via, &cert, 53)))
        .await
        .unwrap();

    let sess = Session {
        destination: echo.into(),
        ..Default::default()
    };
    let mut over_anytls =
        common::new_socks_stream("127.0.0.1", ports.socks_anytls, &sess, None, None)
            .await
            .unwrap();
    let mut over_mux = common::new_socks_stream("127.0.0.1", ports.socks_mux, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut over_anytls, b"anytls, before")
        .await
        .unwrap();
    round_trip(&mut over_mux, b"sing-mux, before")
        .await
        .unwrap();
    // The sessions the outbounds hold before the reload.
    let (anytls_before, mux_before) = (anytls_open.now(), mux_open.now());
    assert!(!anytls_before.is_empty() && !mux_before.is_empty());

    client_instance
        .reload(Some(Config::Json(client(
            &ports, anytls_via, mux_via, &cert, 5353,
        ))))
        .await
        .unwrap();

    // The held connections go on.
    let anytls_after = round_trip(&mut over_anytls, b"anytls, after").await;
    let mux_after = round_trip(&mut over_mux, b"sing-mux, after").await;
    // New connections work, on sessions of the rebuilt outbounds.
    let mut fresh = common::new_socks_stream("127.0.0.1", ports.socks_anytls, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut fresh, b"anytls, new").await.unwrap();
    let mut fresh_mux = common::new_socks_stream("127.0.0.1", ports.socks_mux, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut fresh_mux, b"sing-mux, new").await.unwrap();

    // Once the held connections end, the replaced outbounds' sessions
    // close: none is left to the server for good.
    drop((over_anytls, over_mux));
    let anytls_left = closed(&anytls_open, &anytls_before, CLOSED_WITHIN).await;
    let mux_left = closed(&mux_open, &mux_before, CLOSED_WITHIN).await;

    client_instance.stop().await.unwrap();
    server_instance.stop().await.unwrap();
    assert!(
        anytls_after.is_ok() && mux_after.is_ok(),
        "held through the reload: anytls {:?}, sing-mux {:?}",
        anytls_after,
        mux_after
    );
    assert!(
        anytls_left.is_empty() && mux_left.is_empty(),
        "the replaced outbounds' sessions still open {:?} after their connections closed: \
         anytls {:?} of {:?}, sing-mux {:?} of {:?}",
        CLOSED_WITHIN,
        anytls_left,
        anytls_before,
        mux_left,
        mux_before
    );
}
