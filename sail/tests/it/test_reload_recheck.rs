//! A reload asked to recheck the connections open (`RecheckOpen::CloseRejected`)
//! matches each against the routing it leaves: it closes those the new
//! rules reject, tells those they send to another outbound, and leaves the
//! rest. A reload not asked to leaves them all. A connection the routing
//! before routed and listed only after the recheck went by is rechecked as
//! it is listed, until the next reload.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sail::embed::{Config, Instance, Network, Options, RecheckOpen, ReloadOptions, Threads};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::common;

/// A TCP echo server of its own.
async fn echo() -> SocketAddr {
    let (addr, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    addr
}

/// A SOCKS5 connection through the inbound on `port` to `host`:`to`,
/// relayed.
async fn through(port: u16, host: &str, to: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut greeted = [0u8; 2];
    s.read_exact(&mut greeted).await?;
    let mut request = vec![5, 1, 0];
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            request.push(1);
            request.extend(ip.octets());
        }
        Err(_) => {
            request.push(3);
            request.push(host.len() as u8);
            request.extend(host.as_bytes());
        }
    }
    request.extend(to.to_be_bytes());
    s.write_all(&request).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS REP {}", reply[1])));
    }
    Ok(s)
}

/// Sends through `s` and has it back from the echo server.
async fn relays(s: &mut TcpStream) -> bool {
    let relayed = async {
        s.write_all(b"still here").await?;
        let mut back = [0u8; 10];
        s.read_exact(&mut back).await?;
        std::io::Result::Ok(back == *b"still here")
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(5), relayed).await,
        Ok(Ok(true))
    )
}

/// Whether `s` was closed: a read ends or fails within 5 s.
async fn closed(s: &mut TcpStream) -> bool {
    let mut buf = [0u8; 16];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// An instance's configuration: a SOCKS inbound on `socks`, `outbounds`
/// and `rules`, `final` the first outbound, `dns` as given.
fn config(
    socks: u16,
    dns: serde_json::Value,
    outbounds: serde_json::Value,
    rules: serde_json::Value,
) -> Config {
    let first = outbounds[0]["tag"].clone();
    Config::Json(
        serde_json::json!({
            "log": { "level": "info" },
            "dns": dns,
            "inbounds": [{ "type": "socks", "tag": "socks",
                           "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": outbounds,
            "route": { "rules": rules, "final": first },
        })
        .to_string(),
    )
}

fn direct() -> serde_json::Value {
    serde_json::json!([{ "type": "direct", "tag": "direct" }])
}

fn close_rejected() -> ReloadOptions {
    ReloadOptions::new().recheck_open(RecheckOpen::CloseRejected)
}

async fn instance(config: Config) -> Instance {
    let instance = Instance::new(Options::new().threads(Threads::One).log_lines(100)).unwrap();
    instance.start(config).await.unwrap();
    instance
}

/// The id the connections list the one of `network` to port `to` by.
async fn id_of(instance: &Instance, network: Network, to: u16) -> u64 {
    instance
        .connections()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.network == network && c.destination.port() == to)
        .map(|c| c.id)
        .expect("the connection is listed")
}

/// Of two connections open, the one to the port a new rule rejects is
/// closed and listed with that rule's index; the other carries on both
/// ways. A reload with the very configuration that runs, of the inbounds
/// alone, rechecks against the routing that ran, and finds nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recheck_closes_the_connections_the_new_rules_reject() {
    let (to_reject, to_keep) = (echo().await, echo().await);
    let [socks] = common::free_ports();
    let none = serde_json::json!({});
    let instance = instance(config(socks, none.clone(), direct(), serde_json::json!([]))).await;
    let mut rejected = through(socks, "127.0.0.1", to_reject.port()).await.unwrap();
    let mut kept = through(socks, "127.0.0.1", to_keep.port()).await.unwrap();
    assert!(relays(&mut rejected).await && relays(&mut kept).await);
    let id = id_of(&instance, Network::Tcp, to_reject.port()).await;

    let rules = serde_json::json!([
        { "port": [1], "outbound": "direct" },
        { "port": [to_reject.port()], "action": "reject" },
    ]);
    let report = instance
        .reload_rechecking(
            Some(config(socks, none.clone(), direct(), rules.clone())),
            close_rejected(),
        )
        .await
        .unwrap();
    let recheck = report.recheck.expect("a recheck ran");
    let closed_ones: Vec<_> = recheck.closed.iter().map(|c| (c.id, c.rule)).collect();
    assert_eq!(closed_ones, vec![(id, Some(1))]);
    assert!(recheck.differ.is_empty(), "{:?}", recheck.differ);
    assert!(
        closed(&mut rejected).await,
        "the rejected connection is open"
    );
    assert!(relays(&mut kept).await, "the other connection was closed");

    let report = instance
        .reload_rechecking(Some(config(socks, none, direct(), rules)), close_rejected())
        .await
        .unwrap();
    assert_eq!(report.path, sail::embed::ReloadPath::InboundsOnly);
    let recheck = report.recheck.expect("a recheck ran");
    assert!(
        recheck.closed.is_empty() && recheck.differ.is_empty(),
        "{:?}",
        recheck
    );
    assert!(relays(&mut kept).await);
    instance.stop().await.unwrap();
}

/// A reload not asked to recheck, the default, leaves every connection
/// open, those the new rules reject too, and tells no recheck.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_recheck_a_reload_leaves_the_connections_open() {
    let to = echo().await;
    let [socks] = common::free_ports();
    let none = serde_json::json!({});
    let instance = instance(config(socks, none.clone(), direct(), serde_json::json!([]))).await;
    let mut open = through(socks, "127.0.0.1", to.port()).await.unwrap();
    assert!(relays(&mut open).await);

    let rules = serde_json::json!([{ "port": [to.port()], "action": "reject" }]);
    let report = instance
        .reload_rechecking(
            Some(config(socks, none.clone(), direct(), rules)),
            ReloadOptions::new().recheck_open(RecheckOpen::Keep),
        )
        .await
        .unwrap();
    assert!(report.recheck.is_none(), "{:?}", report.recheck);
    assert!(relays(&mut open).await);

    let rules = serde_json::json!([
        { "port": [1], "outbound": "direct" },
        { "port": [to.port()], "action": "reject" },
    ]);
    let report = instance
        .reload(Some(config(socks, none, direct(), rules)))
        .await
        .unwrap();
    assert!(report.recheck.is_none(), "{:?}", report.recheck);
    assert!(relays(&mut open).await);
    instance.stop().await.unwrap();
}

/// A connection the new rules send to another outbound is told, with the
/// outbound it went to and the one it would go to now, and goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recheck_tells_the_connections_sent_elsewhere_now() {
    let to = echo().await;
    let [socks] = common::free_ports();
    let none = serde_json::json!({});
    // Unlike, so that each is an outbound of its own.
    let outbounds = serde_json::json!([
        { "type": "direct", "tag": "a" },
        { "type": "direct", "tag": "b", "connect_timeout": "9s" },
    ]);
    let rules = |tag: &str| serde_json::json!([{ "port": [to.port()], "outbound": tag }]);
    let instance = instance(config(socks, none.clone(), outbounds.clone(), rules("a"))).await;
    let mut open = through(socks, "127.0.0.1", to.port()).await.unwrap();
    assert!(relays(&mut open).await);
    let id = id_of(&instance, Network::Tcp, to.port()).await;

    let report = instance
        .reload_rechecking(
            Some(config(socks, none, outbounds, rules("b"))),
            close_rejected(),
        )
        .await
        .unwrap();
    let recheck = report.recheck.expect("a recheck ran");
    assert!(recheck.closed.is_empty(), "{:?}", recheck.closed);
    let differ: Vec<_> = recheck
        .differ
        .iter()
        .map(|d| (d.id, d.old.as_str(), d.new.as_str()))
        .collect();
    assert_eq!(differ, vec![(id, "a", "b")]);
    assert!(
        relays(&mut open).await,
        "a connection sent elsewhere was closed"
    );
    instance.stop().await.unwrap();
}

/// A UDP session is rechecked by its first destination: a rule on another
/// it sent to since leaves it, one on the first closes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_udp_session_is_rechecked_by_its_first_destination() {
    use sail::session::{Session, SocksAddr};

    let (first, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let (second, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [socks] = common::free_ports();
    let none = serde_json::json!({});
    let instance = instance(config(socks, none.clone(), direct(), serde_json::json!([]))).await;
    let sess = Session {
        destination: SocksAddr::from(first),
        ..Default::default()
    };
    let datagram = common::scoped(common::new_socks_datagram(
        "127.0.0.1",
        socks,
        &sess,
        None,
        None,
    ))
    .await
    .unwrap();
    let (mut recv, mut send) = datagram.split();
    // Whether a datagram sent to `to` on the session comes back.
    macro_rules! echoed {
        ($to:expr) => {{
            let to = SocksAddr::from($to);
            let mut buf = [0u8; 64];
            send.send_to(b"ping", &to).await.is_ok()
                && matches!(
                    tokio::time::timeout(Duration::from_secs(2), recv.recv_from(&mut buf)).await,
                    Ok(Ok((4, _)))
                )
        }};
    }
    assert!(echoed!(first) && echoed!(second));
    let id = id_of(&instance, Network::Udp, first.port()).await;

    let reject = |port: u16| serde_json::json!([{ "port": [port], "action": "reject" }]);
    let report = instance
        .reload_rechecking(
            Some(config(socks, none.clone(), direct(), reject(second.port()))),
            close_rejected(),
        )
        .await
        .unwrap();
    let recheck = report.recheck.expect("a recheck ran");
    assert!(recheck.closed.is_empty(), "{:?}", recheck.closed);
    assert!(echoed!(first), "the session was closed");

    let report = instance
        .reload_rechecking(
            Some(config(socks, none, direct(), reject(first.port()))),
            close_rejected(),
        )
        .await
        .unwrap();
    let recheck = report.recheck.expect("a recheck ran");
    let closed_ones: Vec<_> = recheck.closed.iter().map(|c| (c.id, c.rule)).collect();
    assert_eq!(closed_ones, vec![(id, Some(0))]);
    assert!(!echoed!(first), "the session goes on");
    instance.stop().await.unwrap();
}

/// A DNS server that answers every question with 127.0.0.1, A or not,
/// those for the names it holds only once they are let go; it keeps the
/// names it was asked.
struct HeldDns {
    port: u16,
    held: Arc<Mutex<HashSet<String>>>,
    let_go: Arc<tokio::sync::Notify>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl HeldDns {
    async fn start(held: &[&str]) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dns = HeldDns {
            port: socket.local_addr().unwrap().port(),
            held: Arc::new(Mutex::new(held.iter().map(|n| n.to_string()).collect())),
            let_go: Default::default(),
            asked: Default::default(),
        };
        let (held, let_go, asked) = (dns.held.clone(), dns.let_go.clone(), dns.asked.clone());
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, from) = common::recv_past_errors(&socket, &mut buf).await;
                let query = buf[..n].to_vec();
                let mut name = Vec::new();
                let mut at = 12;
                while query[at] != 0 {
                    let len = query[at] as usize;
                    name.push(String::from_utf8_lossy(&query[at + 1..at + 1 + len]).to_lowercase());
                    at += 1 + len;
                }
                let name = name.join(".");
                asked.lock().unwrap().push(name.clone());
                let mut answer = query[..at + 5].to_vec();
                let a = query[at + 1..at + 3] == [0, 1];
                answer[2] = 0x81;
                answer[3] = 0x80;
                answer[6..12].copy_from_slice(&[0, u8::from(a), 0, 0, 0, 0]);
                if a {
                    answer.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
                }
                let (socket, held, let_go) = (socket.clone(), held.clone(), let_go.clone());
                tokio::spawn(async move {
                    loop {
                        let notified = let_go.notified();
                        if !held.lock().unwrap().contains(&name) {
                            break;
                        }
                        notified.await;
                    }
                    let _ = socket.send_to(&answer, from).await;
                });
            }
        });
        dns
    }

    /// Answers `name` from now on, and the questions for it waiting.
    fn let_go(&self, name: &str) {
        self.held.lock().unwrap().remove(name);
        self.let_go.notify_waiters();
    }

    /// Once `name` was asked for, 10 s at most.
    async fn asked_for(&self, name: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !self.asked.lock().unwrap().iter().any(|n| n == name) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{} was not asked for",
                name
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// A connection the routing before routed, held in its dial (the name it
/// goes to not answered) while the recheck goes by, is rechecked as it is
/// listed, and closed. Once a reload not asked to recheck took, one so
/// held is listed as it was routed, and carries on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_listed_after_the_recheck_is_rechecked_until_the_next_reload() {
    let to = echo().await;
    let dns = HeldDns::start(&["first.held.test", "second.held.test"]).await;
    let [socks] = common::free_ports();
    let dns_config = serde_json::json!({
        "servers": [{ "type": "udp", "tag": "held", "server": "127.0.0.1", "server_port": dns.port }],
        "strategy": "ipv4_only",
    });
    let open = serde_json::json!([{ "port": [1], "outbound": "direct" }]);
    let reject = serde_json::json!([{ "port": [to.port()], "action": "reject" }]);
    let configured =
        |rules: &serde_json::Value| config(socks, dns_config.clone(), direct(), rules.clone());
    let instance = instance(configured(&open)).await;

    let first = tokio::spawn(async move { through(socks, "first.held.test", to.port()).await });
    dns.asked_for("first.held.test").await;
    let report = instance
        .reload_rechecking(Some(configured(&reject)), close_rejected())
        .await
        .unwrap();
    assert!(report.recheck.expect("a recheck ran").closed.is_empty());
    dns.let_go("first.held.test");
    match first.await.unwrap() {
        // Refused in its handshake, or closed once relayed.
        Err(_) => {}
        Ok(mut s) => assert!(
            closed(&mut s).await,
            "the late connection was not rechecked"
        ),
    }

    instance.reload(Some(configured(&open))).await.unwrap();
    let second = tokio::spawn(async move { through(socks, "second.held.test", to.port()).await });
    dns.asked_for("second.held.test").await;
    instance
        .reload_rechecking(Some(configured(&reject)), close_rejected())
        .await
        .unwrap();
    // The same configuration, of the inbounds alone: no recheck asked.
    instance.reload(Some(configured(&reject))).await.unwrap();
    dns.let_go("second.held.test");
    let mut second = second.await.unwrap().expect("the connection is relayed");
    assert!(
        relays(&mut second).await,
        "a connection listed after a plain reload was rechecked"
    );
    instance.stop().await.unwrap();
}
