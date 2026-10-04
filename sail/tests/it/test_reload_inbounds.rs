//! A reload's inbounds: those the new configuration has are those that
//! run after it. One the reload adds listens; one it no longer has stops
//! and its connections close; one changed in more than its users and
//! certificate is replaced, its connections closed; the others, and their
//! connections, are not touched. A reload that cannot bind what it adds
//! or replaces changes nothing. It tells what became of each inbound.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]

use std::net::SocketAddr;
use std::time::Duration;

use sail::embed::{Config, ErrorKind, InboundChange, Instance, Options, Threads};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common;

fn config(inbounds: serde_json::Value) -> Config {
    Config::Json(
        serde_json::json!({
            "log": { "level": "info" },
            "inbounds": inbounds,
            "outbounds": [{ "type": "direct", "tag": "direct" }],
        })
        .to_string(),
    )
}

fn socks(tag: &str, listen: &str, port: u16) -> serde_json::Value {
    serde_json::json!({ "type": "socks", "tag": tag, "listen": listen, "listen_port": port })
}

fn instance() -> Instance {
    Instance::new(Options::new().threads(Threads::One).log_lines(100)).unwrap()
}

/// A SOCKS5 connection through the inbound on `port` to `to`, relayed.
async fn through(port: u16, to: SocketAddr) -> std::io::Result<TcpStream> {
    let SocketAddr::V4(to) = to else {
        return Err(std::io::Error::other("an IPv4 destination"));
    };
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut greeted = [0u8; 2];
    s.read_exact(&mut greeted).await?;
    let mut request = vec![5, 1, 0, 1];
    request.extend(to.ip().octets());
    request.extend(to.port().to_be_bytes());
    s.write_all(&request).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS REP {}", reply[1])));
    }
    Ok(s)
}

/// Whether `s` still relays: what it sends comes back.
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

/// Whether `s` was closed: a read ends within 5 s.
async fn closed(s: &mut TcpStream) -> bool {
    let mut buf = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

/// Whether anything listens on `port`.
async fn listens(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).await.is_ok()
}

fn change(report: &sail::embed::ReloadReport, tag: &str) -> Option<InboundChange> {
    report
        .inbounds
        .iter()
        .find(|(t, _)| t == tag)
        .map(|(_, change)| *change)
}

/// One reload that leaves an inbound alone, removes one, moves one to
/// another port, changes one on the port it has, and adds one: each is as
/// the configuration has it after, only the connections of those removed
/// and replaced are closed, and the reload tells which is which.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_adds_removes_and_replaces_inbounds_and_tells_which() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [keep, gone, moved_from, moved_to, same, added] = common::free_ports();
    let instance = instance();
    instance
        .start(config(serde_json::json!([
            socks("keep", "127.0.0.1", keep),
            socks("gone", "127.0.0.1", gone),
            socks("moved", "127.0.0.1", moved_from),
            socks("same", "127.0.0.1", same),
        ])))
        .await
        .unwrap();
    let mut on_keep = through(keep, echo).await.unwrap();
    let mut on_gone = through(gone, echo).await.unwrap();
    let mut on_moved = through(moved_from, echo).await.unwrap();
    let mut on_same = through(same, echo).await.unwrap();
    for held in [&mut on_keep, &mut on_gone, &mut on_moved, &mut on_same] {
        assert!(relays(held).await);
    }

    // `same` keeps its address and changes otherwise: the one before must
    // stop before this one binds.
    let mut changed = socks("same", "127.0.0.1", same);
    changed["tcp_keep_alive_interval"] = "30s".into();
    let report = instance
        .reload(Some(config(serde_json::json!([
            socks("keep", "127.0.0.1", keep),
            socks("moved", "127.0.0.1", moved_to),
            changed,
            socks("added", "127.0.0.1", added),
        ]))))
        .await
        .unwrap();
    assert_eq!(
        report.inbounds,
        [
            ("keep".to_string(), InboundChange::Untouched),
            ("moved".to_string(), InboundChange::Replaced),
            ("same".to_string(), InboundChange::Replaced),
            ("added".to_string(), InboundChange::Added),
            ("gone".to_string(), InboundChange::Removed),
        ]
    );
    // Closed once the reload returned, not a moment later.
    for (port, what) in [
        (gone, "the removed inbound's port"),
        (moved_from, "the port the moved inbound left"),
    ] {
        assert!(
            std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
            "{} still listens once the reload returned",
            what
        );
    }

    assert!(
        relays(&mut on_keep).await,
        "an untouched inbound's connection"
    );
    assert!(closed(&mut on_gone).await, "a removed inbound's connection");
    assert!(
        closed(&mut on_moved).await,
        "a replaced inbound's connection"
    );
    assert!(
        closed(&mut on_same).await,
        "a replaced inbound's connection"
    );
    for port in [keep, moved_to, same, added] {
        let mut s = through(port, echo).await.unwrap();
        assert!(relays(&mut s).await, "port {} serves", port);
    }
    let mut tags: Vec<String> = instance
        .inbounds()
        .unwrap()
        .into_iter()
        .map(|i| i.tag)
        .collect();
    tags.sort();
    assert_eq!(tags, ["added", "keep", "moved", "same"]);

    // The same configuration again: nothing to do, and nothing done.
    let mut changed = socks("same", "127.0.0.1", same);
    changed["tcp_keep_alive_interval"] = "30s".into();
    let report = instance
        .reload(Some(config(serde_json::json!([
            socks("keep", "127.0.0.1", keep),
            socks("moved", "127.0.0.1", moved_to),
            changed,
            socks("added", "127.0.0.1", added),
        ]))))
        .await
        .unwrap();
    assert!(
        report
            .inbounds
            .iter()
            .all(|(_, change)| *change == InboundChange::Untouched),
        "{:?}",
        report
    );
    assert!(relays(&mut on_keep).await);
    instance.stop().await.unwrap();
}

/// A reload whose new inbound cannot bind changes nothing, whether it is
/// one added, or one put on the address of the inbound it replaces, where
/// the one before is stopped first and put back: those running listen as
/// they did, and their connections were never touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_that_cannot_bind_leaves_everything_as_it_was() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [keep, wide] = common::free_ports();
    // A port something else holds.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken_port = taken.local_addr().unwrap().port();
    let running = serde_json::json!([
        socks("keep", "127.0.0.1", keep),
        socks("wide", "0.0.0.0", wide),
    ]);
    let instance = instance();
    instance.start(config(running.clone())).await.unwrap();
    let mut on_keep = through(keep, echo).await.unwrap();
    let mut on_wide = through(wide, echo).await.unwrap();

    // One added, on a port in use.
    let failed = instance
        .reload(Some(config(serde_json::json!([
            socks("keep", "127.0.0.1", keep),
            socks("wide", "0.0.0.0", wide),
            socks("added", "127.0.0.1", taken_port),
        ]))))
        .await
        .unwrap_err();
    assert_eq!(failed.kind(), ErrorKind::Config, "{}", failed);

    // `wide` replaced on its own port, at an address that is not this
    // machine's (192.0.2.0/24 is for documentation): the one on every
    // address holds the port, so it is stopped first; the bind fails, and
    // it is put back.
    let failed = instance
        .reload(Some(config(serde_json::json!([
            socks("keep", "127.0.0.1", keep),
            socks("wide", "192.0.2.1", wide),
        ]))))
        .await
        .unwrap_err();
    assert_eq!(failed.kind(), ErrorKind::Config, "{}", failed);

    assert!(relays(&mut on_keep).await);
    assert!(
        relays(&mut on_wide).await,
        "its connections were not touched"
    );
    for port in [keep, wide] {
        let mut s = through(port, echo).await.unwrap();
        assert!(relays(&mut s).await, "port {} serves as before", port);
    }
    let mut tags: Vec<String> = instance
        .inbounds()
        .unwrap()
        .into_iter()
        .map(|i| i.tag)
        .collect();
    tags.sort();
    assert_eq!(tags, ["keep", "wide"]);
    drop(taken);
    instance.stop().await.unwrap();
}

/// The configuration is what runs: an inbound added while it ran, by the
/// host or through the API, and not in the configuration reloaded, is
/// removed by the reload; one in it stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_removes_an_inbound_added_at_run_time_that_the_configuration_lacks() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [keep, proxy] = common::free_ports();
    let instance = instance();
    let file = serde_json::json!([socks("keep", "127.0.0.1", keep)]);
    instance.start(config(file.clone())).await.unwrap();
    instance
        .add_inbound(socks("system-proxy", "127.0.0.1", proxy))
        .await
        .unwrap();
    let mut on_proxy = through(proxy, echo).await.unwrap();
    assert!(relays(&mut on_proxy).await);

    // A host that keeps what it added in the configuration it reloads
    // with keeps it running, untouched.
    let report = instance
        .reload(Some(config(serde_json::json!([
            socks("keep", "127.0.0.1", keep),
            socks("system-proxy", "127.0.0.1", proxy),
        ]))))
        .await
        .unwrap();
    assert_eq!(
        change(&report, "system-proxy"),
        Some(InboundChange::Untouched)
    );
    assert!(relays(&mut on_proxy).await);

    // Without it, the reload removes it.
    let report = instance.reload(Some(config(file))).await.unwrap();
    assert_eq!(
        change(&report, "system-proxy"),
        Some(InboundChange::Removed)
    );
    assert_eq!(change(&report, "keep"), Some(InboundChange::Untouched));
    assert!(closed(&mut on_proxy).await);
    assert!(!listens(proxy).await);
    instance.stop().await.unwrap();
}

/// Connections on an inbound a reload does not touch carry on through it,
/// every byte: a reload that adds, removes and replaces others while they
/// send and receive loses and changes none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_on_an_untouched_inbound_lose_nothing_to_a_reload() {
    const CONNECTIONS: usize = 24;
    const CHUNKS: usize = 64;
    const CHUNK: usize = 8 * 1024;

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [keep, gone, moved_from, moved_to, added] = common::free_ports();
    let instance = instance();
    instance
        .start(config(serde_json::json!([
            socks("keep", "127.0.0.1", keep),
            socks("gone", "127.0.0.1", gone),
            socks("moved", "127.0.0.1", moved_from),
        ])))
        .await
        .unwrap();

    let (begun_tx, mut begun) = tokio::sync::mpsc::channel::<()>(CONNECTIONS);
    let mut carrying = Vec::new();
    for n in 0..CONNECTIONS {
        let begun_tx = begun_tx.clone();
        carrying.push(tokio::spawn(async move {
            let mut s = through(keep, echo).await.unwrap();
            let mut back = vec![0u8; CHUNK];
            for i in 0..CHUNKS {
                // Bytes that differ by connection, chunk and place.
                let sent: Vec<u8> = (0..CHUNK).map(|at| (n * 31 + i * 7 + at) as u8).collect();
                s.write_all(&sent).await.unwrap();
                s.read_exact(&mut back).await.unwrap();
                assert!(back == sent, "connection {} chunk {} changed", n, i);
                if i == 4 {
                    let _ = begun_tx.send(()).await;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }
    drop(begun_tx);
    // Every connection is carrying when the reload comes.
    for _ in 0..CONNECTIONS {
        begun.recv().await.expect("a connection began");
    }
    let report = instance
        .reload(Some(config(serde_json::json!([
            socks("keep", "127.0.0.1", keep),
            socks("moved", "127.0.0.1", moved_to),
            socks("added", "127.0.0.1", added),
        ]))))
        .await
        .unwrap();
    assert_eq!(change(&report, "keep"), Some(InboundChange::Untouched));
    assert_eq!(change(&report, "gone"), Some(InboundChange::Removed));
    for carried in carrying {
        tokio::time::timeout(Duration::from_secs(30), carried)
            .await
            .expect("a connection carried on to its end")
            .unwrap();
    }
    instance.stop().await.unwrap();
}
