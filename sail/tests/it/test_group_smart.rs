#![cfg(all(feature = "outbound-smart", feature = "outbound-socks"))]

use crate::test_group_common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::future::{abortable, AbortHandle};
use serde_json::json;
use test_group_common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Probes through a member reach its server whatever the URL says.
const URL: &str = "http://probe.test/generate_204";

/// A SOCKS5 server that takes every request to the HTTP server on
/// `upstream`, whatever it asks for; stopped when the handle is aborted.
async fn socks(upstream: u16) -> (AbortHandle, u16) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (task, handle) = abortable(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 262];
                // Greeting: version, methods; no authentication.
                client.read_exact(&mut buf[..2]).await?;
                let n = buf[1] as usize;
                client.read_exact(&mut buf[..n]).await?;
                client.write_all(&[5, 0]).await?;
                // Request: version, command, reserved, address, port.
                client.read_exact(&mut buf[..4]).await?;
                let len = match buf[3] {
                    1 => 4,
                    4 => 16,
                    _ => {
                        client.read_exact(&mut buf[..1]).await?;
                        buf[0] as usize
                    }
                };
                client.read_exact(&mut buf[..len + 2]).await?;
                let mut server = TcpStream::connect(("127.0.0.1", upstream)).await?;
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                tokio::io::copy_bidirectional(&mut client, &mut server).await?;
                Ok::<_, std::io::Error>(())
            });
        }
    });
    tokio::spawn(task);
    (handle, port)
}

/// A server that answers a probe (a request starting `GET`) with 204, and
/// `BLK` with `BULK` bytes; it counts the bulk transfers. It reads the
/// whole request first: unread bytes at the close would reset the
/// connection under what is still in flight.
async fn bulk() -> (AbortHandle, Arc<AtomicUsize>, u16) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let transfers = Arc::new(AtomicUsize::new(0));
    let counted = transfers.clone();
    let (task, handle) = abortable(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                continue;
            };
            let counted = counted.clone();
            tokio::spawn(async move {
                let mut first = [0u8; 3];
                client.read_exact(&mut first).await?;
                if &first == b"GET" {
                    client
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                } else {
                    counted.fetch_add(1, Ordering::SeqCst);
                    client.write_all(&vec![0u8; BULK]).await?;
                }
                client.shutdown().await?;
                Ok::<_, std::io::Error>(())
            });
        }
    });
    tokio::spawn(task);
    (handle, transfers, port)
}

/// Bytes of one bulk transfer: more than the 1 MiB a rate needs.
const BULK: usize = 2 << 20;

/// A SOCKS5 server like `socks`, that answers each request after `delay`
/// and passes what comes back at most 16 KiB each `pace` (16 KiB each
/// 8 ms is 16 Mbit/s).
async fn socks_paced(upstream: u16, delay: Duration, pace: Option<Duration>) -> (AbortHandle, u16) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (task, handle) = abortable(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 262];
                client.read_exact(&mut buf[..2]).await?;
                let n = buf[1] as usize;
                client.read_exact(&mut buf[..n]).await?;
                client.write_all(&[5, 0]).await?;
                client.read_exact(&mut buf[..4]).await?;
                let len = match buf[3] {
                    1 => 4,
                    4 => 16,
                    _ => {
                        client.read_exact(&mut buf[..1]).await?;
                        buf[0] as usize
                    }
                };
                client.read_exact(&mut buf[..len + 2]).await?;
                tokio::time::sleep(delay).await;
                let server = TcpStream::connect(("127.0.0.1", upstream)).await?;
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                let (mut from_client, mut to_client) = client.into_split();
                let (mut from_server, mut to_server) = server.into_split();
                tokio::spawn(
                    async move { tokio::io::copy(&mut from_client, &mut to_server).await },
                );
                let mut chunk = vec![0u8; 16 * 1024];
                loop {
                    let n = from_server.read(&mut chunk).await?;
                    if n == 0 {
                        break;
                    }
                    to_client.write_all(&chunk[..n]).await?;
                    if let Some(pace) = pace {
                        tokio::time::sleep(pace).await;
                    }
                }
                to_client.shutdown().await?;
                Ok::<_, std::io::Error>(())
            });
        }
    });
    tokio::spawn(task);
    (handle, port)
}

/// A server that takes connections and never answers.
async fn blackhole() -> (AbortHandle, u16) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (task, handle) = abortable(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    tokio::spawn(task);
    (handle, port)
}

fn smart(members: &[(&str, u16)], extra: serde_json::Value) -> serde_json::Value {
    let tags: Vec<&str> = members.iter().map(|(tag, _)| *tag).collect();
    let mut group = json!({
        "type": "smart",
        "tag": "auto",
        "outbounds": tags,
        "url": URL,
        "timeout": "500ms",
    });
    group
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let mut outbounds = vec![group];
    outbounds.extend(members.iter().map(|(tag, port)| {
        json!({ "type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": port })
    }));
    serde_json::Value::Array(outbounds)
}

#[test]
fn a_member_that_refuses_is_passed_over() {
    rt().block_on(async {
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let (socks_b, s_b) = socks(p_b).await;
        // Held, so no server of another test takes it meanwhile.
        let (_held, dead) = refusing_port();
        let m = manager(
            smart(&[("a", dead), ("b", s_b)], json!({})),
            &env("smart-refuses"),
        )
        .unwrap();
        for i in 0..5 {
            let sess = session("10.0.0.1", &format!("site{}.example", i));
            assert_eq!(reached(&m, "auto", &sess).await.unwrap(), "b");
        }
        socks_b.abort();
    });
}

#[test]
fn a_member_that_never_answers_is_passed_over_and_then_left() {
    rt().block_on(async {
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let (socks_b, s_b) = socks(p_b).await;
        let (hole, p_hole) = blackhole().await;
        let m = manager(
            smart(
                &[("a", p_hole), ("b", s_b)],
                // Probes a long way off: what is learnt comes from the
                // connections.
                json!({ "interval": "1h" }),
            ),
            &env("smart-blackhole"),
        )
        .unwrap();
        let sess = session("10.0.0.1", "example.com");
        assert_eq!(reached(&m, "auto", &sess).await.unwrap(), "b");
        // a failed where b did not: the next connections, to any site, go
        // to b at once.
        for i in 0..5 {
            let sess = session("10.0.0.1", &format!("other{}.example", i));
            let start = std::time::Instant::now();
            assert_eq!(reached(&m, "auto", &sess).await.unwrap(), "b");
            assert!(
                start.elapsed() < Duration::from_millis(400),
                "{:?}",
                start.elapsed()
            );
        }
        hole.abort();
        socks_b.abort();
    });
}

#[test]
fn a_site_stays_on_one_member() {
    rt().block_on(async {
        let (_a, p_a) = serve("a", Duration::ZERO).await;
        let (_b, p_b) = serve("b", Duration::ZERO).await;
        let (socks_a, s_a) = socks(p_a).await;
        let (socks_b, s_b) = socks(p_b).await;
        let m = manager(
            smart(
                &[("a", s_a), ("b", s_b)],
                // Both are always within the tolerance of each other.
                json!({ "tolerance": 10000 }),
            ),
            &env("smart-site"),
        )
        .unwrap();
        assert!(
            eventually(Duration::from_secs(5), || latencies(&m, "auto")
                .iter()
                .all(|(_, l)| l.is_some()))
            .await
        );
        for site in ["example.com", "example.org", "example.net"] {
            let mut reached_by = Vec::new();
            for host in ["www", "api", "static"] {
                let sess = session("10.0.0.1", &format!("{}.{}", host, site));
                reached_by.push(reached(&m, "auto", &sess).await.unwrap());
            }
            reached_by.dedup();
            assert_eq!(reached_by.len(), 1, "{}: {:?}", site, reached_by);
        }
        // The member shown is one it uses.
        let shown = selected(&m, "auto");
        assert!(shown == "a" || shown == "b", "{}", shown);
        socks_a.abort();
        socks_b.abort();
    });
}

#[test]
fn a_bulk_site_goes_to_the_member_that_moves_its_bytes_faster() {
    rt().block_on(async {
        // a answers at once but carries 16 Mbit/s; b answers 100 ms later
        // and carries what the host can.
        let (server_a, transfers_a, p_a) = bulk().await;
        let (server_b, transfers_b, p_b) = bulk().await;
        let (socks_a, s_a) = socks_paced(p_a, Duration::ZERO, Some(Duration::from_millis(8))).await;
        let (socks_b, s_b) = socks_paced(p_b, Duration::from_millis(100), None).await;
        let m = manager(
            smart(&[("a", s_a), ("b", s_b)], json!({})),
            &env("smart-bulk"),
        )
        .unwrap();
        let sess = session("10.0.0.1", "downloads.example");
        let mut went = String::new();
        for _ in 0..4 {
            let (a, b) = (
                transfers_a.load(Ordering::SeqCst),
                transfers_b.load(Ordering::SeqCst),
            );
            let mut stream = connect(&m, "auto", &sess).await.unwrap();
            stream.write_all(b"BLK").await.unwrap();
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got.len(), BULK);
            drop(stream);
            went.push(if transfers_a.load(Ordering::SeqCst) > a {
                'a'
            } else {
                assert!(transfers_b.load(Ordering::SeqCst) > b);
                'b'
            });
        }
        // At most one transfer to find a slow, then b, however a answers.
        assert!(went.matches('a').count() <= 1, "{}", went);
        assert!(went.ends_with("bb"), "{}", went);
        for h in [socks_a, socks_b, server_a, server_b] {
            h.abort();
        }
    });
}

#[test]
fn it_is_not_selected_by_hand() {
    let m = manager(
        smart(&[("a", UNSERVED), ("b", UNSERVED)], json!({})),
        &env("smart-by-hand"),
    )
    .unwrap();
    rt().block_on(async {
        let selector = m.get_selector("auto").unwrap();
        assert!(!selector.read().await.is_selectable());
        assert!(selector.write().await.set_selected("b").is_err());
    });
}

#[test]
fn configuration_mistakes_are_errors() {
    let error = |extra: serde_json::Value| {
        manager(smart(&[("a", UNSERVED)], extra), &env("smart-error"))
            .err()
            .expect("the configuration must be refused")
            .to_string()
    };
    for (extra, field) in [
        (json!({ "tolerance_ratio": -0.1 }), "tolerance_ratio"),
        (
            json!({ "policy_priority": [{ "regex": "HK", "factor": 0 }] }),
            "policy_priority[0].factor",
        ),
        (
            json!({ "policy_priority": [{ "regex": "(", "factor": 1 }] }),
            "policy_priority[0].regex",
        ),
        (json!({ "policy_priority": [{ "regex": "HK" }] }), "factor"),
        (json!({ "site_capacity": 0 }), "site_capacity"),
        (json!({ "site_ttl": "0s" }), "site_ttl"),
        (json!({ "interval": "0s" }), "interval"),
        (json!({ "timeout": "0s" }), "timeout"),
        (json!({ "url": "ftp://x/" }), "url"),
        (json!({ "asn_file": "asn.mmdb" }), "asn_file"),
        (json!({ "prefer_asn": true }), "asn.mmdb"),
        (
            json!({ "prefer_asn": true, "asn_file": "/nowhere/GeoLite2-ASN.mmdb" }),
            "GeoLite2-ASN.mmdb",
        ),
        (json!({ "strategy": "round-robin" }), "strategy"),
    ] {
        let msg = error(extra.clone());
        assert!(msg.contains("[auto]"), "{}: {}", extra, msg);
        assert!(msg.contains(field), "{}: {}", extra, msg);
    }
    let msg = manager(
        json!([{ "type": "smart", "tag": "auto", "outbounds": [] }]),
        &env("smart-error"),
    )
    .err()
    .expect("no member")
    .to_string();
    assert!(msg.contains("[auto]"), "{}", msg);
}
