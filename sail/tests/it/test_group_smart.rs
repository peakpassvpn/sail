#![cfg(all(feature = "outbound-smart", feature = "outbound-socks"))]

use crate::test_group_common;

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

/// A port nothing listens on.
async fn refusing() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    listener.local_addr().unwrap().port()
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
        let dead = refusing().await;
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
