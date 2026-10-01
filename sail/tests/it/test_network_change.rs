//! A change of network drops the connections made on the one before; a
//! roam within one network does not.

#![cfg(all(feature = "inbound-socks", feature = "outbound-direct"))]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

// socks client -> (socks)sail(direct) -> a server that holds the
// connection; the host tells sail of the network.
#[test]
fn a_move_closes_the_connections_and_a_roam_does_not() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let hold = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        anyhow::Ok(port)
    })?;
    let (ids, socks) = common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [
                { "type": "socks", "listen": "127.0.0.1", "listen_port": socks }
            ],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            socks,
        ))
    })?;
    let id = ids[0];
    let network = |interface: &str, ssid: &str| {
        serde_json::json!({
            "interface": interface, "type": "wifi", "ssid": ssid,
            "gateway": "192.168.1.1", "addresses": ["192.168.1.2/24"],
        })
        .to_string()
    };
    let checked = rt.block_on(async {
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                hold,
            ))),
            ..Default::default()
        };
        sail::set_network_state(id, &network("en0", "Home"))?;
        let mut conn = common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await?;
        conn.write_all(b"x").await?;
        let mut buf = [0u8; 1];
        // A roam: another access point, the same interface and addresses.
        sail::set_network_state(id, &network("en0", "Home 5G"))?;
        let read = tokio::time::timeout(Duration::from_millis(500), conn.read(&mut buf)).await;
        assert!(read.is_err(), "the connection survives a roam: {:?}", read);
        // A move: another interface.
        sail::set_network_state(id, &network("en1", "Home"))?;
        let read = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
            .await
            .expect("the connection is closed");
        assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);
        // A new one works on the network there is now.
        let mut conn = common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await?;
        conn.write_all(b"x").await?;
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}

/// With `outbounds` and `final`, which let no connection through, a
/// connection is let through behind a captive portal, as the host says,
/// and not before or after.
#[cfg(feature = "outbound-drop")]
fn a_portal_lets_through(outbounds: serde_json::Value, last: &str) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let server = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        anyhow::Ok(port)
    })?;
    let (ids, socks) = common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [
                { "type": "socks", "listen": "127.0.0.1", "listen_port": socks }
            ],
            "outbounds": outbounds,
            "route": { "final": last },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            socks,
        ))
    })?;
    let id = ids[0];
    let checked = rt.block_on(async {
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                server,
            ))),
            ..Default::default()
        };
        let connect = || common::new_socks_stream("127.0.0.1", socks, &sess, None, None);
        let reaches = |stream: anyhow::Result<sail::adapter::AnyStream>| async move {
            let Ok(mut stream) = stream else {
                return false;
            };
            let mut buf = [0u8; 1];
            stream.write_all(b"x").await.is_ok()
                && tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf))
                    .await
                    .is_err()
        };
        // Errors, not panics: the instance is shut down whatever happens.
        anyhow::ensure!(
            !reaches(connect().await).await,
            "the rules let nothing through"
        );
        sail::set_network_state(id, r#"{ "interface": "en0", "captive": true }"#)?;
        anyhow::ensure!(reaches(connect().await).await, "direct behind the portal");
        sail::set_network_state(id, r#"{ "interface": "en0" }"#)?;
        anyhow::ensure!(!reaches(connect().await).await, "the rules again");
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}

// socks client -> (socks)sail(rules: block) -> server; behind a captive
// portal, as the host says, it goes direct whatever the rules say.
#[cfg(feature = "outbound-drop")]
#[test]
fn behind_a_captive_portal_every_connection_goes_direct() -> anyhow::Result<()> {
    a_portal_lets_through(
        serde_json::json!([{ "type": "block", "tag": "block" }]),
        "block",
    )
}

// socks client -> (socks)sail(final: the configuration's DIRECT, a block)
// -> server: the rules take the configuration's DIRECT by its tag, the
// portal sail's own direct, which no tag names.
#[cfg(feature = "outbound-drop")]
#[test]
fn the_portal_s_direct_is_not_an_outbound_tagged_direct() -> anyhow::Result<()> {
    a_portal_lets_through(
        // The configuration's DIRECT reaches nothing; only sail's own
        // direct, which no tag names, can let it through.
        serde_json::json!([{ "type": "block", "tag": "DIRECT" }]),
        "DIRECT",
    )
}

/// A DNS upstream answering every A query with 10.0.0.7 for an hour,
/// counting the queries it is asked.
#[cfg(feature = "inbound-direct")]
fn counting_upstream(
    rt: &tokio::runtime::Runtime,
) -> anyhow::Result<(u16, std::sync::Arc<std::sync::atomic::AtomicUsize>)> {
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::{rdata::A, RData, Record};
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let port = rt.block_on(async {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
        let asked = asked.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(q) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut r = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
                for query in &q.queries {
                    r.add_query(query.clone());
                    r.add_answer(Record::from_rdata(
                        query.name().clone(),
                        3600,
                        RData::A(A::new(10, 0, 0, 7)),
                    ));
                }
                let _ = socket.send_to(&r.to_vec().unwrap(), peer).await;
            }
        });
        anyhow::Ok(port)
    })?;
    Ok((port, asked))
}

/// Asks sail's DNS at `port` for an A record of `name`.
#[cfg(feature = "inbound-direct")]
async fn ask(port: u16, name: &str) -> anyhow::Result<()> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    let mut m = Message::new(7, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    udp.send_to(&m.to_vec()?, ("127.0.0.1", port)).await?;
    let mut buf = vec![0u8; 1500];
    tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf)).await??;
    Ok(())
}

// dns client -> (direct, hijack-dns)sail -> a counting upstream; the host
// tells sail of the network.
//
// Locks 2.12's promise that an answer of the network before is not given
// on the next: a move empties the DNS cache, and the upstream is asked
// again; a roam within one network keeps what was cached.
#[cfg(feature = "inbound-direct")]
#[test]
fn a_move_forgets_the_dns_answers_and_a_roam_keeps_them() -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (upstream, asked) = counting_upstream(&rt)?;
    let (ids, port) = common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let config = serde_json::json!({
            "dns": { "servers": [
                { "type": "udp", "server": "127.0.0.1", "server_port": upstream }
            ] },
            "inbounds": [{
                "type": "direct", "tag": "dns-in",
                "listen": "127.0.0.1", "listen_port": port,
            }],
            "outbounds": [{ "type": "direct" }],
            "route": { "rules": [{ "inbound": "dns-in", "action": "hijack-dns" }] },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            port,
        ))
    })?;
    let id = ids[0];
    let network = |interface: &str, ssid: &str| {
        serde_json::json!({
            "interface": interface, "type": "wifi", "ssid": ssid,
            "gateway": "192.168.1.1", "addresses": ["192.168.1.2/24"],
        })
        .to_string()
    };
    let checked = rt.block_on(async {
        sail::set_network_state(id, &network("en0", "Home"))?;
        ask(port, "kept.example.").await?;
        ask(port, "kept.example.").await?;
        anyhow::ensure!(asked.load(Ordering::SeqCst) == 1, "the answer is cached");

        // A roam: the cache is kept. Long enough for a flush to have run,
        // had there been one.
        sail::set_network_state(id, &network("en0", "Home 5G"))?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        ask(port, "kept.example.").await?;
        anyhow::ensure!(
            asked.load(Ordering::SeqCst) == 1,
            "a roam keeps the answer, asked {}",
            asked.load(Ordering::SeqCst)
        );

        // A move: the cache is emptied as the change is handled, and the
        // next query goes to the upstream.
        sail::set_network_state(id, &network("en1", "Home"))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while asked.load(Ordering::SeqCst) < 2 {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "the answer of the network before is still given"
            );
            ask(port, "kept.example.").await?;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ask(port, "kept.example.").await?;
        anyhow::ensure!(
            asked.load(Ordering::SeqCst) == 2,
            "the new answer is cached, asked {}",
            asked.load(Ordering::SeqCst)
        );
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}

// a urltest group of two direct members -> an HTTP server counting the
// requests its tests make; the host tells sail of the network.
//
// Locks that a change of network reaches the outbounds of a running
// instance (each hears of it): a group tests its members again at once on
// a move, as sing-box's do, and not on a roam.
#[cfg(feature = "outbound-urltest")]
#[test]
fn a_move_has_a_group_test_its_members_again_and_a_roam_does_not() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let requests = std::sync::Arc::new(AtomicUsize::new(0));
    let web = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let requests = requests.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let requests = requests.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if matches!(s.read(&mut buf).await, Ok(n) if n > 0) {
                        requests.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = s
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        anyhow::Ok(port)
    })?;
    let (ids, _) = common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [
                { "type": "socks", "listen": "127.0.0.1", "listen_port": socks }
            ],
            "outbounds": [
                { "type": "urltest", "tag": "auto", "outbounds": ["a", "b"],
                  "url": format!("http://127.0.0.1:{}/", web), "interval": "1h" },
                { "type": "direct", "tag": "a" },
                { "type": "direct", "tag": "b" },
            ],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            socks,
        ))
    })?;
    let id = ids[0];
    let network = |interface: &str, ssid: &str| {
        serde_json::json!({
            "interface": interface, "type": "wifi", "ssid": ssid,
            "gateway": "192.168.1.1", "addresses": ["192.168.1.2/24"],
        })
        .to_string()
    };
    let settled = |at_least: usize| {
        let requests = requests.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while requests.load(Ordering::SeqCst) < at_least {
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "{} requests, not {}",
                    requests.load(Ordering::SeqCst),
                    at_least
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // Whatever else of the round is still coming.
            tokio::time::sleep(Duration::from_millis(300)).await;
            anyhow::Ok(requests.load(Ordering::SeqCst))
        }
    };
    let checked = rt.block_on(async {
        sail::set_network_state(id, &network("en0", "Home"))?;
        // The first round, one request a member.
        let first = settled(2).await?;

        sail::set_network_state(id, &network("en0", "Home 5G"))?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        anyhow::ensure!(
            requests.load(Ordering::SeqCst) == first,
            "a roam tests nothing again: {} after {}",
            requests.load(Ordering::SeqCst),
            first
        );

        sail::set_network_state(id, &network("en1", "Home"))?;
        let after = settled(first + 2).await?;
        anyhow::ensure!(after >= first + 2, "{} after {}", after, first);
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}
