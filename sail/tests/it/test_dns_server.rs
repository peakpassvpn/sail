#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// dig -> (direct)sail, a hijack-dns rule for the inbound -> hosts server
//
// A direct inbound with a hijack-dns rule for it is a DNS server, as in
// sing-box: queries over UDP and TCP to its port are answered by the DNS
// client, as its rules pick a server; a UDP answer too big for the client
// comes back cut down to 512 bytes with TC set, and in full over TCP.
#[cfg(feature = "inbound-direct")]
#[test]
fn a_direct_inbound_hijacked_is_a_dns_server() -> anyhow::Result<()> {
    use std::net::IpAddr;
    use std::str::FromStr;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn query(name: &str, ty: RecordType) -> Vec<u8> {
        let mut m = Message::new(9, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str(name).unwrap(), ty));
        m.to_vec().unwrap()
    }

    fn addresses(reply: &[u8]) -> (bool, Vec<IpAddr>) {
        let m = Message::from_vec(reply).unwrap();
        assert_eq!(m.metadata.id, 9);
        let ips = m
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .collect();
        (m.metadata.truncation, ips)
    }

    let many: Vec<String> = (1..=60).map(|i| format!("2001:db8::{:x}", i)).collect();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, port) = common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let config = serde_json::json!({
            "dns": { "servers": [
                { "type": "hosts", "predefined": {
                    "one.sail": "192.0.2.1",
                    "many.sail": many,
                } }
            ] },
            "inbounds": [{
                "type": "direct", "tag": "dns-in",
                "listen": "127.0.0.1", "listen_port": port,
            }],
            "route": { "rules": [{ "inbound": "dns-in", "action": "hijack-dns" }] },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            port,
        ))
    })?;
    let server = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    rt.block_on(async {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let mut buf = vec![0u8; 65535];
        let mut ask_udp = async |q: Vec<u8>| -> anyhow::Result<Vec<u8>> {
            udp.send_to(&q, server).await?;
            let (n, from) =
                tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
                    .await??;
            assert_eq!(from, server);
            Ok(buf[..n].to_vec())
        };
        let one = ask_udp(query("one.sail.", RecordType::A)).await?;
        assert_eq!(addresses(&one), (false, vec!["192.0.2.1".parse()?]));

        let cut = ask_udp(query("many.sail.", RecordType::AAAA)).await?;
        assert!(cut.len() <= 512, "{}", cut.len());
        let (truncated, ips) = addresses(&cut);
        assert!(truncated && !ips.is_empty() && ips.len() < 60, "{:?}", ips);

        let mut tcp = tokio::net::TcpStream::connect(server).await?;
        let q = query("many.sail.", RecordType::AAAA);
        tcp.write_u16(q.len() as u16).await?;
        tcp.write_all(&q).await?;
        let len = tcp.read_u16().await? as usize;
        let mut reply = vec![0u8; len];
        tcp.read_exact(&mut reply).await?;
        let (truncated, ips) = addresses(&reply);
        assert!(!truncated);
        assert_eq!(ips.len(), 60);
        anyhow::Ok(())
    })?;
    common::shutdown_instances(&rt, ids);
    Ok(())
}

// dig -> (direct)sail, hijacked -> fakeip server; sail stopped and started
// again with the same cache file
//
// With `store_fakeip`, the fake IPs handed out before a restart are what
// the domains have after it: a domain asked for again gets the address it
// had, not the next one free.
#[cfg(feature = "inbound-direct")]
#[test]
fn fake_ips_outlive_a_restart_in_the_cache_file() -> anyhow::Result<()> {
    use std::net::IpAddr;
    use std::str::FromStr;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};

    let dir = common::TempDir::new("fakeip-cache")?;
    let cache = dir.join("cache.db");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let ask = |port: u16, name: &str| -> anyhow::Result<IpAddr> {
        let mut m = Message::new(3, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str(name)?, RecordType::A));
        rt.block_on(async {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            udp.send_to(&m.to_vec()?, ("127.0.0.1", port)).await?;
            let mut buf = vec![0u8; 1500];
            let (n, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
                    .await??;
            let reply = Message::from_vec(&buf[..n])?;
            match reply.answers.first().map(|r| &r.data) {
                Some(RData::A(a)) => Ok(IpAddr::V4(a.0)),
                other => Err(anyhow::anyhow!("{}: {:?}", name, other)),
            }
        })
    };
    let start = || {
        common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let config = serde_json::json!({
                "experimental": { "cache_file": {
                    "enabled": true,
                    "path": cache.to_str().unwrap(),
                    "store_fakeip": true,
                } },
                "dns": { "servers": [
                    { "type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15" }
                ] },
                "inbounds": [{
                    "type": "direct", "tag": "dns-in",
                    "listen": "127.0.0.1", "listen_port": port,
                }],
                "route": { "rules": [{ "inbound": "dns-in", "action": "hijack-dns" }] },
            });
            Ok((
                common::run_sail_instances(&rt, vec![config.to_string()])?,
                port,
            ))
        })
    };

    let (ids, port) = start()?;
    let a = ask(port, "a.example.")?;
    let b = ask(port, "b.example.")?;
    assert_ne!(a, b);
    common::shutdown_instances(&rt, ids);
    // Closed as the instance stopped, not when the last of what used it
    // goes: free at once for the next start.
    drop(redb::Database::create(&cache)?);

    let (ids, port) = start()?;
    // b first: without the file, it would get the first address, a's.
    assert_eq!(ask(port, "b.example.")?, b);
    assert_eq!(ask(port, "a.example.")?, a);
    let c = ask(port, "c.example.")?;
    assert!(c != a && c != b, "{}", c);
    common::shutdown_instances(&rt, ids);
    Ok(())
}

// dig -> (direct)sail, hijacked -> hosts server; the API reports the DNS
// cache, and clears it.
#[cfg(all(feature = "inbound-direct", feature = "api"))]
#[test]
fn the_api_reports_the_dns_cache_and_clears_it() -> anyhow::Result<()> {
    use std::str::FromStr;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, dns_port, api_port) = common::retry_port_clash(|| {
        let [dns_port, api_port] = common::free_ports();
        let config = serde_json::json!({
            "api": {
                "listen": format!("127.0.0.1:{}", api_port),
                "secret": "Zq3Lp8Rk1Vn6Xc2Bm7Ws4Ty9Hd5Gf0Ja",
            },
            "dns": { "servers": [
                { "type": "hosts", "predefined": { "one.sail": "192.0.2.1" } }
            ] },
            "inbounds": [{
                "type": "direct", "tag": "dns-in",
                "listen": "127.0.0.1", "listen_port": dns_port,
            }],
            "route": { "rules": [{ "inbound": "dns-in", "action": "hijack-dns" }] },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            dns_port,
            api_port,
        ))
    })?;
    let api = |method: &str, path: &str| -> anyhow::Result<(u16, String)> {
        rt.block_on(async {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", api_port)).await?;
            let request = format!(
                "{} {} HTTP/1.1\r\nHost: sail\r\nContent-Length: 0\r\nConnection: close\r\n\
                 Authorization: Bearer Zq3Lp8Rk1Vn6Xc2Bm7Ws4Ty9Hd5Gf0Ja\r\n\r\n",
                method, path
            );
            s.write_all(request.as_bytes()).await?;
            let mut reply = String::new();
            s.read_to_string(&mut reply).await?;
            let status = reply
                .split(' ')
                .nth(1)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            let body = reply.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
            Ok((status, body))
        })
    };
    let stats = || -> anyhow::Result<serde_json::Value> {
        let (status, body) = api("GET", "/api/v1/runtime/dns/cache")?;
        assert_eq!(status, 200, "{}", body);
        Ok(serde_json::from_str(&body)?)
    };
    let ask = || -> anyhow::Result<()> {
        let mut m = Message::new(5, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str("one.sail.")?, RecordType::A));
        rt.block_on(async {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            udp.send_to(&m.to_vec()?, ("127.0.0.1", dns_port)).await?;
            let mut buf = vec![0u8; 1500];
            tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
                .await??;
            anyhow::Ok(())
        })
    };

    ask()?;
    ask()?;
    let s = stats()?;
    assert_eq!(
        (
            s["entries"].as_u64(),
            s["hits"].as_u64(),
            s["misses"].as_u64()
        ),
        (Some(1), Some(1), Some(1)),
        "{}",
        s
    );
    assert_eq!(s["capacity"], 1024);
    let (status, _) = api("POST", "/api/v1/runtime/dns/cache/flush")?;
    assert_eq!(status, 204);
    assert_eq!(stats()?["entries"], 0);
    common::shutdown_instances(&rt, ids);
    Ok(())
}

// dig -> (direct)sail, hijacked -> a UDP server; sail stopped and started
// again with the same cache file
//
// With `store_dns`, the answers kept outlive the restart: the server is not
// asked again for what it answered before.
#[cfg(feature = "inbound-direct")]
#[test]
fn dns_answers_outlive_a_restart_in_the_cache_file() -> anyhow::Result<()> {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};

    let dir = common::TempDir::new("dns-cache")?;
    let cache = dir.join("cache.db");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    // An upstream answering every A query with 10.0.0.7 for an hour.
    let asked = Arc::new(AtomicUsize::new(0));
    let upstream = rt.block_on(async {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
        let asked = asked.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = crate::common::recv_past_errors(&socket, &mut buf).await;
                let Ok(q) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                asked.fetch_add(1, Ordering::SeqCst);
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
    let ask = |port: u16| -> anyhow::Result<u32> {
        let mut m = Message::new(4, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(
            Name::from_str("kept.example.")?,
            RecordType::A,
        ));
        rt.block_on(async {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            udp.send_to(&m.to_vec()?, ("127.0.0.1", port)).await?;
            let mut buf = vec![0u8; 1500];
            let (n, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
                    .await??;
            let reply = Message::from_vec(&buf[..n])?;
            Ok(reply.answers.first().map(|r| r.ttl).unwrap_or(0))
        })
    };
    let start = || {
        common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let config = serde_json::json!({
                "experimental": { "cache_file": {
                    "enabled": true,
                    "path": cache.to_str().unwrap(),
                    "store_dns": true,
                } },
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
        })
    };

    let (ids, port) = start()?;
    assert_eq!(ask(port)?, 3600);
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    common::shutdown_instances(&rt, ids);

    let (ids, port) = start()?;
    let ttl = ask(port)?;
    assert!(ttl > 3500 && ttl <= 3600, "{}", ttl);
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    common::shutdown_instances(&rt, ids);
    Ok(())
}
