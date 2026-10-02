#![cfg(all(feature = "inbound-socks", feature = "outbound-socks"))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

// app(socks) -> sail(sniff, then route by the sniffed domain) -> echo
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]
#[test]
fn a_sniffed_domain_is_routed_by_the_rules_after_the_sniff() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": {
                "rules": [
                    { "action": "sniff", "sniffer": ["http"] },
                    { "domain_suffix": ["blocked.test"], "action": "reject" }
                ]
            }
        });

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        // Fails with an error rather than a panic, so that the instance is
        // shut down either way.
        let result = rt.block_on(async {
            let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            tokio::spawn(echo);
            tokio::time::sleep(Duration::from_millis(200)).await;

            // To the echo server's address: the domain is only in the request.
            let sess = sail::session::Session {
                destination: sail::session::SocksAddr::from(echo_addr),
                ..Default::default()
            };
            let request = |host: &str| format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);

            let mut allowed =
                common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
            allowed
                .write_all(request("allowed.test").as_bytes())
                .await?;
            let mut buf = vec![0u8; 256];
            let n = timeout(Duration::from_secs(10), allowed.read(&mut buf)).await??;
            anyhow::ensure!(
                &buf[..n] == request("allowed.test").as_bytes(),
                "an allowed connection should be relayed"
            );

            let mut blocked =
                common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
            blocked
                .write_all(request("www.blocked.test").as_bytes())
                .await?;
            let read = timeout(Duration::from_secs(10), blocked.read(&mut buf)).await?;
            anyhow::ensure!(
                matches!(read, Ok(0) | Err(_)),
                "a rejected connection should be closed, read {:?}",
                read
            );
            anyhow::Ok(())
        });
        for id in ids {
            assert!(sail::shutdown(id));
        }
        result
    })
}

// app(socks, QUIC's Initials) -> sail(sniff QUIC, override the destination)
// -> echo
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "btls"
))]
#[test]
fn a_quic_session_is_routed_by_its_server_name() -> anyhow::Result<()> {
    use sail::session::SocksAddr;

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/quic");
    let initials: Vec<Vec<u8>> = (0..2)
        .map(|i| std::fs::read(format!("{}/chrome-154-{}.initial", dir, i)))
        .collect::<Result<_, _>>()?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (echo_addr, echo) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
        rt.spawn(echo);
        // Another echo server, which the rules reject by the name Chrome
        // asked for.
        let (rejected_addr, rejected) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
        rt.spawn(rejected);
        let config = serde_json::json!({
            "dns": { "servers": [
                { "type": "hosts", "predefined": { "localhost": "127.0.0.1" } }
            ] },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": {
                "rules": [
                    { "action": "sniff", "sniffer": ["quic"], "override_destination": "at_sniff" },
                    { "domain": ["localhost"], "port": [rejected_addr.port()], "action": "reject" }
                ]
            }
        });
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let result = rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let to = |port: u16| {
                SocksAddr::from(("127.0.0.1".parse::<std::net::IpAddr>().unwrap(), port))
            };

            // To the echo server's address, which the domain overrides; the
            // replies come back from the address.
            let sess = sail::session::Session {
                destination: to(echo_addr.port()),
                ..Default::default()
            };
            let (mut recv, mut send) =
                common::new_socks_datagram("127.0.0.1", port, &sess, None, None)
                    .await?
                    .split();
            for initial in &initials {
                send.send_to(initial, &sess.destination).await?;
            }
            let mut buf = vec![0u8; 2048];
            for initial in &initials {
                let (n, from) =
                    timeout(Duration::from_secs(10), recv.recv_from(&mut buf)).await??;
                anyhow::ensure!(buf[..n] == initial[..], "the datagrams should be echoed");
                anyhow::ensure!(from == sess.destination, "a reply from {}", from);
            }

            let sess = sail::session::Session {
                destination: to(rejected_addr.port()),
                ..Default::default()
            };
            let (mut recv, mut send) =
                common::new_socks_datagram("127.0.0.1", port, &sess, None, None)
                    .await?
                    .split();
            for initial in &initials {
                send.send_to(initial, &sess.destination).await?;
            }
            let read = timeout(Duration::from_millis(500), recv.recv_from(&mut buf)).await;
            anyhow::ensure!(
                !matches!(read, Ok(Ok(_))),
                "a rejected session should get no reply, read {:?}",
                read
            );
            anyhow::Ok(())
        });
        for id in ids {
            assert!(sail::shutdown(id));
        }
        result
    })
}

// app(socks, as a user) -> sail(route by the user) -> echo
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]
#[test]
fn an_authenticated_user_is_routed_by_name() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        let config = serde_json::json!({
            "inbounds": [{
                "type": "socks", "listen": "127.0.0.1", "listen_port": port,
                "users": [{ "username": "alice", "password": "secret" }]
            }],
            "outbounds": [{ "type": "direct" }],
            "route": { "rules": [{ "auth_user": ["alice"], "action": "reject" }] }
        });
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let result = rt.block_on(async {
            let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            tokio::spawn(echo);
            tokio::time::sleep(Duration::from_millis(200)).await;
            let sess = sail::session::Session {
                destination: sail::session::SocksAddr::from(echo_addr),
                ..Default::default()
            };
            // Her connect is answered with a failure, as sing-box answers
            // a rejected one.
            let connected = common::new_socks_stream(
                "127.0.0.1",
                port,
                &sess,
                Some("alice".into()),
                Some("secret".into()),
            )
            .await;
            anyhow::ensure!(connected.is_err(), "alice's connection should be rejected");
            anyhow::Ok(())
        });
        for id in ids {
            assert!(sail::shutdown(id));
        }
        result
    })
}

/// A DNS query of `name`, type A, id 7.
fn a_query(name: &str) -> Vec<u8> {
    let mut query = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

/// Whether `reply` answers query 7 with `127.0.0.1` alone.
fn answers_localhost(reply: &[u8]) -> bool {
    reply.len() > 12
        && reply[..2] == [0, 7]
        && reply[2] & 0x80 != 0
        && reply[3] & 0x0f == 0
        && reply[6..8] == [0, 1]
        && reply.ends_with(&[0, 4, 127, 0, 0, 1])
        && reply.len() >= 20
        && {
            // Type A, class IN, then a TTL of a hosts server's 600 at most:
            // a cached answer has less left.
            let record = &reply[reply.len() - 14..];
            let ttl = u32::from_be_bytes([record[4], record[5], record[6], record[7]]);
            record[..4] == [0, 1, 0, 1] && (1..=600).contains(&ttl)
        }
}

// app(socks, DNS to an address nothing listens on) -> sail(hijack-dns)
#[test]
fn hijacked_dns_is_answered_by_sail_over_udp_and_tcp() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "dns": { "servers": [
                { "type": "hosts", "predefined": { "hijacked.test": "127.0.0.1" } }
            ] },
            "route": { "rules": [{ "port": 53, "action": "hijack-dns" }] }
        });
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let result = rt.block_on(async {
            // The documentation range: no server answers there.
            let server =
                sail::session::SocksAddr::from(("192.0.2.1".parse::<std::net::IpAddr>()?, 53));
            let sess = sail::session::Session {
                destination: server.clone(),
                ..Default::default()
            };
            let datagram = common::new_socks_datagram("127.0.0.1", port, &sess, None, None).await?;
            let (mut recv, mut send) = datagram.split();
            send.send_to(&a_query("hijacked.test"), &server).await?;
            let mut buf = [0u8; 512];
            let (n, from) = timeout(Duration::from_secs(10), recv.recv_from(&mut buf)).await??;
            anyhow::ensure!(from == server, "answered from {}", from);
            anyhow::ensure!(answers_localhost(&buf[..n]), "udp answer {:?}", &buf[..n]);

            let mut stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
            for _ in 0..2 {
                let query = a_query("hijacked.test");
                stream.write_u16(query.len() as u16).await?;
                stream.write_all(&query).await?;
                let len = timeout(Duration::from_secs(10), stream.read_u16()).await?? as usize;
                let mut reply = vec![0u8; len];
                stream.read_exact(&mut reply).await?;
                anyhow::ensure!(answers_localhost(&reply), "tcp answer {:?}", reply);
            }
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks, to a destination nothing listens on) -> sail(override_address,
// override_port) -> echo
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]
#[test]
fn an_overridden_destination_is_reached_and_answers_as_the_original() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (tcp_echo, tcp) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
        let (udp_echo, udp) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
        rt.spawn(tcp);
        rt.spawn(udp);
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": { "rules": [
                { "domain": "moved.test", "action": "route-options",
                  "override_address": "127.0.0.1", "override_port": tcp_echo.port() },
                { "ip_cidr": "192.0.2.9", "network": "udp", "outbound": "direct",
                  "override_address": "127.0.0.1", "override_port": udp_echo.port(),
                  "udp_timeout": "30s" },
            ] }
        });
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let result = rt.block_on(async {
            let sess = sail::session::Session {
                destination: sail::session::SocksAddr::Domain("moved.test".into(), 1),
                ..Default::default()
            };
            let mut stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
            stream.write_all(b"ping").await?;
            let mut buf = [0u8; 4];
            timeout(Duration::from_secs(10), stream.read_exact(&mut buf)).await??;
            anyhow::ensure!(&buf == b"ping", "echoed {:?}", buf);

            let target =
                sail::session::SocksAddr::from(("192.0.2.9".parse::<std::net::IpAddr>()?, 9));
            let sess = sail::session::Session {
                destination: target.clone(),
                ..Default::default()
            };
            let datagram = common::new_socks_datagram("127.0.0.1", port, &sess, None, None).await?;
            let (mut recv, mut send) = datagram.split();
            let mut buf = [0u8; 64];
            for payload in [&b"one"[..], b"two"] {
                send.send_to(payload, &target).await?;
                let (n, from) =
                    timeout(Duration::from_secs(10), recv.recv_from(&mut buf)).await??;
                anyhow::ensure!(&buf[..n] == payload, "echoed {:?}", &buf[..n]);
                anyhow::ensure!(from == target, "echoed from {}", from);
            }
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks, UDP to a domain) -> sail(udp_connect, udp_disable_domain_unmapping)
// -> echo
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]
#[test]
fn udp_route_options_say_how_datagrams_go_and_come_back() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let port = common::free_port();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (echo, udp) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
        rt.spawn(udp);
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "dns": { "servers": [{ "type": "hosts", "predefined": {
                "connected.test": "127.0.0.1", "unmapped.test": "127.0.0.1",
                "both.test": "127.0.0.1"
            } }] },
            "route": { "rules": [
                { "domain": ["connected.test", "both.test"], "action": "route-options",
                  "udp_connect": true },
                { "domain": ["unmapped.test", "both.test"], "action": "route-options",
                  "udp_disable_domain_unmapping": true },
            ] }
        });
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let result = rt.block_on(async {
            for (domain, unmapped) in [
                ("unmapped.test", true),
                ("connected.test", false),
                ("both.test", true),
            ] {
                let target = sail::session::SocksAddr::Domain(domain.into(), echo.port());
                let sess = sail::session::Session {
                    destination: target.clone(),
                    ..Default::default()
                };
                let datagram =
                    common::new_socks_datagram("127.0.0.1", port, &sess, None, None).await?;
                let (mut recv, mut send) = datagram.split();
                send.send_to(b"ping", &target).await?;
                let mut buf = [0u8; 16];
                let (n, from) =
                    timeout(Duration::from_secs(10), recv.recv_from(&mut buf)).await??;
                anyhow::ensure!(&buf[..n] == b"ping", "{}: echoed {:?}", domain, &buf[..n]);
                let expected = if unmapped {
                    sail::session::SocksAddr::from(echo)
                } else {
                    target
                };
                anyhow::ensure!(from == expected, "{}: echoed from {}", domain, from);
            }
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}
