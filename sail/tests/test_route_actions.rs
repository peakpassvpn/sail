mod common;

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
                    { "action": "sniff", "sniffer": ["quic"], "override_destination": true },
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
            let mut stream = common::new_socks_stream(
                "127.0.0.1",
                port,
                &sess,
                Some("alice".into()),
                Some("secret".into()),
            )
            .await?;
            stream.write_all(b"ping").await?;
            let mut buf = [0u8; 4];
            let read = timeout(Duration::from_secs(10), stream.read(&mut buf)).await?;
            anyhow::ensure!(
                matches!(read, Ok(0) | Err(_)),
                "alice's connection should be rejected, read {:?}",
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
