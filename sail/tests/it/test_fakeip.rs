#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// app(socks) -> (socks)sail(direct) -> echo at 127.0.0.1
//
// With a fakeip server whose range holds the echo server's address, that
// address is a fake IP no domain was handed out for (past the four
// reserved at the start of the range): the connection is
// refused, as sing-box refuses it, not sent to the address. Without one,
// it goes through.
#[cfg(all(feature = "inbound-socks", feature = "outbound-direct"))]
#[test]
fn an_unknown_fake_ip_is_refused() -> anyhow::Result<()> {
    for (dns, refused) in [
        (
            serde_json::json!({ "servers": [
                { "type": "fakeip", "inet4_range": "126.0.0.0/7" }
            ] }),
            true,
        ),
        (serde_json::json!({}), false),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let config = serde_json::json!({
                "dns": dns,
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
                "outbounds": [{ "type": "direct" }]
            });
            common::test_configs(vec![config.to_string()], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), refused, "{}: {:?}", dns, result);
    }
    Ok(())
}

// dns client -> (direct, hijack-dns)sail(fakeip); app(socks) -> sail ->
// echo at 127.0.0.1, a fake IP as the destination.
//
// Locks that a connection to a fake IP is routed by the domain it was
// handed out for: the domain is restored, the rules on it decide (one
// domain blocked, the other direct), and the direct one is dialled at the
// domain's real address, which sail's own lookup takes past the fakeip
// rule.
#[cfg(all(
    feature = "inbound-socks",
    feature = "inbound-direct",
    feature = "outbound-direct",
    feature = "outbound-drop"
))]
#[test]
fn a_fake_ip_is_routed_by_its_domain() -> anyhow::Result<()> {
    use std::net::{IpAddr, SocketAddr};

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let echo = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        anyhow::Ok(port)
    })?;
    let (ids, (socks, dns)) = common::retry_port_clash(|| {
        let [socks, dns] = common::free_ports();
        let config = serde_json::json!({
            "dns": {
                "servers": [
                    { "type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15" },
                    { "type": "hosts", "tag": "real", "predefined": {
                        "open.example": "127.0.0.1", "shut.example": "127.0.0.1" } }
                ],
                "rules": [{ "query_type": "A", "server": "fake" }],
                "final": "real"
            },
            "inbounds": [
                { "type": "socks", "listen": "127.0.0.1", "listen_port": socks },
                { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": dns }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                "rules": [
                    { "inbound": "dns-in", "action": "hijack-dns" },
                    { "domain": "shut.example", "outbound": "block" }
                ],
                "final": "direct"
            }
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            (socks, dns),
        ))
    })?;
    let fake_ip = |name: &'static str| async move {
        let mut m = Message::new(3, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        udp.send_to(&m.to_vec()?, ("127.0.0.1", dns)).await?;
        let mut buf = vec![0u8; 1500];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_from(&mut buf))
                .await??;
        let reply = Message::from_vec(&buf[..n])?;
        match reply.answers.first().map(|r| &r.data) {
            Some(RData::A(a)) => anyhow::Ok(IpAddr::V4(a.0)),
            other => anyhow::bail!("{}: no A answer: {:?}", name, other),
        }
    };
    let echoes = |ip: IpAddr| async move {
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(SocketAddr::new(ip, echo)),
            ..Default::default()
        };
        let Ok(mut s) = common::new_socks_stream("127.0.0.1", socks, &sess, None, None).await
        else {
            return false;
        };
        let mut back = [0u8; 4];
        s.write_all(b"ping").await.is_ok()
            && tokio::time::timeout(std::time::Duration::from_secs(3), s.read_exact(&mut back))
                .await
                .is_ok_and(|r| r.is_ok())
            && &back == b"ping"
    };
    let checked = rt.block_on(async {
        let open = fake_ip("open.example.").await?;
        let shut = fake_ip("shut.example.").await?;
        for ip in [open, shut] {
            anyhow::ensure!(
                matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 198),
                "{} is no fake IP",
                ip
            );
        }
        anyhow::ensure!(
            echoes(open).await,
            "the open domain's fake IP reaches the echo"
        );
        anyhow::ensure!(!echoes(shut).await, "the shut domain's fake IP is blocked");
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    checked
}
