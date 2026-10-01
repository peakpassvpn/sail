#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// app(socks) -> (mixed)sail, read from a Clash configuration -> echo
//
// Its rules decide: through a group to DIRECT, or REJECT for the echo
// server's address.
#[cfg(all(
    feature = "config-clash",
    feature = "inbound-mixed",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-select"
))]
#[test]
fn a_clash_configuration_routes() -> anyhow::Result<()> {
    for (rules, rejected) in [
        ("  - MATCH,Proxy\n", false),
        (
            "  - IP-CIDR,127.0.0.0/8,REJECT,no-resolve\n  - MATCH,Proxy\n",
            true,
        ),
        ("  - DST-PORT,1-65535,REJECT-DROP\n  - MATCH,Proxy\n", true),
        ("  - NETWORK,tcp,PASS\n  - MATCH,Proxy\n", false),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let yaml = format!(
                "mixed-port: {}\n\
                 log-level: silent\n\
                 proxy-groups:\n  - {{ name: Proxy, type: select, proxies: [DIRECT] }}\n\
                 rules:\n{}",
                port, rules
            );
            common::test_configs(vec![yaml], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", rules, result);
    }
    Ok(())
}

// app(socks) -> (listener)sail -> echo
//
// A listener with a proxy sends everything there, the rules, which reject
// everything, notwithstanding; one without follows the rules.
#[cfg(all(
    feature = "config-clash",
    feature = "inbound-mixed",
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-drop"
))]
#[test]
fn a_listener_s_proxy_goes_before_the_rules() -> anyhow::Result<()> {
    for (proxy, rejected) in [("proxy: DIRECT, ", false), ("", true)] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let yaml = format!(
                "log-level: silent\n\
                 listeners:\n  - {{ name: IN, type: socks, listen: 127.0.0.1, {}port: {}, udp: true }}\n\
                 rules:\n  - MATCH,REJECT\n",
                proxy, port
            );
            common::test_configs(vec![yaml], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), rejected, "{:?}: {:?}", proxy, result);
    }
    Ok(())
}

// app(socks) -> (mixed)sail -> echo, from 127.0.0.1: lan-disallowed-ips
// keeps it out, as Mihomo does.
#[cfg(all(
    feature = "config-clash",
    feature = "inbound-mixed",
    feature = "outbound-direct"
))]
#[test]
fn lan_ips_keep_clients_out() -> anyhow::Result<()> {
    for (lan, rejected) in [("lan-disallowed-ips: [127.0.0.1/32]\n", true), ("", false)] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let yaml = format!(
                "mixed-port: {}\nlog-level: silent\n{}rules:\n  - MATCH,DIRECT\n",
                port, lan
            );
            common::test_configs(vec![yaml], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), rejected, "{:?}: {:?}", lan, result);
    }
    Ok(())
}

// app -> (tunnel)sail -> echo: a tunnel forwards to its target.
#[cfg(all(
    feature = "config-clash",
    feature = "inbound-direct",
    feature = "outbound-direct"
))]
#[test]
fn a_tunnel_forwards_to_its_target() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (echo, echo_fut) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    rt.spawn(echo_fut);
    common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let yaml = format!(
            "log-level: silent\n\
             tunnels: [\"tcp,127.0.0.1:{},{}\"]\n\
             rules: [\"MATCH,DIRECT\"]\n",
            port, echo
        );
        let ids = common::run_sail_instances(&rt, vec![yaml])?;
        let result = rt.block_on(async {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            stream.write_all(b"through the tunnel").await?;
            let mut buf = [0u8; 18];
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read_exact(&mut buf),
            )
            .await??;
            anyhow::ensure!(&buf == b"through the tunnel", "echoed {:?}", buf);
            Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// app(socks) -> (mixed)sail -> smart group -> DIRECT -> echo: sail's smart
// group takes what a fork's smart group lowers to.
#[cfg(all(
    feature = "config-clash",
    feature = "inbound-mixed",
    feature = "outbound-direct",
    feature = "outbound-smart"
))]
#[test]
fn a_smart_group_routes() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let yaml = format!(
            "mixed-port: {}\nlog-level: silent\n\
             proxies:\n  - {{ name: direct, type: direct }}\n\
             proxy-groups:\n  - {{ name: Auto, type: smart, proxies: [direct], policy-priority: 'direct:2' }}\n\
             rules:\n  - MATCH,Auto\n",
            port
        );
        common::test_configs(vec![yaml], "127.0.0.1", port)
    })
}

// The same, by rule-providers read from files: Mihomo's binary (MRS) and
// text forms of a set holding the loopback range.
#[cfg(all(
    feature = "config-clash",
    feature = "rule-set",
    feature = "inbound-mixed",
    feature = "outbound-direct",
    feature = "outbound-drop",
    feature = "outbound-select"
))]
#[test]
fn rule_providers_route() -> anyhow::Result<()> {
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rule_set");
    for (provider, rejected) in [
        (
            "{ type: file, behavior: ipcidr, format: mrs, path: loopback.mrs }".to_string(),
            true,
        ),
        (
            "{ type: file, behavior: ipcidr, format: text, path: ./loopback.list }".to_string(),
            true,
        ),
        (
            "{ type: file, behavior: ipcidr, format: mrs, path: geoip-telegram.mrs }".to_string(),
            false,
        ),
        (
            "{ type: inline, behavior: classical, payload: ['IP-CIDR,127.0.0.1/32'] }".to_string(),
            true,
        ),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let yaml = format!(
                "mixed-port: {}\n\
                 log-level: silent\n\
                 rule-providers:\n  lo: {}\n\
                 rules:\n  - RULE-SET,lo,REJECT,no-resolve\n  - MATCH,DIRECT\n",
                port, provider
            );
            // The fixtures are the data directory, which a provider's
            // path stays in, as in Mihomo.
            common::test_configs_in(
                vec![yaml],
                "127.0.0.1",
                port,
                std::path::Path::new(fixtures),
            )
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", provider, result);
    }
    Ok(())
}

/// A plain DNS server on a port of its own, answering every A query with
/// `answer`.
#[cfg(feature = "config-clash")]
async fn udp_dns_server(answer: std::net::Ipv4Addr) -> u16 {
    use hickory_proto::op::{Message, MessageType, ResponseCode};
    use hickory_proto::rr::{rdata::A, RData, Record, RecordType};

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut resp = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            resp.metadata.recursion_desired = query.metadata.recursion_desired;
            resp.metadata.response_code = ResponseCode::NoError;
            for q in &query.queries {
                resp.add_query(q.clone());
                if q.query_type() == RecordType::A {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(answer)),
                    ));
                }
            }
            let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    port
}

// A Clash configuration's `dns`, fake IPs and a policy, answered by the
// DNS client it lowers to: clients get fake addresses but for what the
// filter keeps out, whose queries go to the policy's server or the
// nameserver; the instance's own lookups get real ones.
#[cfg(feature = "config-clash")]
#[tokio::test]
async fn a_clash_dns_answers_as_mihomo_s() {
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType};
    use std::net::{IpAddr, Ipv4Addr};

    let nameserver = udp_dns_server(Ipv4Addr::new(10, 0, 0, 7)).await;
    let policy = udp_dns_server(Ipv4Addr::new(10, 0, 0, 8)).await;
    let yaml = format!(
        "dns:\n\
         \x20 enable: true\n\
         \x20 enhanced-mode: fake-ip\n\
         \x20 fake-ip-range: 198.18.0.1/16\n\
         \x20 fake-ip-filter: ['+.real.test', '+.policy.test']\n\
         \x20 nameserver: ['127.0.0.1:{}']\n\
         \x20 nameserver-policy:\n\
         \x20   '+.policy.test': '127.0.0.1:{}'\n\
         \x20   '+.blocked.test': 'rcode://name_error'\n",
        nameserver, policy
    );
    let config = sail::config::from_string(&yaml).unwrap();
    let client =
        sail::app::dns_client::DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap();

    let ask = |name: &str, ty: RecordType| {
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii(format!("{}.", name)).unwrap(),
            ty,
        ));
        query.metadata.recursion_desired = true;
        let query = query.to_vec().unwrap();
        let client = &client;
        async move {
            let answer = client.exchange(&query, &Default::default()).await.unwrap();
            Message::from_vec(&answer).unwrap()
        }
    };
    let ips = |message: &Message| -> Vec<IpAddr> {
        message
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                _ => None,
            })
            .collect()
    };
    let fake = ask("a.example", RecordType::A).await;
    assert_eq!(ips(&fake), ["198.18.0.4".parse::<IpAddr>().unwrap()]);
    // Mihomo's fake-ip-ttl, 1 unless set.
    assert_eq!(fake.answers[0].ttl, 1);
    let https = ask("a.example", RecordType::HTTPS).await;
    assert_eq!(https.metadata.response_code, ResponseCode::NoError);
    assert!(https.answers.is_empty());
    let real = ask("www.real.test", RecordType::A).await;
    assert_eq!(ips(&real), ["10.0.0.7".parse::<IpAddr>().unwrap()]);
    let policy = ask("www.policy.test", RecordType::A).await;
    assert_eq!(ips(&policy), ["10.0.0.8".parse::<IpAddr>().unwrap()]);
    // The fake address comes first: the rcode is for the rest.
    let blocked = ask("ads.blocked.test", RecordType::MX).await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
    // The instance's own lookups get real addresses.
    assert_eq!(
        client.lookup("a.example").await.unwrap(),
        ["10.0.0.7".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        client.lookup("www.policy.test").await.unwrap(),
        ["10.0.0.8".parse::<IpAddr>().unwrap()]
    );
}
