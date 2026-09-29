#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

/// A plain DNS server on a port of its own, answering every A query with
/// 10.0.0.7, and the number of queries it got.
#[cfg(all(feature = "outbound-direct", feature = "outbound-drop"))]
async fn udp_server() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use hickory_proto::op::{Message, MessageType, ResponseCode};
    use hickory_proto::rr::{rdata::A, RData, Record, RecordType};

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
                        RData::A(A(std::net::Ipv4Addr::new(10, 0, 0, 7))),
                    ));
                }
            }
            let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    (port, count)
}

/// A server with `respect_rules` goes through the outbound the routing
/// rules pick for it, which see its domain: DIRECT reaches it, a block
/// outbound does not.
#[cfg(all(feature = "outbound-direct", feature = "outbound-drop"))]
#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_respects_the_rules_goes_where_they_say() {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use sail::app::dispatcher::Dispatcher;
    use sail::app::dns_client::DnsClient;
    use sail::app::outbound::manager::OutboundManager;
    use sail::app::router::Router;
    use sail::app::stat_manager::StatManager;

    let (port, count) = udp_server().await;
    for (rule, reached) in [
        (
            serde_json::json!({ "port": port, "outbound": "direct" }),
            true,
        ),
        (
            serde_json::json!({ "port": port, "outbound": "blocked" }),
            false,
        ),
        // The rules see the server's domain.
        (
            serde_json::json!({ "domain": "dns.sail.test", "outbound": "blocked" }),
            false,
        ),
    ] {
        let config = sail::config::Config::from_json(
            &serde_json::json!({
                "dns": {
                    "servers": [
                        { "type": "udp", "tag": "ruled", "server": "dns.sail.test",
                          "server_port": port, "respect_rules": true,
                          "domain_resolver": "hosts" },
                        { "type": "hosts", "tag": "hosts",
                          "predefined": { "dns.sail.test": "127.0.0.1" } }
                    ],
                    "strategy": "ipv4_only",
                    "timeout": "1s"
                },
                "outbounds": [
                    { "type": "direct", "tag": "direct" },
                    { "type": "block", "tag": "blocked" }
                ],
                "route": { "rules": [rule], "final": "direct" }
            })
            .to_string(),
        )
        .unwrap();
        let env = Arc::new(sail::runtime::RuntimeEnv::default());
        let dial = Arc::new(sail::net::DialOptions::default());
        let client = DnsClient::new(&config.dns, dial.clone(), &env).unwrap();
        client
            .check_loops(&config.outbounds, &config.route)
            .unwrap();
        let dns_client = client.into_shared();
        let outbound_manager = Arc::new(arc_swap::ArcSwap::from_pointee(
            OutboundManager::new(&config.outbounds, &dial, &env, dns_client.clone()).unwrap(),
        ));
        let router = Arc::new(arc_swap::ArcSwap::from_pointee(
            Router::new(&config.route, dns_client.clone(), &env).unwrap(),
        ));
        let stat_manager = Arc::new(tokio::sync::RwLock::new(StatManager::new()));
        let dispatcher = Arc::new(Dispatcher::new(
            outbound_manager,
            router,
            dns_client.clone(),
            stat_manager,
            env,
        ));
        dns_client
            .load()
            .set_dispatcher(Arc::downgrade(&dispatcher));

        let before = count.load(Ordering::SeqCst);
        let result = dns_client.load().lookup("a.example").await;
        assert_eq!(result.is_ok(), reached, "{}: {:?}", rule, result);
        if reached {
            assert_eq!(
                result.unwrap(),
                vec!["10.0.0.7".parse::<std::net::IpAddr>().unwrap()]
            );
        }
        assert_eq!(count.load(Ordering::SeqCst) > before, reached, "{}", rule);
    }
}
