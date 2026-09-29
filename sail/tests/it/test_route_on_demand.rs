#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]

use crate::common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::timeout;

/// A plain DNS server answering every A query with 127.0.0.1, and the
/// number of queries it got.
async fn udp_server() -> (u16, Arc<AtomicUsize>) {
    use hickory_proto::op::{Message, MessageType, ResponseCode};
    use hickory_proto::rr::{rdata::A, RData, Record, RecordType};

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            counter.fetch_add(1, Ordering::SeqCst);
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
                        RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
                    ));
                }
            }
            let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    (port, count)
}

// app(socks) -> sail(on_demand resolve; a domain rule, then an address rule)
//
// A connection a domain rule decides is never resolved: the DNS server gets
// no query. One that reaches the rule on addresses is resolved once, right
// before it, and that rule decides.
#[test]
fn an_on_demand_resolve_asks_only_for_a_rule_on_addresses() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (dns_port, queries) = rt.block_on(udp_server());
        let port = common::free_port();
        let config = serde_json::json!({
            "dns": {
                "servers": [{ "type": "udp", "server": "127.0.0.1", "server_port": dns_port }],
                "strategy": "ipv4_only",
            },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": {
                "rules": [
                    { "action": "resolve", "on_demand": true },
                    { "domain_suffix": "early.test", "action": "reject" },
                    { "ip_cidr": "127.0.0.0/8", "action": "reject" },
                ],
            },
        });
        let ids = common::run_sail_instances(&rt, vec![config.to_string()])?;
        let result = rt.block_on(async {
            // Where `final` would take late.test: its connection would be
            // relayed, not refused, were the rule on addresses not matched.
            let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            tokio::spawn(echo);
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Whether sail refused the connection to `host`.
            let refused = |host: &'static str| async move {
                let sess = sail::session::Session {
                    destination: sail::session::SocksAddr::Domain(host.into(), echo_addr.port()),
                    ..Default::default()
                };
                let Ok(mut stream) =
                    common::new_socks_stream("127.0.0.1", port, &sess, None, None).await
                else {
                    return true;
                };
                let mut buf = [0u8; 16];
                let read = timeout(Duration::from_secs(10), stream.read(&mut buf)).await;
                matches!(read, Ok(Ok(0) | Err(_)))
            };

            anyhow::ensure!(refused("www.early.test").await, "early.test is rejected");
            let asked = queries.load(Ordering::SeqCst);
            anyhow::ensure!(asked == 0, "early.test asked {} queries", asked);

            anyhow::ensure!(refused("late.test").await, "late.test is rejected");
            let asked = queries.load(Ordering::SeqCst);
            anyhow::ensure!(asked == 1, "late.test asked {} queries", asked);
            anyhow::Ok(())
        });
        for id in ids {
            assert!(sail::shutdown(id));
        }
        result
    })
}
