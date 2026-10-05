use std::sync::Arc;

use super::*;
use crate::config::Config;
use crate::net::DialDefaults;
use crate::runtime::RuntimeEnv;
use crate::session::{Network, SocksAddr};

/// The router and the outbounds of `rules`, over the outbounds `a` and `b`.
fn routing(rules: serde_json::Value) -> (Router, OutboundManager) {
    let config = Config::from_json(
        &serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "a" },
                { "type": "direct", "tag": "b", "connect_timeout": "9s" },
            ],
            "route": { "rules": rules, "final": "a" },
        })
        .to_string(),
    )
    .unwrap();
    let dial = DialDefaults::default();
    let dns =
        crate::app::dns::DnsClient::new(&config.dns, Arc::new(dial.clone()), &Default::default())
            .unwrap()
            .into_shared();
    let env = RuntimeEnv::default();
    let outbounds = OutboundManager::new(&config.outbounds, &dial, &env, dns.clone()).unwrap();
    (Router::new(&config.route, dns, &env).unwrap(), outbounds)
}

/// Lists a TCP connection to `destination`, which the router numbered
/// `routed_by` routed to `a`, as the dispatcher lists one.
fn list(stats: &StatManager, destination: SocksAddr, routed_by: u64) -> crate::adapter::AnyStream {
    let (stream, peer) = tokio::io::duplex(64);
    std::mem::forget(peer);
    let sess = Session {
        network: Network::Tcp,
        destination,
        outbound_tag: "a".into(),
        routed_by,
        ..Default::default()
    };
    stats.stat_stream(Box::new(stream), sess)
}

/// The pass over 10k connections open, against rules alike to a client's:
/// how long it takes, measured. Every tenth goes to a port a rule rejects,
/// every seventh to a domain another rule sends to `b`; a host's own dial,
/// routed by no rule, is passed over.
#[tokio::test]
async fn a_pass_over_10k_connections_is_timed() {
    let (router, outbounds) = routing(serde_json::json!([
        { "domain_suffix": ["ads.example", "track.example", "metrics.example"], "action": "reject" },
        { "ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"], "outbound": "a" },
        { "port": [9], "action": "reject" },
        { "domain_keyword": ["video"], "outbound": "b" },
        { "domain_suffix": ["example.org", "example.net"], "outbound": "a" },
        { "network": "udp", "port": [443], "action": "reject" },
    ]));
    let stats = StatManager::default();
    let mut streams = Vec::new();
    let (mut rejected, mut elsewhere) = (0, 0);
    for i in 0..10_000u32 {
        let destination = if i % 10 == 0 {
            rejected += 1;
            SocksAddr::from((std::net::Ipv4Addr::new(203, 0, 113, (i % 250) as u8), 9))
        } else if i % 7 == 0 {
            elsewhere += 1;
            SocksAddr::Domain(format!("cdn{}.video.example.com", i), 443)
        } else if i % 2 == 0 {
            SocksAddr::Domain(format!("www{}.example.org", i), 443)
        } else {
            SocksAddr::from((std::net::Ipv4Addr::new(198, 51, 100, (i % 250) as u8), 443))
        };
        streams.push(list(&stats, destination, 1));
    }
    streams.push(list(
        &stats,
        SocksAddr::from((std::net::Ipv4Addr::LOCALHOST, 9)),
        0,
    ));
    let started = std::time::Instant::now();
    let report = pass(&stats, &router, &outbounds).await;
    let took = started.elapsed();
    eprintln!("the pass over 10001 connections took {:?}", took);
    assert_eq!(report.closed.len(), rejected);
    assert!(report.closed.iter().all(|c| c.rule == Some(2)));
    assert_eq!(report.differ.len(), elsewhere);
    assert!(report.differ.iter().all(|d| d.old == "a" && d.new == "b"));
    let closed = stats
        .connections()
        .iter()
        .filter(|c| c.closer.is_closed())
        .count();
    assert_eq!(closed, rejected, "the host's own dial was rechecked");
    // A judgment bound, far above what it takes: the reload waits for it.
    assert!(took < std::time::Duration::from_secs(2), "{:?}", took);
}
