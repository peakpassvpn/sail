use std::sync::Arc;

use protobuf::Message;
use tokio::sync::RwLock;

use leaf::app::dns_client::DnsClient;
use leaf::app::outbound::manager::OutboundManager;
use leaf::config;

fn outbound(tag: &str, protocol: &str, settings: Vec<u8>) -> config::Outbound {
    let mut o = config::Outbound::new();
    o.tag = tag.to_string();
    o.protocol = protocol.to_string();
    o.settings = settings;
    o
}

fn chain(tag: &str, actors: &[&str]) -> config::Outbound {
    let mut settings = config::ChainOutboundSettings::new();
    settings.actors = actors.iter().map(|a| a.to_string()).collect();
    outbound(tag, "chain", settings.write_to_bytes().unwrap())
}

fn manager(outbounds: &[config::Outbound]) -> anyhow::Result<OutboundManager> {
    // The DNS settings an otherwise empty configuration gets.
    let defaults = config::json::to_internal(config::json::Config {
        log: None,
        env: None,
        inbounds: None,
        outbounds: None,
        router: None,
        dns: None,
    })?;
    let dns_client = Arc::new(RwLock::new(DnsClient::new(&defaults.dns)?));
    OutboundManager::new(outbounds, dns_client)
}

#[test]
fn an_unknown_protocol_is_an_error_that_names_the_outbound() {
    let err = manager(&[
        outbound("direct", "direct", Vec::new()),
        outbound("proxy-1", "no-such-protocol", Vec::new()),
    ])
    .err()
    .expect("an unknown protocol must fail the whole configuration");
    let msg = err.to_string();
    assert!(msg.contains("[proxy-1]"), "{}", msg);
    assert!(msg.contains("\"no-such-protocol\""), "{}", msg);
}

#[test]
fn a_group_is_built_whatever_its_place_in_the_configuration() {
    let m = manager(&[
        chain("outer", &["inner"]),
        chain("inner", &["direct"]),
        outbound("direct", "direct", Vec::new()),
    ])
    .unwrap();
    assert!(m.get("inner").is_some());
    assert!(m.get("outer").is_some());
    // The first outbound is the default one, even when it is a group.
    assert_eq!(m.default_handler().as_deref(), Some("outer"));
}

#[test]
fn a_cycle_leaves_only_its_members_unbuilt() {
    let m = manager(&[
        outbound("direct", "direct", Vec::new()),
        chain("a", &["b"]),
        chain("b", &["a"]),
        chain("ok", &["direct"]),
    ])
    .unwrap();
    assert!(m.get("a").is_none());
    assert!(m.get("b").is_none());
    assert!(m.get("ok").is_some());
}

#[test]
fn a_group_with_a_missing_member_is_skipped() {
    let m = manager(&[
        outbound("direct", "direct", Vec::new()),
        chain("broken", &["direct", "nowhere"]),
    ])
    .unwrap();
    assert!(m.get("broken").is_none());
    assert!(m.get("direct").is_some());
}
