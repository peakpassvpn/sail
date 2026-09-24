use std::sync::Arc;

use serde_json::json;
use tokio::sync::RwLock;

use leaf::app::dns_client::DnsClient;
use leaf::app::outbound::manager::OutboundManager;
use leaf::config;

fn outbound(tag: &str, protocol: &str, options: serde_json::Value) -> config::Outbound {
    let serde_json::Value::Object(options) = options else {
        panic!("options must be an object");
    };
    config::Outbound {
        protocol: protocol.to_string(),
        tag: tag.to_string(),
        options,
    }
}

fn chain(tag: &str, actors: &[&str]) -> config::Outbound {
    outbound(tag, "chain", json!({ "outbounds": actors }))
}

fn manager(outbounds: &[config::Outbound]) -> anyhow::Result<OutboundManager> {
    let dns_client = Arc::new(RwLock::new(DnsClient::new(&config::Dns::default())?));
    OutboundManager::new(outbounds, dns_client)
}

#[test]
fn an_unknown_protocol_is_an_error_that_names_the_outbound() {
    let err = manager(&[
        outbound("direct", "direct", json!({})),
        outbound("proxy-1", "no-such-protocol", json!({})),
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
        outbound("direct", "direct", json!({})),
    ])
    .unwrap();
    assert!(m.get("inner").is_some());
    assert!(m.get("outer").is_some());
    // The first outbound is the default one, even when it is a group.
    assert_eq!(m.default_handler().as_deref(), Some("outer"));
}

#[test]
fn a_cycle_is_an_error() {
    let err = manager(&[
        outbound("direct", "direct", json!({})),
        chain("a", &["b"]),
        chain("b", &["a"]),
    ])
    .err()
    .expect("a cycle must fail the whole configuration");
    assert_eq!(
        err.to_string(),
        "outbounds depend on each other in a cycle: a -> b -> a"
    );
}

#[test]
fn a_group_with_a_missing_member_is_an_error() {
    let err = manager(&[
        outbound("direct", "direct", json!({})),
        chain("broken", &["direct", "nowhere"]),
    ])
    .err()
    .expect("a missing member must fail the whole configuration");
    assert_eq!(
        err.to_string(),
        "[broken] outbound: depends on [nowhere], which does not exist"
    );
}

#[test]
fn a_group_without_members_is_an_error() {
    let err = manager(&[chain("empty", &[])])
        .err()
        .expect("an empty group must fail the whole configuration");
    assert_eq!(
        err.to_string(),
        "[empty] outbound: needs at least one actor"
    );
}

#[test]
fn a_tag_used_twice_is_an_error() {
    let err = manager(&[
        outbound("proxy", "direct", json!({})),
        outbound("proxy", "block", json!({})),
    ])
    .err()
    .expect("a duplicate tag must fail the whole configuration");
    assert_eq!(err.to_string(), "[proxy] outbound: tag used more than once");
}

#[test]
fn options_errors_name_the_outbound_and_the_field() {
    let err = manager(&[outbound(
        "ss",
        "shadowsocks",
        json!({ "server": "1.2.3.4", "server_port": "x", "method": "aes-128-gcm", "password": "p" }),
    )])
    .err()
    .expect("a mistyped field must fail the whole configuration");
    assert!(
        err.to_string().starts_with("[ss] outbound: server_port: "),
        "{}",
        err
    );

    let err = manager(&[outbound("d", "direct", json!({ "server": "1.2.3.4" }))])
        .err()
        .expect("an unknown field must fail the whole configuration");
    assert!(
        err.to_string().contains("unknown field `server`"),
        "{}",
        err
    );
}

#[test]
fn a_blank_ech_config_list_is_an_error() {
    let err = manager(&[outbound(
        "tls",
        "tls",
        json!({ "server_name": "example.com", "ech": true, "ech_config_list": "   " }),
    )])
    .err()
    .expect("a blank ech_config_list must fail the whole configuration");
    assert_eq!(
        err.to_string(),
        "[tls] outbound: ech_config_list: cannot be empty"
    );
}
