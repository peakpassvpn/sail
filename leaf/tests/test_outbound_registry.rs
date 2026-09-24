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

fn group(tag: &str, members: &[&str]) -> config::Outbound {
    outbound(tag, "tryall", json!({ "outbounds": members }))
}

fn ss(tag: &str, extra: serde_json::Value) -> config::Outbound {
    let mut options = json!({
        "server": "127.0.0.1",
        "server_port": 8388,
        "method": "aes-128-gcm",
        "password": "password",
    });
    options
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    outbound(tag, "shadowsocks", options)
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
        group("outer", &["inner"]),
        group("inner", &["direct"]),
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
        group("a", &["b"]),
        group("b", &["a"]),
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
        group("broken", &["direct", "nowhere"]),
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
    let err = manager(&[group("empty", &[])])
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
fn a_blank_ech_config_is_an_error() {
    let err = manager(&[outbound(
        "t",
        "trojan",
        json!({
            "server": "1.2.3.4",
            "server_port": 443,
            "password": "p",
            "tls": { "enabled": true, "ech": { "enabled": true, "config": "   " } },
        }),
    )])
    .err()
    .expect("a blank ech config must fail the whole configuration");
    assert_eq!(
        err.to_string(),
        "[t] outbound: tls.ech.config: cannot be empty"
    );
}

#[test]
fn a_detour_is_built_first_and_a_detour_cycle_is_an_error() {
    let m = manager(&[
        ss("outer", json!({ "detour": "inner" })),
        ss("inner", json!({})),
    ])
    .unwrap();
    assert!(m.get("outer").is_some());

    let err = manager(&[
        ss("a", json!({ "detour": "b" })),
        ss("b", json!({ "detour": "a" })),
    ])
    .err()
    .expect("a detour cycle must fail the whole configuration");
    assert_eq!(
        err.to_string(),
        "outbounds depend on each other in a cycle: a -> b -> a"
    );

    let err = manager(&[ss("a", json!({ "detour": "nowhere" }))])
        .err()
        .expect("a missing detour must fail the whole configuration");
    assert_eq!(
        err.to_string(),
        "[a] outbound: depends on [nowhere], which does not exist"
    );
}

#[test]
fn a_block_the_protocol_does_not_take_is_an_unknown_field() {
    let err = manager(&[ss("ss", json!({ "tls": { "enabled": true } }))])
        .err()
        .expect("tls on shadowsocks must fail the whole configuration");
    assert!(err.to_string().contains("unknown field `tls`"), "{}", err);
}

#[test]
fn block_errors_name_their_path() {
    let trojan = |blocks: serde_json::Value| {
        let mut options = json!({ "server": "1.2.3.4", "server_port": 443, "password": "p" });
        options
            .as_object_mut()
            .unwrap()
            .extend(blocks.as_object().unwrap().clone());
        outbound("t", "trojan", options)
    };
    let err = manager(&[trojan(json!({ "tls": { "enabled": true, "sni": "x" } }))])
        .err()
        .unwrap();
    assert!(
        err.to_string()
            .starts_with("[t] outbound: tls.sni: unknown field"),
        "{}",
        err
    );

    let err = manager(&[trojan(json!({ "transport": { "type": "grpc" } }))])
        .err()
        .unwrap();
    assert!(
        err.to_string()
            .starts_with("[t] outbound: transport.type: unknown variant `grpc`"),
        "{}",
        err
    );

    let err = manager(&[trojan(
        json!({ "multiplex": { "enabled": true, "protocol": "smux" } }),
    )])
    .err()
    .unwrap();
    assert_eq!(
        err.to_string(),
        "[t] outbound: multiplex.protocol: unsupported protocol \"smux\", only amux is"
    );

    let err = manager(&[trojan(json!({ "transport": { "type": "quic" } }))])
        .err()
        .unwrap();
    assert_eq!(
        err.to_string(),
        "[t] outbound: transport: quic needs the tls block enabled"
    );
}

#[test]
fn shadowsocks_takes_the_obfs_plugin_and_nothing_else() {
    manager(&[ss(
        "ss",
        json!({ "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=example.com" }),
    )])
    .unwrap();

    let err = manager(&[ss("ss", json!({ "plugin": "v2ray-plugin" }))])
        .err()
        .unwrap();
    assert!(err.to_string().contains("unsupported plugin"), "{}", err);

    let err = manager(&[ss(
        "ss",
        json!({ "plugin": "obfs-local", "plugin_opts": "obfs=quic" }),
    )])
    .err()
    .unwrap();
    assert!(
        err.to_string().contains("obfs must be http or tls"),
        "{}",
        err
    );
}

#[test]
fn chain_and_transports_are_not_types_of_their_own() {
    for protocol in ["chain", "tls", "ws", "reality", "quic", "amux", "obfs"] {
        let err = manager(&[outbound("x", protocol, json!({}))])
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("unknown protocol"),
            "{}: {}",
            protocol,
            err
        );
    }
}
