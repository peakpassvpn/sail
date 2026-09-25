use std::sync::Arc;

use serde_json::json;

use sail::app::dns_client::DnsClient;
use sail::app::outbound::manager::OutboundManager;
use sail::config;
use sail::net::DialOptions;

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
    manager_with(outbounds, &DialOptions::default())
}

fn manager_with(
    outbounds: &[config::Outbound],
    dial_defaults: &DialOptions,
) -> anyhow::Result<OutboundManager> {
    let dns_client = DnsClient::new(
        &config::Dns::default(),
        Arc::new(dial_defaults.clone()),
        Default::default(),
    )?
    .into_shared();
    OutboundManager::new(
        outbounds,
        dial_defaults,
        &sail::runtime::RuntimeEnv::default(),
        dns_client,
    )
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

/// What `tag` asks to have dialled, and the options it is dialled with.
fn dial_of(m: &OutboundManager, tag: &str) -> (sail::adapter::OutboundConnect, DialOptions) {
    let (connect, dial) = m
        .get(tag)
        .unwrap()
        .stream()
        .unwrap()
        .connect_addr()
        .with_dial();
    (connect, (*dial).clone())
}

fn server_of(connect: &sail::adapter::OutboundConnect) -> u16 {
    match connect {
        sail::adapter::OutboundConnect::Proxy(_, _, port) => *port,
        other => panic!("not a proxy: {:?}", other),
    }
}

/// An interface every host has, for dial fields that name one.
const LOOPBACK: &str = if cfg!(target_os = "macos") {
    "lo0"
} else {
    "lo"
};

#[cfg(not(windows))]
#[test]
fn an_outbound_dials_with_its_own_options_over_the_defaults() {
    let defaults = DialOptions {
        bind_interface: Some("default0".into()),
        ..Default::default()
    };
    let m = manager_with(
        &[
            ss(
                "own",
                json!({ "bind_interface": LOOPBACK, "connect_timeout": "2s" }),
            ),
            ss("plain", json!({ "server_port": 8389 })),
            outbound(
                "direct",
                "direct",
                json!({ "inet4_bind_address": "10.0.0.2" }),
            ),
        ],
        &defaults,
    )
    .unwrap();

    let (_, own) = dial_of(&m, "own");
    assert_eq!(own.bind_interface.as_deref(), Some(LOOPBACK));
    assert_eq!(own.connect_timeout, std::time::Duration::from_secs(2));

    let (_, plain) = dial_of(&m, "plain");
    assert_eq!(plain.bind_interface.as_deref(), Some("default0"));

    // Bound to an address, it does not also take the default interface.
    let (connect, direct) = dial_of(&m, "direct");
    assert!(matches!(connect, sail::adapter::OutboundConnect::Direct));
    assert_eq!(direct.inet4_bind_address, Some("10.0.0.2".parse().unwrap()));
    assert_eq!(direct.bind_interface, None);
}

#[cfg(not(windows))]
#[test]
fn a_group_passes_its_members_dial_options_on() {
    let m = manager(&[
        outbound("static", "static", json!({ "outbounds": ["member"] })),
        ss("member", json!({ "bind_interface": LOOPBACK })),
    ])
    .unwrap();
    let (_, dial) = dial_of(&m, "static");
    assert_eq!(dial.bind_interface.as_deref(), Some(LOOPBACK));
}

#[cfg(not(windows))]
#[test]
fn an_outbound_through_a_detour_is_dialled_as_the_detour_says() {
    let m = manager(&[
        ss("via", json!({ "server_port": 9000, "detour": "hop" })),
        ss(
            "hop",
            json!({ "server_port": 9001, "bind_interface": LOOPBACK }),
        ),
    ])
    .unwrap();
    let (connect, dial) = dial_of(&m, "via");
    // The detour's server, with the detour's options.
    assert_eq!(server_of(&connect), 9001);
    assert_eq!(dial.bind_interface.as_deref(), Some(LOOPBACK));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn an_interface_that_does_not_exist_is_an_error_when_built() {
    let err = manager(&[ss("ss", json!({ "bind_interface": "no-such-if0" }))])
        .err()
        .unwrap();
    assert_eq!(
        err.to_string(),
        "[ss] outbound: bind_interface: there is no interface \"no-such-if0\""
    );
}

#[test]
fn dial_fields_with_a_detour_are_an_error() {
    let err = manager(&[
        ss("via", json!({ "detour": "hop", "connect_timeout": "1s" })),
        ss("hop", json!({})),
    ])
    .err()
    .unwrap();
    assert_eq!(
        err.to_string(),
        "[via] outbound: connect_timeout: has no effect with a detour; set it on [hop]"
    );
}

#[test]
fn a_bad_dial_field_names_itself() {
    let err = manager(&[ss("ss", json!({ "connect_timeout": "soon" }))])
        .err()
        .unwrap();
    assert!(
        err.to_string()
            .starts_with("[ss] outbound: connect_timeout: invalid duration"),
        "{}",
        err
    );
    let err = manager(&[ss("ss", json!({ "inet4_bind_address": "::1" }))])
        .err()
        .unwrap();
    assert!(
        err.to_string()
            .starts_with("[ss] outbound: inet4_bind_address: "),
        "{}",
        err
    );
    // Groups dial through their members and take no dial fields.
    let err = manager(&[
        outbound(
            "g",
            "static",
            json!({ "outbounds": ["ss"], "bind_interface": "x" }),
        ),
        ss("ss", json!({})),
    ])
    .err()
    .unwrap();
    assert!(
        err.to_string().contains("unknown field `bind_interface`"),
        "{}",
        err
    );
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
fn a_routing_mark_is_linux_only() {
    let err = manager(&[ss("ss", json!({ "routing_mark": 1 }))])
        .err()
        .unwrap();
    assert_eq!(
        err.to_string(),
        "[ss] outbound: routing_mark: only supported on Linux"
    );
}

#[cfg(feature = "outbound-shadowsocks")]
#[test]
fn an_unsupported_cipher_is_an_error_when_built() {
    let err = manager(&[outbound(
        "ss",
        "shadowsocks",
        json!({
            "server": "127.0.0.1",
            "server_port": 8388,
            "method": "no-such-cipher",
            "password": "x"
        }),
    )])
    .err()
    .expect("an unsupported cipher must fail the configuration");
    assert!(
        err.to_string().starts_with("[ss] outbound: method: "),
        "{}",
        err
    );
}

#[cfg(feature = "outbound-vmess")]
#[test]
fn vmess_uuid_and_security_are_checked_when_built() {
    for (options, field) in [
        (
            json!({ "server": "a", "server_port": 1, "uuid": "not-a-uuid", "security": "aes-128-gcm" }),
            "uuid",
        ),
        (
            json!({ "server": "a", "server_port": 1,
                    "uuid": "6c5e8a2e-4d9b-4b52-8d64-0bcb3e1a8a2f", "security": "rot13" }),
            "security",
        ),
    ] {
        let err = manager(&[outbound("vm", "vmess", options)])
            .err()
            .expect("a bad value must fail the configuration");
        assert!(
            err.to_string()
                .starts_with(&format!("[vm] outbound: {}: ", field)),
            "{}",
            err
        );
    }
}
