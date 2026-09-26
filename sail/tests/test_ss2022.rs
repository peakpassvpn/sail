//! Shadowsocks 2022 interop with sing-box, both ways, TCP and UDP.
//!
//! The sing-box tests are ignored by default; run them with
//! `cargo test -p sail --test test_ss2022 -- --ignored`. They look for
//! `sing-box` in `$SING_BOX`, else at `/opt/homebrew/bin/sing-box`, else
//! on the PATH.

mod common;

const AES128_SERVER: &str = "a8C5QncIl9HvTmenrEb7aw==";
const AES128_ALICE: &str = "D8VrI6H92L/B/lcGwE9DNQ==";
const AES128_BOB: &str = "zzOhLj+nKQ5dJKxF9mQK/w==";
const KEY256_SERVER: &str = "/45M1k/d1H+U/ie6QGvrEOfqZIyxpbjuhum51J6KQhw=";
const KEY256_ALICE: &str = "0zuapgRqNMKuuXZZLpVBVo8ATDaGPOXgF3iWioVURaw=";
const KEY256_BOB: &str = "U9BzEGtEZbyXMHnfHzC8aqk0f6ncRK/lRHZpBlzE3mU=";

const AES128: &str = "2022-blake3-aes-128-gcm";
const AES256: &str = "2022-blake3-aes-256-gcm";
const CHACHA: &str = "2022-blake3-chacha20-poly1305";

/// The server key, and the users' keys, of a method.
fn keys(method: &str) -> (&'static str, &'static str, &'static str) {
    if method == AES128 {
        (AES128_SERVER, AES128_ALICE, AES128_BOB)
    } else {
        (KEY256_SERVER, KEY256_ALICE, KEY256_BOB)
    }
}

/// sail (socks in, ss2022 out) -> sing-box (ss2022 in, direct out).
/// `user` picks a user of a multi-user sing-box server.
fn sail_to_sing_box(method: &str, user: Option<&str>) -> anyhow::Result<()> {
    common::retry_port_clash(|| sail_to_sing_box_on(method, user))
}

fn sail_to_sing_box_on(method: &str, user: Option<&str>) -> anyhow::Result<()> {
    let [socks_port, ss_port] = common::free_ports();
    let (server, alice, bob) = keys(method);
    let mut inbound = serde_json::json!({
        "type": "shadowsocks",
        "listen": "127.0.0.1",
        "listen_port": ss_port,
        "method": method,
        "password": server,
    });
    let password = match user {
        None => server.to_string(),
        Some(name) => {
            inbound["users"] = serde_json::json!([
                { "name": "alice", "password": alice },
                { "name": "bob", "password": bob },
            ]);
            let upsk = if name == "alice" { alice } else { bob };
            format!("{}:{}", server, upsk)
        }
    };
    let dir = common::TempDir::new("ss2022")?;
    let _sb = common::Daemon::sing_box(
        dir.path(),
        "in",
        serde_json::json!({
            "inbounds": [inbound],
            "outbounds": [{ "type": "direct" }],
        }),
    )?;
    let sail = serde_json::json!({
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
        }],
        "outbounds": [{
            "type": "shadowsocks",
            "server": "127.0.0.1",
            "server_port": ss_port,
            "method": method,
            "password": password,
        }],
    })
    .to_string();
    common::test_configs(vec![sail.clone()], "127.0.0.1", socks_port)?;
    common::test_data_transfering_reliability_on_configs(vec![sail], "127.0.0.1", socks_port)
}

/// sing-box (socks in, ss2022 out) -> sail (ss2022 in, direct out).
/// With `user`, sail has users and only routes that one's traffic: a user
/// sail misidentifies fails the TCP and UDP checks.
fn sing_box_to_sail(method: &str, user: Option<&str>) -> anyhow::Result<()> {
    common::retry_port_clash(|| sing_box_to_sail_on(method, user))
}

fn sing_box_to_sail_on(method: &str, user: Option<&str>) -> anyhow::Result<()> {
    let [socks_port, ss_port] = common::free_ports();
    let (server, alice, bob) = keys(method);
    let mut inbound = serde_json::json!({
        "type": "shadowsocks",
        "listen": "127.0.0.1",
        "listen_port": ss_port,
        "method": method,
        "password": server,
    });
    let mut route = serde_json::json!({ "rules": [] });
    let password = match user {
        None => server.to_string(),
        Some(name) => {
            inbound["users"] = serde_json::json!([
                { "name": "alice", "password": alice },
                { "name": "bob", "password": bob },
            ]);
            route = serde_json::json!({ "rules": [
                { "auth_user": [name], "outbound": "direct" },
                { "network": ["tcp", "udp"], "action": "reject" },
            ]});
            let upsk = if name == "alice" { alice } else { bob };
            format!("{}:{}", server, upsk)
        }
    };
    let sail = serde_json::json!({
        "inbounds": [inbound],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": route,
    })
    .to_string();
    let dir = common::TempDir::new("ss2022")?;
    let _sb = common::Daemon::sing_box(
        dir.path(),
        "out",
        serde_json::json!({
            "inbounds": [{
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            }],
            "outbounds": [{
                "type": "shadowsocks",
                "server": "127.0.0.1",
                "server_port": ss_port,
                "method": method,
                "password": password,
            }],
        }),
    )?;
    common::test_configs(vec![sail.clone()], "127.0.0.1", socks_port)?;
    if user.is_none() {
        common::test_data_transfering_reliability_on_configs(vec![sail], "127.0.0.1", socks_port)?;
    }
    Ok(())
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_aes128() -> anyhow::Result<()> {
    sail_to_sing_box(AES128, None)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_aes256() -> anyhow::Result<()> {
    sail_to_sing_box(AES256, None)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_chacha() -> anyhow::Result<()> {
    sail_to_sing_box(CHACHA, None)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_aes128_multi_user() -> anyhow::Result<()> {
    sail_to_sing_box(AES128, Some("bob"))
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_aes256_multi_user() -> anyhow::Result<()> {
    sail_to_sing_box(AES256, Some("alice"))
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_aes128() -> anyhow::Result<()> {
    sing_box_to_sail(AES128, None)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_aes256() -> anyhow::Result<()> {
    sing_box_to_sail(AES256, None)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_chacha() -> anyhow::Result<()> {
    sing_box_to_sail(CHACHA, None)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_aes128_multi_user() -> anyhow::Result<()> {
    sing_box_to_sail(AES128, Some("bob"))
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_aes256_multi_user() -> anyhow::Result<()> {
    sing_box_to_sail(AES256, Some("alice"))
}

/// A user the route does not let through: proves the identity header
/// really picks the user, rather than any key working.
#[test]
#[ignore = "needs sing-box"]
fn sail_in_multi_user_routes_by_name() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [socks_port, ss_port] = common::free_ports();
        let (server, alice, bob) = keys(AES256);
        let sail = serde_json::json!({
            "inbounds": [{
                "type": "shadowsocks",
                "listen": "127.0.0.1",
                "listen_port": ss_port,
                "method": AES256,
                "password": server,
                "users": [
                    { "name": "alice", "password": alice },
                    { "name": "bob", "password": bob },
                ],
            }],
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "rules": [{ "auth_user": ["alice"], "action": "reject" }] },
        })
        .to_string();
        let dir = common::TempDir::new("ss2022")?;
        let _sb = common::Daemon::sing_box(
            dir.path(),
            "out-reject",
            serde_json::json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
                "outbounds": [{
                    "type": "shadowsocks",
                    "server": "127.0.0.1",
                    "server_port": ss_port,
                    "method": AES256,
                    "password": format!("{}:{}", server, alice),
                }],
            }),
        )?;
        let res = common::test_configs(vec![sail], "127.0.0.1", socks_port);
        assert!(res.is_err(), "alice's TCP should have been rejected");
        Ok(())
    })
}

/// sail to sail, for the default suite: every method, single and multi
/// user, TCP and UDP.
#[test]
fn sail_to_sail() -> anyhow::Result<()> {
    for (method, users) in [
        (AES128, false),
        (AES256, false),
        (CHACHA, false),
        (AES128, true),
        (AES256, true),
    ] {
        common::retry_port_clash(|| sail_to_sail_on(method, users))
            .map_err(|e| anyhow::anyhow!("{} users={}: {}", method, users, e))?;
    }
    Ok(())
}

fn sail_to_sail_on(method: &str, users: bool) -> anyhow::Result<()> {
    let [port, ss_port] = common::free_ports();
    let (server, alice, bob) = keys(method);
    let mut inbound = serde_json::json!({
        "type": "shadowsocks",
        "listen": "127.0.0.1",
        "listen_port": ss_port,
        "method": method,
        "password": server,
    });
    let mut password = server.to_string();
    let mut route = serde_json::json!({ "rules": [] });
    if users {
        // Only bob gets through, over TCP and UDP alike, so a user
        // misidentified on either fails the checks.
        route = serde_json::json!({ "rules": [
            { "auth_user": ["bob"], "outbound": "direct" },
            { "network": ["tcp", "udp"], "action": "reject" },
        ]});
        inbound["users"] = serde_json::json!([
            { "name": "alice", "password": alice },
            { "name": "bob", "password": bob },
        ]);
        password = format!("{}:{}", server, bob);
    }
    let client = serde_json::json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{
            "type": "shadowsocks",
            "server": "127.0.0.1",
            "server_port": ss_port,
            "method": method,
            "password": password,
        }],
    })
    .to_string();
    let server = serde_json::json!({
        "inbounds": [inbound],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": route,
    })
    .to_string();
    common::test_configs(vec![client, server], "127.0.0.1", port)
}

/// Configuration mistakes fail the start.
#[test]
fn config_mistakes_are_errors() {
    let (server, alice, _) = keys(AES256);
    let [port, server_port, socks_port] = common::free_ports();
    let bad = [
        // A PSK of the wrong length.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
            "method": AES128, "password": KEY256_SERVER }),
        // Not base64.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
            "method": AES256, "password": "not a key" }),
        // Users with a legacy method.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
            "method": "aes-256-gcm", "password": "x", "users": [{ "name": "a", "password": alice }] }),
        // Users with the ChaCha method, which has no identity headers.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
            "method": CHACHA, "password": server, "users": [{ "name": "a", "password": alice }] }),
        // An unknown field.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
            "method": AES256, "password": server, "user": [] }),
        // An unknown 2022 method.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
            "method": "2022-blake3-aes-192-gcm", "password": server }),
    ];
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for inbound in bad {
        let config = serde_json::json!({
            "inbounds": [inbound],
            "outbounds": [{ "type": "direct" }],
        })
        .to_string();
        assert!(
            common::run_sail_instances(&rt, vec![config]).is_err(),
            "{}",
            inbound
        );
    }
    let bad_outbounds = [
        // An iPSK:uPSK chain with the ChaCha method.
        serde_json::json!({ "type": "shadowsocks", "server": "127.0.0.1", "server_port": server_port,
            "method": CHACHA, "password": format!("{}:{}", server, alice) }),
        // A prefix with a 2022 method.
        serde_json::json!({ "type": "shadowsocks", "server": "127.0.0.1", "server_port": server_port,
            "method": AES256, "password": server, "prefix": "abc" }),
        // A PSK of the wrong length in the chain.
        serde_json::json!({ "type": "shadowsocks", "server": "127.0.0.1", "server_port": server_port,
            "method": AES256, "password": format!("{}:{}", server, AES128_ALICE) }),
    ];
    for outbound in bad_outbounds {
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
            "outbounds": [outbound],
        })
        .to_string();
        assert!(
            common::run_sail_instances(&rt, vec![config]).is_err(),
            "{}",
            outbound
        );
    }
}
