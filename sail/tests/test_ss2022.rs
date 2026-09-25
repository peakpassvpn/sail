//! Shadowsocks 2022 interop with sing-box, both ways, TCP and UDP.
//!
//! The sing-box tests are ignored by default; run them with
//! `cargo test -p sail --test test_ss2022 -- --ignored --test-threads=1`
//! (the reliability check in `common` writes a file at a fixed path, so
//! they cannot run in parallel). They look for
//! `sing-box` in `$SING_BOX`, else on the PATH, else at
//! `/opt/homebrew/bin/sing-box`.
//!
//! Ports: 32100-32199 only.

mod common;

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

/// A running sing-box, killed on drop.
struct SingBox {
    child: Child,
    config: PathBuf,
}

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

fn sing_box_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("SING_BOX") {
        return p.into();
    }
    if let Ok(out) = Command::new("which").arg("sing-box").output() {
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && !path.is_empty() {
            return path.into();
        }
    }
    "/opt/homebrew/bin/sing-box".into()
}

/// Starts sing-box with `config` and waits until it listens on `port`.
fn run_sing_box(name: &str, config: serde_json::Value, port: u16) -> anyhow::Result<SingBox> {
    let path =
        std::env::temp_dir().join(format!("sail-ss2022-{}-{}.json", std::process::id(), name));
    std::fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    let child = Command::new(sing_box_bin())
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("start sing-box: {}", e))?;
    let mut sb = SingBox {
        child,
        config: path,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(sb);
        }
        if let Some(status) = sb.child.try_wait()? {
            anyhow::bail!("sing-box exited: {}", status);
        }
        if Instant::now() > deadline {
            anyhow::bail!("sing-box did not listen on {} within 10s", port);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn log() -> serde_json::Value {
    serde_json::json!({ "level": "warn" })
}

/// sail (socks in, ss2022 out) -> sing-box (ss2022 in, direct out).
/// `user` picks a user of a multi-user sing-box server.
fn sail_to_sing_box(
    method: &str,
    user: Option<&str>,
    socks_port: u16,
    ss_port: u16,
) -> anyhow::Result<()> {
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
    let _sb = run_sing_box(
        &format!("in-{}", ss_port),
        serde_json::json!({
            "log": log(),
            "inbounds": [inbound],
            "outbounds": [{ "type": "direct" }],
        }),
        ss_port,
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
/// With `user`, sail has users and only routes that one's TCP: a user
/// sail misidentifies fails the TCP check.
fn sing_box_to_sail(
    method: &str,
    user: Option<&str>,
    socks_port: u16,
    ss_port: u16,
) -> anyhow::Result<()> {
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
            // UDP users do not reach the session yet, so UDP goes
            // through regardless.
            route = serde_json::json!({ "rules": [
                { "auth_user": [name], "outbound": "direct" },
                { "network": ["udp"], "outbound": "direct" },
                { "network": ["tcp"], "action": "reject" },
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
    let _sb = run_sing_box(
        &format!("out-{}", socks_port),
        serde_json::json!({
            "log": log(),
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
        socks_port,
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
    sail_to_sing_box(AES128, None, 32100, 32101)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_aes256() -> anyhow::Result<()> {
    sail_to_sing_box(AES256, None, 32102, 32103)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_chacha() -> anyhow::Result<()> {
    sail_to_sing_box(CHACHA, None, 32104, 32105)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_aes128_multi_user() -> anyhow::Result<()> {
    sail_to_sing_box(AES128, Some("bob"), 32106, 32107)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_out_aes256_multi_user() -> anyhow::Result<()> {
    sail_to_sing_box(AES256, Some("alice"), 32108, 32109)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_aes128() -> anyhow::Result<()> {
    sing_box_to_sail(AES128, None, 32110, 32111)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_aes256() -> anyhow::Result<()> {
    sing_box_to_sail(AES256, None, 32112, 32113)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_chacha() -> anyhow::Result<()> {
    sing_box_to_sail(CHACHA, None, 32114, 32115)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_aes128_multi_user() -> anyhow::Result<()> {
    sing_box_to_sail(AES128, Some("bob"), 32116, 32117)
}

#[test]
#[ignore = "needs sing-box"]
fn sail_in_aes256_multi_user() -> anyhow::Result<()> {
    sing_box_to_sail(AES256, Some("alice"), 32118, 32119)
}

/// A user the route does not let through: proves the identity header
/// really picks the user, rather than any key working.
#[test]
#[ignore = "needs sing-box"]
fn sail_in_multi_user_routes_by_name() -> anyhow::Result<()> {
    let (server, alice, bob) = keys(AES256);
    let sail = serde_json::json!({
        "inbounds": [{
            "type": "shadowsocks",
            "listen": "127.0.0.1",
            "listen_port": 32121,
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
    let _sb = run_sing_box(
        "out-reject",
        serde_json::json!({
            "log": log(),
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": 32120 }],
            "outbounds": [{
                "type": "shadowsocks",
                "server": "127.0.0.1",
                "server_port": 32121,
                "method": AES256,
                "password": format!("{}:{}", server, alice),
            }],
        }),
        32120,
    )?;
    let res = common::test_configs(vec![sail], "127.0.0.1", 32120);
    assert!(res.is_err(), "alice's TCP should have been rejected");
    Ok(())
}

/// sail to sail, for the default suite: every method, single and multi
/// user, TCP and UDP.
#[test]
fn sail_to_sail() -> anyhow::Result<()> {
    let mut port = 32130;
    for (method, users) in [
        (AES128, false),
        (AES256, false),
        (CHACHA, false),
        (AES128, true),
        (AES256, true),
    ] {
        let (server, alice, bob) = keys(method);
        let mut inbound = serde_json::json!({
            "type": "shadowsocks",
            "listen": "127.0.0.1",
            "listen_port": port + 1,
            "method": method,
            "password": server,
        });
        let mut password = server.to_string();
        if users {
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
                "server_port": port + 1,
                "method": method,
                "password": password,
            }],
        })
        .to_string();
        let server = serde_json::json!({
            "inbounds": [inbound],
            "outbounds": [{ "type": "direct" }],
        })
        .to_string();
        common::test_configs(vec![client, server], "127.0.0.1", port)
            .map_err(|e| anyhow::anyhow!("{} users={}: {}", method, users, e))?;
        port += 2;
    }
    Ok(())
}

/// Configuration mistakes fail the start.
#[test]
fn config_mistakes_are_errors() {
    let (server, alice, _) = keys(AES256);
    let bad = [
        // A PSK of the wrong length.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 32190,
            "method": AES128, "password": KEY256_SERVER }),
        // Not base64.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 32190,
            "method": AES256, "password": "not a key" }),
        // Users with a legacy method.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 32190,
            "method": "aes-256-gcm", "password": "x", "users": [{ "name": "a", "password": alice }] }),
        // Users with the ChaCha method, which has no identity headers.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 32190,
            "method": CHACHA, "password": server, "users": [{ "name": "a", "password": alice }] }),
        // An unknown field.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 32190,
            "method": AES256, "password": server, "user": [] }),
        // An unknown 2022 method.
        serde_json::json!({ "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": 32190,
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
        serde_json::json!({ "type": "shadowsocks", "server": "127.0.0.1", "server_port": 32191,
            "method": CHACHA, "password": format!("{}:{}", server, alice) }),
        // A prefix with a 2022 method.
        serde_json::json!({ "type": "shadowsocks", "server": "127.0.0.1", "server_port": 32191,
            "method": AES256, "password": server, "prefix": "abc" }),
        // A PSK of the wrong length in the chain.
        serde_json::json!({ "type": "shadowsocks", "server": "127.0.0.1", "server_port": 32191,
            "method": AES256, "password": format!("{}:{}", server, AES128_ALICE) }),
    ];
    for outbound in bad_outbounds {
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": 32192 }],
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
