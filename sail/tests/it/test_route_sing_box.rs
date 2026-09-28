//! Routing decisions against sing-box's: the same rules, run by both, on
//! the same connections, allow and reject the same ones.
//!
//! Each rule condition gets an inbound of its own, whose connections are
//! rejected unless the condition matches; the rest go to an echo server.
//! Needs `sing-box` (1.11 or later) on the PATH, in /opt/homebrew/bin, or
//! in `$SING_BOX`; ignored unless asked for:
//! `cargo test -p sail --test it test_route_sing_box:: -- --ignored`.

#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

/// The conditions compared, each a rule's.
fn conditions() -> Vec<serde_json::Value> {
    vec![
        json!({ "domain": "a.test" }),
        json!({ "domain_suffix": ".b.test" }),
        json!({ "domain_suffix": "b.test" }),
        json!({ "domain_keyword": "key" }),
        json!({ "domain_regex": "^r[0-9]+\\." }),
        json!({ "port": 443 }),
        json!({ "port_range": "8000:9000" }),
        json!({ "ip_cidr": "10.0.0.0/8" }),
        json!({ "ip_is_private": true }),
        json!({ "ip_version": 6 }),
        json!({ "ip_version": 4 }),
        json!({ "source_ip_cidr": "127.0.0.0/8" }),
        json!({ "source_ip_is_private": true }),
        json!({ "source_port_range": ":1023" }),
        json!({ "network": "udp" }),
        json!({ "domain": "a.test", "port": 443 }),
        json!({ "domain": "a.test", "ip_cidr": "10.0.0.0/8" }),
        json!({ "domain_suffix": "test", "invert": true }),
        json!({ "ip_cidr": "10.0.0.0/8", "port": 80, "invert": true }),
        json!({ "type": "logical", "mode": "or", "rules": [
            { "port": 80 }, { "domain_suffix": "b.test", "invert": true }
        ] }),
        json!({ "type": "logical", "mode": "and", "invert": true, "rules": [
            { "domain_keyword": "test" },
            { "type": "logical", "mode": "or", "rules": [
                { "port_range": ":100" }, { "ip_version": 6 }
            ] }
        ] }),
    ]
}

/// Where the connections go.
const DESTINATIONS: &[&str] = &[
    "a.test:443",
    "x.b.test:80",
    "b.test:8080",
    "key.test:1",
    "r12.test:8500",
    "10.1.2.3:443",
    "10.1.2.3:80",
    "8.8.8.8:80",
    "[2001:db8::1]:443",
    "[fd00::1]:80",
    "z.test:22",
];

fn destination(value: &str) -> SocksAddr {
    match value.parse::<std::net::SocketAddr>() {
        Ok(addr) => SocksAddr::from(addr),
        Err(_) => {
            let (host, port) = value.rsplit_once(':').unwrap();
            SocksAddr::Domain(host.into(), port.parse().unwrap())
        }
    }
}

/// A configuration with an inbound per condition, on `ports`: a
/// connection to one is rejected unless its condition matches, and else
/// goes to `echo`, whatever it asked for.
fn config(ports: &[u16], echo: u16) -> serde_json::Value {
    let mut inbounds = Vec::new();
    let mut rules = Vec::new();
    for (i, (condition, port)) in conditions().into_iter().zip(ports).enumerate() {
        let tag = format!("in{}", i);
        inbounds.push(json!({
            "type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": port
        }));
        rules.push(json!({
            "type": "logical", "mode": "and", "action": "reject", "rules": [
                { "inbound": tag },
                { "type": "logical", "mode": "and", "invert": true, "rules": [condition] }
            ]
        }));
    }
    rules.push(json!({
        "network": "tcp", "outbound": "direct",
        "override_address": "127.0.0.1", "override_port": echo
    }));
    json!({
        "inbounds": inbounds,
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "rules": rules, "final": "direct" }
    })
}

/// Whether a connection through the socks inbound on `port` to
/// `destination` is relayed.
async fn allowed(port: u16, destination: &str) -> bool {
    let sess = Session {
        destination: self::destination(destination),
        ..Default::default()
    };
    let attempt = async {
        let mut stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
        stream.write_all(b"ping").await?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        anyhow::ensure!(&buf == b"ping", "echoed {:?}", buf);
        anyhow::Ok(())
    };
    matches!(timeout(Duration::from_secs(5), attempt).await, Ok(Ok(())))
}

/// What each condition decides for each destination, through inbounds on
/// `ports`.
async fn decisions(ports: &[u16]) -> Vec<Vec<bool>> {
    let mut all = Vec::new();
    for &port in ports {
        let mut row = Vec::new();
        for destination in DESTINATIONS {
            row.push(allowed(port, destination).await);
        }
        all.push(row);
    }
    all
}

#[test]
#[ignore]
fn rules_decide_as_sing_box_decides() -> anyhow::Result<()> {
    let n = conditions().len();
    common::retry_port_clash(|| {
        let dir = common::TempDir::new("route-sing-box")?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (echo, server) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
        rt.spawn(server);
        let sail_ports: Vec<u16> = (0..n).map(|_| common::free_port()).collect();
        let sing_box_ports: Vec<u16> = (0..n).map(|_| common::free_port()).collect();

        let _sing_box =
            common::Daemon::sing_box(dir.path(), "route", config(&sing_box_ports, echo.port()))?;
        let ids =
            common::run_sail_instances(&rt, vec![config(&sail_ports, echo.port()).to_string()])?;
        let result = rt.block_on(async {
            let sail = decisions(&sail_ports).await;
            let sing_box = decisions(&sing_box_ports).await;
            let mut differences = Vec::new();
            for (i, condition) in conditions().iter().enumerate() {
                for (j, destination) in DESTINATIONS.iter().enumerate() {
                    if sail[i][j] != sing_box[i][j] {
                        differences.push(format!(
                            "{} to {}: sail {}, sing-box {}",
                            condition, destination, sail[i][j], sing_box[i][j]
                        ));
                    }
                }
            }
            anyhow::ensure!(
                differences.is_empty(),
                "{} decisions differ:\n{}",
                differences.len(),
                differences.join("\n")
            );
            // Neither lets everything through, nor nothing.
            let flat: Vec<bool> = sail.concat();
            anyhow::ensure!(flat.iter().any(|a| *a) && flat.iter().any(|a| !*a));
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}
