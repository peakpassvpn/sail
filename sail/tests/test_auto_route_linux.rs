//! auto_route and strict_route on Linux, without auto_redirect, as root,
//! inside the namespaces tests/scripts/auto_route_netns.sh builds. sail
//! runs as its binary, so that it can be stopped and killed as a host
//! would.
//!
//! Whether a connection went through sail is told by a rule that blocks
//! some addresses: one that reaches a blocked address went past sail.
//!
//! Locks:
//! - the TUN takes TCP and UDP, and sail's own connections go out of the
//!   uplink (auto_detect_interface is implied, or they would loop);
//! - the main table's own routes (the LAN) and route_exclude_address go
//!   past sail;
//! - strict_route makes the IPv6 the TUN does not carry unreachable;
//! - sail follows the default route to the other uplink;
//! - a stop removes the rules and empties the table, and traffic goes
//!   direct again;
//! - a crash leaves rules that route nothing, and the next start replaces
//!   them.
//!
//! The script also checks, in the host's namespace, that the host's DNS
//! settings are as they were: resolved is the host's, and sail in a
//! namespace once set the host's eth0's servers by the namespace's
//! interface numbers.
#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};

/// What sail's rules and table are, as tun/inbound.rs numbers them.
const TABLE: &str = "2022";
const RULE_PRIORITIES: std::ops::RangeInclusive<u32> = 9000..=9010;

/// The plain server; one sail leaves out; one sail blocks; one on the LAN,
/// which sail blocks too.
const SERVER: &str = "198.51.100.10";
const EXCLUDED: &str = "198.51.100.11";
const BLOCKED: &str = "198.51.100.12";
const LAN: &str = "10.241.0.3";
/// What the server sees as the peer through each uplink.
const FIRST_UPLINK: &str = "peer=10.241.0.1";
const SECOND_UPLINK: &str = "peer=10.242.0.1";

fn run(program: &str, args: &str) -> Result<String> {
    let out = Command::new(program)
        .args(args.split_whitespace())
        .output()
        .with_context(|| format!("{} {}", program, args))?;
    ensure!(
        out.status.success(),
        "{} {}: {}",
        program,
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// sail's policy rules, as `ip rule` (or `ip -6 rule`) lists them.
fn sail_rules(family: &str) -> Result<Vec<String>> {
    Ok(run("ip", &format!("{} rule", family))?
        .lines()
        .filter(|line| {
            line.split(':')
                .next()
                .and_then(|p| p.trim().parse::<u32>().ok())
                .is_some_and(|p| RULE_PRIORITIES.contains(&p))
        })
        .map(str::to_string)
        .collect())
}

/// What the server at `addr` answers on TCP, if anything within 3 s.
fn tcp(addr: &str) -> Option<String> {
    use std::io::Read;
    let addr = format!("{}:8080", addr).parse().ok()?;
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out.trim().to_string())
}

/// Whether the server at `addr` echoes a datagram within 3 s.
fn udp_echoes(addr: &str) -> bool {
    let echoed = || -> Result<bool> {
        let s = UdpSocket::bind("0.0.0.0:0")?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        s.send_to(b"ping-udp", format!("{}:9999", addr))?;
        let mut buf = [0u8; 16];
        let (n, _) = s.recv_from(&mut buf)?;
        Ok(&buf[..n] == b"ping-udp")
    };
    echoed().unwrap_or(false)
}

struct Sail {
    child: Option<Child>,
}

impl Sail {
    /// Starts sail with `more` tun fields, and waits for its rules.
    fn start(dir: &std::path::Path, more: &str) -> Result<Self> {
        let config = dir.join("config.json");
        std::fs::write(
            &config,
            format!(
                r#"{{
                    "inbounds": [{{
                        "type": "tun", "tag": "tun-in", "interface_name": "sartun",
                        "address": ["172.31.241.1/30"],
                        "auto_route": true, "strict_route": true{more}
                    }}],
                    "outbounds": [
                        {{ "type": "direct", "tag": "direct" }},
                        {{ "type": "block", "tag": "block" }}
                    ],
                    "route": {{
                        "rules": [{{ "ip_cidr": ["{BLOCKED}/32", "{LAN}/32", "{EXCLUDED}/32"],
                                     "outbound": "block" }}],
                        "final": "direct"
                    }}
                }}"#
            ),
        )?;
        let bin = PathBuf::from(std::env::var("SAIL_BIN").context("SAIL_BIN")?);
        let child = Command::new(bin)
            .arg("-c")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let sail = Self { child: Some(child) };
        let started = Instant::now();
        while run("ip", "link show sartun").is_err()
            || !run("ip", &format!("route show table {}", TABLE))?.contains("sartun")
        {
            ensure!(
                started.elapsed() < Duration::from_secs(10),
                "sail did not set up its routes"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // The default-interface follower settles within 1 s.
        std::thread::sleep(Duration::from_millis(1200));
        Ok(sail)
    }

    /// Stops sail as a service manager would, and waits for it.
    fn stop(mut self) -> Result<()> {
        let mut child = self.child.take().context("running")?;
        run("kill", &format!("-TERM {}", child.id()))?;
        child.wait()?;
        Ok(())
    }

    /// Kills sail, which leaves what it set up behind.
    fn crash(mut self) -> Result<()> {
        let mut child = self.child.take().context("running")?;
        child.kill()?;
        child.wait()?;
        Ok(())
    }
}

impl Drop for Sail {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
#[ignore = "needs root, in the namespace tests/scripts/auto_route_netns.sh builds"]
fn auto_route_takes_the_host_s_traffic_and_gives_it_back() -> Result<()> {
    ensure!(
        std::env::var_os("SAIL_BIN").is_some(),
        "run through tests/scripts/auto_route_netns.sh"
    );
    let dir = std::env::temp_dir().join(format!("sail-auto-route-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;

    let sail = Sail::start(&dir, "")?;
    ensure!(
        tcp(SERVER).as_deref() == Some(FIRST_UPLINK),
        "TCP through sail and out of the first uplink: {:?}",
        tcp(SERVER)
    );
    ensure!(
        tcp(BLOCKED).is_none(),
        "TCP goes through sail, whose rule blocks it"
    );
    ensure!(udp_echoes(SERVER), "UDP through sail");
    ensure!(
        !udp_echoes(BLOCKED),
        "UDP goes through sail, whose rule blocks it"
    );
    ensure!(
        tcp(LAN).as_deref() == Some(FIRST_UPLINK),
        "the LAN goes past sail: {:?}",
        tcp(LAN)
    );
    ensure!(
        sail_rules("-6")?.iter().any(|r| r.contains("unreachable")),
        "strict_route makes the IPv6 the TUN does not carry unreachable: {:?}",
        sail_rules("-6")?
    );

    // The default route moves to the second uplink, and sail follows.
    run("ip", "route replace default via 10.242.0.2 dev sar-rb")?;
    std::thread::sleep(Duration::from_millis(1500));
    let after = tcp(SERVER);
    run("ip", "route replace default via 10.241.0.2 dev sar-ra")?;
    std::thread::sleep(Duration::from_millis(1500));
    ensure!(
        after.as_deref() == Some(SECOND_UPLINK),
        "sail follows the default route: {:?}",
        after
    );

    sail.stop()?;
    ensure!(
        sail_rules("")?.is_empty(),
        "a stop removes the rules: {:?}",
        sail_rules("")?
    );
    ensure!(
        run("ip", &format!("route show table {}", TABLE))?
            .trim()
            .is_empty(),
        "a stop empties the table"
    );
    ensure!(tcp(BLOCKED).is_some(), "and traffic goes direct");

    // From here, one address is left out of the TUN.
    let more = format!(r#", "route_exclude_address": ["{EXCLUDED}/32"]"#);
    Sail::start(&dir, &more)?.crash()?;
    let left = sail_rules("")?;
    ensure!(!left.is_empty(), "a crash leaves the rules");
    ensure!(
        tcp(BLOCKED).is_some(),
        "they route nothing, and traffic goes direct"
    );
    let sail = Sail::start(&dir, &more)?;
    let replaced = sail_rules("")?;
    ensure!(
        replaced.len() == left.len(),
        "a restart replaces what the crash left: {:?} then {:?}",
        left,
        replaced
    );
    ensure!(tcp(BLOCKED).is_none(), "and routes again");
    ensure!(
        tcp(EXCLUDED).as_deref() == Some(FIRST_UPLINK),
        "route_exclude_address goes past sail: {:?}",
        tcp(EXCLUDED)
    );
    sail.stop()?;

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
