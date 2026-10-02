//! auto_redirect on Linux, as root, inside the namespaces
//! tests/scripts/auto_redirect_netns.sh builds. sail runs as its binary, so
//! that it can be stopped as a host would stop it.
//!
//! Whether a connection went through sail is told, where it can be, by a
//! rule that blocks some addresses: one that reaches a blocked address went
//! past sail. Two things leave no such trace and are read from sail's log:
//! that a `bypass` connection never reached the dispatcher (pre-match let
//! it go), and that an address added to an interface joined the local set.
//!
//! Locks:
//! - TCP and UDP, IPv4 and IPv6, are redirected through sail;
//! - a `bypass` rule lets its connections go out unredirected, before the
//!   dispatcher sees them;
//! - the LAN goes past sail;
//! - an address added to an interface joins the local set;
//! - the host's DNS is left alone by sail in a namespace;
//! - a stop removes the nftables table and the ip rules, and traffic goes
//!   direct again;
//! - route_address_set takes its rule-set's addresses only, a reload that
//!   changes the rule-set changes what is taken, and a reload that drops the
//!   rule-set fails and keeps what was taken.
#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};

/// sail's ip rules and nftables table, as tun/inbound.rs and
/// tun/auto_redirect.rs name them.
const RULE_PRIORITIES: std::ops::RangeInclusive<u32> = 9000..=9010;
const NFT_TABLE: &str = "sail";

/// The plain server; one sail blocks; one a `bypass` rule lets go; one only
/// a rule-set names; their IPv6 kin; and one on the LAN, which sail blocks
/// too.
const SERVER: &str = "198.51.100.20";
const BYPASSED: &str = "198.51.100.21";
const BLOCKED: &str = "198.51.100.22";
const SPARE: &str = "198.51.100.23";
const SERVER6: &str = "2001:db8:53::10";
const BLOCKED6: &str = "2001:db8:53::11";
const LAN: &str = "10.233.0.3";
/// What the server sees as the peer, from the host's uplink.
const PEER4: &str = "peer=10.233.0.1";
const PEER6: &str = "peer=fd33::1";

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

/// Whether sail's nftables table is there.
fn nft_table() -> Result<bool> {
    Ok(run("nft", "list tables")?
        .lines()
        .any(|line| line.split_whitespace().last() == Some(NFT_TABLE)))
}

/// What the server at `addr` answers on TCP, if anything within 3 s.
fn tcp(addr: &str) -> Option<String> {
    use std::io::Read;
    let addr = if addr.contains(':') {
        format!("[{}]:8080", addr)
    } else {
        format!("{}:8080", addr)
    };
    let addr = addr.parse().ok()?;
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out.trim().to_string())
}

/// Whether the server at `addr` echoes a datagram within 3 s, from the
/// address it was sent to.
fn udp_echoes(addr: &str) -> bool {
    let echoed = || -> Result<bool> {
        let (bind, to) = if addr.contains(':') {
            ("[::]:0".to_string(), format!("[{}]:9999", addr))
        } else {
            ("0.0.0.0:0".to_string(), format!("{}:9999", addr))
        };
        let s = UdpSocket::bind(bind)?;
        s.connect(&to)?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        s.send(b"ping-udp")?;
        let mut buf = [0u8; 16];
        let n = s.recv(&mut buf)?;
        Ok(&buf[..n] == b"ping-udp")
    };
    echoed().unwrap_or(false)
}

/// The lines sail logged that name `needle`, but for pre-match's own.
fn dispatched(log: &Path, needle: &str) -> Result<usize> {
    Ok(std::fs::read_to_string(log)?
        .lines()
        .filter(|line| line.contains(needle))
        .filter(|line| !line.contains("pre-match") && !line.contains("prematch"))
        .count())
}

/// Polls `check` until it holds or `limit` passes.
fn eventually(limit: Duration, mut check: impl FnMut() -> Result<bool>) -> Result<bool> {
    let started = Instant::now();
    loop {
        if check()? {
            return Ok(true);
        }
        if started.elapsed() > limit {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Sail {
    child: Option<Child>,
}

impl Sail {
    /// Writes `config` to `dir` and starts sail on it, with `args`, and waits
    /// for its nftables table.
    fn start(dir: &Path, config: &str, args: &[&str]) -> Result<Self> {
        let path = dir.join("config.json");
        std::fs::write(&path, config)?;
        let bin = PathBuf::from(std::env::var("SAIL_BIN").context("SAIL_BIN")?);
        let child = Command::new(bin)
            .arg("-c")
            .arg(&path)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let sail = Self { child: Some(child) };
        ensure!(
            eventually(Duration::from_secs(10), nft_table)?,
            "sail did not set up auto_redirect"
        );
        // The default-interface follower and pre-match settle.
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
}

impl Drop for Sail {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A TUN with auto_redirect, logging to `log`, with `more` tun fields and
/// `route` as the route section.
fn config(log: &Path, more: &str, route: &str) -> String {
    format!(
        r#"{{
            "log": {{ "level": "debug", "output": "{log}" }},
            "inbounds": [{{
                "type": "tun", "tag": "tun-in", "interface_name": "sadtun",
                "address": ["172.31.233.1/30", "fdfe:233::1/126"],
                "auto_route": true, "auto_redirect": true{more}
            }}],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "block" }}
            ],
            "route": {route}
        }}"#,
        log = log.display()
    )
}

#[test]
#[ignore = "needs root, in the namespace tests/scripts/auto_redirect_netns.sh builds"]
fn auto_redirect_takes_the_host_s_traffic_and_gives_it_back() -> Result<()> {
    ensure!(
        std::env::var_os("SAIL_BIN").is_some(),
        "run through tests/scripts/auto_redirect_netns.sh"
    );
    let dir = std::env::temp_dir().join(format!("sail-auto-redirect-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let log = dir.join("sail.log");
    std::fs::write(&log, "")?;

    let route = format!(
        r#"{{
            "rules": [
                {{ "ip_cidr": ["{BYPASSED}/32"], "action": "bypass" }},
                {{ "ip_cidr": ["{BLOCKED}/32", "{BLOCKED6}/128", "{LAN}/32"],
                   "outbound": "block" }}
            ],
            "final": "direct"
        }}"#
    );
    // systemd-resolved serves the host, whose links are numbered as the
    // namespace's are not: the TUN is the namespace's index 2, as the
    // host's first interface is, and sail in a namespace must leave that
    // interface's DNS alone. Read from the host's namespace, where the
    // links' names are the host's.
    let host_dns = || run("nsenter", "--net=/proc/1/ns/net resolvectl dns").ok();
    let before = host_dns();
    let sail = Sail::start(&dir, &config(&log, "", &route), &[])?;
    ensure!(
        host_dns() == before,
        "sail in a namespace changed the host's DNS: {:?} then {:?}",
        before,
        host_dns()
    );

    ensure!(
        tcp(SERVER).as_deref() == Some(PEER4),
        "TCP is redirected through sail: {:?}",
        tcp(SERVER)
    );
    ensure!(
        tcp(BLOCKED).is_none(),
        "TCP goes through sail, whose rule blocks it"
    );
    ensure!(udp_echoes(SERVER), "UDP is redirected through sail");
    ensure!(
        !udp_echoes(BLOCKED),
        "UDP goes through sail, whose rule blocks it"
    );
    ensure!(
        tcp(SERVER6).as_deref() == Some(PEER6),
        "TCP over IPv6 is redirected through sail: {:?}",
        tcp(SERVER6)
    );
    ensure!(
        tcp(BLOCKED6).is_none(),
        "TCP over IPv6 goes through sail, whose rule blocks it"
    );
    ensure!(
        tcp(LAN).as_deref() == Some(PEER4),
        "the LAN goes past sail: {:?}",
        tcp(LAN)
    );

    // bypass: out, and never in front of the dispatcher.
    ensure!(
        tcp(BYPASSED).as_deref() == Some(PEER4),
        "a bypass rule's TCP reaches its server: {:?}",
        tcp(BYPASSED)
    );
    ensure!(udp_echoes(BYPASSED), "a bypass rule's UDP is echoed");
    std::thread::sleep(Duration::from_millis(300));
    ensure!(
        dispatched(&log, &format!("{BYPASSED}:"))? == 0,
        "a bypass rule's connections never reach the dispatcher"
    );

    // An address added to an interface joins the local set.
    run("ip", "addr add 192.0.2.1/24 dev sad-ha")?;
    let joined = eventually(Duration::from_secs(3), || {
        Ok(std::fs::read_to_string(&log)?
            .lines()
            .any(|line| line.contains("local addresses now") && line.contains("192.0.2.0")))
    })?;
    run("ip", "addr del 192.0.2.1/24 dev sad-ha")?;
    ensure!(joined, "an added address joins the local set");

    sail.stop()?;
    ensure!(!nft_table()?, "a stop removes the nftables table");
    ensure!(
        sail_rules("")?.is_empty() && sail_rules("-6")?.is_empty(),
        "a stop removes the ip rules: {:?} {:?}",
        sail_rules("")?,
        sail_rules("-6")?
    );
    ensure!(
        tcp(BLOCKED).as_deref() == Some(PEER4),
        "after a stop, traffic goes direct"
    );

    // route_address_set: only its rule-set's addresses are taken. Both
    // candidates are blocked, so one that is taken does not answer.
    let reloading = |taken: Option<&str>| {
        let rule_set = taken.map_or(String::new(), |address| {
            format!(
                r#"{{ "type": "inline", "tag": "taken", "rules": [{{ "ip_cidr": ["{address}/32"] }}] }}"#
            )
        });
        config(
            &log,
            r#", "route_address_set": ["taken"]"#,
            &format!(
                r#"{{
                    "rule_set": [{rule_set}],
                    "rules": [{{ "ip_cidr": ["{SERVER}/32", "{SPARE}/32"], "outbound": "block" }}],
                    "final": "direct"
                }}"#
            ),
        )
    };
    let reloads = || -> Result<usize> {
        Ok(std::fs::read_to_string(&log)?
            .lines()
            .filter(|line| line.contains("reloaded from config file"))
            .count())
    };
    let sail = Sail::start(&dir, &reloading(Some(SERVER)), &["--auto-reload"])?;
    ensure!(
        tcp(SERVER).is_none(),
        "route_address_set takes its rule-set's addresses"
    );
    ensure!(
        tcp(SPARE).as_deref() == Some(PEER4),
        "route_address_set leaves the others"
    );

    let before = reloads()?;
    std::fs::write(dir.join("config.json"), reloading(Some(SPARE)))?;
    ensure!(
        eventually(Duration::from_secs(5), || Ok(reloads()? > before))?,
        "the reload happened"
    );
    std::thread::sleep(Duration::from_millis(500));
    ensure!(
        tcp(SPARE).is_none() && tcp(SERVER).as_deref() == Some(PEER4),
        "after a reload, the new rule-set's addresses are taken and the old ones are not"
    );

    // A reload without the rule-set the TUN names fails, and changes
    // nothing.
    let before = reloads()?;
    std::fs::write(dir.join("config.json"), reloading(None))?;
    // runtime/watch.rs logs a reload that fails with this.
    let failed = eventually(Duration::from_secs(5), || {
        Ok(std::fs::read_to_string(&log)?
            .lines()
            .any(|line| line.contains("reload failed")))
    })?;
    ensure!(failed, "a reload without the rule-set fails");
    ensure!(reloads()? == before, "and is not applied");
    ensure!(tcp(SPARE).is_none(), "a failed reload keeps what was taken");
    sail.stop()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
