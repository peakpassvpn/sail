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
//!   rule-set fails and keeps what was taken;
//! - what a killed instance left (its ip rules, a throw route, the
//!   nftables table) goes when the next starts, even one with no TUN, and
//!   another's rule at one of its priorities stays.
#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};

/// sail's ip rules and nftables table, as tun/inbound.rs and
/// tun/auto_redirect.rs name them.
const RULE_PRIORITIES: std::ops::RangeInclusive<u32> = 9000..=9010;
/// The nftables table of the TUN `sadtun`, named after it.
const NFT_TABLE: &str = "sail_sadtun";

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

/// The tests share one namespace, its nftables table and its rules: one at
/// a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

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
    nft_table_named(NFT_TABLE)
}

fn nft_table_named(name: &str) -> Result<bool> {
    Ok(run("nft", "list tables")?
        .lines()
        .any(|line| line.split_whitespace().last() == Some(name)))
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

/// Whether TCP to `addr` is kept from the server. Redirected, a connection
/// is accepted by sail's listener before it is routed: one sail blocks is
/// closed without a word, not refused.
fn blocked(addr: &str) -> bool {
    !tcp(addr).is_some_and(|answer| answer.starts_with("peer="))
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
    /// Writes `config` to `dir` and starts sail on it, with `args` and its
    /// ledgers in `dir`/run.
    fn spawn(dir: &Path, config: &str, args: &[&str]) -> Result<Self> {
        let path = dir.join("config.json");
        std::fs::write(&path, config)?;
        let bin = PathBuf::from(std::env::var("SAIL_BIN").context("SAIL_BIN")?);
        let child = Command::new(bin)
            .arg("-c")
            .arg(&path)
            .arg("--run-dir")
            .arg(dir.join("run"))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self { child: Some(child) })
    }

    /// `spawn`, then waits for its nftables table.
    fn start(dir: &Path, config: &str, args: &[&str]) -> Result<Self> {
        let sail = Self::spawn(dir, config, args)?;
        ensure!(
            eventually(Duration::from_secs(10), nft_table)?,
            "sail did not set up auto_redirect"
        );
        // The default-interface follower and pre-match settle.
        std::thread::sleep(Duration::from_millis(1200));
        Ok(sail)
    }

    /// Kills sail, which leaves what it set up behind.
    fn crash(mut self) -> Result<()> {
        let mut child = self.child.take().context("running")?;
        child.kill()?;
        child.wait()?;
        Ok(())
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
    config_for(
        log,
        "sadtun",
        r#""172.31.233.1/30", "fdfe:233::1/126""#,
        true,
        more,
        route,
    )
}

/// A TUN called `tun` with `addresses`, auto_redirect or only auto_route.
fn config_for(
    log: &Path,
    tun: &str,
    addresses: &str,
    redirect: bool,
    more: &str,
    route: &str,
) -> String {
    format!(
        r#"{{
            "log": {{ "level": "debug", "output": "{log}" }},
            "inbounds": [{{
                "type": "tun", "tag": "tun-in", "interface_name": "{tun}",
                "address": [{addresses}],
                "auto_route": true, "auto_redirect": {redirect}{more}
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
    let _one = one_at_a_time();
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
        std::fs::read_to_string(&log)?
            .lines()
            .any(|line| line.contains("DNS is not set through systemd-resolved")),
        "sail says why it left the system's DNS alone"
    );

    ensure!(
        tcp(SERVER).as_deref() == Some(PEER4),
        "TCP is redirected through sail: {:?}",
        tcp(SERVER)
    );
    ensure!(
        blocked(BLOCKED),
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
        blocked(BLOCKED6),
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
        blocked(SERVER),
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
        blocked(SPARE) && tcp(SERVER).as_deref() == Some(PEER4),
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
    ensure!(blocked(SPARE), "a failed reload keeps what was taken");
    sail.stop()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The rules at `priorities`, of both families, as `ip rule` lists them.
fn rules_at(priorities: &[u32]) -> Result<Vec<String>> {
    let mut found = Vec::new();
    for family in ["", "-6"] {
        for line in run("ip", &format!("{} rule", family))?.lines() {
            let priority = line
                .split(':')
                .next()
                .and_then(|p| p.trim().parse::<u32>().ok());
            if priority.is_some_and(|p| priorities.contains(&p)) {
                found.push(format!("{} {}", family, line.trim()));
            }
        }
    }
    Ok(found)
}

#[test]
#[ignore = "needs root, in the namespace tests/scripts/auto_redirect_netns.sh builds"]
fn what_a_killed_instance_left_goes_at_the_next_start() -> Result<()> {
    let _one = one_at_a_time();
    ensure!(
        std::env::var_os("SAIL_BIN").is_some(),
        "run through tests/scripts/auto_redirect_netns.sh"
    );
    let dir = std::env::temp_dir().join(format!("sail-sweep-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let log = dir.join("sail.log");
    std::fs::write(&log, "")?;
    // Indexes of its own: the sweep undoes what the killed instance made,
    // not what the next one's configuration would.
    let more = r#", "iproute2_table_index": 2100, "iproute2_rule_index": 9100,
                  "auto_redirect_iproute2_fallback_rule_index": 32100,
                  "route_exclude_address": ["198.51.100.23/32"]"#;
    let sails: Vec<u32> = (9100..=9110).chain([32100]).collect();
    let route = r#"{ "final": "direct" }"#;
    Sail::start(&dir, &config(&log, more, route), &[])?.crash()?;
    let left = rules_at(&sails)?;
    ensure!(nft_table()?, "a kill leaves the nftables table");
    ensure!(!left.is_empty(), "and the ip rules");
    // Someone else's rule among sail's priorities, made since (a start
    // clears the priorities it takes, as sing-tun's does; a sweep removes
    // only what it wrote down).
    run("ip", "rule add priority 9105 lookup 3000")?;
    let neighbour = rules_at(&[9105])?;
    ensure!(
        run("ip", "route show table 2100 type throw")?.contains("198.51.100.23"),
        "and the throw route, which names no device"
    );

    // An instance with no TUN at all sweeps them.
    let plain = format!(
        r#"{{ "log": {{ "level": "debug", "output": "{}" }},
             "inbounds": [{{ "type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": 10800 }}],
             "outbounds": [{{ "type": "direct", "tag": "direct" }}] }}"#,
        log.display()
    );
    let sail = Sail::spawn(&dir, &plain, &[])?;
    ensure!(
        eventually(Duration::from_secs(10), || Ok(
            std::net::TcpStream::connect("127.0.0.1:10800").is_ok()
        ))?,
        "the plain instance did not start"
    );
    ensure!(!nft_table()?, "the next start removes the nftables table");
    ensure!(
        rules_at(&sails)? == neighbour,
        "and sail's rules, leaving the neighbour's: {:?}",
        rules_at(&sails)?
    );
    ensure!(
        run("ip", "route show table 2100")?.trim().is_empty(),
        "and the throw route"
    );
    ensure!(
        std::fs::read_dir(dir.join("run"))?.count() == 0,
        "and the ledger"
    );
    sail.stop()?;
    run("ip", "rule del priority 9105 lookup 3000")?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A configuration with no TUN: a SOCKS inbound on `port`.
fn plain(log: &Path, port: u16) -> String {
    format!(
        r#"{{ "log": {{ "level": "debug", "output": "{}" }},
             "inbounds": [{{ "type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": {port} }}],
             "outbounds": [{{ "type": "direct", "tag": "direct" }}] }}"#,
        log.display()
    )
}

/// Starts a plain instance in `dir` and waits for it to listen on `port`.
fn start_plain(dir: &Path, log: &Path, port: u16) -> Result<Sail> {
    let sail = Sail::spawn(dir, &plain(log, port), &[])?;
    ensure!(
        eventually(Duration::from_secs(10), || Ok(
            std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        ))?,
        "the plain instance did not start"
    );
    Ok(sail)
}

#[test]
#[ignore = "needs root, in the namespace tests/scripts/auto_redirect_netns.sh builds"]
fn a_sweep_leaves_another_live_instance_alone() -> Result<()> {
    let _one = one_at_a_time();
    ensure!(
        std::env::var_os("SAIL_BIN").is_some(),
        "run through tests/scripts/auto_redirect_netns.sh"
    );
    let base = std::env::temp_dir().join(format!("sail-two-{}", std::process::id()));
    // Two hosts' worth of run directories, configurations and logs.
    let (one, two) = (base.join("one"), base.join("two"));
    for dir in [&one, &two] {
        std::fs::create_dir_all(dir)?;
    }
    let (log_one, log_two) = (one.join("sail.log"), two.join("sail.log"));
    let route = r#"{ "final": "direct" }"#;

    // One: auto_redirect on sadtun, sail's default indexes.
    let first = Sail::start(&one, &config(&log_one, "", route), &[])?;
    let first_rules = rules_at(&(9000..=9010).chain([32768]).collect::<Vec<_>>())?;
    ensure!(!first_rules.is_empty(), "the first instance's rules");

    // Two: auto_route on sadtwo, indexes of its own, killed.
    let second = Sail::spawn(
        &two,
        &config_for(
            &log_two,
            "sadtwo",
            r#""172.31.234.1/30""#,
            false,
            r#", "iproute2_table_index": 2200, "iproute2_rule_index": 9200"#,
            route,
        ),
        &[],
    )?;
    let seconds: Vec<u32> = (9200..=9210).collect();
    ensure!(
        eventually(Duration::from_secs(10), || Ok(
            !rules_at(&seconds)?.is_empty()
        ))?,
        "the second instance did not route"
    );
    second.crash()?;
    ensure!(!rules_at(&seconds)?.is_empty(), "a kill leaves its rules");

    // The next start in the second's run directory sweeps the second's,
    // and nothing of the first's.
    let plain_two = start_plain(&two, &log_two, 10801)?;
    ensure!(rules_at(&seconds)?.is_empty(), "the killed one's rules go");
    ensure!(nft_table()?, "the live one keeps its table");
    ensure!(
        rules_at(&(9000..=9010).chain([32768]).collect::<Vec<_>>())? == first_rules,
        "and its rules"
    );
    ensure!(
        tcp(SERVER).as_deref() == Some(PEER4),
        "and carries traffic: {:?}",
        tcp(SERVER)
    );
    plain_two.stop()?;

    // A dead ledger naming the live one's TUN (its name taken again since)
    // waits: whoever holds the name holds what is named after it.
    let netns = std::fs::metadata("/proc/self/ns/net").map(|m| {
        use std::os::unix::fs::MetadataExt;
        m.ino()
    })?;
    let stale = two.join("run").join("1-1.json");
    std::fs::create_dir_all(two.join("run"))?;
    std::fs::write(
        &stale,
        format!(
            r#"{{"pid":1,"start":0,"instance":1,"netns":{netns},
                "items":[{{"tun":"sadtun"}},{{"nft_table":"{NFT_TABLE}"}}]}}"#
        ),
    )?;
    let plain_two = start_plain(&two, &log_two, 10801)?;
    ensure!(nft_table()?, "a ledger whose TUN is up takes nothing");
    ensure!(stale.exists(), "and waits");
    plain_two.stop()?;
    std::fs::remove_file(&stale)?;

    first.stop()?;
    ensure!(!nft_table()?, "a stop removes its own table");
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}
