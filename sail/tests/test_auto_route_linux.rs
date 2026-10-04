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
//! - with a TUN taking the default route, a DNS server without a detour,
//!   `local` (which asks the servers of resolv.conf), `udp`, `tcp` or `tls`
//!   (whose connections DoH makes as well), sends its queries out of the
//!   uplink too, not into the TUN, where `hijack-dns`
//!   would hand them back to it in a loop.
//!
//! The script also checks, in the host's namespace, that the host's DNS
//! settings are as they were: resolved is the host's, and sail in a
//! namespace once set the host's eth0's servers by the namespace's
//! interface numbers.
#![cfg(target_os = "linux")]
// Tests drive tasks of their own.
#![allow(clippy::disallowed_methods)]

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
/// The DNS server the host's resolv.conf names, which answers every name
/// with SERVER.
const DNS: &str = "198.51.100.53";
/// sail's mixed inbound, in the host's namespace.
const PROXY: &str = "127.0.0.1:1080";
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

/// What the server answers on TCP for the name `name`, connected to
/// through sail's SOCKS5 inbound, which resolves the name; nothing within
/// 12 s, more than a DNS query's time, if it cannot.
fn tcp_by_name(name: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut s =
        std::net::TcpStream::connect_timeout(&PROXY.parse().ok()?, Duration::from_secs(3)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(12))).ok()?;
    s.write_all(&[5, 1, 0]).ok()?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).ok()?;
    let mut connect = vec![5, 1, 0, 3, name.len() as u8];
    connect.extend_from_slice(name.as_bytes());
    connect.extend_from_slice(&8080u16.to_be_bytes());
    s.write_all(&connect).ok()?;
    let mut reply = [0u8; 4];
    s.read_exact(&mut reply).ok()?;
    if reply[1] != 0 {
        return None;
    }
    let bound = match reply[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        _ => return None,
    };
    s.read_exact(&mut vec![0u8; bound]).ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out.trim().to_string())
}

struct Sail {
    child: Option<Child>,
}

impl Sail {
    /// Starts sail with `more` tun fields, and waits for its rules.
    fn start(dir: &std::path::Path, more: &str) -> Result<Self> {
        Self::start_config(
            dir,
            &format!(
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
        )
    }

    /// Starts sail with the TUN, a mixed inbound on PROXY, the DNS server
    /// `server` as the default domain resolver, and a rule that blocks DNS:
    /// a query that enters the TUN goes nowhere.
    fn start_dns(dir: &std::path::Path, server: &str) -> Result<Self> {
        Self::start_config(
            dir,
            &format!(
                r#"{{
                    "inbounds": [
                        {{
                            "type": "tun", "tag": "tun-in", "interface_name": "sartun",
                            "address": ["172.31.241.1/30"],
                            "auto_route": true, "strict_route": true
                        }},
                        {{ "type": "mixed", "tag": "mixed", "listen": "127.0.0.1",
                           "listen_port": 1080 }}
                    ],
                    "outbounds": [
                        {{ "type": "direct", "tag": "direct" }},
                        {{ "type": "block", "tag": "block" }}
                    ],
                    "dns": {{ "servers": [{server}] }},
                    "route": {{
                        "rules": [{{ "ip_cidr": ["{DNS}/32"], "outbound": "block" }}],
                        "final": "direct",
                        "default_domain_resolver": "resolver"
                    }}
                }}"#
            ),
        )
    }

    /// Starts sail with `config`, and waits for its rules.
    fn start_config(dir: &std::path::Path, config_text: &str) -> Result<Self> {
        let config = dir.join("config.json");
        std::fs::write(&config, config_text)?;
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

#[test]
#[ignore = "needs root, in the namespace tests/scripts/auto_route_netns.sh builds"]
fn dns_servers_without_a_detour_go_out_of_the_uplink() -> Result<()> {
    ensure!(
        std::env::var_os("SAIL_BIN").is_some(),
        "run through tests/scripts/auto_route_netns.sh"
    );
    let dir = std::env::temp_dir().join(format!("sail-auto-route-dns-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    for server in [
        r#"{ "type": "local", "tag": "resolver" }"#.to_string(),
        format!(r#"{{ "type": "udp", "tag": "resolver", "server": "{DNS}" }}"#),
        format!(r#"{{ "type": "tcp", "tag": "resolver", "server": "{DNS}" }}"#),
        format!(
            r#"{{ "type": "tls", "tag": "resolver", "server": "{DNS}",
                  "tls": {{ "server_name": "dns.test", "insecure": true }} }}"#
        ),
    ] {
        let sail = Sail::start_dns(&dir, &server)?;
        let answered = tcp_by_name("server.test");
        sail.stop()?;
        ensure!(
            answered.as_deref() == Some(FIRST_UPLINK),
            "{}: the name resolved past the TUN, and the connection went out \
             of the first uplink: {:?}",
            server,
            answered
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// What the host does when it is told the outbounds are built, while the
/// instance starts and before the TUN is opened: opens UDP to `to` through
/// the direct outbound, and notes whether the TUN was there.
struct DialsAsItStarts {
    to: std::net::SocketAddr,
    dialled: std::sync::Mutex<Option<(bool, Result<sail::control::Dialed, String>)>>,
}

impl sail::runtime::Platform for DialsAsItStarts {
    fn log(&self, _line: &str) {}

    fn dialable(&self, dialer: &sail::control::Dialer) {
        let tun_was_up = run("ip", "link show sartun").is_ok();
        let dialled = dialer
            .handle()
            .block_on(dialer.env().scope.enter(dialer.dial(
                "direct",
                sail::session::Network::Udp,
                sail::session::SocksAddr::from(self.to),
                Duration::from_secs(5),
            )))
            .map_err(|e| e.to_string());
        *self.dialled.lock().unwrap() = Some((tun_was_up, dialled));
    }
}

/// A direct dial a host makes while the instance starts, before the TUN is
/// opened and routed, stays out of the TUN once it is: its socket is bound
/// to the uplink when it is dialled, and the rules auto_route adds later
/// leave it there. It reaches an address the rules block, which what goes
/// through the TUN does not.
#[test]
#[ignore = "needs root, in the namespace tests/scripts/auto_route_netns.sh builds"]
fn a_dial_made_while_it_starts_stays_out_of_the_tun() -> Result<()> {
    use sail::embed::{Config, Instance, Options};
    use sail::session::SocksAddr;

    let to: std::net::SocketAddr = format!("{}:9999", BLOCKED).parse()?;
    let host = std::sync::Arc::new(DialsAsItStarts {
        to,
        dialled: Default::default(),
    });
    let config = format!(
        r#"{{
            "inbounds": [{{
                "type": "tun", "tag": "tun-in", "interface_name": "sartun",
                "address": ["172.31.241.1/30"],
                "auto_route": true, "strict_route": true
            }}],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "block" }}
            ],
            "route": {{
                "rules": [{{ "ip_cidr": ["{BLOCKED}/32"], "outbound": "block" }}],
                "final": "direct"
            }}
        }}"#
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async {
        let instance = Instance::new(Options::new().platform(host.clone()))
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        instance
            .start(Config::Json(config))
            .await
            .map_err(|e| anyhow::anyhow!("start: {}", e))?;
        let checked = async {
            let (tun_was_up, dialled) = host
                .dialled
                .lock()
                .unwrap()
                .take()
                .context("the host was told the outbounds were built")?;
            ensure!(
                !tun_was_up,
                "the TUN was open before the outbounds were dialable"
            );
            let sail::control::Dialed::Datagram(datagram) =
                dialled.map_err(|e| anyhow::anyhow!("the dial while it started: {}", e))?
            else {
                anyhow::bail!("a UDP dial gives datagrams");
            };
            // The TUN is up and takes the host's traffic: what goes through
            // it to the blocked address goes nowhere.
            ensure!(run("ip", "link show sartun").is_ok(), "the TUN is up");
            ensure!(
                run("ip", &format!("route show table {}", TABLE))?.contains("sartun"),
                "its routes are in place"
            );
            ensure!(
                !udp_echoes(BLOCKED),
                "the blocked address was reached through the TUN"
            );
            // The socket dialled before goes out of the uplink still.
            let (mut recv, mut send) = datagram.split();
            send.send_to(b"ping-udp", &SocksAddr::from(to)).await?;
            let mut buf = [0u8; 16];
            let (n, _) = tokio::time::timeout(Duration::from_secs(3), recv.recv_from(&mut buf))
                .await
                .context(
                    "no answer on the socket dialled while it started: it went into the TUN",
                )??;
            ensure!(&buf[..n] == b"ping-udp", "echoed");
            Ok(())
        };
        let result = checked.await;
        // Whatever was found, what it set up on the system goes.
        let stopped = instance.stop().await;
        result?;
        stopped.map_err(|e| anyhow::anyhow!("stop: {}", e))
    })
}

/// What the server at `addr` answers on TCP to a connection made through
/// the SOCKS5 inbound on `proxy`, if anything within 3 s: the address it
/// sees the connection come from.
fn tcp_through(proxy: u16, addr: &str) -> Option<String> {
    use std::io::{Read, Write};
    let to: std::net::Ipv4Addr = addr.parse().ok()?;
    let mut s = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], proxy)),
        Duration::from_secs(3),
    )
    .ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    s.write_all(&[5, 1, 0]).ok()?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).ok()?;
    let mut connect = vec![5, 1, 0, 1];
    connect.extend(to.octets());
    connect.extend(8080u16.to_be_bytes());
    s.write_all(&connect).ok()?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).ok()?;
    if reply[1] != 0 {
        return None;
    }
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out.trim().to_string())
}

/// The packets `interface` has sent.
fn sent(interface: &str) -> Result<u64> {
    Ok(std::fs::read_to_string(format!(
        "/sys/class/net/{}/statistics/tx_packets",
        interface
    ))?
    .trim()
    .parse()?)
}

/// A reload that changes the interface dials go out of, or their mark,
/// reaches the connections made after it, with no restart; what was
/// dialled before keeps the socket it has.
#[test]
#[ignore = "needs root, in the namespace tests/scripts/auto_route_netns.sh builds"]
fn a_reload_s_interface_and_mark_reach_the_connections_made_after() -> Result<()> {
    use sail::embed::{Address, Config, Instance, Options, ReloadPath};

    const SOCKS: u16 = 1081;
    const MARK: u32 = 0x66;
    const TABLE_OF_MARK: &str = "266";
    let config = |route: &str| {
        Config::Json(format!(
            r#"{{
                "inbounds": [{{ "type": "socks", "tag": "socks",
                                "listen": "127.0.0.1", "listen_port": {SOCKS} }}],
                "outbounds": [{{ "type": "direct", "tag": "direct" }}],
                "route": {{ {route} "final": "direct" }}
            }}"#
        ))
    };
    // A way out of the second uplink for what is bound to it, and for what
    // carries the mark: the default route stays the first uplink's.
    run(
        "ip",
        "route add default via 10.242.0.2 dev sar-rb metric 500",
    )?;
    run(
        "ip",
        &format!(
            "route add default via 10.242.0.2 dev sar-rb table {}",
            TABLE_OF_MARK
        ),
    )?;
    run(
        "ip",
        &format!(
            "rule add fwmark {} lookup {} priority 8000",
            MARK, TABLE_OF_MARK
        ),
    )?;
    let undo = || {
        let _ = run(
            "ip",
            &format!(
                "rule del fwmark {} lookup {} priority 8000",
                MARK, TABLE_OF_MARK
            ),
        );
        let _ = run("ip", &format!("route flush table {}", TABLE_OF_MARK));
        let _ = run(
            "ip",
            "route del default via 10.242.0.2 dev sar-rb metric 500",
        );
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let failed = |what: &str, e: sail::embed::Error| anyhow::anyhow!("{}: {}", what, e);
        let instance = Instance::new(Options::new()).map_err(|e| failed("new", e))?;
        instance
            .start(config(r#""default_interface": "sar-ra","#))
            .await
            .map_err(|e| failed("start", e))?;
        let checked = async {
            ensure!(
                tcp_through(SOCKS, SERVER).as_deref() == Some(FIRST_UPLINK),
                "bound to the first uplink, it goes out of it"
            );
            // Dialled before the reload: UDP through the direct outbound,
            // its socket bound to the first uplink.
            let to: std::net::SocketAddr = format!("{}:9999", SERVER).parse()?;
            let held = instance
                .dial_udp("direct", Address::from(to), Duration::from_secs(5))
                .await
                .map_err(|e| failed("dial", e))?;
            let mut buf = [0u8; 16];
            held.send(b"before").await?;
            tokio::time::timeout(Duration::from_secs(3), held.recv_from(&mut buf))
                .await
                .context("no echo before the reload")??;

            // The interface changes: connections made after go out of the
            // second uplink.
            let report = instance
                .reload(Some(config(r#""default_interface": "sar-rb","#)))
                .await
                .map_err(|e| failed("reload to the second uplink", e))?;
            ensure!(report.path == ReloadPath::Full, "{:?}", report);
            ensure!(
                tcp_through(SOCKS, SERVER).as_deref() == Some(SECOND_UPLINK),
                "after the reload a new connection goes out of the second uplink"
            );
            // What was dialled before keeps its socket: its datagrams
            // still leave by the first uplink, and come back.
            let (first, second) = (sent("sar-ra")?, sent("sar-rb")?);
            for _ in 0..5 {
                held.send(b"after!").await?;
                tokio::time::timeout(Duration::from_secs(3), held.recv_from(&mut buf))
                    .await
                    .context("no echo on the socket dialled before the reload")??;
            }
            ensure!(
                sent("sar-ra")? >= first + 5,
                "the datagrams of the socket dialled before did not leave by the first uplink"
            );
            ensure!(
                sent("sar-rb")? < second + 5,
                "the socket dialled before moved to the second uplink"
            );

            // No interface, a mark: the rule for it sends what carries it
            // out of the second uplink; without it, the default route's.
            let report = instance
                .reload(Some(config(&format!(r#""default_mark": {},"#, MARK))))
                .await
                .map_err(|e| failed("reload to the mark", e))?;
            ensure!(report.path == ReloadPath::Full, "{:?}", report);
            ensure!(
                tcp_through(SOCKS, SERVER).as_deref() == Some(SECOND_UPLINK),
                "a new connection carries the mark the reload set"
            );
            instance
                .reload(Some(config("")))
                .await
                .map_err(|e| failed("reload to no mark", e))?;
            ensure!(
                tcp_through(SOCKS, SERVER).as_deref() == Some(FIRST_UPLINK),
                "with the mark gone, a new connection goes by the default route"
            );

            // An interface there is none of: refused, what runs runs on.
            let refused = instance
                .reload(Some(config(r#""default_interface": "sar-none","#)))
                .await;
            ensure!(refused.is_err(), "an interface that is not there was taken");
            ensure!(
                tcp_through(SOCKS, SERVER).as_deref() == Some(FIRST_UPLINK),
                "a refused reload changed where connections go out"
            );
            Ok(())
        };
        let result = checked.await;
        let stopped = instance.stop().await;
        result?;
        stopped.map_err(|e| failed("stop", e))
    });
    undo();
    result
}
