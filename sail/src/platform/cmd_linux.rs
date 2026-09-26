use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};

use super::{output, run, sysctl_flag};

/// Runs `ip` for something that may already be undone -- a route that went
/// away with its device, say -- where the failure is not worth a word.
fn ip_quiet(args: &[&str]) {
    let _ = Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Flags `ip route` prints that it does not take back.
const PRINTED_ONLY: &[&str] = &[
    "linkdown",
    "dead",
    "offload",
    "rt_offload",
    "trap",
    "pervasive",
];

/// The main table's default routes, as `ip route` prints them, so that they
/// can be put back exactly -- gateway, device, protocol, source, metric --
/// after the TUN has taken the default route.
pub fn get_default_routes(v6: bool) -> Result<Vec<String>> {
    let family = if v6 { "-6" } else { "-4" };
    let out = Command::new("ip")
        .args([family, "route", "show", "table", "main", "default"])
        .output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "ip route show: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("default"))
        .map(String::from)
        .collect())
}

/// Puts back the routes `get_default_routes` read.
pub fn restore_default_routes(v6: bool, routes: &[String]) -> Result<()> {
    let family = if v6 { "-6" } else { "-4" };
    for route in routes {
        let mut args = vec![family, "route", "replace"];
        let mut words = route.split_whitespace();
        while let Some(word) = words.next() {
            match word {
                w if PRINTED_ONLY.contains(&w) => {}
                // A lifetime counting down when it was read.
                "expires" => {
                    words.next();
                }
                w => args.push(w),
            }
        }
        args.extend(["table", "main"]);
        let status = Command::new("ip").args(&args).status()?;
        if !status.success() {
            return Err(anyhow!("could not restore the route \"{}\"", route));
        }
    }
    Ok(())
}

/// The word after `key` in what `ip route get` prints for the route to
/// `dst` through a gateway: "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.2".
fn route_get(v6: bool, dst: &str, key: &str) -> Result<String> {
    let family = if v6 { "-6" } else { "-4" };
    let out = output(Command::new("ip").args([family, "route", "get", dst]))?;
    let line = out
        .lines()
        .find(|l| l.split_whitespace().any(|w| w == "via"))
        .ok_or_else(|| anyhow!("ip route get {}: no gateway", dst))?;
    let mut words = line.split_whitespace();
    words
        .by_ref()
        .find(|w| *w == key)
        .and_then(|_| words.next())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("ip route get {}: no {}", dst, key))
}

pub fn get_default_ipv4_gateway() -> Result<String> {
    route_get(false, "1", "via")
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    route_get(true, "::2", "via")
}

pub fn get_default_ipv4_address() -> Result<String> {
    route_get(false, "1", "src")
}

pub fn get_default_ipv6_address() -> Result<String> {
    route_get(true, "::2", "src")
}

pub fn get_default_interface() -> Result<String> {
    route_get(false, "1", "dev")
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    _gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    // `replace`: creating the device may have assigned it already.
    run(Command::new("ip")
        .args(["addr", "replace"])
        .arg(format!("{}/{}", addr, mask))
        .arg("dev")
        .arg(name))
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    run(Command::new("ip")
        .args(["-6", "addr", "replace"])
        .arg(format!("{}/{}", addr, prefixlen))
        .arg("dev")
        .arg(name))
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    let mut cmd = Command::new("ip");
    cmd.args(["route", "add", "default", "via"])
        .arg(gateway.to_string());
    if primary {
        cmd.args(["table", "main"]);
    } else {
        cmd.arg("dev").arg(interface).args(["table", "default"]);
    }
    run(&mut cmd)
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> {
    let table = if primary { "main" } else { "default" };
    run(Command::new("ip")
        .args(["-6", "route", "add", "default", "via"])
        .arg(gateway.to_string())
        .arg("dev")
        .arg(interface)
        .args(["table", table]))
}

pub fn delete_default_ipv4_route(ifscope: Option<String>) -> Result<()> {
    let table = if ifscope.is_some() { "default" } else { "main" };
    ip_quiet(&["route", "del", "default", "table", table]);
    Ok(())
}

pub fn delete_default_ipv6_route(ifscope: Option<String>) -> Result<()> {
    let table = if ifscope.is_some() { "default" } else { "main" };
    ip_quiet(&["-6", "route", "del", "default", "table", table]);
    Ok(())
}

pub fn add_default_ipv4_rule(addr: Ipv4Addr) -> Result<()> {
    run(Command::new("ip")
        .args(["rule", "add", "from"])
        .arg(addr.to_string())
        .args(["table", "default"]))
}

pub fn add_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    run(Command::new("ip")
        .args(["-6", "rule", "add", "from"])
        .arg(addr.to_string())
        .args(["table", "default"]))
}

pub fn delete_default_ipv4_rule(addr: Ipv4Addr) -> Result<()> {
    ip_quiet(&["rule", "del", "from", &addr.to_string(), "table", "default"]);
    Ok(())
}

pub fn delete_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    ip_quiet(&[
        "-6",
        "rule",
        "del",
        "from",
        &addr.to_string(),
        "table",
        "default",
    ]);
    Ok(())
}

pub fn get_ipv4_forwarding() -> Result<bool> {
    sysctl_flag("net.ipv4.ip_forward")
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    sysctl_flag("net.ipv6.conf.all.forwarding")
}

pub fn set_ipv4_forwarding(val: bool) -> Result<()> {
    run(Command::new("sysctl").arg("-w").arg(format!(
        "net.ipv4.ip_forward={}",
        if val { "1" } else { "0" }
    )))
}

pub fn set_ipv6_forwarding(val: bool) -> Result<()> {
    run(Command::new("sysctl").arg("-w").arg(format!(
        "net.ipv6.conf.all.forwarding={}",
        if val { "1" } else { "0" }
    )))
}

pub fn add_iptable_forward(interface: &str) -> Result<()> {
    run(Command::new("iptables").args(["-I", "FORWARD", "-o", interface, "-j", "ACCEPT"]))
}

pub fn delete_iptable_forward(interface: &str) -> Result<()> {
    run(Command::new("iptables").args(["-D", "FORWARD", "-o", interface, "-j", "ACCEPT"]))
}
