use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};

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

pub fn get_default_ipv4_gateway() -> Result<String> {
    let out = Command::new("ip")
        .arg("route")
        .arg("get")
        .arg("1")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .find(|l| l.contains("via"))
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 3);
    let res = cols[2].to_string();
    Ok(res)
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    let out = Command::new("ip")
        .arg("-6")
        .arg("route")
        .arg("get")
        .arg("::2")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .find(|l| l.contains("via"))
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 5);
    let res = cols[4].to_string();
    Ok(res)
}

pub fn get_default_ipv4_address() -> Result<String> {
    let out = Command::new("ip")
        .arg("route")
        .arg("get")
        .arg("1")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .find(|l| l.contains("via"))
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 7);
    let res = cols[6].to_string();
    Ok(res)
}

pub fn get_default_ipv6_address() -> Result<String> {
    let out = Command::new("ip")
        .arg("-6")
        .arg("route")
        .arg("get")
        .arg("::2")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .find(|l| l.contains("via"))
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 11);
    let res = cols[10].to_string();
    Ok(res)
}

pub fn get_default_interface() -> Result<String> {
    let out = Command::new("ip")
        .arg("route")
        .arg("get")
        .arg("1")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .find(|l| l.contains("via"))
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 5);
    let res = cols[4].to_string();
    Ok(res)
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    _gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    // `replace`: creating the device may have assigned it already.
    Command::new("ip")
        .arg("addr")
        .arg("replace")
        .arg(format!("{}/{}", addr, mask))
        .arg("dev")
        .arg(name)
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    Command::new("ip")
        .arg("-6")
        .arg("addr")
        .arg("replace")
        .arg(format!("{}/{}", addr, prefixlen))
        .arg("dev")
        .arg(name)
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    if primary {
        Command::new("ip")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("table")
            .arg("main")
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("ip")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("dev")
            .arg(interface)
            .arg("table")
            .arg("default")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> {
    if primary {
        Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("dev")
            .arg(interface)
            .arg("table")
            .arg("main")
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("dev")
            .arg(interface)
            .arg("table")
            .arg("default")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
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
    Command::new("ip")
        .arg("rule")
        .arg("add")
        .arg("from")
        .arg(addr.to_string())
        .arg("table")
        .arg("default")
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    Command::new("ip")
        .arg("-6")
        .arg("rule")
        .arg("add")
        .arg("from")
        .arg(addr.to_string())
        .arg("table")
        .arg("default")
        .status()
        .expect("failed to execute command");
    Ok(())
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
    let out = Command::new("sysctl")
        .arg("-n")
        .arg("net.ipv4.ip_forward")
        .output()
        .expect("failed to execute command");
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let res = out
        .trim()
        .parse::<i8>()
        .expect("unexpected ip_forward value")
        != 0;
    Ok(res)
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    let out = Command::new("sysctl")
        .arg("-n")
        .arg("net.ipv6.conf.all.forwarding")
        .output()
        .expect("failed to execute command");
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let res = out
        .trim()
        .parse::<i8>()
        .expect("unexpected ip_forward value")
        != 0;
    Ok(res)
}

pub fn set_ipv4_forwarding(val: bool) -> Result<()> {
    Command::new("sysctl")
        .arg("-w")
        .arg(format!(
            "net.ipv4.ip_forward={}",
            if val { "1" } else { "0" }
        ))
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn set_ipv6_forwarding(val: bool) -> Result<()> {
    Command::new("sysctl")
        .arg("-w")
        .arg(format!(
            "net.ipv6.conf.all.forwarding={}",
            if val { "1" } else { "0" }
        ))
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_iptable_forward(interface: &str) -> Result<()> {
    Command::new("iptables")
        .arg("-I")
        .arg("FORWARD")
        .arg("-o")
        .arg(interface)
        .arg("-j")
        .arg("ACCEPT")
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn delete_iptable_forward(interface: &str) -> Result<()> {
    Command::new("iptables")
        .arg("-D")
        .arg("FORWARD")
        .arg("-o")
        .arg(interface)
        .arg("-j")
        .arg("ACCEPT")
        .status()
        .expect("failed to execute command");
    Ok(())
}
