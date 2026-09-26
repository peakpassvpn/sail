use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::{anyhow, Result};

use super::{output, run, sysctl_flag};

/// The value `route -n get` prints for `key` (as in "  gateway: 10.0.0.1")
/// when asked about `args`.
fn route_get(args: &[&str], key: &str) -> Result<String> {
    let out = output(Command::new("route").arg("-n").arg("get").args(args))?;
    let label = format!("{}:", key);
    out.lines()
        .find_map(|line| {
            let mut cols = line.split_whitespace();
            if cols.next()? == label {
                cols.next().map(str::to_string)
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("route get {}: no {}", args.join(" "), key))
}

pub fn get_default_ipv4_gateway() -> Result<String> {
    route_get(&["1"], "gateway")
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    let gateway = route_get(&["-inet6", "::2"], "gateway")?;
    // A link-local gateway is printed with its scope: fe80::1%en0.
    Ok(gateway
        .split('%')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string())
}

pub fn get_default_interface() -> Result<String> {
    route_get(&["1"], "interface")
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    run(Command::new("ifconfig")
        .arg(name)
        .arg("inet")
        .arg(addr.to_string())
        .arg("netmask")
        .arg(mask.to_string())
        .arg(gw.to_string()))
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    run(Command::new("ifconfig")
        .arg(name)
        .arg("inet6")
        .arg(addr.to_string())
        .arg("prefixlen")
        .arg(prefixlen.to_string()))
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    let mut cmd = Command::new("route");
    cmd.arg("add")
        .arg("-inet")
        .arg("default")
        .arg(gateway.to_string());
    if !primary {
        cmd.arg("-ifscope").arg(interface);
    }
    run(&mut cmd)
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> {
    // FIXME https://doc.rust-lang.org/std/net/struct.Ipv6Addr.html#method.is_global
    let gw = if (gateway.segments()[0] & 0xffc0) == 0xfe80 {
        format!("{}%{}", gateway, interface)
    } else {
        gateway.to_string()
    };
    let mut cmd = Command::new("route");
    cmd.arg("add").arg("-inet6").arg("default").arg(gw);
    if !primary {
        cmd.arg("-ifscope").arg(interface);
    }
    run(&mut cmd)
}

pub fn delete_default_ipv4_route(ifscope: Option<String>) -> Result<()> {
    let mut cmd = Command::new("route");
    cmd.arg("delete").arg("-inet").arg("default");
    if let Some(ifscope) = ifscope {
        cmd.arg("-ifscope").arg(ifscope);
    }
    run(&mut cmd)
}

pub fn delete_default_ipv6_route(ifscope: Option<String>) -> Result<()> {
    let mut cmd = Command::new("route");
    cmd.arg("delete").arg("-inet6").arg("default");
    if let Some(ifscope) = ifscope {
        cmd.arg("-ifscope").arg(ifscope);
    }
    run(&mut cmd)
}

pub fn get_ipv4_forwarding() -> Result<bool> {
    sysctl_flag("net.inet.ip.forwarding")
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    sysctl_flag("net.inet6.ip6.forwarding")
}

pub fn set_ipv4_forwarding(val: bool) -> Result<()> {
    run(Command::new("sysctl").arg("-w").arg(format!(
        "net.inet.ip.forwarding={}",
        if val { "1" } else { "0" }
    )))
}

pub fn set_ipv6_forwarding(val: bool) -> Result<()> {
    run(Command::new("sysctl").arg("-w").arg(format!(
        "net.inet6.ip6.forwarding={}",
        if val { "1" } else { "0" }
    )))
}
