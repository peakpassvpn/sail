//! `tun`, as a TUN inbound tagged `DEFAULT-TUN`, as Mihomo names it for
//! `IN-NAME` rules, and its `dns-hijack` as a `hijack-dns` rule before
//! every other: as Mihomo's, it takes DNS over TCP and UDP alike to the
//! addresses listed, whatever scheme they name, `any` meaning port 53 on
//! any address; and to the address after the device's own.
//!
//! The device's IPv4 address is Mihomo's: the first of `fake-ip-range`,
//! 198.18.0.1 without one, as a /30. `auto-redirect` is taken on Linux
//! alone, and passed over elsewhere, as Mihomo does; and with it alone
//! `route-address-set` and `route-exclude-address-set`, as Mihomo takes
//! them.

use std::net::IpAddr;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::node::Node;
use super::provider::Sets;
use super::Lowered;
use crate::config::rule_set::ClashBehavior;

use Tier::*;

/// The inbound's tag.
pub const TAG: &str = "DEFAULT-TUN";

const FIELDS: &[(&str, Tier)] = &[
    // One stack serves every one, and sail's own offload.
    ("stack", Ignored),
    ("gso", Ignored),
    ("gso-max-size", Ignored),
    ("endpoint-independent-nat", Ignored),
    ("udp-timeout", Ignored),
    ("icmp-timeout", Ignored),
    ("disable-icmp-forwarding", Ignored),
    ("recvmsgx", Ignored),
    ("sendmsgx", Ignored),
    ("processors-per-channel", Ignored),
    // Which traffic is taken.
    ("exclude-src-port", Unsupported),
    ("exclude-src-port-range", Unsupported),
    ("exclude-dst-port", Unsupported),
    ("exclude-dst-port-range", Unsupported),
    ("include-mac-address", Unsupported),
    ("exclude-mac-address", Unsupported),
];

/// Mihomo's own names and sail's, of what they both take as it is.
const SAME: &[(&str, &str)] = &[
    ("auto-route", "auto_route"),
    ("auto-redirect", "auto_redirect"),
    ("strict-route", "strict_route"),
];
const SAME_LISTS: &[(&str, &str)] = &[
    ("include-interface", "include_interface"),
    ("exclude-interface", "exclude_interface"),
    ("include-uid-range", "include_uid_range"),
    ("exclude-uid-range", "exclude_uid_range"),
    ("include-package", "include_package"),
    ("exclude-package", "exclude_package"),
    ("loopback-address", "loopback_address"),
];
const SAME_NUMBERS: &[(&str, &str)] = &[
    ("mtu", "mtu"),
    ("iproute2-table-index", "iproute2_table_index"),
    ("iproute2-rule-index", "iproute2_rule_index"),
    ("auto-redirect-input-mark", "auto_redirect_input_mark"),
    ("auto-redirect-output-mark", "auto_redirect_output_mark"),
    (
        "auto-redirect-iproute2-fallback-rule-index",
        "auto_redirect_iproute2_fallback_rule_index",
    ),
];

/// The address of `fake-ip-range`, which the device takes: read before the
/// DNS section is.
pub fn fake_ip_address(doc: &mut Fields) -> Option<IpAddr> {
    let dns = doc.take("dns")?;
    let address = match &dns {
        Node::Map(m) => m
            .get("fake-ip-range")
            .and_then(Node::as_string)
            .and_then(|r| r.split('/').next().and_then(|a| a.parse().ok())),
        _ => None,
    };
    doc.put("dns", dns);
    address
}

pub fn lower(
    doc: &mut Fields,
    fake_ip: Option<IpAddr>,
    sets: &mut Sets,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let Some(mut f) = doc.map("tun")? else {
        return Ok(());
    };
    if !f.bool("enable")?.unwrap_or(false) {
        for key in f.keys() {
            f.take(&key);
        }
        return Ok(());
    }
    let mut tun = Map::new();
    tun.insert("type".into(), json!("tun"));
    tun.insert("tag".into(), json!(TAG));
    if let Some(device) = f.string("device")?.filter(|d| !d.is_empty()) {
        tun.insert("interface_name".into(), json!(device));
    }
    let ipv4 = match fake_ip {
        Some(IpAddr::V4(a)) => a,
        _ => std::net::Ipv4Addr::new(198, 18, 0, 1),
    };
    let mut address = vec![format!("{}/30", ipv4)];
    // The address after the device's, where Mihomo answers DNS.
    let mut gateways = vec![IpAddr::V4(std::net::Ipv4Addr::from(u32::from(ipv4) + 1))];
    let inet6_at = f.at("inet6-address");
    let inet6 = f.strings("inet6-address")?;
    if inet6.len() > 1 {
        return Err(anyhow!("{}: sail takes one IPv6 address", inet6_at));
    }
    for prefix in inet6 {
        let ip: std::net::Ipv6Addr = prefix
            .split('/')
            .next()
            .and_then(|a| a.parse().ok())
            .ok_or_else(|| anyhow!("{}: {:?} is not an IPv6 prefix", inet6_at, prefix))?;
        gateways.push(IpAddr::V6(std::net::Ipv6Addr::from(u128::from(ip) + 1)));
        address.push(prefix);
    }
    tun.insert("address".into(), json!(address));
    // Mihomo's, where sing-box has 9000 only on Android.
    tun.insert("mtu".into(), json!(9000));
    for (key, name) in SAME {
        if let Some(on) = f.bool(key)? {
            tun.insert((*name).into(), json!(on));
        }
    }
    for (key, name) in SAME_LISTS {
        let list = f.strings(key)?;
        if !list.is_empty() {
            tun.insert((*name).into(), json!(list));
        }
    }
    for (key, name) in SAME_NUMBERS {
        if let Some(n) = f.int::<u32>(key)?.filter(|n| *n > 0) {
            tun.insert((*name).into(), json!(n));
        }
    }
    for (key, name) in [
        ("include-uid", "include_uid"),
        ("exclude-uid", "exclude_uid"),
    ] {
        let at = f.at(key);
        let uids = f
            .strings(key)?
            .iter()
            .map(|u| {
                u.parse::<u32>()
                    .map_err(|_| anyhow!("{}: {:?} is not a user ID", at, u))
            })
            .collect::<Result<Vec<_>>>()?;
        if !uids.is_empty() {
            tun.insert(name.into(), json!(uids));
        }
    }
    let at = f.at("include-android-user");
    let users = f
        .strings("include-android-user")?
        .iter()
        .map(|u| {
            u.parse::<u32>()
                .map_err(|_| anyhow!("{}: {:?} is not a user", at, u))
        })
        .collect::<Result<Vec<_>>>()?;
    if !users.is_empty() {
        tun.insert("include_android_user".into(), json!(users));
    }
    // The deprecated per-family lists, and the one of both.
    let mut route = f.strings("route-address")?;
    route.extend(f.strings("inet4-route-address")?);
    route.extend(f.strings("inet6-route-address")?);
    let mut exclude = f.strings("route-exclude-address")?;
    exclude.extend(f.strings("inet4-route-exclude-address")?);
    exclude.extend(f.strings("inet6-route-exclude-address")?);
    if !route.is_empty() {
        tun.insert("route_address".into(), json!(route));
    }
    if !exclude.is_empty() {
        tun.insert("route_exclude_address".into(), json!(exclude));
    }
    // As Mihomo, which turns it off where the system has no redirect.
    if !cfg!(target_os = "linux") {
        tun.retain(|key, _| !key.starts_with("auto_redirect"));
    }
    // Mihomo takes the rule-providers these name with auto-redirect alone,
    // and passes them over without.
    let redirect = tun.get("auto_redirect") == Some(&json!(true));
    for (key, name) in [
        ("route-address-set", "route_address_set"),
        ("route-exclude-address-set", "route_exclude_address_set"),
    ] {
        let at = f.at(key);
        let names = f.strings(key)?;
        if !redirect || names.is_empty() {
            continue;
        }
        for (i, set) in names.iter().enumerate() {
            address_set(set, sets).map_err(|e| anyhow!("{}[{}]: {}", at, i, e))?;
        }
        tun.insert(name.into(), json!(names));
    }
    // `interface-name` wins, as Mihomo's dialer looks the interface up
    // only without one.
    if f.bool("auto-detect-interface")?.unwrap_or(false)
        && !out.route.contains_key("default_interface")
    {
        out.route
            .insert("auto_detect_interface".into(), json!(true));
    }
    let hijack = hijack(&f.strings("dns-hijack")?, &f.at("dns-hijack"), &gateways)?;
    if let Some(fd) = f.int::<i64>("file-descriptor")?.filter(|fd| *fd > 0) {
        return Err(anyhow!(
            "{}: {}: sail does not take a device opened elsewhere yet",
            f.at("file-descriptor"),
            fd
        ));
    }
    f.finish(FIELDS, |_| false, warnings)?;
    out.inbounds.push(Value::Object(tun));
    // Before every other rule, sniffing among them: Mihomo answers these
    // before a connection is routed.
    out.rules.insert(0, hijack);
    Ok(())
}

/// Checks that `set` names a rule-provider of IP prefixes, as Mihomo
/// looks it up: by its name alone.
fn address_set(set: &str, sets: &mut Sets) -> Result<()> {
    match sets.provider(set)? {
        ClashBehavior::Domain => Err(anyhow!(
            "rule-provider {:?} is of domains, not IP prefixes",
            set
        )),
        _ => Ok(()),
    }
}

/// The rule that hands DNS to the device's addresses and to those listed
/// to the DNS client.
fn hijack(entries: &[String], at: &str, gateways: &[IpAddr]) -> Result<Value> {
    let mut any = false;
    let mut to: Vec<(IpAddr, u16)> = gateways.iter().map(|ip| (*ip, 53)).collect();
    for (i, entry) in entries.iter().enumerate() {
        let address = entry.split_once("://").map_or(entry.as_str(), |(_, a)| a);
        let (host, port) = address
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("{}[{}]: {:?} names no port", at, i, entry))?;
        let port: u16 = port
            .parse()
            .map_err(|_| anyhow!("{}[{}]: {:?} names no port", at, i, entry))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host == "any" || host == "0.0.0.0" || host == "::" {
            // As Mihomo has it: any address, on port 53 whatever is named.
            any = true;
            continue;
        }
        let ip: IpAddr = host
            .parse()
            .map_err(|_| anyhow!("{}[{}]: {:?} is not an address", at, i, entry))?;
        to.push((ip, port));
    }
    let mut alternatives = Vec::new();
    if any {
        alternatives.push(json!({ "port": [53] }));
    }
    for (ip, port) in to {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        alternatives.push(json!({ "ip_cidr": [format!("{}/{}", ip, prefix)], "port": [port] }));
    }
    Ok(json!({
        "type": "logical",
        "mode": "and",
        "rules": [
            { "inbound": [TAG] },
            { "type": "logical", "mode": "or", "rules": alternatives },
        ],
        "action": "hijack-dns",
    }))
}
