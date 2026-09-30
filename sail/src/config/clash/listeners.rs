//! `listeners`: inbounds of their own, each tagged with its name, which
//! `IN-NAME` rules match and `IN-TYPE` ones by its type. One with a `proxy`
//! sends everything to that policy, whatever the rules and the mode say,
//! as Mihomo does: its rule stands before every other but the sniffer's,
//! as Mihomo sniffs before it looks.
//!
//! `tunnels` forward what comes in on an address to a target, through
//! the rules or a `proxy` of their own, as direct inbounds doing so.
//!
//! `lan-allowed-ips` and `lan-disallowed-ips` keep to them those who may
//! use the listeners that authenticate as `authentication` says, as
//! Mihomo keeps them: a rule before every other rejects the others' TCP
//! and UDP alike.
//!
//! Where sail does otherwise: its SOCKS, mixed and shadowsocks inbounds
//! carry UDP whatever `udp` says, where Mihomo's listeners carry it only
//! with `udp: true`. A connection `lan-allowed-ips` keeps out is rejected
//! once its client has asked for a destination, where Mihomo closes it at
//! once.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::general::LISTENERS;
use super::group::Policies;
use super::rule::{target, Target};
use super::Lowered;

use Tier::*;

/// Mihomo's listener types sail has, and its inbounds of them.
const TYPES: &[(&str, &str)] = &[
    ("mixed", "mixed"),
    ("socks", "socks"),
    ("http", "http"),
    ("redir", "redirect"),
    ("tproxy", "tproxy"),
    ("shadowsocks", "shadowsocks"),
];

const FIELDS: &[(&str, Tier)] = &[
    // Which policy what comes in goes to.
    ("rule", Unsupported),
    ("routing-mark", Ignored),
    // TLS, and what shadowsocks is wrapped in.
    ("certificate", Unsupported),
    ("private-key", Unsupported),
    ("client-auth-type", Unsupported),
    ("client-auth-cert", Unsupported),
    ("ech-key", Unsupported),
    ("reality-config", Unsupported),
    ("mux-option", Unsupported),
    ("shadow-tls", Unsupported),
    ("res-tls", Unsupported),
    ("jls-config", Unsupported),
    ("kcp-tun", Unsupported),
    ("simple-obfs", Unsupported),
];

/// The listeners, lowered: their inbounds are out's already.
#[derive(Default)]
pub struct Listeners {
    /// Each one's inbound type, which `IN-TYPE` names, and its name.
    pub kinds: Vec<(String, String)>,
    /// The rules of those with a `proxy`.
    rules: Vec<Value>,
}

impl Listeners {
    /// Puts their rules before every other, the sniffer's to come.
    pub fn apply(self, out: &mut Lowered) {
        out.rules.splice(0..0, self.rules);
    }
}

pub fn lower(
    doc: &mut Fields,
    policies: &Policies,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<Listeners> {
    let mut listeners = Listeners::default();
    for (i, node) in doc.list("listeners")?.into_iter().enumerate() {
        let mut f = Fields::of(node, &format!("listeners[{}]", i))?;
        let name = f
            .string("name")?
            .filter(|n| !n.is_empty())
            .ok_or_else(|| anyhow!("{}: missing", f.at("name")))?;
        if LISTENERS.iter().any(|(_, _, tag)| *tag == name)
            || listeners.kinds.iter().any(|(_, n)| *n == name)
        {
            return Err(anyhow!(
                "{}: another listener is named {:?}",
                f.at("name"),
                name
            ));
        }
        let kind = f
            .string("type")?
            .ok_or_else(|| anyhow!("{}: missing", f.at("type")))?
            .to_ascii_lowercase();
        let protocol = TYPES
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, p)| *p)
            .ok_or_else(|| {
                anyhow!(
                    "{}: sail does not implement {:?} listeners yet",
                    f.at("type"),
                    kind
                )
            })?;
        let mut inbound = Map::new();
        inbound.insert("type".into(), json!(protocol));
        inbound.insert("tag".into(), json!(name));
        inbound.insert(
            "listen".into(),
            json!(f
                .string("listen")?
                .filter(|l| !l.is_empty())
                .unwrap_or_else(|| "0.0.0.0".into())),
        );
        let port_at = f.at("port");
        let port = f
            .string("port")?
            .ok_or_else(|| anyhow!("{}: missing", port_at))?;
        let port: u16 = port.trim().parse().map_err(|_| {
            anyhow!(
                "{}: {:?}: sail takes one port, not ranges, yet",
                port_at,
                port
            )
        })?;
        inbound.insert("listen_port".into(), json!(port));
        match protocol {
            "mixed" | "socks" | "http" => {
                // None: those of `authentication`; an empty list: anyone.
                let users = if f.has("users") {
                    let users_at = f.at("users");
                    let mut users = Vec::new();
                    for (j, item) in f.list("users")?.into_iter().enumerate() {
                        let mut u = Fields::of(item, &format!("{}[{}]", users_at, j))?;
                        let username = u.string("username")?.unwrap_or_default();
                        let password = u.string("password")?.unwrap_or_default();
                        u.finish(&[], |_| false, warnings)?;
                        users.push(json!({ "username": username, "password": password }));
                    }
                    users
                } else {
                    out.lan_inbounds.push(name.clone());
                    out.authentication.clone()
                };
                if !users.is_empty() {
                    inbound.insert("users".into(), Value::Array(users));
                }
            }
            "shadowsocks" => {
                let method = f
                    .string("cipher")?
                    .ok_or_else(|| anyhow!("{}: missing", f.at("cipher")))?;
                let password = f
                    .string("password")?
                    .ok_or_else(|| anyhow!("{}: missing", f.at("password")))?;
                inbound.insert("method".into(), json!(method));
                inbound.insert("password".into(), json!(password));
            }
            _ => {}
        }
        // Mihomo's are TCP alone without it; sail's carry UDP all the same.
        let udp = f.bool("udp")?;
        if matches!(protocol, "mixed" | "socks" | "shadowsocks") && udp != Some(true) {
            warnings.push(format!(
                "{}: not true: sail's {} inbound carries UDP all the same",
                f.at("udp"),
                protocol
            ));
        }
        if let Some(proxy) = f.string("proxy")?.filter(|p| !p.is_empty()) {
            let target = match target(&proxy, policies) {
                Ok(Target::Pass | Target::HijackDns) => {
                    return Err(anyhow!(
                        "{}: {:?} is no proxy or group",
                        f.at("proxy"),
                        proxy
                    ))
                }
                Ok(target) => target,
                Err(e) => return Err(anyhow!("{}: {}", f.at("proxy"), e)),
            };
            let mut rule = Map::new();
            rule.insert("inbound".into(), json!([name]));
            target.apply(&mut rule);
            listeners.rules.push(Value::Object(rule));
        }
        f.finish(FIELDS, |_| false, warnings)?;
        out.inbounds.push(Value::Object(inbound));
        listeners.kinds.push((protocol.to_string(), name));
    }
    for (i, node) in doc.list("tunnels")?.into_iter().enumerate() {
        let at = format!("tunnels[{}]", i);
        let tunnel = tunnel(node, &at, warnings)?;
        let tag = format!("tunnel:{}", tunnel.address);
        if listeners.kinds.iter().any(|(_, n)| *n == tag) {
            return Err(anyhow!(
                "{}: another tunnel listens on {}",
                at,
                tunnel.address
            ));
        }
        let (host, port) = split_host_port(&tunnel.address)
            .ok_or_else(|| anyhow!("{}: {:?} names no port", at, tunnel.address))?;
        let (target_host, target_port) = split_host_port(&tunnel.target)
            .ok_or_else(|| anyhow!("{}: {:?} names no port", at, tunnel.target))?;
        let mut inbound = Map::new();
        inbound.insert("type".into(), json!("direct"));
        inbound.insert("tag".into(), json!(tag));
        inbound.insert(
            "listen".into(),
            json!(if host.is_empty() { "0.0.0.0" } else { host }),
        );
        inbound.insert("listen_port".into(), json!(port));
        if let [one] = tunnel.network.as_slice() {
            inbound.insert("network".into(), json!(one));
        }
        inbound.insert("override_address".into(), json!(target_host));
        inbound.insert("override_port".into(), json!(target_port));
        if let Some(proxy) = tunnel.proxy.filter(|p| !p.is_empty()) {
            let target = match target(&proxy, policies) {
                Ok(Target::Pass | Target::HijackDns) => {
                    return Err(anyhow!("{}.proxy: {:?} is no proxy or group", at, proxy))
                }
                Ok(target) => target,
                Err(e) => return Err(anyhow!("{}.proxy: {}", at, e)),
            };
            let mut rule = Map::new();
            rule.insert("inbound".into(), json!([tag]));
            target.apply(&mut rule);
            listeners.rules.push(Value::Object(rule));
        }
        out.inbounds.push(Value::Object(inbound));
        listeners.kinds.push(("tunnel".to_string(), tag));
    }
    Ok(listeners)
}

/// A tunnel, as Mihomo writes one: a map, or `tcp/udp,address,target`
/// with a proxy after it.
struct Tunnel {
    network: Vec<String>,
    address: String,
    target: String,
    proxy: Option<String>,
}

fn tunnel(node: super::node::Node, at: &str, warnings: &mut Vec<String>) -> Result<Tunnel> {
    let tunnel = match node.as_string() {
        Some(line) => {
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if !(3..=4).contains(&parts.len()) {
                return Err(anyhow!(
                    "{}: {:?} is not network,address,target and a proxy",
                    at,
                    line
                ));
            }
            Tunnel {
                network: parts[0].split('/').map(str::to_string).collect(),
                address: parts[1].to_string(),
                target: parts[2].to_string(),
                proxy: parts.get(3).map(|p| p.to_string()),
            }
        }
        None => {
            let mut f = Fields::typed(node, at)?;
            let tunnel = Tunnel {
                network: f.strings("network")?,
                address: f
                    .string("address")?
                    .ok_or_else(|| anyhow!("{}: missing", f.at("address")))?,
                target: f
                    .string("target")?
                    .ok_or_else(|| anyhow!("{}: missing", f.at("target")))?,
                proxy: f.string("proxy")?,
            };
            f.finish(&[], |_| false, warnings)?;
            tunnel
        }
    };
    if tunnel.network.is_empty() {
        return Err(anyhow!("{}: no network", at));
    }
    if let Some(n) = tunnel
        .network
        .iter()
        .find(|n| !matches!(n.as_str(), "tcp" | "udp"))
    {
        return Err(anyhow!("{}: {:?} is neither tcp nor udp", at, n));
    }
    Ok(tunnel)
}

/// `host:port`, `[v6]:port` or `:port`, split.
fn split_host_port(address: &str) -> Option<(&str, u16)> {
    let (host, port) = address.rsplit_once(':')?;
    let port = port.parse().ok()?;
    Some((host.trim_start_matches('[').trim_end_matches(']'), port))
}

/// The rule `lan-allowed-ips` and `lan-disallowed-ips` make, if they keep
/// anyone out.
pub fn lan_rule(out: &Lowered) -> Option<Value> {
    if out.lan_inbounds.is_empty() {
        return None;
    }
    let mut out_of = Vec::new();
    match &out.lan_allowed {
        None => {}
        // No one allowed: every client.
        Some(allowed) if allowed.is_empty() => {
            out_of.push(json!({ "source_ip_cidr": ["0.0.0.0/0", "::/0"] }))
        }
        Some(allowed) => out_of.push(json!({ "source_ip_cidr": allowed, "invert": true })),
    }
    if !out.lan_disallowed.is_empty() {
        out_of.push(json!({ "source_ip_cidr": out.lan_disallowed }));
    }
    if out_of.is_empty() {
        return None;
    }
    Some(json!({
        "type": "logical",
        "mode": "and",
        "rules": [
            { "inbound": out.lan_inbounds },
            { "type": "logical", "mode": "or", "rules": out_of },
        ],
        "action": "reject",
    }))
}
