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
//! The proxy listeners (trojan, vless) serve sing-mux, as all of Mihomo's do,
//! over a websocket at `ws-path` or gRPC under `grpc-service-name` where
//! one is given.
//!
//! Where sail does otherwise: its SOCKS, mixed and shadowsocks inbounds
//! carry UDP whatever `udp` says, where Mihomo's listeners carry it only
//! with `udp: true`. A websocket listener takes websocket clients alone,
//! where Mihomo's takes v2ray's HTTP upgrade on the same path too. A connection `lan-allowed-ips` keeps out is rejected
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
    ("trojan", "trojan"),
    ("vless", "vless"),
];

/// The early data a websocket client may send in `Sec-WebSocket-Protocol`,
/// which Mihomo's listeners read of any size: Xray's 2048 bytes, all that
/// its clients and Mihomo's send.
const WS_EARLY_DATA: usize = 2048;

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
    ("ss-option", Unsupported),
    ("xhttp-config", Unsupported),
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
        out.rules.extend_front(self.rules);
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
                let own = f.has("users");
                let users = if own {
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
                    // Mihomo's skip-auth-prefixes, but where it names
                    // users of its own.
                    if !own && !out.skip_auth.is_empty() {
                        inbound.insert("skip_auth_prefixes".into(), json!(out.skip_auth));
                    }
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
            "trojan" => {
                let users = users(&mut f, "password", warnings)?;
                inbound.insert("users".into(), Value::Array(users));
            }
            "vless" => {
                let users = users(&mut f, "uuid", warnings)?;
                inbound.insert("users".into(), Value::Array(users));
                // VLESS encryption, Mihomo's and Xray's: none is "none".
                let at = f.at("decryption");
                if let Some(d) = f
                    .string("decryption")?
                    .filter(|d| !d.is_empty() && d != "none")
                {
                    return Err(anyhow!(
                        "{}: {:?}: sail does not implement VLESS encryption",
                        at,
                        d
                    ));
                }
            }
            _ => {}
        }
        if matches!(protocol, "http" | "trojan" | "vless") {
            tls(&mut f, out.home.as_deref(), &mut inbound, warnings)?;
        }
        if matches!(protocol, "trojan" | "vless") {
            // As Mihomo: none of these but by leave.
            let insecure = f.bool("allow-insecure")?.unwrap_or(false);
            if !inbound.contains_key("tls") && !insecure {
                return Err(anyhow!(
                    "{}: no certificate or REALITY, and not allow-insecure: Mihomo refuses \
                     a {} listener without TLS",
                    f.at("certificate"),
                    protocol
                ));
            }
            carriers(&mut f, &mut inbound, warnings)?;
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

/// A listener's TLS, as Mihomo's `ca.NewTLSKeyPairLoader` takes it: a
/// certificate and its key, each PEM or else a path, which stays in the
/// data directory (`home`) as Mihomo's IsSafePath keeps it. With one of
/// them alone Mihomo listens without TLS, and so does sail. Or REALITY,
/// `reality-config`, never with a certificate, as Mihomo has it.
fn tls(
    f: &mut Fields,
    home: Option<&std::path::Path>,
    inbound: &mut Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let certificate = f.string("certificate")?.filter(|c| !c.is_empty());
    let key = f.string("private-key")?.filter(|k| !k.is_empty());
    let reality_at = f.at("reality-config");
    if let Some(r) = f.map("reality-config")? {
        if let Some(tls) = reality(r, warnings)? {
            if certificate.is_some() && key.is_some() {
                return Err(anyhow!(
                    "{}: with a certificate: Mihomo takes one of the two",
                    reality_at
                ));
            }
            inbound.insert("tls".into(), tls);
            return Ok(());
        }
    }
    let (certificate, key) = match (certificate, key) {
        (None, None) => return Ok(()),
        (Some(certificate), Some(key)) => (certificate, key),
        (certificate, _) => {
            let (has, lacks) = if certificate.is_some() {
                ("certificate", "private-key")
            } else {
                ("private-key", "certificate")
            };
            warnings.push(format!(
                "{}: without {} Mihomo listens without TLS, and so does sail; ignored",
                f.at(has),
                lacks
            ));
            return Ok(());
        }
    };
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    for (name, field, value) in [
        ("certificate", "certificate", certificate),
        ("private-key", "key", key),
    ] {
        if value.contains("-----BEGIN") {
            tls.insert(field.into(), json!(value));
        } else if crate::common::path::stays_in(home, &value) {
            tls.insert(format!("{}_path", field), json!(value));
        } else {
            return Err(anyhow!(
                "{}: {:?} is not in the data directory, which a listener's certificate \
                 stays in, as in Mihomo",
                f.at(name),
                value
            ));
        }
    }
    inbound.insert("tls".into(), Value::Object(tls));
    Ok(())
}

/// REALITY, as Mihomo's `reality-config`, in place of a certificate; none
/// with no `private-key`, as Mihomo has it. Mihomo's `max-time-difference`
/// is in microseconds, as its code multiplies it, and so it is here: a
/// profile runs as Mihomo runs it, though Xray's same field is in
/// milliseconds, and an Xray value copied gives a window 1000 times
/// shorter.
fn reality(mut r: Fields, warnings: &mut Vec<String>) -> Result<Option<Value>> {
    // What Mihomo requires of the block, private-key among them.
    for key in ["dest", "private-key", "short-id", "server-names"] {
        if !r.has(key) {
            return Err(anyhow!("{}: missing", r.at(key)));
        }
    }
    let key = r.string("private-key")?.unwrap_or_default();
    let dest_at = r.at("dest");
    let dest = r.string("dest")?.unwrap_or_default();
    let short_ids = r.strings("short-id")?;
    let names_at = r.at("server-names");
    let names = r.strings("server-names")?;
    let micros = r.int::<u64>("max-time-difference")?.unwrap_or(0);
    let proxy_at = r.at("proxy");
    let proxy = r.string("proxy")?.filter(|p| !p.is_empty());
    for key in ["limit-fallback-upload", "limit-fallback-download"] {
        let at = r.at(key);
        if let Some(mut limit) = r.map(key)? {
            let mut set = false;
            for rate in ["after-bytes", "bytes-per-sec", "burst-bytes-per-sec"] {
                set |= limit.int::<u64>(rate)?.unwrap_or(0) > 0;
            }
            limit.finish(&[], |_| false, warnings)?;
            if set {
                warnings.push(format!(
                    "{}: sail does not limit what REALITY relays to the site it imitates; \
                     ignored",
                    at
                ));
            }
        }
    }
    r.finish(&[], |_| false, warnings)?;
    if key.is_empty() {
        return Ok(None);
    }
    let (host, port) =
        split_host_port(&dest).ok_or_else(|| anyhow!("{}: {:?} names no port", dest_at, dest))?;
    let name = match names.as_slice() {
        [name] => name.clone(),
        [] => return Err(anyhow!("{}: empty: no client would be taken", names_at)),
        _ => {
            return Err(anyhow!(
                "{}: sail does not take more than one name yet",
                names_at
            ))
        }
    };
    if proxy.is_some() {
        return Err(anyhow!(
            "{}: sail does not dial the site REALITY imitates through a proxy yet",
            proxy_at
        ));
    }
    let mut reality = Map::new();
    reality.insert("enabled".into(), json!(true));
    reality.insert(
        "handshake".into(),
        json!({ "server": host, "server_port": port }),
    );
    reality.insert("private_key".into(), json!(key));
    reality.insert("short_id".into(), json!(short_ids));
    if micros > 0 {
        reality.insert("max_time_difference".into(), json!(format!("{}us", micros)));
    }
    Ok(Some(
        json!({ "enabled": true, "server_name": name, "reality": reality }),
    ))
}

/// A proxy listener's users, by `secret`, the password or the UUID, its
/// `username` the user's name, and a vless user's `flow`; of two with one
/// secret the last is taken, as Mihomo keys them by it.
fn users(f: &mut Fields, secret: &str, warnings: &mut Vec<String>) -> Result<Vec<Value>> {
    let at = f.at("users");
    let mut users: Vec<(String, Value)> = Vec::new();
    for (j, item) in f.list("users")?.into_iter().enumerate() {
        let mut u = Fields::of(item, &format!("{}[{}]", at, j))?;
        let value = u
            .string(secret)?
            .ok_or_else(|| anyhow!("{}: missing", u.at(secret)))?;
        let mut user = Map::new();
        if let Some(name) = u.string("username")?.filter(|n| !n.is_empty()) {
            user.insert("name".into(), json!(name));
        }
        user.insert(secret.into(), json!(value));
        if secret == "uuid" {
            if let Some(flow) = u.string("flow")?.filter(|f| !f.is_empty()) {
                user.insert("flow".into(), json!(flow));
            }
        }
        if let Some(k) = users.iter().position(|(v, _)| *v == value) {
            users.remove(k);
            warnings.push(format!(
                "{}: the {} of a user before it: Mihomo takes this one alone, \
                 and so does sail",
                u.at(secret),
                secret
            ));
        }
        u.finish(&[], |_| false, warnings)?;
        users.push((value, Value::Object(user)));
    }
    Ok(users.into_iter().map(|(_, user)| user).collect())
}

/// What a proxy listener carries its protocol in: a websocket at
/// `ws-path`, taking early data as Mihomo's does, or gRPC under
/// `grpc-service-name`; and sing-mux, which Mihomo's serve whatever they
/// say, `mux-option` tuning it.
fn carriers(
    f: &mut Fields,
    inbound: &mut Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let ws = f.string("ws-path")?.filter(|p| !p.is_empty());
    let grpc_at = f.at("grpc-service-name");
    let grpc = f.string("grpc-service-name")?.filter(|s| !s.is_empty());
    match (ws, grpc) {
        (Some(_), Some(_)) => {
            return Err(anyhow!(
                "{}: with ws-path: sail does not serve two transports on one port",
                grpc_at
            ))
        }
        (Some(path), None) => {
            inbound.insert(
                "transport".into(),
                json!({ "type": "ws", "path": path,
                    "early_data_header_name": "Sec-WebSocket-Protocol",
                    "max_early_data": WS_EARLY_DATA }),
            );
        }
        (None, Some(name)) => {
            inbound.insert(
                "transport".into(),
                json!({ "type": "grpc", "service_name": name }),
            );
        }
        (None, None) => {}
    }
    let mut multiplex = Map::new();
    multiplex.insert("enabled".into(), json!(true));
    if let Some(mut m) = f.map("mux-option")? {
        if m.bool("padding")?.unwrap_or(false) {
            multiplex.insert("padding".into(), json!(true));
        }
        if let Some(mut b) = m.map("brutal")? {
            // A rate missing, or one Mihomo cannot read, is 0 there, and
            // sing-mux takes the lower of the two ends' rates: brutal does
            // nothing then, and is left off here.
            let enabled = b.bool("enabled")?.unwrap_or(false);
            let mut rates = Vec::new();
            for key in ["up", "down"] {
                let at = b.at(key);
                let rate = b.string(key)?;
                if !enabled {
                    continue;
                }
                match rate.as_deref().map(super::proxy::mbps) {
                    Some(Ok(mbps)) => rates.push(mbps),
                    Some(Err(e)) => warnings.push(format!(
                        "{}: {}: 0 to Mihomo, so brutal does nothing; left off",
                        at, e
                    )),
                    None => warnings.push(format!(
                        "{}: missing: 0 to Mihomo, so brutal does nothing; left off",
                        at
                    )),
                }
            }
            if let [up, down] = rates[..] {
                multiplex.insert(
                    "brutal".into(),
                    json!({ "enabled": true, "up_mbps": up, "down_mbps": down }),
                );
            }
            b.finish(&[], |_| false, warnings)?;
        }
        m.finish(&[], |_| false, warnings)?;
    }
    inbound.insert("multiplex".into(), Value::Object(multiplex));
    Ok(())
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
