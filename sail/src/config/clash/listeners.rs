//! `listeners`: inbounds of their own, each tagged with its name, which
//! `IN-NAME` rules match and `IN-TYPE` ones by its type. One with a `proxy`
//! sends everything to that policy, whatever the rules and the mode say,
//! as Mihomo does: its rule stands before every other but the sniffer's,
//! as Mihomo sniffs before it looks.
//!
//! Where sail does otherwise: its SOCKS, mixed and shadowsocks inbounds
//! carry UDP whatever `udp` says, where Mihomo's listeners carry it only
//! with `udp: true`.

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
    Ok(listeners)
}
