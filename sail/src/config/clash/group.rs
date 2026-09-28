//! `proxy-groups`: `select`, `url-test`, `fallback` and `load-balance`, as
//! sail's groups of those kinds, and Mihomo's own policies: `DIRECT`,
//! `REJECT` and the `GLOBAL` group `mode: global` sends everything to.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::proxy::{Proxies, BUILT_IN};
use super::Lowered;

use Tier::*;

/// What a rule may name: proxies, groups and Mihomo's own policies.
pub struct Policies {
    names: HashSet<String>,
    /// The `dns` proxies, which answer DNS themselves.
    pub dns: HashSet<String>,
}

impl Policies {
    pub fn has(&self, name: &str) -> bool {
        self.names.contains(name)
    }
}

/// The fields every group takes that sail does not implement yet.
const COMMON: &[(&str, Tier)] = &[
    // How members are tested, not which carries what.
    ("timeout", Ignored),
    ("max-failed-times", Ignored),
    ("expected-status", Ignored),
    ("lazy", Ignored),
    ("disable-udp", Ignored),
    // Members from providers, or filtered by name or type: later.
    ("use", Unsupported),
    ("include-all", Unsupported),
    ("include-all-providers", Unsupported),
    ("filter", Unsupported),
    ("exclude-filter", Unsupported),
    ("exclude-type", Unsupported),
    ("empty-fallback", Unsupported),
];

/// The defaults of a group's health checks, Mihomo's.
const URL: &str = "https://www.gstatic.com/generate_204";
const INTERVAL: u64 = 300;

pub fn lower(
    doc: &mut Fields,
    proxies: &Proxies,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<Policies> {
    let groups = doc.list("proxy-groups")?;
    // Every name first: groups may name those listed after them.
    let mut names: Vec<String> = proxies.names.clone();
    let mut group_names = Vec::new();
    for (i, node) in groups.iter().enumerate() {
        let name = match node {
            super::node::Node::Map(m) => m.get("name").and_then(|n| n.as_string()),
            _ => None,
        }
        .filter(|n| !n.is_empty())
        .ok_or_else(|| anyhow!("proxy-groups[{}].name: missing", i))?;
        if names.contains(&name) {
            return Err(anyhow!(
                "proxy-groups[{}].name: {:?} names another proxy or group",
                i,
                name
            ));
        }
        if BUILT_IN.contains(&name.as_str()) && name != "GLOBAL" {
            return Err(anyhow!(
                "proxy-groups[{}].name: {} is Mihomo's own policy",
                i,
                name
            ));
        }
        names.push(name.clone());
        group_names.push(name);
    }
    let known: HashSet<String> = names
        .iter()
        .cloned()
        .chain(["DIRECT", "REJECT", "REJECT-DROP"].map(String::from))
        .collect();
    for (i, node) in groups.into_iter().enumerate() {
        let mut f = Fields::of(node, &format!("proxy-groups[{}]", i))?;
        let group = group(&mut f, &known, &proxies.dns)?;
        // What other kinds of group take, which Mihomo passes over, as
        // templates apply one anchor to groups of every kind; and what only
        // a dashboard shows, which sail has none of yet.
        f.finish(
            COMMON,
            |key| {
                matches!(
                    key,
                    "tolerance" | "strategy" | "url" | "interval" | "icon" | "hidden"
                )
            },
            warnings,
        )?;
        out.outbounds.push(group);
    }
    // Mihomo's own: DIRECT, which is also where connections no rule matches
    // go, REJECT, and GLOBAL, unless a group takes the name.
    out.outbounds
        .push(json!({ "type": "direct", "tag": "DIRECT" }));
    out.outbounds
        .push(json!({ "type": "block", "tag": "REJECT" }));
    if !group_names.iter().any(|n| n == "GLOBAL") {
        let members: Vec<&str> = ["DIRECT", "REJECT"]
            .into_iter()
            .chain(
                names
                    .iter()
                    .map(String::as_str)
                    .filter(|n| !proxies.dns.contains(*n)),
            )
            .collect();
        out.outbounds.push(json!({
            "type": "selector",
            "tag": "GLOBAL",
            "outbounds": members,
        }));
    }
    let mut all: HashSet<String> = names.into_iter().collect();
    all.extend(BUILT_IN.iter().map(|s| s.to_string()));
    Ok(Policies {
        names: all,
        dns: proxies.dns.clone(),
    })
}

fn group(f: &mut Fields, known: &HashSet<String>, dns: &HashSet<String>) -> Result<Value> {
    let name = f.string("name")?.unwrap_or_default();
    let kind = f
        .string("type")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("type")))?
        .to_ascii_lowercase();
    let members = f.strings("proxies")?;
    let proxies_at = f.at("proxies");
    if members.is_empty() {
        return Err(anyhow!(
            "{}: a group of no proxies; sail does not read members from providers yet",
            proxies_at
        ));
    }
    for (i, member) in members.iter().enumerate() {
        if dns.contains(member) {
            return Err(anyhow!(
                "{}[{}]: {} is a dns proxy, which sail takes in rules alone",
                proxies_at,
                i,
                member
            ));
        }
        if !known.contains(member) {
            return Err(anyhow!(
                "{}[{}]: no proxy or group is named {:?}",
                proxies_at,
                i,
                member
            ));
        }
    }
    // REJECT-DROP, where a group has it, rejects as REJECT does.
    let members: Vec<String> = members
        .into_iter()
        .map(|m| {
            if m == "REJECT-DROP" {
                "REJECT".to_string()
            } else {
                m
            }
        })
        .collect();
    let mut o = Map::new();
    o.insert("tag".into(), json!(name));
    o.insert("outbounds".into(), json!(members));
    let url = f.string("url")?.unwrap_or_else(|| URL.to_string());
    let interval = f.int::<u64>("interval")?.unwrap_or(INTERVAL);
    let health = |o: &mut Map<String, Value>| {
        o.insert("url".into(), json!(url));
        if interval > 0 {
            o.insert("interval".into(), json!(format!("{}s", interval)));
        }
    };
    match kind.as_str() {
        "select" => {
            o.insert("type".into(), json!("selector"));
            f.take("url");
            f.take("interval");
        }
        "url-test" => {
            o.insert("type".into(), json!("urltest"));
            health(&mut o);
            if let Some(ms) = f.int::<u16>("tolerance")? {
                o.insert("tolerance".into(), json!(ms));
            }
        }
        "fallback" => {
            o.insert("type".into(), json!("fallback"));
            health(&mut o);
        }
        "load-balance" => {
            o.insert("type".into(), json!("load-balance"));
            health(&mut o);
            let strategy = f
                .string("strategy")?
                .unwrap_or_else(|| "consistent-hashing".to_string());
            match strategy.as_str() {
                "consistent-hashing" | "round-robin" | "sticky-sessions" => {
                    o.insert("strategy".into(), json!(strategy));
                }
                other => {
                    return Err(anyhow!(
                        "{}: {:?} is none of consistent-hashing, round-robin and \
                         sticky-sessions",
                        f.at("strategy"),
                        other
                    ))
                }
            }
        }
        "relay" | "smart" => {
            return Err(anyhow!(
                "{}: sail does not implement \"{}\" groups yet",
                f.at("type"),
                kind
            ))
        }
        other => {
            return Err(anyhow!(
                "{}: {:?} is none of select, url-test, fallback and load-balance",
                f.at("type"),
                other
            ))
        }
    }
    Ok(Value::Object(o))
}
