//! `proxy-groups`: `select`, `url-test`, `fallback` and `load-balance`, as
//! sail's groups of those kinds, and Mihomo's own policies: `DIRECT`,
//! `REJECT` and the `GLOBAL` group `mode: global` sends everything to.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::proxy::{Proxies, BUILT_IN};
use super::proxy_provider::{split, Providers};
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
];

/// The defaults of a group's health checks, Mihomo's.
const URL: &str = "https://www.gstatic.com/generate_204";
const INTERVAL: u64 = 300;

pub fn lower(
    doc: &mut Fields,
    proxies: &Proxies,
    providers: &Providers,
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
        .chain(["DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE"].map(String::from))
        .collect();
    // The proxies `include-all-proxies` takes, by name as Mihomo sorts them.
    let mut all_proxies: Vec<&str> = proxies
        .names
        .iter()
        .map(String::as_str)
        .filter(|n| !proxies.dns.contains(*n))
        .collect();
    all_proxies.sort();
    let context = Context {
        known: &known,
        dns: &proxies.dns,
        groups: &group_names,
        all_proxies: &all_proxies,
        providers,
    };
    for (i, node) in groups.into_iter().enumerate() {
        let mut f = Fields::of(node, &format!("proxy-groups[{}]", i))?;
        let group = group(&mut f, &context, warnings)?;
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
    // What a group of no members has, as Mihomo's: a DIRECT by another name.
    out.outbounds
        .push(json!({ "type": "direct", "tag": "COMPATIBLE" }));
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

/// What a group's members are named among.
struct Context<'a> {
    /// Proxies, groups and Mihomo's own policies.
    known: &'a HashSet<String>,
    /// The `dns` proxies.
    dns: &'a HashSet<String>,
    groups: &'a [String],
    /// The proxies, sorted, for `include-all-proxies`.
    all_proxies: &'a [&'a str],
    providers: &'a Providers,
}

fn group(f: &mut Fields, cx: &Context, warnings: &mut Vec<String>) -> Result<Value> {
    let name = f.string("name")?.unwrap_or_default();
    let kind = f
        .string("type")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("type")))?
        .to_ascii_lowercase();
    let mut members = f.strings("proxies")?;
    let proxies_at = f.at("proxies");
    for (i, member) in members.iter().enumerate() {
        if cx.dns.contains(member) {
            return Err(anyhow!(
                "{}[{}]: {} is a dns proxy, which sail takes in rules alone",
                proxies_at,
                i,
                member
            ));
        }
        if !cx.known.contains(member) {
            return Err(anyhow!(
                "{}[{}]: no proxy or group is named {:?}",
                proxies_at,
                i,
                member
            ));
        }
    }
    let filter = split(f.string("filter")?, '`');
    let exclude_filter = split(f.string("exclude-filter")?, '`');
    let exclude_type = split(f.string("exclude-type")?, '|');
    let include_all = f.bool("include-all")?.unwrap_or(false);
    let all_providers = include_all || f.bool("include-all-providers")?.unwrap_or(false);
    let all_proxies = include_all || f.bool("include-all-proxies")?.unwrap_or(false);
    // `include-all-providers` takes the place of `use`, as in Mihomo.
    let used = f.strings("use")?;
    let use_at = f.at("use");
    let providers: Vec<String> = if all_providers {
        cx.providers.names.clone()
    } else {
        for (i, p) in used.iter().enumerate() {
            if !cx.providers.has(p) {
                return Err(anyhow!(
                    "{}[{}]: no proxy-provider is named {:?}",
                    use_at,
                    i,
                    p
                ));
            }
        }
        used
    };
    let empty_fallback = f
        .string("empty-fallback")?
        .unwrap_or_else(|| "COMPATIBLE".to_string());
    if cx.groups.contains(&empty_fallback) || !cx.known.contains(&empty_fallback) {
        return Err(anyhow!(
            "{}: no proxy, not a group, is named {:?}",
            f.at("empty-fallback"),
            empty_fallback
        ));
    }
    if all_proxies {
        // The proxies whose names match a filter, or all without one.
        let picked = pick(cx.all_proxies, &filter, warnings)
            .map_err(|e| anyhow!("{}: {}", f.at("filter"), e))?;
        for proxy in picked {
            if !members.iter().any(|m| m == proxy) {
                members.push(proxy.to_string());
            }
        }
        if members.is_empty() && providers.is_empty() {
            members.push(empty_fallback.clone());
        }
    }
    if members.is_empty() && providers.is_empty() {
        return Err(anyhow!(
            "{}: a group of no proxies and no providers",
            proxies_at
        ));
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
    if !providers.is_empty() {
        // Of the providers' proxies alone; those of `include-all-proxies`
        // were picked above.
        if !filter.is_empty() {
            o.insert("filter".into(), json!(filter));
        }
    }
    // Mihomo has every group fall back so; only these can be left with
    // no member.
    let may_empty = !providers.is_empty() || !exclude_filter.is_empty() || !exclude_type.is_empty();
    for (key, list) in [
        ("exclude_filter", exclude_filter),
        ("exclude_type", exclude_type),
    ] {
        if !list.is_empty() {
            o.insert(key.into(), json!(list));
        }
    }
    if may_empty {
        o.insert("empty_fallback".into(), json!(empty_fallback));
    }
    // Without a URL of its own, the first provider's health check's, as
    // Mihomo has it.
    let provider_url = providers
        .iter()
        .find_map(|p| cx.providers.health_urls.get(p).cloned());
    if !providers.is_empty() {
        o.insert("providers".into(), json!(providers));
    }
    let url = f
        .string("url")?
        .or(provider_url)
        .unwrap_or_else(|| URL.to_string());
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
        // The Mihomo forks' (vernesong's), as sail's own smart group.
        "smart" => {
            o.insert("type".into(), json!("smart"));
            health(&mut o);
            if let Some(ms) = f.int::<u16>("tolerance")? {
                o.insert("tolerance".into(), json!(ms));
            }
            if let Some(ms) = f.int::<u64>("timeout")?.filter(|ms| *ms > 0) {
                o.insert("timeout".into(), json!(format!("{}ms", ms)));
            }
            if f.bool("prefer-asn")?.unwrap_or(false) {
                o.insert("prefer_asn".into(), json!(true));
            }
            let at = f.at("policy-priority");
            if let Some(priority) = f.string("policy-priority")? {
                let priority = policy_priority(&priority, &at, warnings);
                if !priority.is_empty() {
                    o.insert("policy_priority".into(), Value::Array(priority));
                }
            }
            for key in ["uselightgbm", "collectdata", "sample-rate", "strategy"] {
                if f.take(key).is_some() {
                    warnings.push(format!(
                        "{}: sail's smart group has no model; ignored",
                        f.at(key)
                    ));
                }
            }
        }
        "relay" => {
            return Err(anyhow!(
                "{}: sail does not implement \"{}\" groups yet",
                f.at("type"),
                kind
            ))
        }
        other => {
            return Err(anyhow!(
                "{}: {:?} is none of select, url-test, fallback, load-balance and smart",
                f.at("type"),
                other
            ))
        }
    }
    Ok(Value::Object(o))
}

/// The names `filters` pick of `names`, in order: any matching one, or
/// all without filters.
fn pick<'a>(
    names: &[&'a str],
    filters: &[String],
    warnings: &mut Vec<String>,
) -> Result<Vec<&'a str>> {
    if filters.is_empty() {
        return Ok(names.to_vec());
    }
    let filters = filters
        .iter()
        .map(|f| crate::common::name_filter::NameFilter::new(f))
        .collect::<Result<Vec<_>>>()?;
    Ok(names
        .iter()
        .copied()
        .filter(|n| filters.iter().any(|f| f.matches(n, warnings)))
        .collect())
}

/// The fork's `policy-priority`, `pattern:factor;…` split at the last
/// colon not escaped, as sail's `policy_priority`: the fork's factor is
/// how much more a member is wanted, sail's how much longer it seems, so
/// it is inverted. A pair the fork would pass over, with no factor or one
/// not above 0, is passed over with a warning. Patterns are the fork's
/// regular expressions, lookarounds and all.
fn policy_priority(value: &str, at: &str, warnings: &mut Vec<String>) -> Vec<Value> {
    let mut out = Vec::new();
    for pair in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let colon = pair.char_indices().rev().find(|&(i, c)| {
            c == ':' && pair[..i].chars().rev().take_while(|c| *c == '\\').count() % 2 == 0
        });
        let factor = colon.and_then(|(i, _)| pair[i + 1..].trim().parse::<f64>().ok());
        let (Some((i, _)), Some(factor)) = (colon, factor.filter(|f| *f > 0.0)) else {
            warnings.push(format!(
                "{}: {:?} is not pattern:factor, the factor above 0; passed over, as by Mihomo",
                at, pair
            ));
            continue;
        };
        let mut pattern = String::new();
        let mut chars = pair[..i].trim().chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => pattern.extend(chars.next()),
                c => pattern.push(c),
            }
        }
        out.push(json!({ "regex": pattern, "factor": 1.0 / factor }));
    }
    out
}
