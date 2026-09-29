//! `[Proxy Group]`: each line `Name = type, member, ..., key=value` a
//! sail group of that type: `select`, `url-test`, `fallback` and
//! `load-balance` and `smart`. Its members are those it names, then those
//! of the groups `include-other-group` names, then every proxy with
//! `include-all-proxies`, the last two as `policy-regex-filter` picks them;
//! a group left with none is DIRECT, as Surge has it.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::general::General;
use super::params::{Params, Tier};
use super::proxy::{Kind, Proxies, Reject, BUILT_IN};
use super::text::{self, Line};
use super::Lowered;

use Tier::*;

/// The parameters of groups sail does not implement, or that mean nothing
/// but in Surge's interface.
const PARAMS: &[(&str, Tier)] = &[
    ("hidden", Silent),
    ("no-alert", Silent),
    ("icon-url", Silent),
    ("category", Silent),
    // No effect in Surge either, but on `policy-path`.
    ("url", Silent),
    ("update-interval", Silent),
    ("external-policy-modifier", Silent),
    ("external-policy-name-prefix", Silent),
    ("policy-path", Unsupported(" (C.5c)")),
    ("underlying-proxy", Unsupported(" (C.5c)")),
];

/// Whether a policy carries UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Udp {
    Yes,
    No,
    /// A group of some that do and some that do not.
    Some,
}

/// Where a rule sends what it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Outbound(String),
    Reject(Reject),
}

/// What rules may name: Surge's own policies, the proxies and the groups.
pub struct Policies {
    kinds: HashMap<String, Kind>,
    /// Each group's members, as outbounds.
    groups: HashMap<String, Vec<String>>,
}

impl Policies {
    /// Where what the policy `name` gets goes.
    pub fn target(&self, name: &str) -> Result<Target> {
        match name {
            "" => Err(anyhow!("no policy")),
            "DIRECT" => Ok(Target::Outbound("DIRECT".into())),
            "REJECT" | "REJECT-TINYGIF" => Ok(Target::Reject(Reject::Plain)),
            "REJECT-NO-DROP" => Ok(Target::Reject(Reject::NoDrop)),
            "REJECT-DROP" => Ok(Target::Reject(Reject::Drop)),
            "CELLULAR" | "CELLULAR-ONLY" | "HYBRID" | "NO-HYBRID" => Err(anyhow!(
                "{}: sail does not implement Surge iOS's cellular policies",
                name
            )),
            name if name.starts_with("DEVICE:") => {
                Err(anyhow!("{}: sail does not implement Surge Ponte", name))
            }
            name => match self.kinds.get(name) {
                Some(Kind::Reject(how)) => Ok(Target::Reject(*how)),
                Some(_) => Ok(Target::Outbound(name.to_string())),
                None if self.groups.contains_key(name) => Ok(Target::Outbound(name.to_string())),
                None => Err(anyhow!("no policy or group is named {:?}", name)),
            },
        }
    }

    /// Whether what goes to the outbound `name` may be UDP.
    pub fn udp(&self, name: &str) -> Udp {
        self.udp_of(name, &mut Vec::new())
    }

    fn udp_of(&self, name: &str, seen: &mut Vec<String>) -> Udp {
        if let Some(Kind::Proxy { udp: false }) = self.kinds.get(name) {
            return Udp::No;
        }
        let Some(members) = self.groups.get(name) else {
            return Udp::Yes;
        };
        if seen.iter().any(|s| s == name) {
            return Udp::Yes;
        }
        seen.push(name.to_string());
        let mut all = None;
        for member in members {
            let udp = self.udp_of(member, seen);
            all = match (all, udp) {
                (None, udp) => Some(udp),
                (Some(a), b) if a == b => Some(a),
                _ => Some(Udp::Some),
            };
        }
        seen.pop();
        all.unwrap_or(Udp::Yes)
    }
}

/// A group line, read.
struct Group {
    name: String,
    kind: String,
    members: Vec<String>,
    p: Params,
}

pub fn lower(
    lines: Vec<Line>,
    proxies: &Proxies,
    general: &General,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<Policies> {
    // Every name first: groups may name those after them.
    let mut groups: Vec<Group> = Vec::new();
    for line in lines {
        let at = format!("[Proxy Group] {}", line.loc);
        let (name, rest) = text::key_value(&line.text)
            .ok_or_else(|| anyhow!("{}: {:?} is not Name = type, ...", at, line.text))?;
        let name = text::unquote(&name);
        if BUILT_IN.contains(&name.as_str()) {
            return Err(anyhow!("{}: {} is Surge's own policy", at, name));
        }
        if proxies.kinds.contains_key(&name) || groups.iter().any(|g| g.name == name) {
            return Err(anyhow!("{}: {:?} names another policy or group", at, name));
        }
        let at = format!("{}: {}", at, name);
        let parts = text::split(&rest, false);
        let kind = parts[0].to_ascii_lowercase();
        match kind.as_str() {
            "select" | "url-test" | "fallback" | "load-balance" | "smart" => {}
            "subnet" | "ssid" => {
                return Err(anyhow!(
                    "{}: sail does not implement {} groups yet (C.5d)",
                    at,
                    kind
                ))
            }
            other => {
                return Err(anyhow!(
                    "{}: {:?} is none of select, url-test, fallback, load-balance, smart and \
                     subnet",
                    at,
                    other
                ))
            }
        }
        let mut p = Params::new(at.clone());
        let mut members = Vec::new();
        for part in &parts[1..] {
            if part.is_empty() {
                continue;
            }
            match text::param(part) {
                Some((key, value, stray)) => {
                    if stray {
                        warnings.push(format!(
                            "{}: {}: a parameter in quotes; read as {}={}",
                            at, key, key, value
                        ));
                    }
                    p.insert(&key, value, None);
                }
                None => members.push(text::unquote(part)),
            }
        }
        groups.push(Group {
            name,
            kind,
            members,
            p,
        });
    }
    let names: HashSet<String> = groups.iter().map(|g| g.name.clone()).collect();

    // Members, as each group names them.
    let mut resolved: HashMap<String, Vec<String>> = HashMap::new();
    let mut includes: HashMap<String, Vec<String>> = HashMap::new();
    let mut filters: HashMap<String, Option<String>> = HashMap::new();
    let mut all_proxies: HashSet<String> = HashSet::new();
    for g in &mut groups {
        let at = g.p.at("include-other-group");
        let others = g.p.list("include-other-group");
        for other in &others {
            if !names.contains(other) {
                return Err(anyhow!("{}: no group is named {:?}", at, other));
            }
        }
        includes.insert(g.name.clone(), others);
        filters.insert(g.name.clone(), g.p.string("policy-regex-filter"));
        if g.p.bool("include-all-proxies")?.unwrap_or(false) {
            all_proxies.insert(g.name.clone());
        }
    }
    let context = Context {
        groups: &groups,
        includes: &includes,
        filters: &filters,
        all_proxies: &all_proxies,
        proxies,
    };
    for g in &groups {
        let members = context.members(&g.name, &mut Vec::new(), warnings)?;
        resolved.insert(g.name.clone(), members);
    }

    let mut kinds: HashMap<String, Kind> = proxies.kinds.clone();
    let mut outbound_members: HashMap<String, Vec<String>> = HashMap::new();
    for mut g in groups {
        let at = g.p.path().to_string();
        let mut members = resolved.remove(&g.name).unwrap_or_default();
        for member in &members {
            let known = names.contains(member)
                || proxies.kinds.contains_key(member)
                || matches!(
                    member.as_str(),
                    "DIRECT" | "REJECT" | "REJECT-DROP" | "REJECT-NO-DROP" | "REJECT-TINYGIF"
                );
            if !known {
                return Err(anyhow!("{}: no policy or group is named {:?}", at, member));
            }
        }
        if g.kind == "smart" {
            // Only proxies, as Surge has it.
            members.retain(|m| matches!(proxies.kinds.get(m), Some(Kind::Proxy { .. })));
        }
        // The REJECT policies, where a group has them, reject as REJECT.
        let mut outbounds: Vec<String> = Vec::new();
        for m in members {
            let m = if m.starts_with("REJECT") && !proxies.kinds.contains_key(&m) {
                "REJECT".to_string()
            } else {
                m
            };
            if !outbounds.contains(&m) {
                outbounds.push(m);
            }
        }
        if outbounds.is_empty() {
            outbounds.push("DIRECT".to_string());
        }
        let value = group(&mut g, &outbounds, general, warnings)?;
        g.p.finish(PARAMS, "parameter", warnings)?;
        out.outbounds.push(value);
        kinds.remove(&g.name);
        outbound_members.insert(g.name, outbounds);
    }
    // Surge's own.
    out.outbounds
        .push(json!({ "type": "direct", "tag": "DIRECT" }));
    out.outbounds
        .push(json!({ "type": "block", "tag": "REJECT" }));
    let policies = Policies {
        kinds,
        groups: outbound_members,
    };
    cycles(&policies)?;
    for (at, via) in &proxies.detours {
        match policies.target(via) {
            Ok(Target::Outbound(_)) => {}
            Ok(Target::Reject(_)) => {
                return Err(anyhow!("{}: {} rejects; it dials nothing", at, via))
            }
            Err(e) => return Err(anyhow!("{}: {}", at, e)),
        }
    }
    Ok(policies)
}

/// A group within itself, which Surge rejects with, is an error.
fn cycles(policies: &Policies) -> Result<()> {
    fn walk(
        name: &str,
        p: &Policies,
        stack: &mut Vec<String>,
        done: &mut HashSet<String>,
    ) -> Result<()> {
        if done.contains(name) {
            return Ok(());
        }
        if let Some(i) = stack.iter().position(|s| s == name) {
            let mut path = stack[i..].to_vec();
            path.push(name.to_string());
            return Err(anyhow!(
                "[Proxy Group]: {} holds itself: {}",
                name,
                path.join(" -> ")
            ));
        }
        if let Some(members) = p.groups.get(name) {
            stack.push(name.to_string());
            for m in members {
                walk(m, p, stack, done)?;
            }
            stack.pop();
        }
        done.insert(name.to_string());
        Ok(())
    }
    let mut done = HashSet::new();
    let mut names: Vec<&String> = policies.groups.keys().collect();
    names.sort();
    for name in names {
        walk(name, policies, &mut Vec::new(), &mut done)?;
    }
    Ok(())
}

struct Context<'a> {
    groups: &'a [Group],
    includes: &'a HashMap<String, Vec<String>>,
    filters: &'a HashMap<String, Option<String>>,
    all_proxies: &'a HashSet<String>,
    proxies: &'a Proxies,
}

impl Context<'_> {
    /// The members of the group `name`: those it names, then those of the
    /// groups it includes, then every proxy, the last two filtered; each
    /// once.
    fn members(
        &self,
        name: &str,
        stack: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<String>> {
        let g = self
            .groups
            .iter()
            .find(|g| g.name == name)
            .expect("a group");
        if stack.iter().any(|s| s == name) {
            return Err(anyhow!(
                "{}: include-other-group leads back to it: {} -> {}",
                g.p.path(),
                stack.join(" -> "),
                name
            ));
        }
        stack.push(name.to_string());
        let mut members = g.members.clone();
        let mut included = Vec::new();
        for other in &self.includes[name] {
            included.extend(self.members(other, stack, warnings)?);
        }
        if self.all_proxies.contains(name) {
            included.extend(self.proxies.names.iter().cloned());
        }
        if let Some(pattern) = &self.filters[name] {
            let filter = crate::common::name_filter::NameFilter::new(pattern)
                .map_err(|e| anyhow!("{}: policy-regex-filter: {}", g.p.path(), e))?;
            included.retain(|n| filter.matches(n, warnings));
        }
        for m in included {
            if !members.contains(&m) {
                members.push(m);
            }
        }
        stack.pop();
        Ok(members)
    }
}

/// The group, of `members`.
fn group(
    g: &mut Group,
    members: &[String],
    general: &General,
    warnings: &mut Vec<String>,
) -> Result<Value> {
    let mut o = Map::new();
    o.insert("tag".into(), json!(g.name));
    o.insert("outbounds".into(), json!(members));
    let p = &mut g.p;
    let interval = p.num::<u64>("interval")?.unwrap_or(600);
    let health = |o: &mut Map<String, Value>| {
        o.insert("url".into(), json!(general.test_url));
        if interval > 0 {
            o.insert("interval".into(), json!(format!("{}s", interval)));
        }
    };
    // A smart group's is its own; the others test first as they always do.
    let evaluate = match g.kind.as_str() {
        "smart" => None,
        _ => p.take_at("evaluate-before-use"),
    };
    match g.kind.as_str() {
        "select" => {
            o.insert("type".into(), json!("selector"));
            // What only an automatic group takes, as a template may give it.
            p.take_at("persistent");
        }
        "smart" => {
            o.insert("type".into(), json!("smart"));
            // It tests its members every five minutes, whatever `interval`
            // says, as Surge's does.
            o.insert("url".into(), json!(general.test_url));
            if let Some(tolerance) = p.num::<u16>("tolerance")? {
                o.insert("tolerance".into(), json!(tolerance));
            }
            if let Some(seconds) = p.num::<f64>("timeout")? {
                o.insert(
                    "timeout".into(),
                    json!(format!("{}ms", (seconds * 1000.0).ceil().max(1.0) as u64)),
                );
            }
            if let Some((value, at)) = p.take_at("policy-priority") {
                o.insert(
                    "policy_priority".into(),
                    priorities(&value).map_err(|e| anyhow!("{}: {}", at, e))?,
                );
            }
            if let Some(yes) = p.bool("evaluate-before-use")? {
                o.insert("evaluate_before_use".into(), json!(yes));
            }
        }
        "url-test" => {
            o.insert("type".into(), json!("urltest"));
            health(&mut o);
            o.insert(
                "tolerance".into(),
                json!(p.num::<u16>("tolerance")?.unwrap_or(100)),
            );
            if let Some((_, at)) = p.take_at("timeout") {
                warnings.push(format!(
                    "{}: sail does not keep out members slower than this; ignored",
                    at
                ));
            }
        }
        "fallback" => {
            o.insert("type".into(), json!("fallback"));
            health(&mut o);
            // How slow a member may be, else as slow as a test may take.
            let timeout = p.num::<f64>("timeout")?;
            let seconds = timeout.map_or(general.test_timeout, |s| (s.ceil() as u64).max(1));
            o.insert("timeout".into(), json!(format!("{}s", seconds)));
        }
        "load-balance" => {
            o.insert("type".into(), json!("load-balance"));
            health(&mut o);
            // Persistent: by the target's host; else spread.
            let strategy = if p.bool("persistent")?.unwrap_or(false) {
                "consistent-hashing"
            } else {
                "round-robin"
            };
            o.insert("strategy".into(), json!(strategy));
            if let Some((_, at)) = p.take_at("timeout") {
                warnings.push(format!(
                    "{}: sail does not keep out members slower than this; ignored",
                    at
                ));
            }
        }
        _ => unreachable!("groups are of the types read"),
    }
    if let Some((_, at)) = evaluate {
        if g.kind != "select" {
            warnings.push(format!(
                "{}: sail uses a group's first member until its tests end; ignored",
                at
            ));
        }
    }
    for key in ["interval", "tolerance", "persistent", "timeout"] {
        p.take_at(key);
    }
    Ok(Value::Object(o))
}

/// `policy-priority`: `regex:factor` pairs separated by `;`, each factor
/// above 0.
fn priorities(value: &str) -> Result<Value> {
    let mut list = Vec::new();
    for pair in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (regex, factor) = pair
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("{:?} is not regex:factor", pair))?;
        let factor: f64 = factor
            .trim()
            .parse()
            .ok()
            .filter(|f: &f64| f.is_finite())
            .ok_or_else(|| anyhow!("{:?}: {:?} is not a number", pair, factor))?;
        if factor <= 0.0 {
            return Err(anyhow!("{:?}: a factor is above 0", pair));
        }
        list.push(json!({ "regex": regex, "factor": factor }));
    }
    Ok(Value::Array(list))
}
