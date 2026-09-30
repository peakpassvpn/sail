//! `[Proxy Group]`: each line `Name = type, member, ..., key=value` a
//! sail group of that type: `select`, `url-test`, `fallback` and
//! `load-balance` and `smart`. Its members are those it names, then those
//! of the groups `include-other-group` names, then every proxy with
//! `include-all-proxies`, then those of its `policy-path`, all but the
//! first as `policy-regex-filter` picks them; a group left with none is
//! DIRECT, as Surge has it.
//!
//! A `policy-path` is an outbound provider, remote or local, that groups
//! whose policy-paths are alike share: its members are the group's after
//! those of the profile, whatever order Surge would put them in, and a
//! member named as a policy of the profile is one besides it. Its
//! `external-policy-name-prefix` and `external-policy-modifier` are the
//! provider's `override` (the modifier's parameters as Mihomo names them;
//! those it has no name for are ignored, or an error where they would
//! route or secure otherwise), `underlying-proxy` its `detour`. The
//! `policy-regex-filter` of each group the members pass through on their
//! way, the group's own and those of the groups including it, are the
//! group's `filter`, and all of them must match; the provider's where a
//! prefix is added after it, or where the groups' filters would not be
//! the same for every provider of the group.
//!
//! A group's `underlying-proxy` dials its proxies through a policy, as
//! Surge does: each is a proxy of its own, `Name (via Policy)`, and those
//! of its policy-path are named so too.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::general::General;
use super::params::{Params, Tier};
use super::proxy::{self, Kind, Proxies, Reject, BUILT_IN};
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
    // No effect in Surge either.
    ("url", Silent),
    // Of a group without `policy-path`.
    ("update-interval", Silent),
    ("external-policy-modifier", Silent),
    ("external-policy-name-prefix", Silent),
];

/// How often a remote `policy-path` is downloaded again, as Surge does it
/// by default: a day.
const INTERVAL: u64 = 86400;
/// Ten years, for an interval below 0: never.
const NEVER: u64 = 10 * 365 * 86400;

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
    /// Each group's outbound providers.
    providers: HashMap<String, Vec<String>>,
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

    /// Whether `outbound` is the group `group`, or a group that holds it,
    /// itself or through its members.
    fn holds(&self, outbound: &str, group: &str) -> bool {
        self.reaches(outbound, &mut Vec::new(), &mut |name| name == group)
    }

    /// Whether `outbound` is a group that takes the members of the
    /// provider `provider`, itself or through its members.
    fn takes(&self, outbound: &str, provider: &str) -> bool {
        self.reaches(outbound, &mut Vec::new(), &mut |name| {
            self.providers
                .get(name)
                .is_some_and(|p| p.iter().any(|p| p == provider))
        })
    }

    /// Whether `found` holds of `name` or a group it holds.
    fn reaches(
        &self,
        name: &str,
        seen: &mut Vec<String>,
        found: &mut dyn FnMut(&str) -> bool,
    ) -> bool {
        if found(name) {
            return true;
        }
        if seen.iter().any(|s| s == name) {
            return false;
        }
        seen.push(name.to_string());
        let members = self.groups.get(name).cloned().unwrap_or_default();
        members.iter().any(|m| self.reaches(m, seen, found))
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
        // What a provider's members carry is known once they are read.
        if self.providers.get(name).is_some_and(|p| !p.is_empty()) {
            return Udp::Some;
        }
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

/// A `subnet` group (once `ssid`): the policy of the first expression
/// the network matches, else the default one; a `network` group.
struct Subnet {
    /// The expressions' conditions, and their policies, in order.
    branches: Vec<(Map<String, Value>, String)>,
    default: String,
}

impl Subnet {
    /// Every policy it may choose.
    fn policies(&self) -> Vec<String> {
        let mut policies: Vec<String> = Vec::new();
        for policy in self.branches.iter().map(|(_, p)| p).chain([&self.default]) {
            if !policies.contains(policy) {
                policies.push(policy.clone());
            }
        }
        policies
    }

    /// The `network` group, the REJECT policies as REJECT.
    fn lower(self, name: &str, proxies: &HashMap<String, Kind>) -> Value {
        let policy = |p: String| match p.starts_with("REJECT") && !proxies.contains_key(&p) {
            true => "REJECT".to_string(),
            false => p,
        };
        let branches: Vec<Value> = self
            .branches
            .into_iter()
            .map(|(mut conditions, p)| {
                conditions.insert("outbound".into(), json!(policy(p)));
                Value::Object(conditions)
            })
            .collect();
        json!({
            "type": "network",
            "tag": name,
            "branches": branches,
            "default": policy(self.default),
        })
    }
}

/// A `subnet` group's entries: `default`, `cellular` (before the others,
/// as it takes precedence), and `expression = policy`, in order; only
/// `hidden`, `icon-url` and `category` besides, as Surge has it.
fn subnet(at: &str, parts: &[String]) -> Result<Subnet> {
    let mut branches = Vec::new();
    let mut default = None;
    let mut cellular = None;
    for part in parts {
        if part.trim().is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .map(|(k, v)| (text::unquote(k.trim()), text::unquote(v.trim())))
            .ok_or_else(|| {
                anyhow!(
                    "{}: {:?}: a subnet group takes `default = policy` and \
                     `expression = policy`, no members",
                    at,
                    part
                )
            })?;
        if value.is_empty() {
            return Err(anyhow!("{}: {}: no policy", at, key));
        }
        match key.to_ascii_lowercase().as_str() {
            "default" => default = Some(value),
            "cellular" => cellular = Some(value),
            "hidden" | "icon-url" | "category" | "no-alert" => {}
            k if PARAMS.iter().any(|(p, _)| *p == k)
                || matches!(
                    k,
                    "policy-path"
                        | "include-all-proxies"
                        | "include-other-group"
                        | "policy-regex-filter"
                ) =>
            {
                return Err(anyhow!(
                    "{}: {}: subnet groups take no {}, as in Surge",
                    at,
                    key,
                    key
                ))
            }
            _ => {
                let conditions =
                    super::subnet::conditions(&key).map_err(|e| anyhow!("{}: {}", at, e))?;
                branches.push((conditions, value));
            }
        }
    }
    if let Some(policy) = cellular {
        let mut conditions = Map::new();
        conditions.insert("network_type".into(), json!(["cellular"]));
        branches.insert(0, (conditions, policy));
    }
    let default = default.ok_or_else(|| anyhow!("{}: default: missing", at))?;
    Ok(Subnet { branches, default })
}

/// A group line, read.
struct Group {
    name: String,
    kind: String,
    members: Vec<String>,
    p: Params,
}

/// The provider of a `policy-path`, but its tag: groups whose
/// policy-paths are alike share one.
#[derive(Debug, Clone, PartialEq)]
struct Source {
    /// A URL, or a file.
    path: String,
    remote: bool,
    /// Seconds, of a URL.
    interval: u64,
    /// `external-policy-name-prefix`.
    prefix: Option<String>,
    /// `external-policy-modifier`, in Mihomo's override keys, but its
    /// `underlying-proxy`.
    overrides: Map<String, Value>,
    /// The modifier's `underlying-proxy`.
    modifier_via: Option<String>,
    /// The `underlying-proxy` of the group the members are of, which names
    /// them too.
    via: Option<String>,
    /// Filters on the names as the policy-path gives them, any of which
    /// must match.
    filter: Vec<String>,
}

/// Members a group takes from a provider: those of `source` whose names
/// match every filter of `chain`.
#[derive(Debug, Clone)]
struct Entry {
    source: Source,
    chain: Vec<String>,
}

pub fn lower(
    lines: Vec<Line>,
    proxies: &Proxies,
    general: &General,
    dir: Option<&Path>,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<Policies> {
    // Every name first: groups may name those after them.
    let mut groups: Vec<Group> = Vec::new();
    let mut subnets: HashMap<String, Subnet> = HashMap::new();
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
                let subnet = subnet(&at, &parts[1..])?;
                let members = subnet.policies();
                subnets.insert(name.clone(), subnet);
                groups.push(Group {
                    name,
                    kind,
                    members,
                    p: Params::new(at),
                });
                continue;
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
    let mut sources: HashMap<String, Source> = HashMap::new();
    let mut vias: HashMap<String, (String, String)> = HashMap::new();
    for g in &mut groups {
        if let Some(source) = policy_path(&mut g.p, dir, warnings)? {
            sources.insert(g.name.clone(), source);
        }
        if let Some((via, at)) = g.p.take_at("underlying-proxy") {
            if via != "DIRECT" && !via.is_empty() {
                vias.insert(g.name.clone(), (text::unquote(&via), at));
            }
        }
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
        sources: &sources,
        vias: &vias,
        derived: RefCell::new(Vec::new()),
    };
    let mut entries: HashMap<String, Vec<Entry>> = HashMap::new();
    for g in &groups {
        let members = context.members(&g.name, &mut Vec::new(), warnings)?;
        resolved.insert(g.name.clone(), members);
        entries.insert(g.name.clone(), context.entries(&g.name));
    }

    let mut kinds: HashMap<String, Kind> = proxies.kinds.clone();
    // The proxies dialled through a group's `underlying-proxy`.
    for Derived {
        name,
        base,
        via,
        at,
    } in context.derived.take()
    {
        if kinds.contains_key(&name) || names.contains(&name) {
            return Err(anyhow!(
                "{}: {:?}, {} dialled through {}, names another policy or group",
                at,
                name,
                base,
                via
            ));
        }
        derive(&base, &name, &via, out);
        kinds.insert(name, kinds[&base]);
    }
    let mut registry = Registry::default();
    let mut outbound_members: HashMap<String, Vec<String>> = HashMap::new();
    let mut group_providers: HashMap<String, Vec<String>> = HashMap::new();
    for mut g in groups {
        let at = g.p.path().to_string();
        let mut members = resolved.remove(&g.name).unwrap_or_default();
        for member in &members {
            let known = names.contains(member)
                || kinds.contains_key(member)
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
            members.retain(|m| matches!(kinds.get(m), Some(Kind::Proxy { .. })));
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
        if let Some(subnet) = subnets.remove(&g.name) {
            out.outbounds.push(subnet.lower(&g.name, &proxies.kinds));
            kinds.remove(&g.name);
            outbound_members.insert(g.name.clone(), outbounds);
            continue;
        }
        let (providers, filter) = registry
            .assign(&g.name, entries.remove(&g.name).unwrap_or_default())
            .map_err(|e| anyhow!("{}: {}", at, e))?;
        if outbounds.is_empty() && providers.is_empty() {
            outbounds.push("DIRECT".to_string());
        }
        let mut value = group(&mut g, &outbounds, general, warnings)?;
        if !providers.is_empty() {
            value["providers"] = json!(providers);
            if !filter.is_empty() {
                value["filter"] = json!(filter);
            }
            // DIRECT while it has no member, as a group of none is.
            value["empty_fallback"] = json!("DIRECT");
        }
        g.p.finish(PARAMS, "parameter", warnings)?;
        out.outbounds.push(value);
        kinds.remove(&g.name);
        outbound_members.insert(g.name.clone(), outbounds);
        group_providers.insert(g.name, providers);
    }
    out.outbound_providers.extend(registry.providers);
    // Surge's own.
    out.outbounds
        .push(json!({ "type": "direct", "tag": "DIRECT" }));
    out.outbounds
        .push(json!({ "type": "block", "tag": "REJECT" }));
    let policies = Policies {
        kinds,
        groups: outbound_members,
        providers: group_providers,
    };
    cycles(&policies)?;
    // A group's proxies, or a provider's, dialled through what holds them
    // would go round in a loop.
    for (group, (via, at)) in &vias {
        match policies.target(via) {
            Ok(Target::Outbound(_)) => {}
            Ok(Target::Reject(_)) => {
                return Err(anyhow!("{}: {} rejects; it dials nothing", at, via))
            }
            Err(e) => return Err(anyhow!("{}: {}", at, e)),
        }
        if policies.holds(via, group) {
            return Err(anyhow!(
                "{}: {} holds the group; its proxies would be dialled through themselves",
                at,
                via
            ));
        }
    }
    for provider in &out.outbound_providers {
        let (Some(tag), Some(detour)) = (
            provider["tag"].as_str(),
            provider.get("detour").and_then(Value::as_str),
        ) else {
            continue;
        };
        if let Err(e) = policies.target(detour) {
            return Err(anyhow!(
                "[Proxy Group]: external-policy-modifier: underlying-proxy: {}",
                e
            ));
        }
        if policies.takes(detour, tag) {
            return Err(anyhow!(
                "[Proxy Group]: {} takes the policies of {}; they would be dialled through \
                 themselves",
                detour,
                provider_path(provider)
            ));
        }
    }
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
    /// Each group's `policy-path`.
    sources: &'a HashMap<String, Source>,
    /// Each group's `underlying-proxy`, and where it is.
    vias: &'a HashMap<String, (String, String)>,
    /// The proxies dialled through an `underlying-proxy`, as members name
    /// them.
    derived: RefCell<Vec<Derived>>,
}

/// A proxy dialled through a group's `underlying-proxy`.
struct Derived {
    /// `Base (via Policy)`.
    name: String,
    base: String,
    via: String,
    /// Where the `underlying-proxy` is.
    at: String,
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
        if let Some((via, at)) = self.vias.get(name) {
            members = members
                .into_iter()
                .map(|m| self.through(m, via, at))
                .collect();
        }
        stack.pop();
        Ok(members)
    }

    /// The member `member` dialled through `via`, where it is a proxy: of
    /// the profile, or dialled through another.
    fn through(&self, member: String, via: &str, at: &str) -> String {
        let mut derived = self.derived.borrow_mut();
        let base = match derived.iter().find(|d| d.name == member) {
            Some(d) => d.base.clone(),
            None => member,
        };
        if !matches!(self.proxies.kinds.get(&base), Some(Kind::Proxy { .. })) {
            return base;
        }
        let name = format!("{} (via {})", base, via);
        if !derived.iter().any(|d| d.name == name) {
            derived.push(Derived {
                name: name.clone(),
                base,
                via: via.to_string(),
                at: at.to_string(),
            });
        }
        name
    }

    /// The members the group `name` takes from providers: those of the
    /// groups it includes, then its own policy-path's, as the filters of
    /// the groups they pass through pick them.
    fn entries(&self, name: &str) -> Vec<Entry> {
        self.entries_of(name, &mut Vec::new())
    }

    fn entries_of(&self, name: &str, stack: &mut Vec<String>) -> Vec<Entry> {
        // `members` found includes that lead back.
        if stack.iter().any(|s| s == name) {
            return Vec::new();
        }
        stack.push(name.to_string());
        let filter = self.filters[name].clone();
        let mut entries = Vec::new();
        for other in &self.includes[name] {
            for mut entry in self.entries_of(other, stack) {
                entry.chain.extend(filter.clone());
                entries.push(entry);
            }
        }
        if let Some(source) = self.sources.get(name) {
            let mut source = source.clone();
            // The prefix comes after the group's filter.
            let chain = match (&source.prefix, &filter) {
                (Some(_), Some(filter)) => {
                    source.filter = vec![filter.clone()];
                    Vec::new()
                }
                _ => filter.into_iter().collect(),
            };
            entries.push(Entry { source, chain });
        }
        if let Some((via, _)) = self.vias.get(name) {
            for entry in &mut entries {
                entry.source.via = Some(via.clone());
            }
        }
        stack.pop();
        entries
    }
}

/// The providers a group takes members from, as their tags, and its
/// filter.
#[derive(Default)]
struct Registry {
    sources: Vec<(Source, String)>,
    providers: Vec<Value>,
}

impl Registry {
    /// The providers of `entries`, those not yet made made, for the group
    /// `group`; and the group's filter.
    fn assign(&mut self, group: &str, entries: Vec<Entry>) -> Result<(Vec<String>, Vec<String>)> {
        // Each provider once, with the filters of each way it is taken:
        // none where one takes them all.
        let mut by: Vec<(Source, Option<Vec<String>>)> = Vec::new();
        for Entry { source, chain } in entries {
            let chain = (!chain.is_empty()).then(|| compose(&chain));
            match by.iter_mut().find(|(s, _)| *s == source) {
                Some((_, filters)) => match (filters.as_mut(), chain) {
                    (Some(filters), Some(chain)) => {
                        if !filters.contains(&chain) {
                            filters.push(chain);
                        }
                    }
                    _ => *filters = None,
                },
                None => by.push((source, chain.map(|c| vec![c]))),
            }
        }
        let Some((_, first)) = by.first() else {
            return Ok((Vec::new(), Vec::new()));
        };
        let first = first.clone();
        // The group filters, where it would filter each provider alike;
        // else each provider does.
        let (filter, own) = if by.iter().all(|(_, f)| *f == first) {
            (first.unwrap_or_default(), false)
        } else {
            (Vec::new(), true)
        };
        let mut providers = Vec::new();
        for (mut source, filters) in by {
            if own {
                if let Some(filters) = filters {
                    if !source.filter.is_empty() {
                        return Err(anyhow!(
                            "policy-regex-filter: sail cannot filter the policies of {} both \
                             before external-policy-name-prefix names them and after, with \
                             other groups' policies filtered otherwise",
                            source.path
                        ));
                    }
                    source.filter = filters;
                }
            }
            providers.push(self.tag(source, group));
        }
        Ok((providers, filter))
    }

    /// The tag of the provider of `source`, made for `group` if there is
    /// none yet.
    fn tag(&mut self, source: Source, group: &str) -> String {
        if let Some((_, tag)) = self.sources.iter().find(|(s, _)| *s == source) {
            return tag.clone();
        }
        let mut tag = group.to_string();
        let mut n = 1;
        while self.sources.iter().any(|(_, t)| *t == tag) {
            n += 1;
            tag = format!("{} #{}", group, n);
        }
        let mut p = Map::new();
        p.insert("tag".into(), json!(tag));
        if source.remote {
            p.insert("type".into(), json!("remote"));
            p.insert("url".into(), json!(source.path));
            p.insert(
                "update_interval".into(),
                json!(format!("{}s", source.interval)),
            );
            // Directly, as Surge downloads it.
            p.insert("download_detour".into(), json!("DIRECT"));
        } else {
            p.insert("type".into(), json!("local"));
            p.insert("path".into(), json!(source.path));
        }
        if !source.filter.is_empty() {
            p.insert("filter".into(), json!(source.filter));
        }
        let mut overrides = source.overrides.clone();
        if let Some(prefix) = &source.prefix {
            overrides.insert("additional-prefix".into(), json!(prefix));
        }
        if let Some(via) = &source.via {
            overrides.insert("additional-suffix".into(), json!(format!(" (via {})", via)));
        }
        if !overrides.is_empty() {
            p.insert("override".into(), Value::Object(overrides));
        }
        if let Some(via) = source.via.as_ref().or(source.modifier_via.as_ref()) {
            p.insert("detour".into(), json!(via));
        }
        self.providers.push(Value::Object(p));
        self.sources.push((source, tag.clone()));
        tag
    }
}

/// One regular expression that matches where each of `chain` does.
fn compose(chain: &[String]) -> String {
    match chain {
        [one] => one.clone(),
        _ => {
            let mut all = "^".to_string();
            for filter in chain {
                all.push_str(&format!("(?=[\\s\\S]*?(?:{}))", filter));
            }
            all
        }
    }
}

/// Where a provider's policies are, as errors write it.
fn provider_path(provider: &Value) -> &str {
    provider
        .get("url")
        .or_else(|| provider.get("path"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// A group's `policy-path`, and the parameters of what it holds.
fn policy_path(
    p: &mut Params,
    dir: Option<&Path>,
    warnings: &mut Vec<String>,
) -> Result<Option<Source>> {
    let Some((path, at)) = p.take_at("policy-path") else {
        return Ok(None);
    };
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err(anyhow!("{}: empty", at));
    }
    let remote = path.starts_with("http://") || path.starts_with("https://");
    if !remote && path.contains("://") {
        return Err(anyhow!(
            "{}: {:?} is neither an http(s) URL nor a file",
            at,
            path
        ));
    }
    let interval = p.num::<i64>("update-interval")?;
    let path = match dir {
        Some(dir) if !remote && Path::new(&path).is_relative() => {
            dir.join(&path).to_string_lossy().to_string()
        }
        _ => path,
    };
    let prefix = p.string("external-policy-name-prefix");
    if let Some(prefix) = &prefix {
        if prefix.contains('=') {
            return Err(anyhow!(
                "{}: {:?} holds =, which a prefix may not",
                p.at("external-policy-name-prefix"),
                prefix
            ));
        }
    }
    let (overrides, modifier_via) = match p.take_at("external-policy-modifier") {
        Some((value, at)) => modifier(&value, &at, warnings)?,
        None => (Map::new(), None),
    };
    Ok(Some(Source {
        path,
        remote,
        // Below 0 never, as a rule-set's; 0 the day.
        interval: match interval {
            Some(seconds) if seconds > 0 => seconds as u64,
            Some(seconds) if seconds < 0 => NEVER,
            _ => INTERVAL,
        },
        prefix,
        overrides,
        modifier_via,
        via: None,
        filter: Vec::new(),
    }))
}

/// `external-policy-modifier`, `key=value,...` of Surge's policy
/// parameters: those with a name in Mihomo's `override`, in it, and the
/// `underlying-proxy`.
fn modifier(
    value: &str,
    at: &str,
    warnings: &mut Vec<String>,
) -> Result<(Map<String, Value>, Option<String>)> {
    let mut p = Params::new(at);
    for part in text::split(value, false) {
        if part.is_empty() {
            continue;
        }
        let (key, value, _) =
            text::param(&part).ok_or_else(|| anyhow!("{}: {:?} is not key=value", at, part))?;
        p.insert(&key, value, None);
    }
    let mut overrides = Map::new();
    let via = p.string("underlying-proxy").filter(|v| v != "DIRECT");
    if let Some(yes) = p.bool("skip-cert-verify")? {
        overrides.insert("skip-cert-verify".into(), json!(yes));
    }
    if let Some(interface) = p.string("interface") {
        overrides.insert("interface-name".into(), json!(interface));
    }
    if let Some((version, at)) = p.take_at("ip-version") {
        let mihomo = match version.to_ascii_lowercase().as_str() {
            "dual" => "dual",
            "v4-only" => "ipv4",
            "v6-only" => "ipv6",
            "prefer-v4" => "ipv4-prefer",
            "prefer-v6" => "ipv6-prefer",
            _ => {
                return Err(anyhow!(
                    "{}: {:?} is none of dual, v4-only, v6-only, prefer-v4 and prefer-v6",
                    at,
                    version
                ))
            }
        };
        overrides.insert("ip-version".into(), json!(mihomo));
    }
    // sail carries UDP through the proxies that relay it either way.
    p.bool("udp-relay")?;
    if p.bool("tfo")? == Some(true) {
        warnings.push(format!(
            "{}: tfo: sail does not implement TCP Fast Open; ignored",
            at
        ));
    }
    if p.bool("block-quic")? == Some(true) {
        warnings.push(format!(
            "{}: block-quic: sail does not block QUIC; ignored, and QUIC goes through the \
             policy",
            at
        ));
    }
    p.finish(&proxy::modifier_tiers(), "parameter", warnings)?;
    Ok((overrides, via))
}

/// The proxy `base`, dialled through `via`, as the outbound `name`.
fn derive(base: &str, name: &str, via: &str, out: &mut Lowered) {
    for list in [&mut out.outbounds, &mut out.endpoints] {
        if let Some(value) = list.iter().find(|v| v["tag"] == base) {
            let mut value = value.clone();
            value["tag"] = json!(name);
            value["detour"] = json!(via);
            list.push(value);
            return;
        }
    }
    unreachable!("a proxy is lowered")
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
