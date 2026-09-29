//! `rules` and `sub-rules`, as routing rules: each of Mihomo's rule types
//! sail has the condition of, split as Mihomo's `ParseRulePayload` splits
//! it. A logical rule (`AND`, `OR`, `NOT`) is sail's logical rule; a
//! `SUB-RULE` is its sub-rules, each put where it stands with the
//! condition that leads to it.

use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use super::fields::Fields;
use super::general::LISTENERS;
use super::group::Policies;
use super::node::Node;
use super::provider::Sets;
use super::Lowered;
use crate::config::rule_set::ClashBehavior;

/// A rule, split: its type, payload, target and parameters.
struct Split<'a> {
    kind: String,
    payload: String,
    target: &'a str,
    params: Vec<&'a str>,
}

/// Splits `rule` as Mihomo does; `need_target` is whether it names where
/// what it matches goes, as a rule in a logical one does not.
fn split(rule: &str, need_target: bool) -> Split<'_> {
    let mut items: Vec<&str> = rule.split(',').map(str::trim).collect();
    let kind = items[0].to_ascii_uppercase();
    let mut split = Split {
        kind,
        payload: String::new(),
        target: "",
        params: Vec::new(),
    };
    if items.len() < 2 {
        return split;
    }
    match split.kind.as_str() {
        "MATCH" => split.target = items[1],
        "NOT" | "OR" | "AND" | "SUB-RULE" | "DOMAIN-REGEX" | "PROCESS-NAME-REGEX"
        | "PROCESS-PATH-REGEX" => {
            if need_target {
                split.target = items[items.len() - 1];
                items.pop();
            }
            split.payload = items[1..].join(",");
        }
        _ => {
            split.payload = items[1].to_string();
            if items.len() > 2 {
                if need_target {
                    split.target = items[2];
                    split.params = items[3..].to_vec();
                } else {
                    split.params = items[2..].to_vec();
                }
            }
        }
    }
    split
}

/// What lowering the rules needs to keep.
struct Walk<'a> {
    policies: &'a Policies,
    sets: &'a mut Sets,
    sub_rules: IndexMap<String, Vec<String>>,
    out: &'a mut Lowered,
    /// Whether a rule before resolves the domain already.
    resolved: bool,
}

impl Walk<'_> {
    /// Adds a rule of `conditions`, all of which must hold, to `target`.
    fn push(&mut self, conditions: Vec<Map<String, Value>>, resolves: bool, target: Target) {
        if resolves && !self.resolved {
            // Mihomo resolves the domain at the first IP rule to match it
            // against, and a domain that does not resolve matches no IP
            // rule; so does sail, from here on.
            self.out
                .rules
                .push(json!({ "action": "resolve", "ignore_failure": true }));
            self.resolved = true;
        }
        if let Target::Pass = target {
            return;
        }
        let mut rule = match <[_; 1]>::try_from(conditions) {
            Ok([one]) => one,
            Err(many) => {
                let mut rule = Map::new();
                rule.insert("type".into(), json!("logical"));
                rule.insert("mode".into(), json!("and"));
                rule.insert(
                    "rules".into(),
                    Value::Array(many.into_iter().map(Value::Object).collect()),
                );
                rule
            }
        };
        target.apply(&mut rule);
        self.out.rules.push(Value::Object(rule));
    }

    /// The rules of the sub-rules `name`, each put where it stands, under
    /// `guard`: the conditions that lead to them. As in Mihomo, a
    /// `SUB-RULE` among them whose condition holds but none of whose own
    /// rules matches ends them, and the rules after it hold only where its
    /// condition does not.
    fn sub_rules(
        &mut self,
        name: &str,
        guard: Vec<(Map<String, Value>, bool)>,
        stack: &mut Vec<String>,
    ) -> Result<()> {
        if stack.iter().any(|n| n == name) {
            return Err(anyhow!(
                "sub-rules: {} leads back to itself: {} -> {}",
                name,
                stack.join(" -> "),
                name
            ));
        }
        let rules = self
            .sub_rules
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("no sub-rules are named {:?}", name))?;
        stack.push(name.to_string());
        let mut guard = guard;
        for (i, rule) in rules.iter().enumerate() {
            let at = format!("sub-rules.{}[{}]", name, i);
            let s = split(rule, true);
            if s.kind == "SUB-RULE" {
                let inner =
                    sub_condition(&s.payload, self.sets).map_err(|e| anyhow!("{}: {}", at, e))?;
                let mut nested = guard.clone();
                nested.push(inner.clone());
                self.sub_rules(s.target, nested, stack)
                    .map_err(|e| anyhow!("{}: {}", at, e))?;
                guard.push((not(inner.0), inner.1));
                continue;
            }
            let target = target(s.target, self.policies).map_err(|e| anyhow!("{}: {}", at, e))?;
            let mut conditions: Vec<_> = guard.clone();
            if s.kind != "MATCH" {
                conditions.push(condition(&s, self.sets).map_err(|e| anyhow!("{}: {}", at, e))?);
            }
            let resolves = conditions.iter().any(|(_, r)| *r);
            self.push(
                conditions.into_iter().map(|(c, _)| c).collect(),
                resolves,
                target,
            );
            if s.kind == "MATCH" {
                break;
            }
        }
        stack.pop();
        Ok(())
    }
}

/// The condition of `line`, a Clash rule without its target, as a
/// classical rule-provider holds it.
pub(super) fn headless(line: &str) -> Result<Map<String, Value>> {
    let s = split(line, false);
    match s.kind.as_str() {
        "" | "MATCH" | "SUB-RULE" | "RULE-SET" => {
            Err(anyhow!("{:?} is no rule a rule-provider holds", line))
        }
        _ => condition(&s, &mut Sets::none()).map(|(condition, _)| condition),
    }
}

/// A rule of a list that matches domains alone, as `dns.fake-ip-filter`
/// holds them in rule mode: its condition, none for `MATCH`, and its
/// target, as written.
pub(super) fn domain_rule(
    line: &str,
    sets: &mut Sets,
) -> Result<(Option<Map<String, Value>>, String)> {
    let s = split(line, true);
    if s.target.is_empty() {
        return Err(anyhow!("{:?}: no target", line));
    }
    let target = s.target.to_string();
    match s.kind.as_str() {
        "MATCH" => Ok((None, target)),
        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-REGEX" | "DOMAIN-WILDCARD"
        | "GEOSITE" => Ok((Some(condition(&s, sets)?.0), target)),
        "RULE-SET" => {
            if sets.provider(&s.payload)? == ClashBehavior::Ipcidr {
                return Err(anyhow!(
                    "RULE-SET: {:?} is a rule-set of IP prefixes, not of domains",
                    s.payload
                ));
            }
            Ok((Some(condition(&s, sets)?.0), target))
        }
        other => Err(anyhow!(
            "{} rules match no domain; only domain rules are allowed here",
            other
        )),
    }
}

/// A rule that holds where `condition` does not.
pub(super) fn not(condition: Map<String, Value>) -> Map<String, Value> {
    let mut rule = Map::new();
    rule.insert("type".into(), json!("logical"));
    rule.insert("mode".into(), json!("and"));
    rule.insert("rules".into(), json!([condition]));
    rule.insert("invert".into(), json!(true));
    rule
}

/// The condition of a `SUB-RULE`: `(TYPE,payload)`.
fn sub_condition(payload: &str, sets: &mut Sets) -> Result<(Map<String, Value>, bool)> {
    let inner = payload
        .strip_prefix('(')
        .and_then(|p| p.strip_suffix(')'))
        .ok_or_else(|| anyhow!("SUB-RULE: its condition is written (TYPE,payload)"))?;
    let s = split(inner, false);
    match s.kind.as_str() {
        "" | "MATCH" | "SUB-RULE" => Err(anyhow!("SUB-RULE: {:?} is no condition", inner)),
        _ => condition(&s, sets),
    }
}

/// The rules a logical rule's payload holds: `((A,a),(B,b))`, as Mihomo's
/// `format` and `findSubRuleRange` split it.
fn logical_parts(payload: &str) -> Result<Vec<&str>> {
    if !payload.starts_with('(') || !payload.ends_with(')') {
        return Err(anyhow!("its rules are written ((A,a),(B,b))"));
    }
    let mut stack = Vec::new();
    let mut ranges = Vec::new();
    for (i, c) in payload.char_indices() {
        match c {
            '(' => stack.push(i),
            ')' => {
                let start = stack
                    .pop()
                    .ok_or_else(|| anyhow!("a ')' without its '('"))?;
                ranges.push((start, i));
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(anyhow!("a '(' without its ')'"));
    }
    ranges.sort();
    let mut parts: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if start == 0 && end == payload.len() - 1 {
            continue;
        }
        if parts.iter().any(|(s, e)| *s < start && *e > end) {
            continue;
        }
        parts.push((start, end));
    }
    Ok(parts.into_iter().map(|(s, e)| &payload[s + 1..e]).collect())
}

/// A logical rule's conditions, sail's logical rule.
fn logical(kind: &str, payload: &str, sets: &mut Sets) -> Result<(Map<String, Value>, bool)> {
    let mut rules = Vec::new();
    let mut resolves = false;
    for part in logical_parts(payload).map_err(|e| anyhow!("{}: {}", kind, e))? {
        let s = split(part, false);
        match s.kind.as_str() {
            "" => return Err(anyhow!("{}: {:?} is no rule", kind, part)),
            "MATCH" | "SUB-RULE" => {
                return Err(anyhow!("{}: a {} rule cannot be within", kind, s.kind))
            }
            _ => {}
        }
        let (condition, r) = condition(&s, sets)?;
        resolves |= r;
        rules.push(Value::Object(condition));
    }
    let mut rule = Map::new();
    rule.insert("type".into(), json!("logical"));
    match kind {
        "NOT" => {
            if rules.len() != 1 {
                return Err(anyhow!("NOT: one rule within, not {}", rules.len()));
            }
            rule.insert("mode".into(), json!("and"));
            rule.insert("invert".into(), json!(true));
        }
        "AND" => {
            rule.insert("mode".into(), json!("and"));
        }
        _ => {
            rule.insert("mode".into(), json!("or"));
        }
    }
    if rules.is_empty() {
        return Err(anyhow!("{}: no rule within", kind));
    }
    rule.insert("rules".into(), Value::Array(rules));
    Ok((rule, resolves))
}

pub fn lower(
    doc: &mut Fields,
    policies: &Policies,
    sets: &mut Sets,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let mut sub_rules = IndexMap::new();
    if let Some(mut subs) = doc.map("sub-rules")? {
        for name in subs.keys() {
            let at = subs.at(&name);
            let rules = match subs.take(&name) {
                Some(Node::Seq(items)) => items
                    .iter()
                    .enumerate()
                    .map(|(i, n)| {
                        n.as_string()
                            .ok_or_else(|| anyhow!("{}[{}]: a rule, not {}", at, i, n.kind()))
                    })
                    .collect::<Result<Vec<_>>>()?,
                None => Vec::new(),
                Some(other) => return Err(anyhow!("{}: a list, not {}", at, other.kind())),
            };
            sub_rules.insert(name, rules);
        }
    }
    let mut walk = Walk {
        policies,
        sets,
        sub_rules,
        out,
        resolved: false,
    };
    // `mode: global` and `direct`, which the Clash API may switch to.
    walk.out
        .rules
        .push(json!({ "clash_mode": "Global", "outbound": "GLOBAL" }));
    walk.out
        .rules
        .push(json!({ "clash_mode": "Direct", "outbound": "DIRECT" }));
    let mut matched = false;
    let rules = doc.strings("rules")?;
    for (i, rule) in rules.iter().enumerate() {
        let at = format!("rules[{}]", i);
        if matched {
            warnings.push(format!(
                "{}: after MATCH, where no connection gets; ignored",
                at
            ));
            continue;
        }
        let s = split(rule, true);
        if s.kind == "SUB-RULE" {
            let condition =
                sub_condition(&s.payload, walk.sets).map_err(|e| anyhow!("{}: {}", at, e))?;
            walk.sub_rules(s.target, vec![condition], &mut Vec::new())
                .map_err(|e| anyhow!("{}: {}", at, e))?;
            continue;
        }
        let target = target(s.target, policies).map_err(|e| anyhow!("{}: {}", at, e))?;
        if s.kind == "MATCH" {
            match target {
                Target::Outbound(tag) => {
                    walk.out.route.insert("final".into(), json!(tag));
                }
                Target::Pass => {}
                other => {
                    let mut rule = Map::new();
                    // A condition every connection meets.
                    rule.insert("network".into(), json!(["tcp", "udp"]));
                    other.apply(&mut rule);
                    walk.out.rules.push(Value::Object(rule));
                }
            }
            matched = true;
            continue;
        }
        let (condition, resolves) =
            condition(&s, walk.sets).map_err(|e| anyhow!("{}: {}", at, e))?;
        walk.push(vec![condition], resolves, target);
    }
    if !walk.out.route.contains_key("final") {
        // Mihomo's, for what no rule matches.
        walk.out.route.insert("final".into(), json!("DIRECT"));
    }
    Ok(())
}

/// Where a rule sends what it matches.
enum Target {
    Outbound(String),
    Reject,
    Drop,
    HijackDns,
    /// Matching goes on with the next rule.
    Pass,
}

impl Target {
    fn apply(self, rule: &mut Map<String, Value>) {
        match self {
            Target::Outbound(tag) => {
                rule.insert("outbound".into(), json!(tag));
            }
            Target::Reject => {
                rule.insert("action".into(), json!("reject"));
            }
            Target::Drop => {
                rule.insert("action".into(), json!("reject"));
                rule.insert("method".into(), json!("drop"));
            }
            Target::HijackDns => {
                rule.insert("action".into(), json!("hijack-dns"));
            }
            Target::Pass => {}
        }
    }
}

fn target(name: &str, policies: &Policies) -> Result<Target> {
    match name {
        "" => Err(anyhow!("no policy to send what it matches to")),
        "REJECT" => Ok(Target::Reject),
        "REJECT-DROP" => Ok(Target::Drop),
        "PASS" => Ok(Target::Pass),
        "COMPATIBLE" => Err(anyhow!("COMPATIBLE is for groups of no members")),
        name if policies.dns.contains(name) => Ok(Target::HijackDns),
        name if policies.has(name) => Ok(Target::Outbound(name.to_string())),
        name => Err(anyhow!("no proxy or group is named {:?}", name)),
    }
}

/// The conditions of a rule, and whether it matches the destination's
/// addresses, which a domain is resolved to first.
fn condition(s: &Split, sets: &mut Sets) -> Result<(Map<String, Value>, bool)> {
    let mut rule = Map::new();
    let payload = s.payload.as_str();
    if payload.is_empty() {
        return Err(anyhow!("{}: no payload", s.kind));
    }
    let mut no_resolve = false;
    let mut source = false;
    for param in &s.params {
        match param.to_ascii_lowercase().as_str() {
            "no-resolve" => no_resolve = true,
            "src" => source = true,
            other => return Err(anyhow!("{}: unknown parameter {:?}", s.kind, other)),
        }
    }
    let mut resolves = false;
    let key = match s.kind.as_str() {
        "AND" | "OR" | "NOT" => return logical(&s.kind, payload, sets),
        "RULE-SET" => {
            let behavior = sets.provider(payload)?;
            rule.insert("rule_set".into(), json!([payload]));
            if source {
                rule.insert("rule_set_ip_cidr_match_source".into(), json!(true));
            }
            // A set of addresses, or of rules that may be, resolves the
            // domain first, as in Mihomo, unless told not to.
            let resolves = behavior != ClashBehavior::Domain && !no_resolve && !source;
            return Ok((rule, resolves));
        }
        "GEOSITE" => {
            rule.insert("rule_set".into(), json!([sets.geosite(payload)?]));
            return Ok((rule, false));
        }
        "GEOIP" | "SRC-GEOIP" => {
            rule.insert("rule_set".into(), json!([sets.geoip(payload)?]));
            let source = source || s.kind == "SRC-GEOIP";
            if source {
                rule.insert("rule_set_ip_cidr_match_source".into(), json!(true));
            }
            return Ok((rule, !no_resolve && !source));
        }
        "DOMAIN-WILDCARD" => {
            rule.insert("domain_regex".into(), json!([wildcard(payload)]));
            return Ok((rule, false));
        }
        "DOMAIN" => "domain",
        "DOMAIN-SUFFIX" => "domain_suffix",
        "DOMAIN-KEYWORD" => "domain_keyword",
        "DOMAIN-REGEX" => "domain_regex",
        "IP-CIDR" | "IP-CIDR6" if source => "source_ip_cidr",
        "IP-CIDR" | "IP-CIDR6" => {
            resolves = !no_resolve;
            "ip_cidr"
        }
        "SRC-IP-CIDR" => "source_ip_cidr",
        "PROCESS-NAME" => "process_name",
        "PROCESS-PATH" => "process_path",
        "PROCESS-PATH-REGEX" => "process_path_regex",
        "IN-USER" => "auth_user",
        "IN-NAME" => "inbound",
        "DST-PORT" | "SRC-PORT" => {
            let (ports, ranges) = ports(payload)?;
            let (one, many) = match s.kind.as_str() {
                "DST-PORT" => ("port", "port_range"),
                _ => ("source_port", "source_port_range"),
            };
            if !ports.is_empty() {
                rule.insert(one.into(), json!(ports));
            }
            if !ranges.is_empty() {
                rule.insert(many.into(), json!(ranges));
            }
            return Ok((rule, false));
        }
        "NETWORK" => {
            let network = payload.to_ascii_lowercase();
            if !matches!(network.as_str(), "tcp" | "udp") {
                return Err(anyhow!("NETWORK: {:?} is neither tcp nor udp", payload));
            }
            rule.insert("network".into(), json!(network));
            return Ok((rule, false));
        }
        "UID" => {
            let uid: i32 = payload
                .parse()
                .map_err(|_| anyhow!("UID: {:?} is not a user ID", payload))?;
            rule.insert("user_id".into(), json!([uid]));
            return Ok((rule, false));
        }
        "IN-TYPE" => {
            let kind = match payload.to_ascii_uppercase().as_str() {
                "HTTP" => "http",
                "SOCKS" | "SOCKS5" => "socks",
                "MIXED" => "mixed",
                "REDIR" => "redirect",
                "TPROXY" => "tproxy",
                "TUN" => {
                    rule.insert("inbound".into(), json!([super::tun::TAG]));
                    return Ok((rule, false));
                }
                other => {
                    return Err(anyhow!(
                        "IN-TYPE: sail does not implement {:?} yet, only HTTP, SOCKS5, MIXED, \
                         REDIR, TPROXY and TUN",
                        other
                    ))
                }
            };
            let tags: Vec<&str> = LISTENERS
                .iter()
                .filter(|(_, k, _)| *k == kind)
                .map(|(_, _, tag)| *tag)
                .collect();
            rule.insert("inbound".into(), json!(tags));
            return Ok((rule, false));
        }
        other => {
            return Err(anyhow!("sail does not implement {} rules yet", other));
        }
    };
    rule.insert(key.into(), json!([payload]));
    Ok((rule, resolves))
}

/// A domain wildcard as a regular expression: `*` any run of characters,
/// `?` one, as Mihomo's `wildcard.Match` has them.
fn wildcard(pattern: &str) -> String {
    let mut regex = String::from("^");
    for c in pattern.to_ascii_lowercase().chars() {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            c => regex.push_str(&regex_escape(c)),
        }
    }
    regex.push('$');
    regex
}

fn regex_escape(c: char) -> String {
    if "\\.+*?()|[]{}^$#&-~".contains(c) {
        format!("\\{}", c)
    } else {
        c.to_string()
    }
}

/// A port payload: `80`, `80/443`, `8000-9000`, or those with commas. Single
/// ports and ranges, the ranges as sail writes them (`8000:9000`).
fn ports(payload: &str) -> Result<(Vec<u16>, Vec<String>)> {
    let mut ports = Vec::new();
    let mut ranges = Vec::new();
    for part in payload
        .split(['/', ','])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let port = |p: &str| {
            p.trim()
                .parse::<u16>()
                .map_err(|_| anyhow!("{:?} is not a port", p))
        };
        match part.split_once('-') {
            Some((a, b)) => ranges.push(format!("{}:{}", port(a)?, port(b)?)),
            None => ports.push(port(part)?),
        }
    }
    Ok((ports, ranges))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_split_as_mihomo_s() {
        let s = split("DOMAIN-SUFFIX,example.com,Proxy", true);
        assert_eq!(
            (s.kind.as_str(), s.payload.as_str(), s.target),
            ("DOMAIN-SUFFIX", "example.com", "Proxy")
        );
        let s = split("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", true);
        assert_eq!(s.params, ["no-resolve"]);
        let s = split("domain-regex,^a{1,3}\\.example$,Proxy", true);
        assert_eq!(
            (s.kind.as_str(), s.payload.as_str(), s.target),
            ("DOMAIN-REGEX", "^a{1,3}\\.example$", "Proxy")
        );
        let s = split("MATCH,Final", true);
        assert_eq!(s.target, "Final");
    }

    #[test]
    fn ports_and_ranges() {
        assert_eq!(
            ports("80/443,8000-9000").unwrap(),
            (vec![80, 443], vec!["8000:9000".to_string()])
        );
        assert!(ports("http").is_err());
    }
}
