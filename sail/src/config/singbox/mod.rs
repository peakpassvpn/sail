//! sing-box's JSON, sail's own format. The model is written in its shape,
//! so reading it is sorting out what sing-box 1.14 accepts and sail does not
//! implement (see [`upstream`]) before the schema reads the rest.

use anyhow::{anyhow, Result};
use serde::de::{DeserializeSeed, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::Value;

use super::model::Config;

pub mod jsonc;
pub mod upstream;

/// Measured in the default build, whose support tables it writes.
#[cfg(all(
    test,
    feature = "all-endpoints",
    feature = "rule-set",
    feature = "outbound-provider",
    feature = "api",
    feature = "clash-api",
    feature = "dns-doh",
    feature = "dns-h3"
))]
mod registry;

use upstream::Tier;

/// Reads a sing-box configuration.
pub fn parse(s: &str) -> Result<Config> {
    read(s, true)
}

/// `parse`; a field of `upstream` set to its zero value is unset, as in
/// sing-box, unless `zero_unset` is false, which takes it as set.
fn read(s: &str, zero_unset: bool) -> Result<Config> {
    // Comments and trailing commas, as sing-box takes them.
    let s = jsonc::strip(s);
    // Rule by rule when that reads it; anything wrong is read again whole,
    // which finds and words it as it always has.
    let (mut config, warnings) = match by_rule(&s, zero_unset) {
        Some(read) => read,
        None => whole(&s, zero_unset)?,
    };
    // After the schema, as sing-box finds them after what comes before
    // the inbounds.
    for (i, inbound) in config.inbounds.iter_mut().enumerate() {
        for name in upstream::LEGACY_INBOUND {
            if let Some(found) = inbound.options.remove(*name) {
                if !zero(&found) {
                    return Err(anyhow!(
                        "inbounds[{}].{}: {}",
                        i,
                        name,
                        upstream::LEGACY_INBOUND_WHY
                    ));
                }
            }
        }
    }
    config.validate()?;
    config.warnings = warnings;
    Ok(config)
}

/// The document as one `Value`, sorted out and read by the schema.
fn whole(s: &str, zero_unset: bool) -> Result<(Config, Vec<String>)> {
    let mut value: Value = serde_json::from_str(s).map_err(|e| anyhow!("{}", e))?;
    let warnings = sort_out(&mut value, zero_unset, Scope::Whole)?;
    let config: Config = serde_path_to_error::deserialize(value)
        .map_err(|e| anyhow!("{}: {}", super::model::path(&e), e.inner()))?;
    Ok((config, said(warnings)))
}

/// What `whole` reads, read with `route.rules` and `dns.rules` one rule at
/// a time: a profile of thousands of rules is never one `Value` beside the
/// rules read from it. None when anything fails, for `whole` to say what.
fn by_rule(s: &str, zero_unset: bool) -> Option<(Config, Vec<String>)> {
    let mut rules = Rules::default();
    let mut de = serde_json::Deserializer::from_str(s);
    let mut top = Top(&mut rules).deserialize(&mut de).ok()?;
    de.end().ok()?;
    let mut warnings = sort_out(&mut top, zero_unset, Scope::Whole).ok()?;
    let route = one_by_one(rules.route, "route.rules", zero_unset, &mut warnings)?;
    let dns = one_by_one(rules.dns, "dns.rules", zero_unset, &mut warnings)?;
    let mut config: Config = serde_json::from_value(top).ok()?;
    config.route.rules = route;
    config.dns.rules = dns;
    Some((config, said(warnings)))
}

/// The rules of `list`, each sorted out and read alone, in a list as long
/// as they are.
fn one_by_one<T: serde::de::DeserializeOwned>(
    raw: Option<&RawValue>,
    list: &'static str,
    zero_unset: bool,
    warnings: &mut Vec<(Order, String)>,
) -> Option<Vec<T>> {
    let Some(raw) = raw else {
        return Some(Vec::new());
    };
    let each: Vec<&RawValue> = serde_json::from_str(raw.get()).ok()?;
    let mut rules = Vec::with_capacity(each.len());
    for (i, rule) in each.into_iter().enumerate() {
        let mut rule: Value = serde_json::from_str(rule.get()).ok()?;
        warnings.extend(sort_out(&mut rule, zero_unset, Scope::Rule(list, i)).ok()?);
        rules.push(serde_json::from_value(rule).ok()?);
    }
    Some(rules)
}

/// The text of `route.rules` and `dns.rules`, which `Top` leaves out.
#[derive(Default)]
struct Rules<'a> {
    route: Option<&'a RawValue>,
    dns: Option<&'a RawValue>,
}

/// Reads the document into a `Value` as `serde_json` would, but for the
/// rules of `route` and `dns`: an empty list stands in for each, and its
/// text goes to `Rules`. A key given twice is the last, as in a `Value`.
struct Top<'a, 'r>(&'r mut Rules<'a>);

impl<'de> DeserializeSeed<'de> for Top<'de, '_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        de.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Top<'de, '_> {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let slot = match key.as_str() {
                "route" => Some(&mut self.0.route),
                "dns" => Some(&mut self.0.dns),
                _ => None,
            };
            let value = match slot {
                Some(slot) => {
                    *slot = None;
                    map.next_value_seed(Section(slot))?
                }
                None => map.next_value()?,
            };
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
}

/// `route` or `dns`, with its `rules` left as text.
struct Section<'a, 'r>(&'r mut Option<&'a RawValue>);

impl<'de> DeserializeSeed<'de> for Section<'de, '_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        de.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Section<'de, '_> {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = match key.as_str() {
                "rules" => {
                    *self.0 = Some(map.next_value()?);
                    Value::Array(Vec::new())
                }
                _ => map.next_value()?,
            };
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
}

impl Config {
    /// Parses a JSON configuration: sing-box's, with sail's extensions.
    pub fn from_json(s: &str) -> Result<Self> {
        parse(s)
    }
}

/// Where `sort_out` looks.
#[derive(Debug, Clone, Copy)]
enum Scope {
    /// The whole of what it is given.
    Whole,
    /// The rule at an index of a list (`route.rules`, `dns.rules`), given
    /// alone: the patterns under that list, from the rule.
    Rule(&'static str, usize),
}

impl Scope {
    /// The values `pattern` names, with where each is in what `sort_out`
    /// was given.
    fn find(self, value: &Value, pattern: &str) -> Vec<(At, Value)> {
        match self {
            Scope::Whole => find(value, pattern),
            Scope::Rule(list, _) => {
                let mut found = Vec::new();
                if let Some(rest) = pattern
                    .strip_prefix(list)
                    .and_then(|p| p.strip_prefix(".*."))
                {
                    let segments: Vec<&str> = rest.split('.').collect();
                    walk_rule(value, &segments, &mut Vec::new(), &mut found);
                }
                found
            }
        }
    }

    /// `at` as the document has it.
    fn show(self, at: &At) -> At {
        match self {
            Scope::Whole => at.clone(),
            Scope::Rule(list, i) => At(list
                .split('.')
                .map(|k| Step::Key(k.to_string()))
                .chain([Step::Index(i)])
                .chain(at.0.iter().cloned())
                .collect()),
        }
    }

    /// The type of the entry the field at `at`, found by `path`, is in.
    fn entry_type<'a>(self, value: &'a Value, path: &str, at: &At) -> Option<&'a str> {
        match self {
            Scope::Whole => entry_type(value, path, at),
            // The entry the pattern's `*` stands for is the rule.
            Scope::Rule(..) => value.get("type").and_then(Value::as_str),
        }
    }

    /// Where a warning about the match at `seq` of a pattern goes among
    /// those of the same pattern: in the order of the document.
    fn place(self, seq: usize) -> (usize, usize) {
        match self {
            Scope::Whole => (0, seq),
            Scope::Rule(_, i) => (i, seq),
        }
    }
}

/// Where a warning goes among all of them: by the step of `sort_out` that
/// found it, its pattern, then the document's order. The order `sort_out`
/// of the whole document says them in.
type Order = (u8, usize, (usize, usize));

/// The warnings, in their order.
fn said(mut warnings: Vec<(Order, String)>) -> Vec<String> {
    warnings.sort_by_key(|(order, _)| *order);
    warnings.into_iter().map(|(_, w)| w).collect()
}

/// Fails on the first field or value sail does not implement and cannot
/// ignore, and drops, with a warning each, those it can. One set to its
/// zero value (`""`, `false`, `0`, `[]`, `{}`) sing-box takes as unset:
/// dropped without a word, when `zero_unset`.
fn sort_out(value: &mut Value, zero_unset: bool, scope: Scope) -> Result<Vec<(Order, String)>> {
    for (path, values) in upstream::VALUES {
        for (at, found) in scope.find(value, path) {
            let names: Vec<&str> = match &found {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            if let Some(name) = names.into_iter().find(|n| values.contains(n)) {
                return Err(anyhow!(
                    "{}: sail does not implement \"{}\" yet",
                    scope.show(&at),
                    name
                ));
            }
        }
    }
    let mut warnings = Vec::new();
    if let Scope::Whole = scope {
        for (seq, warning) in services(value)?.into_iter().enumerate() {
            warnings.push(((1, 0, scope.place(seq)), warning));
        }
    }
    for (n, (path, no_effect, says)) in upstream::NO_EFFECT.iter().enumerate() {
        for (seq, (at, found)) in scope.find(value, path).into_iter().enumerate() {
            if found.as_str() == Some(no_effect) {
                warnings.push((
                    (2, n, scope.place(seq)),
                    format!("{}: {}", scope.show(&at), says),
                ));
            }
        }
    }
    let paths = upstream::GROUPS
        .iter()
        .flat_map(|g| g.paths.iter().map(move |p| (g, p)));
    for (n, (group, path)) in paths.enumerate() {
        for (seq, (at, found)) in scope.find(value, path).into_iter().enumerate() {
            let kind = scope.entry_type(value, path, &at);
            if !group.types.is_empty() && !kind.is_some_and(|k| group.types.contains(&k)) {
                continue;
            }
            if implemented_for(path, kind) {
                continue;
            }
            if zero_unset && zero(&found) {
                remove(value, &at);
                continue;
            }
            match group.tier {
                Tier::Unsupported => {
                    return Err(anyhow!(
                        "{}: sail does not implement this field yet",
                        scope.show(&at)
                    ));
                }
                Tier::Ignored => {
                    remove(value, &at);
                    warnings.push((
                        (3, n, scope.place(seq)),
                        format!(
                            "{}: sail does not implement this field; ignored",
                            scope.show(&at)
                        ),
                    ));
                }
            }
        }
    }
    for path in upstream::SILENT {
        for (at, _) in scope.find(value, path) {
            remove(value, &at);
        }
    }
    for path in upstream::EMPTIED {
        for (at, found) in scope.find(value, path) {
            if found.as_object().is_some_and(|o| o.is_empty()) {
                remove(value, &at);
            }
        }
    }
    Ok(warnings)
}

/// Whether `value` is the zero value of its type, which sing-box's options
/// take as unset.
fn zero(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// Drops the services sail can do without, with a warning each, and fails
/// on any other.
fn services(value: &mut Value) -> Result<Vec<String>> {
    let Some(Value::Array(services)) = value.get_mut("services") else {
        return Ok(Vec::new());
    };
    let mut warnings = Vec::new();
    for (i, service) in services.iter().enumerate() {
        let kind = service
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !upstream::IGNORED_SERVICES.iter().any(|(k, _)| *k == kind) {
            return Err(anyhow!(
                "services[{}].type: sail does not implement \"{}\" yet",
                i,
                kind
            ));
        }
        warnings.push(format!(
            "services[{}]: sail does not run the {} service; ignored",
            i, kind
        ));
    }
    if let Some(map) = value.as_object_mut() {
        map.remove("services");
    }
    Ok(warnings)
}

/// A step of a concrete path.
#[derive(Debug, Clone, PartialEq)]
enum Step {
    Key(String),
    Index(usize),
}

/// A concrete path, written as the schema's errors write theirs.
#[derive(Debug, Clone, PartialEq)]
struct At(Vec<Step>);

impl std::fmt::Display for At {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (i, step) in self.0.iter().enumerate() {
            match step {
                Step::Key(k) if i == 0 => write!(f, "{}", k)?,
                Step::Key(k) => write!(f, ".{}", k)?,
                Step::Index(n) => write!(f, "[{}]", n)?,
            }
        }
        Ok(())
    }
}

/// The values `pattern` names, with where each is.
fn find(value: &Value, pattern: &str) -> Vec<(At, Value)> {
    let mut found = Vec::new();
    let segments: Vec<&str> = pattern.split('.').collect();
    walk(value, &segments, &mut Vec::new(), &mut found);
    found
}

fn walk(value: &Value, segments: &[&str], at: &mut Vec<Step>, found: &mut Vec<(At, Value)>) {
    let Some((segment, rest)) = segments.split_first() else {
        found.push((At(at.clone()), value.clone()));
        return;
    };
    let mut visit = |step: Step, child: &Value| {
        at.push(step);
        walk(child, rest, at, found);
        at.pop();
    };
    match value {
        Value::Object(map) if *segment == "*" => {
            for (k, v) in map {
                visit(Step::Key(k.clone()), v);
            }
        }
        Value::Object(map) => {
            // `key[type]`: the object at `key`, of that type.
            let (key, kind) = match segment.strip_suffix(']').and_then(|s| s.split_once('[')) {
                Some((key, kind)) => (key, Some(kind)),
                None => (*segment, None),
            };
            if let Some(v) = map.get(key) {
                if kind.is_none_or(|k| v.get("type").and_then(Value::as_str) == Some(k)) {
                    visit(Step::Key(key.to_string()), v);
                }
            }
        }
        Value::Array(list) if *segment == "*" => {
            let rules = matches!(at.last(), Some(Step::Key(k)) if k == "rules");
            for (i, v) in list.iter().enumerate() {
                at.push(Step::Index(i));
                match rules {
                    true => walk_rule(v, rest, at, found),
                    false => walk(v, rest, at, found),
                }
                at.pop();
            }
        }
        _ => {}
    }
}

/// `walk` from a rule, and from each rule it combines, however deep.
fn walk_rule(rule: &Value, segments: &[&str], at: &mut Vec<Step>, found: &mut Vec<(At, Value)>) {
    walk(rule, segments, at, found);
    if let Some(Value::Array(rules)) = rule.get("rules") {
        at.push(Step::Key("rules".to_string()));
        for (i, sub) in rules.iter().enumerate() {
            at.push(Step::Index(i));
            walk_rule(sub, segments, at, found);
            at.pop();
        }
        at.pop();
    }
}

/// The type of the entry the field at `at`, found by `path`, is in: the
/// entry the pattern's first `*` stands for, its inbound or outbound.
fn entry_type<'a>(value: &'a Value, path: &str, at: &At) -> Option<&'a str> {
    let depth = path.split('.').position(|s| s == "*")? + 1;
    let mut entry = value;
    for step in at.0.get(..depth)? {
        entry = match (step, entry) {
            (Step::Key(k), Value::Object(map)) => map.get(k)?,
            (Step::Index(i), Value::Array(list)) => list.get(*i)?,
            _ => return None,
        };
    }
    entry.get("type").and_then(Value::as_str)
}

/// Whether sail implements the field `path` names for entries of type
/// `kind`; see `upstream::IMPLEMENTED_FOR`.
fn implemented_for(path: &str, kind: Option<&str>) -> bool {
    upstream::IMPLEMENTED_FOR
        .iter()
        .any(|(p, types)| *p == path && kind.is_some_and(|k| types.contains(&k)))
}

fn remove(value: &mut Value, at: &At) {
    let Some((last, parents)) = at.0.split_last() else {
        return;
    };
    let mut value = value;
    for step in parents {
        value = match (step, value) {
            (Step::Key(k), Value::Object(map)) => match map.get_mut(k) {
                Some(v) => v,
                None => return,
            },
            (Step::Index(i), Value::Array(list)) => match list.get_mut(*i) {
                Some(v) => v,
                None => return,
            },
            _ => return,
        };
    }
    if let (Step::Key(k), Value::Object(map)) = (last, value) {
        map.remove(k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inbound_detour_is_only_shadowtls_s() {
        let err =
            parse(r#"{ "inbounds": [{ "type": "socks", "listen_port": 1080, "detour": "x" }] }"#)
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "inbounds[0].detour: sail does not implement this field yet"
        );
        let config = parse(
            r#"{ "inbounds": [
                { "type": "shadowtls", "listen_port": 443, "detour": "ss" },
                { "type": "shadowsocks", "tag": "ss" }
            ] }"#,
        )
        .unwrap();
        assert_eq!(config.inbounds[0].options["detour"], "ss");
    }

    #[test]
    fn a_field_sail_can_ignore_is_dropped_with_a_warning() {
        let config = parse(
            r#"{
                "$schema": "https://example.com/schema.json",
                "experimental": { "cache_file": { "enabled": true, "store_rdrc": true } },
                "outbounds": [{ "type": "direct", "tcp_multi_path": true }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            config.warnings,
            [
                "experimental.cache_file.store_rdrc: sail does not implement this field; ignored",
                "outbounds[0].tcp_multi_path: sail does not implement this field; ignored",
            ]
        );
        assert!(!config.outbounds[0].options.contains_key("tcp_multi_path"));
    }

    #[test]
    fn legacy_inbound_fields_are_refused() {
        let err = parse(
            r#"{ "inbounds": [{ "type": "mixed", "listen_port": 1080, "sniff": false,
                 "sniff_override_destination": true }] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "inbounds[0].sniff_override_destination: {}",
                upstream::LEGACY_INBOUND_WHY
            )
        );
        // Unset at their zero value, as in sing-box.
        let config = parse(
            r#"{ "inbounds": [{ "type": "tun", "address": ["172.19.0.1/30"],
                 "sniff": false, "domain_strategy": "" }] }"#,
        )
        .unwrap();
        assert!(!config.inbounds[0].options.contains_key("sniff"));
        assert!(config.warnings.is_empty());
    }

    #[test]
    fn a_zero_value_is_unset() {
        let config = parse(
            r#"{ "inbounds": [{ "type": "socks", "listen_port": 1080, "detour": "",
                   "tcp_fast_open": false, "udp_nat_max": 0 }],
                 "outbounds": [{ "type": "trojan", "server": "a", "server_port": 443,
                   "password": "p", "network": "", "tls": { "enabled": true,
                   "cipher_suites": [], "ech": { "enabled": true,
                   "config_path": "" } } }],
                 "ntp": {} }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
        let tls = &config.outbounds[0].options["tls"];
        assert!(tls.get("cipher_suites").is_none() && tls["ech"].get("config_path").is_none());
        assert!(!config.inbounds[0].options.contains_key("detour"));
        // Set, it is what it was.
        let err =
            parse(r#"{ "inbounds": [{ "type": "socks", "listen_port": 1080, "detour": "x" }] }"#)
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "inbounds[0].detour: sail does not implement this field yet"
        );
    }

    /// A `direct` rule is read, with a warning: it has no effect, as in
    /// sing-box 1.14.1.
    #[test]
    fn a_direct_rule_is_warned_of() {
        let config = parse(
            r#"{ "outbounds": [{ "type": "direct", "tag": "d" }],
                 "route": { "rules": [{ "port": 1, "outbound": "d" },
                   { "port": 2, "action": "direct", "connect_timeout": "2s" }] } }"#,
        )
        .unwrap();
        assert_eq!(
            config.warnings,
            ["route.rules[1].action: the direct action has no effect, as in sing-box 1.14.1"]
        );
        assert_eq!(
            config.route.rules[1].action(),
            crate::config::model::RuleAction::Direct
        );
    }

    #[test]
    fn a_field_that_would_change_routing_is_an_error() {
        let err = parse(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [{ "interface_address": { "eth0": "10.0.0.0/8" }, "outbound": "direct" }] }
            }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route.rules[0].interface_address: sail does not implement this field yet"
        );
    }

    #[test]
    fn a_value_sail_lacks_is_an_error() {
        for (rule, message) in [
            (
                r#"{ "action": "predefined", "port": 53 }"#,
                r#"route.rules[0].action: sail does not implement "predefined" yet"#,
            ),
            (
                r#"{ "action": "sniff", "sniffer": ["tls", "ssh"] }"#,
                r#"route.rules[0].sniffer: sail does not implement "ssh" yet"#,
            ),
        ] {
            let err = parse(&format!(
                r#"{{ "outbounds": [{{ "type": "direct" }}], "route": {{ "rules": [{}] }} }}"#,
                rule
            ))
            .unwrap_err();
            assert_eq!(err.to_string(), message);
        }
    }

    #[test]
    fn the_rules_a_logical_one_combines_are_sorted_out_too() {
        let err = parse(
            r#"{ "outbounds": [{ "type": "direct", "tag": "d" }],
                 "route": { "rules": [{ "type": "logical", "mode": "and", "outbound": "d",
                   "rules": [{ "port": 53 }, { "type": "logical", "mode": "or",
                     "rules": [{ "preferred_by": "d" }] }] }] } }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route.rules[0].rules[1].rules[0].preferred_by: sail does not implement this field yet"
        );
        // A response of their own, as sing-box's DNS rules may name.
        parse(
            r#"{ "dns": { "servers": [{ "type": "local" }], "rules": [
                   { "domain": "a", "action": "evaluate", "server": "local" },
                   { "type": "logical", "mode": "and", "server": "local",
                     "rules": [{ "match_response": true, "ip_accept_any": true }] }] } }"#,
        )
        .unwrap();
    }

    #[test]
    fn services_are_dropped_or_refused_by_type() {
        let config = parse(
            r#"{ "outbounds": [{ "type": "direct" }], "services": [
                 { "type": "api", "listen": "0.0.0.0", "listen_port": 9090,
                   "secret": "s", "dashboard": { "enabled": true, "path": "dashboard" } }
               ] }"#,
        )
        .unwrap();
        assert_eq!(
            config.warnings,
            ["services[0]: sail does not run the api service; ignored"]
        );
        let err = parse(
            r#"{ "outbounds": [{ "type": "direct" }], "services": [
                 { "type": "api" }, { "type": "resolved", "listen": "127.0.0.53" }
               ] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "services[1].type: sail does not implement \"resolved\" yet"
        );
    }

    #[test]
    fn domain_strategy_and_resolver_options_are_read() {
        let config = parse(
            r#"{ "dns": { "servers": [
                   { "type": "udp", "tag": "u", "server": "1.1.1.1" },
                   { "type": "tls", "tag": "t", "server": "dns.example",
                     "domain_strategy": "ipv4_only",
                     "domain_resolver": { "server": "u", "client_subnet": "1.2.3.0/24" } }
                 ] },
                 "outbounds": [{ "type": "direct", "domain_strategy": "ipv6_only",
                   "domain_resolver": { "server": "u", "timeout": "1s",
                     "disable_cache": true, "rewrite_ttl": 30,
                     "disable_optimistic_cache": true } }],
                 "route": { "default_domain_resolver": { "server": "u",
                   "client_subnet": "2001:db8::/48" } } }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
        let resolver: crate::config::model::DomainResolver =
            serde_json::from_value(config.outbounds[0].options["domain_resolver"].clone()).unwrap();
        assert!(resolver.disable_optimistic_cache);
        let resolver = config.route.default_domain_resolver.unwrap();
        assert_eq!(resolver.client_subnet, "2001:db8::/48".parse().ok());
    }

    #[test]
    fn a_route_rule_has_no_response_to_match() {
        let err = parse(
            r#"{ "outbounds": [{ "type": "direct" }],
                 "route": { "rules": [{ "ip_accept_any": true, "outbound": "direct" }] } }"#,
        )
        .unwrap_err();
        assert!(
            format!("{:#}", err)
                .contains("route.rules[0].ip_accept_any: unknown field `ip_accept_any`"),
            "{:#}",
            err
        );
    }

    #[test]
    fn http_clients_are_checked() {
        let with = |clients: &str, route: &str| {
            parse(&format!(
                r#"{{ "outbounds": [{{ "type": "direct", "tag": "direct" }}],
                     "http_clients": {}, "route": {} }}"#,
                clients, route
            ))
        };
        let remote = |client: &str| {
            format!(
                r#"{{ "rule_set": [{{ "type": "remote", "tag": "s",
                     "url": "https://example.com/s.srs"{} }}] }}"#,
                client
            )
        };
        let config = with(
            r#"[{ "tag": "c", "version": 2, "idle_timeout": "1m",
                  "headers": { "Authorization": "Bearer t", "X-A": ["1", "2"] } }]"#,
            &remote(r#", "http_client": "c""#),
        )
        .unwrap();
        assert_eq!(
            config.warnings,
            [
                "http_clients[0].version: sail does not implement this field; ignored",
                "http_clients[0].idle_timeout: sail does not implement this field; ignored",
            ]
        );
        assert_eq!(
            config.http_clients[0].header_lines(),
            [
                ("Authorization".to_string(), "Bearer t".to_string()),
                ("X-A".to_string(), "1".to_string()),
                ("X-A".to_string(), "2".to_string()),
            ]
        );
        // In place, its tag names nothing.
        with(
            "[]",
            &remote(r#", "http_client": { "tag": "none", "detour": "direct" }"#),
        )
        .unwrap();
        for (clients, route, message) in [
            (
                r#"[{ "detour": "direct" }]"#,
                "{}".to_string(),
                "http_clients[0].tag: missing",
            ),
            (
                r#"[{ "tag": "c" }, { "tag": "c" }]"#,
                "{}".to_string(),
                "http_clients[1]: another http client is tagged [c]",
            ),
            (
                r#"[{ "tag": "c", "detour": "proxy" }]"#,
                "{}".to_string(),
                "http_clients[0]: detour: outbound [proxy] does not exist",
            ),
            (
                r#"[{ "tag": "c", "detour": "direct", "routing_mark": 1 }]"#,
                "{}".to_string(),
                "http_clients[0]: routing_mark: has no effect with a detour; set it on [direct]",
            ),
            (
                r#"[{ "tag": "c", "headers": { "X-A": "1\r\nX-B: 2" } }]"#,
                "{}".to_string(),
                r#"http_clients[0]: headers: X-A: "1\r\nX-B: 2" breaks the line"#,
            ),
            (
                r#"[{ "tag": "c", "tls": { "enabled": true } }]"#,
                "{}".to_string(),
                "http_clients[0].tls: sail does not implement this field yet",
            ),
            (
                "[]",
                r#"{ "default_http_client": "c" }"#.to_string(),
                "route.default_http_client: http client [c] does not exist",
            ),
            (
                "[]",
                remote(r#", "http_client": "c""#),
                "route.rule_set[0].http_client: http client [c] does not exist",
            ),
            (
                r#"[{ "tag": "c" }]"#,
                remote(r#", "http_client": "c", "download_detour": "direct""#),
                "route.rule_set[0]: http_client: not with download_detour, which it replaces",
            ),
        ] {
            let err = with(clients, &route).unwrap_err();
            assert_eq!(format!("{:#}", err), message, "{} {}", clients, route);
        }
    }

    #[test]
    fn outbound_client_certificates_and_disable_sni_pass_through() {
        let config = parse(
            r#"{ "outbounds": [{ "type": "trojan", "server": "a", "server_port": 443,
                 "password": "p", "tls": { "enabled": true, "disable_sni": true,
                 "client_certificate_path": "c.crt", "client_key_path": "c.key" } }] }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty());
        let tls = &config.outbounds[0].options["tls"];
        assert_eq!(tls["disable_sni"], true);
        assert_eq!(tls["client_key_path"], "c.key");
        // An inbound verifying clients' certificates is another matter.
        let err = parse(
            r#"{ "inbounds": [{ "type": "trojan", "listen_port": 443, "users": [],
                 "tls": { "enabled": true, "client_certificate_path": ["ca.crt"] } }] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "inbounds[0].tls.client_certificate_path: sail does not implement this field yet"
        );
    }

    #[test]
    fn dial_fields_sail_implements_pass_through() {
        let config = parse(
            r#"{ "outbounds": [{ "type": "direct", "inet4_bind_address": "192.0.2.1",
                 "inet6_bind_address": "2001:db8::1" }] }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty());
        assert!(config.outbounds[0]
            .options
            .contains_key("inet4_bind_address"));
        assert!(config.outbounds[0]
            .options
            .contains_key("inet6_bind_address"));
    }

    #[test]
    fn tcp_keep_alive_fields_are_read() {
        use crate::net::TcpKeepAlive;
        use std::time::Duration;

        let config = parse(
            r#"{ "inbounds": [{ "type": "mixed", "listen_port": 1080,
                   "tcp_keep_alive": "1m", "tcp_keep_alive_interval": "10s" }],
                 "outbounds": [{ "type": "direct", "tcp_keep_alive": "2m",
                   "tcp_keep_alive_interval": "20s" },
                   { "type": "direct", "tag": "off", "disable_tcp_keep_alive": true }] }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
        assert_eq!(
            config.inbounds[0].tcp_keep_alive(),
            Some(TcpKeepAlive {
                idle: Duration::from_secs(60),
                interval: Duration::from_secs(10),
            })
        );
        let dial = |i: usize| {
            let (_, blocks) =
                crate::transport::layers::Blocks::DIAL.split(&config.outbounds[i].options);
            crate::config::model::parse_options::<crate::transport::layers::OutboundBlocks>(
                "outbound", "t", &blocks,
            )
            .unwrap()
            .dialer("t", "direct", &Default::default(), None)
            .unwrap()
            .spec()
            .tcp_keep_alive
        };
        assert_eq!(
            dial(0),
            Some(TcpKeepAlive {
                idle: Duration::from_secs(120),
                interval: Duration::from_secs(20),
            })
        );
        assert_eq!(dial(1), None);
    }

    /// An outbound's `protect_path` protects its own sockets, and not
    /// another outbound's.
    #[cfg(all(unix, feature = "outbound-direct"))]
    #[tokio::test]
    async fn protect_path_protects_the_sockets_of_its_outbound() {
        use crate::net::dial::protect_server::{Answer, Server};

        // One answer: one socket handed over.
        let server = Server::start(vec![Answer::Byte(1)]);
        let config = parse(
            &serde_json::json!({ "outbounds": [
                { "type": "direct", "tag": "protected", "protect_path": server.path },
                { "type": "direct", "tag": "plain" },
            ] })
            .to_string(),
        )
        .unwrap();
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
        let dialer = |i: usize| {
            let outbound = &config.outbounds[i];
            let (_, blocks) = crate::transport::layers::Blocks::DIAL.split(&outbound.options);
            crate::config::model::parse_options::<crate::transport::layers::OutboundBlocks>(
                "outbound",
                &outbound.tag,
                &blocks,
            )
            .unwrap()
            .dialer(&outbound.tag, "direct", &Default::default(), None)
            .unwrap()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (plain, protected) = (dialer(1), dialer(0));
        let (plain, accepted) = tokio::join!(plain.tcp_to(addr), listener.accept());
        plain.unwrap();
        accepted.unwrap();
        let (protected, accepted) = tokio::join!(protected.tcp_to(addr), listener.accept());
        let protected = protected.unwrap();
        accepted.unwrap();
        let taken = server.taken();
        assert_eq!(taken.len(), 1, "sockets handed over");
        let taken = taken[0].as_ref().expect("a descriptor, by SCM_RIGHTS");
        assert_eq!(
            socket2::SockRef::from(taken)
                .local_addr()
                .unwrap()
                .as_socket(),
            Some(protected.local_addr().unwrap())
        );
    }

    /// Outbounds, DNS servers, HTTP clients and REALITY's handshake read
    /// the dial fields alike: the same fields, warnings and errors, each
    /// under the place it is at. Built, as `sail -T` builds a
    /// configuration.
    #[cfg(all(
        feature = "outbound-direct",
        feature = "outbound-socks",
        feature = "inbound-vless",
        feature = "inbound-reality"
    ))]
    #[test]
    fn dial_fields_read_alike_in_every_place() {
        use serde_json::{json, Value};

        let load = |place: usize, dial: &Value| -> Result<Vec<String>, String> {
            let mut places = [
                json!({ "type": "socks", "tag": "o", "server": "192.0.2.2", "server_port": 1080 }),
                json!({ "type": "tcp", "tag": "d", "server": "192.0.2.53" }),
                json!({ "tag": "h" }),
                json!({ "server": "192.0.2.1", "server_port": 443 }),
            ];
            places[place]
                .as_object_mut()
                .unwrap()
                .extend(dial.as_object().unwrap().clone());
            let [outbound, server, client, handshake] = places;
            let config = json!({
                "inbounds": [{
                    "type": "vless", "tag": "r", "listen_port": 1443,
                    "users": [{ "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b" }],
                    "tls": { "enabled": true, "server_name": "example.com", "reality": {
                        "enabled": true, "handshake": handshake,
                        "private_key": "11".repeat(32), "short_id": "0123",
                    } },
                }],
                // A detour to a direct of nothing would be refused first.
                "outbounds": [
                    { "type": "direct", "tag": "direct", "connect_timeout": "5s" },
                    outbound,
                ],
                "dns": { "servers": [server] },
                "http_clients": [client],
            });
            let config = parse(&config.to_string()).map_err(|e| format!("{:#}", e))?;
            crate::check_config(&config, &Default::default()).map_err(|e| format!("{:#}", e))?;
            Ok(config.warnings)
        };
        let at = [
            "outbounds[1]",
            "dns.servers[0]",
            "http_clients[0]",
            "inbounds[0].tls.reality.handshake",
        ];
        for (place, at) in at.into_iter().enumerate() {
            // What each place took before, and takes still.
            let bound = json!({
                "inet4_bind_address": "127.0.0.1", "inet6_bind_address": "::1",
                "connect_timeout": "3s",
            });
            assert_eq!(load(place, &bound), Ok(vec![]), "{}", at);
            // Ignored, or not implemented, the same everywhere.
            assert_eq!(
                load(place, &json!({ "tcp_multi_path": true })),
                Ok(vec![format!(
                    "{}.tcp_multi_path: sail does not implement this field; ignored",
                    at
                )]),
            );
            assert_eq!(
                load(place, &json!({ "netns": "n" })),
                Err(format!(
                    "{}.netns: sail does not implement this field yet",
                    at
                )),
            );
            // The socket options of step 5, and the Happy Eyeballs delay:
            // taken wherever sail dials.
            let socket = json!({
                "tcp_fast_open": cfg!(any(target_os = "linux", target_os = "macos")),
                "udp_fragment": false, "reuse_addr": true, "fallback_delay": "100ms",
            });
            assert_eq!(load(place, &socket), Ok(vec![]), "{}", at);
            // protect_path: wherever sail dials, on Unix.
            let protect = load(place, &json!({ "protect_path": "/run/protect.sock" }));
            if cfg!(unix) {
                assert_eq!(protect, Ok(vec![]), "{}", at);
            } else {
                let err = protect.unwrap_err();
                assert!(
                    err.contains("protect_path: only supported on Unix"),
                    "{}",
                    err
                );
            }
            // Keepalive: taken wherever sail dials a TCP connection of its
            // own accord.
            let keepalive = json!({ "tcp_keep_alive": "1m", "tcp_keep_alive_interval": "10s" });
            assert_eq!(load(place, &keepalive), Ok(vec![]), "{}", at);
        }
        // A value of the wrong type, and a detour that would leave a field
        // without effect: the same error, after the place.
        let errors = |dial: Value| {
            (0..4)
                .map(|place| load(place, &dial).unwrap_err())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            errors(json!({ "routing_mark": "x" })),
            [
                r#"[o] outbound: routing_mark: invalid type: string "x", expected u32"#,
                r#"[d] dns server: routing_mark: invalid type: string "x", expected u32"#,
                r#"http_clients[0]: routing_mark: invalid type: string "x", expected u32"#,
                r#"[r] inbound: tls.reality.handshake: routing_mark: invalid type: string "x", expected u32"#,
            ]
        );
        assert_eq!(
            errors(json!({ "detour": "direct", "tcp_keep_alive": "1m" })),
            [
                "[o] outbound: tcp_keep_alive: has no effect with a detour; set it on [direct]",
                "dns.servers[d]: tcp_keep_alive: has no effect with a detour; set it on [direct]",
                "http_clients[0]: tcp_keep_alive: has no effect with a detour; set it on [direct]",
                "inbounds[0].tls.reality.handshake.detour: sail does not implement this field yet",
            ]
        );
    }

    #[test]
    fn a_field_sing_box_does_not_know_is_a_mistake() {
        let err = parse(r#"{ "outbounds": [{ "type": "direct" }], "dsn": {} }"#).unwrap_err();
        assert!(err.to_string().contains("dsn"), "{}", err);
    }

    #[test]
    fn listable_fields_take_one_value() {
        let config = parse(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [
                    { "action": "sniff", "sniffer": "tls" },
                    { "domain_suffix": "example.com", "port": 443, "outbound": "direct" }
                ] }
            }"#,
        )
        .unwrap();
        assert_eq!(config.route.rules[0].sniffer.len(), 1);
        assert_eq!(config.route.rules[1].domain_suffix, ["example.com"]);
        assert_eq!(config.route.rules[1].port, [443]);
    }

    #[test]
    fn log_fields_are_sing_box_s() {
        let config =
            parse(r#"{ "log": { "disabled": true, "level": "fatal", "timestamp": true } }"#)
                .unwrap();
        assert!(config.log.disabled && config.log.timestamp);
        let config = parse(r#"{ "log": { "level": "warning" } }"#).unwrap();
        assert_eq!(config.log.level, crate::config::model::LogLevel::Warn);
        let err = parse(r#"{ "log": { "level": "none" } }"#).unwrap_err();
        assert!(err.to_string().starts_with("log.level"), "{}", err);
    }

    /// Rule by rule, a document reads as it does whole, warnings and all;
    /// one it does not read so is read whole. Whether it was read rule by
    /// rule, and whether whole.
    fn alike(text: &str) -> (bool, bool) {
        let s = jsonc::strip(text);
        let mut read = (false, false);
        for zero_unset in [true, false] {
            let whole = whole(&s, zero_unset).ok();
            let by_rule = by_rule(&s, zero_unset);
            if by_rule.is_some() {
                assert!(by_rule == whole, "{}", text);
            }
            read = (by_rule.is_some(), whole.is_some());
        }
        read
    }

    #[test]
    fn rules_read_one_at_a_time_as_the_whole_reads_them() {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/sing-box");
        let mut files = 0;
        for entry in std::fs::read_dir(corpus).unwrap() {
            let path = entry.unwrap().path();
            // Every document of the corpus is an object: what reads whole
            // reads rule by rule.
            let (by_rule, whole) = alike(&std::fs::read_to_string(&path).unwrap());
            assert_eq!(by_rule, whole, "{}", path.display());
            files += 1;
        }
        assert!(files > 100, "{}", files);
        for text in [
            r#"[]"#,
            r#"{ "route": [] }"#,
            r#"{ "route": { "rules": {} } }"#,
            r#"{ "route": { "rules": [1] } }"#,
            r#"{ "route": { "rules": [{ "port": 1 }] }, "route": { "final": "a" } }"#,
            r#"{ "route": { "rules": [{ "port": 1 }], "rules": [] } }"#,
            r#"{ "dns": { "rules": [{ "domain": "a.test", "server": "s" }] } } x"#,
        ] {
            alike(text);
        }
    }

    /// Warnings come in the order the whole document's are found: by what
    /// finds them, then where, though the rules are read one by one after
    /// the rest.
    #[test]
    fn warnings_keep_their_order_across_rules_and_the_rest() {
        let text = r#"{
            "outbounds": [{ "type": "direct", "tag": "d", "tcp_multi_path": true }],
            "dns": { "rules": [{ "domain": "a.test", "action": "reject", "method": "drop" }] },
            "route": { "rules": [
                { "port": 1, "action": "direct", "tcp_multi_path": true },
                { "type": "logical", "mode": "and", "outbound": "d",
                  "rules": [{ "port": 2, "tcp_multi_path": true }, { "port": 3 }] }
            ] }
        }"#;
        alike(text);
        let (_, warnings) = by_rule(&jsonc::strip(text), true).unwrap();
        assert_eq!(
            warnings,
            [
                "route.rules[0].action: the direct action has no effect, as in sing-box 1.14.1",
                "dns.rules[0].method: sail does not implement this field; ignored",
                "outbounds[0].tcp_multi_path: sail does not implement this field; ignored",
                "route.rules[0].tcp_multi_path: sail does not implement this field; ignored",
                "route.rules[1].rules[0].tcp_multi_path: sail does not implement this field; ignored",
            ]
        );
    }

    /// The first thing wrong is the one said, wherever the rules are: a
    /// value sail lacks before a field it lacks, either before what the
    /// schema refuses.
    #[test]
    fn errors_in_several_rules_come_out_in_the_order_they_did() {
        let text = r#"{ "route": { "rules": [
            { "port": "x" },
            { "port": 1, "tls_spoof": "a" },
            { "port": 2, "rules": [{ "port": 3, "netns": "n" }], "type": "logical", "mode": "or" },
            { "port": 4, "action": "evaluate" }
        ] } }"#;
        alike(text);
        assert_eq!(
            parse(text).unwrap_err().to_string(),
            "route.rules[3].action: sail does not implement \"evaluate\" yet"
        );
        let text = text.replace("\"evaluate\"", "\"route\"");
        assert_eq!(
            parse(&text).unwrap_err().to_string(),
            "route.rules[1].tls_spoof: sail does not implement this field yet"
        );
        let text = text.replace("\"tls_spoof\": \"a\"", "\"port\": 5");
        assert_eq!(
            parse(&text).unwrap_err().to_string(),
            "route.rules[2].rules[0].netns: sail does not implement this field yet"
        );
    }

    /// Each list of rules takes as much room as its rules, not more.
    #[test]
    fn rules_read_one_at_a_time_take_the_room_they_need() {
        let rules = |n| {
            (0..n)
                .map(|i| serde_json::json!({ "domain": format!("d{}.test", i), "outbound": "a" }))
                .collect::<Vec<_>>()
        };
        let dns = |n| {
            (0..n)
                .map(|i| serde_json::json!({ "domain": format!("d{}.test", i), "server": "s" }))
                .collect::<Vec<_>>()
        };
        let text = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "a" }],
            "dns": { "servers": [{ "type": "local", "tag": "s" }], "rules": dns(1500) },
            "route": { "rules": rules(3000) },
        })
        .to_string();
        let (config, _) = by_rule(&text, true).unwrap();
        assert_eq!(config.route.rules.capacity(), 3000);
        assert_eq!(config.dns.rules.capacity(), 1500);
    }
}
