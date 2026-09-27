//! sing-box's JSON, sail's own format. The model is written in its shape,
//! so reading it is sorting out what sing-box 1.14 accepts and sail does not
//! implement (see [`upstream`]) before the schema reads the rest.

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::model::Config;

pub mod upstream;

use upstream::Tier;

/// Reads a sing-box configuration.
pub fn parse(s: &str) -> Result<Config> {
    let mut value: Value = serde_json::from_str(s).map_err(|e| anyhow!("{}", e))?;
    let warnings = sort_out(&mut value)?;
    let mut config: Config = serde_path_to_error::deserialize(value)
        .map_err(|e| anyhow!("{}: {}", super::model::path(&e), e.inner()))?;
    config.validate()?;
    config.warnings = warnings;
    Ok(config)
}

impl Config {
    /// Parses a JSON configuration: sing-box's, with sail's extensions.
    pub fn from_json(s: &str) -> Result<Self> {
        parse(s)
    }
}

/// Fails on the first field or value sail does not implement and cannot
/// ignore, and drops, with a warning each, those it can.
fn sort_out(value: &mut Value) -> Result<Vec<String>> {
    for (path, values) in upstream::VALUES {
        for (at, found) in find(value, path) {
            let names: Vec<&str> = match &found {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            if let Some(name) = names.into_iter().find(|n| values.contains(n)) {
                return Err(anyhow!("{}: sail does not implement \"{}\" yet", at, name));
            }
        }
    }
    let mut warnings = Vec::new();
    for field in upstream::FIELDS {
        for (at, _) in find(value, field.path) {
            match field.tier {
                Tier::Unsupported => {
                    return Err(anyhow!("{}: sail does not implement this field yet", at));
                }
                Tier::Ignored => {
                    remove(value, &at);
                    warnings.push(format!(
                        "{}: sail does not implement this field; ignored",
                        at
                    ));
                }
            }
        }
    }
    for path in upstream::SILENT {
        for (at, _) in find(value, path) {
            remove(value, &at);
        }
    }
    for path in upstream::EMPTIED {
        for (at, found) in find(value, path) {
            if found.as_object().is_some_and(|o| o.is_empty()) {
                remove(value, &at);
            }
        }
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
            if let Some(v) = map.get(*segment) {
                visit(Step::Key(segment.to_string()), v);
            }
        }
        Value::Array(list) if *segment == "*" => {
            for (i, v) in list.iter().enumerate() {
                visit(Step::Index(i), v);
            }
        }
        _ => {}
    }
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
    fn a_field_sail_can_ignore_is_dropped_with_a_warning() {
        let config = parse(
            r#"{
                "$schema": "https://example.com/schema.json",
                "experimental": { "cache_file": { "enabled": true } },
                "outbounds": [{ "type": "direct", "tcp_fast_open": true }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            config.warnings,
            [
                "experimental.cache_file: sail does not implement this field; ignored",
                "outbounds[0].tcp_fast_open: sail does not implement this field; ignored",
            ]
        );
        assert!(!config.outbounds[0].options.contains_key("tcp_fast_open"));
    }

    #[test]
    fn a_field_that_would_change_routing_is_an_error() {
        let err = parse(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [{ "wifi_ssid": "home", "outbound": "direct" }] }
            }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route.rules[0].wifi_ssid: sail does not implement this field yet"
        );
    }

    #[test]
    fn a_value_sail_lacks_is_an_error() {
        for (rule, message) in [
            (
                r#"{ "action": "bypass", "port": 53 }"#,
                r#"route.rules[0].action: sail does not implement "bypass" yet"#,
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
        let err = parse(r#"{ "log": { "level": "none" } }"#).unwrap_err();
        assert!(err.to_string().starts_with("log.level"), "{}", err);
    }
}
