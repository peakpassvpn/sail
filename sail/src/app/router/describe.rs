//! A rule told in words, as the Clash API lists rules and says which one a
//! connection matched: its conditions and its action, sing-box's way
//! (`domain_suffix=[a b] => route(proxy)`).

use std::sync::Arc;

use serde_json::Value;

use crate::config::model::{self, RuleType};

/// The fields of a rule that say what it does, not what it matches.
const ACTION_FIELDS: &[&str] = &[
    "action",
    "outbound",
    "override_address",
    "override_port",
    "udp_disable_domain_unmapping",
    "udp_connect",
    "udp_timeout",
    "tls_fragment",
    "tls_fragment_fallback_delay",
    "tls_record_fragment",
    "method",
    "no_drop",
    "server",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "client_subnet",
    "sniffer",
    "timeout",
    "override_destination",
    "skip_rule_set",
    "ignore_failure",
    "on_demand",
];

/// The longest a connection's rule is told, in characters: a rule with a
/// long list inline is cut there.
const MATCHED_MAX: usize = 256;

/// A rule, told. Without the Clash API only `matched` is read, by the
/// connections' stats.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "clash-api"), allow(dead_code))]
pub(crate) struct About {
    /// `default` or `logical`, as sing-box's rule types.
    pub kind: &'static str,
    /// What it matches.
    pub payload: String,
    /// What it does.
    pub action: String,
    /// Both, `payload => action`, cut to a length, for the connections it
    /// decides.
    pub matched: Arc<str>,
}

impl About {
    pub(crate) fn of(rule: &model::Rule) -> Self {
        let payload = conditions(rule);
        let action = action(rule);
        let mut matched = format!("{} => {}", payload, action);
        if matched.chars().count() > MATCHED_MAX {
            matched = matched.chars().take(MATCHED_MAX - 1).collect();
            matched.push('…');
        }
        About {
            kind: match rule.kind {
                RuleType::Logical => "logical",
                _ => "default",
            },
            payload,
            action,
            matched: matched.into(),
        }
    }
}

fn conditions(rule: &model::Rule) -> String {
    let told = if rule.kind == RuleType::Logical {
        let join = match rule.mode {
            Some(model::LogicalMode::Or) => " || ",
            _ => " && ",
        };
        let parts: Vec<String> = rule.rules.iter().map(conditions).collect();
        format!("({})", parts.join(join))
    } else {
        let Ok(Value::Object(fields)) = serde_json::to_value(rule) else {
            return String::new();
        };
        let parts: Vec<String> = fields
            .iter()
            .filter(|(name, _)| {
                !ACTION_FIELDS.contains(&name.as_str())
                    && !["type", "mode", "rules", "invert"].contains(&name.as_str())
            })
            .map(|(name, value)| format!("{}={}", name, value_of(value)))
            .collect();
        parts.join(" ")
    };
    if rule.invert {
        format!("!({})", told)
    } else {
        told
    }
}

/// `route(proxy)`, `reject(method=drop)`: the action, then the outbound,
/// then the other fields it sets.
fn action(rule: &model::Rule) -> String {
    let name = match serde_json::to_value(rule.action()) {
        Ok(Value::String(name)) => name,
        _ => "route".to_string(),
    };
    let Ok(Value::Object(fields)) = serde_json::to_value(rule) else {
        return name;
    };
    let mut args: Vec<String> = rule.outbound.iter().cloned().collect();
    args.extend(
        fields
            .iter()
            .filter(|(field, _)| {
                ACTION_FIELDS.contains(&field.as_str())
                    && !["action", "outbound"].contains(&field.as_str())
            })
            .map(|(field, value)| format!("{}={}", field, value_of(value))),
    );
    if args.is_empty() {
        name
    } else {
        format!("{}({})", name, args.join(", "))
    }
}

/// A value as sing-box prints it: a list of more than one in brackets.
fn value_of(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) if items.len() == 1 => value_of(&items[0]),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(value_of).collect::<Vec<_>>().join(" ")
        ),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(json: &str) -> model::Rule {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_rule_is_told_as_sing_box_tells_it() {
        let about = About::of(&rule(
            r#"{ "domain_suffix": ["a.com", "b.com"], "port": 443, "outbound": "proxy" }"#,
        ));
        assert_eq!(about.kind, "default");
        assert_eq!(about.payload, "domain_suffix=[a.com b.com] port=443");
        assert_eq!(about.action, "route(proxy)");
        assert_eq!(
            &*about.matched,
            "domain_suffix=[a.com b.com] port=443 => route(proxy)"
        );

        let about = About::of(&rule(
            r#"{ "type": "logical", "mode": "or", "invert": true,
                 "rules": [{ "network": "udp" }, { "port": 53 }],
                 "action": "reject", "method": "drop" }"#,
        ));
        assert_eq!(about.kind, "logical");
        assert_eq!(about.payload, "!((network=udp || port=53))");
        assert_eq!(about.action, "reject(method=drop)");

        let about = About::of(&rule(r#"{ "action": "sniff" }"#));
        assert_eq!(&*about.matched, " => sniff");
    }

    #[test]
    fn a_long_rule_is_cut_for_its_connections() {
        let domains: Vec<String> = (0..100).map(|i| format!("d{}.example", i)).collect();
        let about = About::of(&rule(
            &serde_json::json!({ "domain": domains, "outbound": "x" }).to_string(),
        ));
        assert!(about.payload.len() > MATCHED_MAX);
        assert_eq!(about.matched.chars().count(), MATCHED_MAX);
        assert!(about.matched.ends_with('…'));
    }
}
