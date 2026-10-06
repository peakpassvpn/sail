//! A rule told in words, as the Clash API lists rules and says which one a
//! connection matched: its conditions and its action, sing-box's way
//! (`domain_suffix=[a b] => route(proxy)`), and as Mihomo lists its own
//! (type `DomainSuffix`, payload `a,b`, proxy `proxy`), which the
//! dashboards read.

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
    "network_strategy",
    "fallback_delay",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "bind_address_no_port",
    "protect_path",
    "routing_mark",
    "reuse_addr",
    "connect_timeout",
    "tcp_fast_open",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "udp_fragment",
    "domain_resolver",
    "skip_default_domain_resolver",
    "domain_strategy",
    "fallback_network_type",
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
    /// What it matches and what it does, sing-box's way (`domain_suffix=a
    /// => route(proxy)`), cut to a length, for the connections it decides.
    pub matched: Arc<str>,
    /// Mihomo's type of it: `DomainSuffix`, `IPCIDR`, `RuleSet`, `AND`,
    /// `Match`; a condition Mihomo has no type for goes by sing-box's
    /// field name.
    pub clash_type: String,
    /// Mihomo's payload of it: `a.com,b.com`, `((DomainSuffix,a.com) &&
    /// (Network,udp))`.
    pub clash_payload: String,
    /// Mihomo's proxy of it: the outbound it routes to, `REJECT` or
    /// `REJECT-DROP`, or else its action (`sniff`).
    pub clash_proxy: String,
    /// The rule-sets it names, whose rules Mihomo counts as its `size`.
    pub rule_sets: Vec<String>,
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
        let (clash_type, clash_payload) = mihomo(rule);
        About {
            clash_proxy: clash_proxy(rule, &action),
            matched: matched.into(),
            clash_type,
            clash_payload,
            rule_sets: rule.rule_set.iter().cloned().collect(),
        }
    }
}

/// The fields that change how others match rather than match themselves.
const MODIFIERS: &[&str] = &["no_resolve", "rule_set_ip_cidr_match_source"];

/// Mihomo's type for a condition of sing-box's `field`, with the
/// payload it puts first, where Mihomo writes it as a value (`GeoIP,
/// private` for `ip_is_private`).
fn mihomo_type(field: &str) -> (&str, Option<&'static str>) {
    let kind = match field {
        "domain" => "Domain",
        "domain_suffix" => "DomainSuffix",
        "domain_keyword" => "DomainKeyword",
        "domain_regex" => "DomainRegex",
        "geosite" => "GeoSite",
        "geoip" => "GeoIP",
        "ip_is_private" => return ("GeoIP", Some("private")),
        "source_ip_is_private" => return ("SrcGeoIP", Some("private")),
        "ip_cidr" => "IPCIDR",
        "source_ip_cidr" => "SrcIPCIDR",
        "ip_asn" => "IPASN",
        "port" | "port_range" => "DstPort",
        "source_port" | "source_port_range" => "SrcPort",
        "inbound" => "InName",
        "auth_user" => "InUser",
        "process_name" => "ProcessName",
        "process_path" => "ProcessPath",
        "process_name_regex" => "ProcessNameRegex",
        "process_path_regex" => "ProcessPathRegex",
        "rule_set" => "RuleSet",
        "network" => "Network",
        "user_id" => "Uid",
        other => other,
    };
    (kind, None)
}

/// A rule's Mihomo type and payload: one condition as itself, several
/// as `AND`, a logical rule as `AND` or `OR` of its rules, an inverted one
/// as `NOT`, and none as `Match`; nested as Mihomo writes them
/// (rules/logic/logic.go): `((T,p) && (T,p))`, `((T,p) || (T,p))`,
/// `(!(T,p))`.
fn mihomo(rule: &model::Rule) -> (String, String) {
    let nested = |parts: &[(String, String)], join: &str| {
        let parts: Vec<String> = parts
            .iter()
            .map(|(kind, payload)| format!("({},{})", kind, payload))
            .collect();
        format!("({})", parts.join(join))
    };
    let (kind, payload) = if rule.kind == RuleType::Logical {
        let parts: Vec<(String, String)> = rule.rules.iter().map(mihomo).collect();
        match rule.mode {
            Some(model::LogicalMode::Or) => ("OR".to_string(), nested(&parts, " || ")),
            _ => ("AND".to_string(), nested(&parts, " && ")),
        }
    } else {
        let Ok(Value::Object(fields)) = serde_json::to_value(rule) else {
            return ("Match".into(), String::new());
        };
        let parts: Vec<(String, String)> = fields
            .iter()
            .filter(|(name, _)| {
                !ACTION_FIELDS.contains(&name.as_str())
                    && !MODIFIERS.contains(&name.as_str())
                    && !["type", "mode", "rules", "invert"].contains(&name.as_str())
            })
            .map(|(name, value)| {
                let (kind, fixed) = mihomo_type(name);
                let payload = match fixed {
                    Some(fixed) => fixed.to_string(),
                    None => payload_of(name, value),
                };
                (kind.to_string(), payload)
            })
            .collect();
        match parts.len() {
            0 => ("Match".into(), String::new()),
            1 => parts.into_iter().next().expect("one"),
            _ => ("AND".into(), nested(&parts, " && ")),
        }
    };
    if rule.invert {
        ("NOT".into(), format!("(!({},{}))", kind, payload))
    } else {
        (kind, payload)
    }
}

/// A condition's values as Mihomo writes a payload: separated by commas,
/// a port range with a dash.
fn payload_of(field: &str, value: &Value) -> String {
    let one = |v: &Value| match v {
        Value::String(s) if field.ends_with("port_range") => s.replace(':', "-"),
        Value::String(s) => s.clone(),
        Value::Bool(true) => String::new(),
        other => other.to_string(),
    };
    match value {
        Value::Array(items) => items.iter().map(one).collect::<Vec<_>>().join(","),
        other => one(other),
    }
}

/// Mihomo's proxy of a rule: the outbound it routes to, `REJECT` or
/// `REJECT-DROP`, or else `action`, as sail tells it.
fn clash_proxy(rule: &model::Rule, action: &str) -> String {
    match (rule.action(), &rule.outbound) {
        (model::RuleAction::Route | model::RuleAction::Bypass, Some(outbound)) => outbound.clone(),
        (model::RuleAction::Reject, _) => match rule.method {
            Some(model::RejectMethod::Drop) => "REJECT-DROP".into(),
            _ => "REJECT".into(),
        },
        _ => action.to_string(),
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
        assert_eq!(
            &*about.matched,
            "domain_suffix=[a.com b.com] port=443 => route(proxy)"
        );

        let about = About::of(&rule(
            r#"{ "type": "logical", "mode": "or", "invert": true,
                 "rules": [{ "network": "udp" }, { "port": 53 }],
                 "action": "reject", "method": "drop" }"#,
        ));
        assert_eq!(
            &*about.matched,
            "!((network=udp || port=53)) => reject(method=drop)"
        );

        let about = About::of(&rule(r#"{ "action": "sniff" }"#));
        assert_eq!(&*about.matched, " => sniff");
    }

    #[test]
    fn a_long_rule_is_cut_for_its_connections() {
        let domains: Vec<String> = (0..100).map(|i| format!("d{}.example", i)).collect();
        let about = About::of(&rule(
            &serde_json::json!({ "domain": domains, "outbound": "x" }).to_string(),
        ));
        assert!(
            conditions(&rule(
                &serde_json::json!({ "domain": domains, "outbound": "x" }).to_string()
            ))
            .len()
                > MATCHED_MAX
        );
        assert_eq!(about.matched.chars().count(), MATCHED_MAX);
        assert!(about.matched.ends_with('…'));
    }

    /// As Mihomo lists rules: a type and a payload of the values, the
    /// outbound as the proxy.
    #[test]
    fn a_rule_is_listed_as_mihomo_lists_it() {
        let listed = |json: &str| {
            let about = About::of(&rule(json));
            (about.clash_type, about.clash_payload, about.clash_proxy)
        };
        let row = |t: &str, p: &str, x: &str| (t.to_string(), p.to_string(), x.to_string());
        assert_eq!(
            listed(r#"{ "domain_suffix": ["a.com", "b.com"], "outbound": "proxy" }"#),
            row("DomainSuffix", "a.com,b.com", "proxy")
        );
        assert_eq!(
            listed(r#"{ "ip_cidr": "10.0.0.0/8", "no_resolve": true, "outbound": "direct" }"#),
            row("IPCIDR", "10.0.0.0/8", "direct")
        );
        assert_eq!(
            listed(r#"{ "rule_set": "geosite-cn", "outbound": "direct" }"#),
            row("RuleSet", "geosite-cn", "direct")
        );
        assert_eq!(
            listed(r#"{ "ip_is_private": true, "outbound": "direct" }"#),
            row("GeoIP", "private", "direct")
        );
        assert_eq!(
            listed(r#"{ "port_range": "1000:2000", "action": "reject", "method": "drop" }"#),
            row("DstPort", "1000-2000", "REJECT-DROP")
        );
        assert_eq!(
            listed(r#"{ "domain": "a.com", "network": "udp", "action": "reject" }"#),
            row("AND", "((Domain,a.com) && (Network,udp))", "REJECT")
        );
        assert_eq!(
            listed(
                r#"{ "type": "logical", "mode": "or",
                     "rules": [{ "domain_keyword": "ads" }, { "port": 853 }],
                     "outbound": "block" }"#
            ),
            row("OR", "((DomainKeyword,ads) || (DstPort,853))", "block")
        );
        assert_eq!(
            listed(r#"{ "invert": true, "geoip": "cn", "outbound": "proxy" }"#),
            row("NOT", "(!(GeoIP,cn))", "proxy")
        );
        assert_eq!(
            listed(r#"{ "outbound": "proxy" }"#),
            row("Match", "", "proxy")
        );
        assert_eq!(
            listed(r#"{ "action": "sniff" }"#),
            row("Match", "", "sniff")
        );
        assert_eq!(
            listed(r#"{ "clash_mode": "Global", "outbound": "proxy" }"#),
            row("clash_mode", "Global", "proxy")
        );
        assert_eq!(
            About::of(&rule(r#"{ "rule_set": ["a", "b"], "outbound": "x" }"#)).rule_sets,
            ["a", "b"]
        );
    }
}
