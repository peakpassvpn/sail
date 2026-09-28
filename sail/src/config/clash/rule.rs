//! `rules`, as routing rules: each of Mihomo's rule types sail has the
//! condition of, split as Mihomo's `ParseRulePayload` splits it.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::Fields;
use super::general::LISTENERS;
use super::group::Policies;
use super::Lowered;

/// A rule, split: its type, payload, target and parameters.
struct Split<'a> {
    kind: String,
    payload: String,
    target: &'a str,
    params: Vec<&'a str>,
}

fn split(rule: &str) -> Split<'_> {
    let items: Vec<&str> = rule.split(',').map(str::trim).collect();
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
            split.target = items[items.len() - 1];
            split.payload = items[1..items.len() - 1].join(",");
        }
        _ => {
            split.payload = items[1].to_string();
            if items.len() > 2 {
                split.target = items[2];
                split.params = items[3..].to_vec();
            }
        }
    }
    split
}

pub fn lower(
    doc: &mut Fields,
    policies: &Policies,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    // `mode: global` and `direct`, which the Clash API may switch to.
    out.rules
        .push(json!({ "clash_mode": "Global", "outbound": "GLOBAL" }));
    out.rules
        .push(json!({ "clash_mode": "Direct", "outbound": "DIRECT" }));
    let mut resolved = false;
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
        let s = split(rule);
        let target = target(s.target, policies).map_err(|e| anyhow!("{}: {}", at, e))?;
        if s.kind == "MATCH" {
            match target {
                Target::Outbound(tag) => {
                    out.route.insert("final".into(), json!(tag));
                }
                Target::Pass => {}
                other => {
                    let mut rule = Map::new();
                    // A condition every connection meets.
                    rule.insert("network".into(), json!(["tcp", "udp"]));
                    other.apply(&mut rule);
                    out.rules.push(Value::Object(rule));
                }
            }
            matched = true;
            continue;
        }
        let (condition, resolves) = condition(&s).map_err(|e| anyhow!("{}: {}", at, e))?;
        if resolves && !resolved {
            // Mihomo resolves the domain at the first IP rule to match it
            // against, and a domain that does not resolve matches no IP
            // rule; so does sail, from here on.
            out.rules
                .push(json!({ "action": "resolve", "ignore_failure": true }));
            resolved = true;
        }
        if let Target::Pass = target {
            continue;
        }
        let mut rule = condition;
        target.apply(&mut rule);
        out.rules.push(Value::Object(rule));
    }
    if !out.route.contains_key("final") {
        // Mihomo's, for what no rule matches.
        out.route.insert("final".into(), json!("DIRECT"));
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
fn condition(s: &Split) -> Result<(Map<String, Value>, bool)> {
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
                other => {
                    return Err(anyhow!(
                        "IN-TYPE: sail does not implement {:?} yet, only HTTP, SOCKS5, MIXED, \
                         REDIR and TPROXY",
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
        let s = split("DOMAIN-SUFFIX,example.com,Proxy");
        assert_eq!(
            (s.kind.as_str(), s.payload.as_str(), s.target),
            ("DOMAIN-SUFFIX", "example.com", "Proxy")
        );
        let s = split("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
        assert_eq!(s.params, ["no-resolve"]);
        let s = split("domain-regex,^a{1,3}\\.example$,Proxy");
        assert_eq!(
            (s.kind.as_str(), s.payload.as_str(), s.target),
            ("DOMAIN-REGEX", "^a{1,3}\\.example$", "Proxy")
        );
        let s = split("MATCH,Final");
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
