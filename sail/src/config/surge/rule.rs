//! `[Rule]`: `TYPE,VALUE,POLICY[,parameter...]`, matched top-down, to the
//! `FINAL` rule every list ends with. A domain goes to its addresses at the
//! first IP rule without `no-resolve`, where Surge resolves it; one that
//! does not resolve fails its connection, as in Surge, unless `FINAL` has
//! `dns-failed`.
//!
//! UDP whose policy carries none (see `udp-policy-not-supported-behaviour`)
//! is rejected, or sent directly, by a rule of its own before.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::general::{General, UdpFallback};
use super::group::{Policies, Target, Udp};
use super::proxy::Reject;
use super::text::{self, Line};
use super::Lowered;
use crate::config::clash::provider::Sets;

/// A rule's parameters sail does not implement, or that change nothing in
/// sail.
fn parameter(key: &str) -> Option<&'static str> {
    match key {
        "extended-matching" => Some(
            "sail does not match the TLS SNI and the HTTP Host until C.5b; matched by the \
             requested name alone",
        ),
        "pre-matching" => Some(""),
        _ => None,
    }
}

/// The rule types of later stages, and those sail does not implement.
fn later(kind: &str) -> Option<&'static str> {
    match kind {
        "RULE-SET" | "DOMAIN-SET" | "AND" | "OR" | "NOT" | "IP-ASN" | "USER-AGENT"
        | "URL-REGEX" | "HOSTNAME-TYPE" => Some(" yet (C.5b)"),
        "SUBNET" | "CELLULAR-RADIO" | "CELLULAR-CARRIER" | "DEVICE-NAME" | "MAC-ADDRESS"
        | "SCRIPT" => Some(""),
        _ => None,
    }
}

/// What lowering the rules keeps track of.
struct Walk<'a> {
    policies: &'a Policies,
    general: &'a General,
    out: &'a mut Lowered,
    /// Whether a rule before resolves the domain already.
    resolved: bool,
    /// Whether a domain that does not resolve goes on, `FINAL,dns-failed`.
    dns_failed: bool,
    /// Whether a rule before sniffs the connection's protocol already.
    sniffed: bool,
}

impl Walk<'_> {
    /// Adds a rule of `condition` to `target`; `resolves` is whether it
    /// matches the destination's address, which a domain is resolved to.
    fn push(&mut self, condition: Map<String, Value>, resolves: bool, target: Target) {
        if resolves && !self.resolved {
            let mut resolve = json!({ "action": "resolve" });
            if self.dns_failed {
                resolve["ignore_failure"] = json!(true);
            }
            self.out.rules.push(resolve);
            self.resolved = true;
        }
        self.fallback(&condition, &target);
        let mut rule = condition;
        apply(&target, &mut rule);
        self.out.rules.push(Value::Object(rule));
    }

    /// Before a rule to a policy of no UDP, the rule for its UDP.
    fn fallback(&mut self, condition: &Map<String, Value>, target: &Target) {
        let Target::Outbound(tag) = target else {
            return;
        };
        if self.policies.udp(tag) != Udp::No {
            return;
        }
        let logical = condition.get("type").and_then(Value::as_str) == Some("logical");
        let mut rule = match condition.get("network") {
            // Of TCP alone, it has no UDP to send.
            Some(network) if !network.to_string().contains("udp") => return,
            _ if logical => {
                let mut rule = Map::new();
                rule.insert("type".into(), json!("logical"));
                rule.insert("mode".into(), json!("and"));
                rule.insert(
                    "rules".into(),
                    json!([Value::Object(condition.clone()), { "network": "udp" }]),
                );
                rule
            }
            _ => {
                let mut rule = condition.clone();
                rule.insert("network".into(), json!("udp"));
                rule
            }
        };
        match self.general.udp_fallback {
            UdpFallback::Reject => apply(&Target::Reject(Reject::Plain), &mut rule),
            UdpFallback::Direct => apply(&Target::Outbound("DIRECT".into()), &mut rule),
        }
        self.out.rules.push(Value::Object(rule));
    }

    /// A sniff of what `PROTOCOL` rules match, before the first of them.
    fn sniff(&mut self) {
        if !self.sniffed {
            self.out.rules.push(json!({
                "action": "sniff",
                "sniffer": ["http", "tls", "quic", "stun"],
            }));
            self.sniffed = true;
        }
    }
}

fn apply(target: &Target, rule: &mut Map<String, Value>) {
    match target {
        Target::Outbound(tag) => {
            rule.insert("outbound".into(), json!(tag));
        }
        Target::Reject(how) => {
            rule.insert("action".into(), json!("reject"));
            match how {
                Reject::Plain => {}
                Reject::NoDrop => {
                    rule.insert("no_drop".into(), json!(true));
                }
                Reject::Drop => {
                    rule.insert("method".into(), json!("drop"));
                }
            }
        }
    }
}

/// A rule line, split: its type, value, policy and parameters.
struct Split {
    kind: String,
    value: String,
    policy: String,
    params: Vec<String>,
}

fn split(line: &str) -> Split {
    let parts = text::split(line, true);
    let kind = parts[0].to_ascii_uppercase();
    let unquoted = |i: usize| parts.get(i).map(|p| text::unquote(p)).unwrap_or_default();
    if kind == "FINAL" {
        return Split {
            kind,
            value: String::new(),
            policy: unquoted(1),
            params: parts.iter().skip(2).cloned().collect(),
        };
    }
    Split {
        value: unquoted(1),
        policy: unquoted(2),
        params: parts.iter().skip(3).cloned().collect(),
        kind,
    }
}

pub fn lower(
    lines: Vec<Line>,
    policies: &Policies,
    general: &General,
    sets: &mut Sets,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let rules: Vec<(String, Split)> = lines
        .iter()
        .map(|l| (format!("[Rule] {}", l.loc), split(&l.text)))
        .collect();
    let dns_failed = rules
        .iter()
        .find(|(_, s)| s.kind == "FINAL")
        .is_some_and(|(_, s)| {
            s.params
                .iter()
                .any(|p| p.trim().eq_ignore_ascii_case("dns-failed"))
        });
    let mut walk = Walk {
        policies,
        general,
        out,
        resolved: false,
        dns_failed,
        sniffed: false,
    };
    let mut ended = false;
    for (at, s) in &rules {
        if ended {
            warnings.push(format!(
                "{}: after FINAL, where no connection gets; ignored",
                at
            ));
            continue;
        }
        let target = policies
            .target(&s.policy)
            .map_err(|e| anyhow!("{}: {}", at, e))?;
        let mut no_resolve = false;
        for param in &s.params {
            let param = text::unquote(param);
            let key = param
                .split_once('=')
                .map_or(param.as_str(), |(k, _)| k)
                .trim()
                .to_ascii_lowercase();
            match key.as_str() {
                "no-resolve" => no_resolve = true,
                "dns-failed" if s.kind == "FINAL" => {}
                "update-interval"
                | "notification-text"
                | "notification-interval"
                | "always-capture"
                | "force-remote-dns" => {}
                key => match parameter(key) {
                    Some("") => {}
                    Some(why) => warnings.push(format!("{}: {}: {}", at, key, why)),
                    None => warnings.push(format!(
                        "{}: {}: not a parameter Surge takes; ignored, as by Surge",
                        at, key
                    )),
                },
            }
        }
        if s.kind == "FINAL" {
            ended = true;
            match target {
                Target::Outbound(tag) => {
                    // Its UDP, when it carries none.
                    walk.fallback(&Map::new(), &Target::Outbound(tag.clone()));
                    walk.out.route.insert("final".into(), json!(tag));
                }
                other => {
                    let mut rule = Map::new();
                    // A condition every connection meets.
                    rule.insert("network".into(), json!(["tcp", "udp"]));
                    apply(&other, &mut rule);
                    walk.out.rules.push(Value::Object(rule));
                }
            }
            continue;
        }
        if s.value.is_empty() {
            return Err(anyhow!("{}: {}: no value", at, s.kind));
        }
        match condition(s, no_resolve, sets, general, &mut walk)
            .map_err(|e| anyhow!("{}: {}", at, e))?
        {
            Some((condition, resolves)) => walk.push(condition, resolves, target),
            None => warnings.push(format!(
                "{}: {},{}: no connection sail sees matches it; ignored",
                at, s.kind, s.value
            )),
        }
    }
    if !ended {
        return Err(anyhow!(
            "[Rule]: no FINAL rule, which Surge requires at the end"
        ));
    }
    Ok(())
}

/// The condition of a rule, and whether it matches the destination's
/// address; none for a rule that never matches in sail.
fn condition(
    s: &Split,
    no_resolve: bool,
    sets: &mut Sets,
    general: &General,
    walk: &mut Walk,
) -> Result<Option<(Map<String, Value>, bool)>> {
    let mut rule = Map::new();
    let value = s.value.as_str();
    let key = match s.kind.as_str() {
        "DOMAIN" => "domain",
        "DOMAIN-SUFFIX" => "domain_suffix",
        "DOMAIN-KEYWORD" => "domain_keyword",
        "DOMAIN-WILDCARD" => {
            rule.insert("domain_regex".into(), json!([wildcard(value)]));
            return Ok(Some((rule, false)));
        }
        "IP-CIDR" | "IP-CIDR6" => {
            rule.insert("ip_cidr".into(), json!([prefix(value)?]));
            return Ok(Some((rule, !no_resolve)));
        }
        "SRC-IP" => {
            rule.insert("source_ip_cidr".into(), json!([prefix(value)?]));
            return Ok(Some((rule, false)));
        }
        "GEOIP" => {
            if value.eq_ignore_ascii_case("UNKNOWN") {
                return Err(anyhow!(
                    "GEOIP,UNKNOWN: sail does not implement addresses of no country yet"
                ));
            }
            rule.insert("rule_set".into(), json!([sets.geoip(value)?]));
            return Ok(Some((rule, !no_resolve)));
        }
        "PROCESS-NAME" => {
            let (key, pattern) = process(value);
            rule.insert(key.into(), json!([pattern]));
            return Ok(Some((rule, false)));
        }
        "DEST-PORT" | "SRC-PORT" => {
            let (one, many) = if s.kind == "DEST-PORT" {
                ("port", "port_range")
            } else {
                ("source_port", "source_port_range")
            };
            match port(value)? {
                Port::One(p) => rule.insert(one.into(), json!([p])),
                Port::Range(r) => rule.insert(many.into(), json!([r])),
            };
            return Ok(Some((rule, false)));
        }
        "IN-PORT" => {
            let tags: Vec<&str> = general
                .listeners
                .iter()
                .filter(|(_, p)| port(value).is_ok_and(|want| want.holds(*p)))
                .map(|(tag, _)| tag.as_str())
                .collect();
            if tags.is_empty() {
                return Ok(None);
            }
            rule.insert("inbound".into(), json!(tags));
            return Ok(Some((rule, false)));
        }
        "PROTOCOL" => {
            // As Surge writes them, in its case.
            let (network, sniffed): (&str, Option<&str>) = match value {
                "TCP" => ("tcp", None),
                "UDP" => ("udp", None),
                "HTTP" => ("tcp", Some("http")),
                "HTTPS" => ("tcp", Some("tls")),
                "QUIC" => ("udp", Some("quic")),
                "STUN" => ("udp", Some("stun")),
                // Surge's own DNS, which sail's routing never sees, and its
                // MTProto server, which sail has none of.
                "DOH" | "DOH3" | "DOQ" | "DOT" | "DNS" | "MTProto" => return Ok(None),
                other => {
                    return Err(anyhow!(
                        "PROTOCOL: {:?} is none of HTTP, HTTPS, TCP, UDP, QUIC, STUN, MTProto, \
                         DOH, DOH3, DOQ, DOT and DNS",
                        other
                    ))
                }
            };
            rule.insert("network".into(), json!([network]));
            if let Some(protocol) = sniffed {
                walk.sniff();
                rule.insert("protocol".into(), json!([protocol]));
            }
            return Ok(Some((rule, false)));
        }
        other => {
            return Err(match later(other) {
                Some(when) => anyhow!("sail does not implement {} rules{}", other, when),
                None => anyhow!("{} is not a rule type Surge takes", other),
            })
        }
    };
    rule.insert(key.into(), json!([value.to_ascii_lowercase()]));
    Ok(Some((rule, false)))
}

/// An address or a prefix, a bare address a prefix of it alone.
fn prefix(value: &str) -> Result<String> {
    let (ip, len) = match value.split_once('/') {
        Some((ip, len)) => (ip, Some(len)),
        None => (value, None),
    };
    let ip: std::net::IpAddr = ip
        .trim()
        .parse()
        .map_err(|_| anyhow!("{:?} is not an address or a prefix", value))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len {
        Some(len) => len
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|l| *l <= max)
            .ok_or_else(|| anyhow!("{:?} is not an address or a prefix", value))?,
        None => max,
    };
    Ok(format!("{}/{}", ip, len))
}

/// A port expression: `80`, `8000-9000`, `>=1024` and the like.
#[derive(Debug, PartialEq)]
enum Port {
    One(u16),
    /// As sail writes ranges: `a:b`, `:b`, `a:`.
    Range(String),
}

impl Port {
    fn holds(&self, port: u16) -> bool {
        match self {
            Port::One(p) => *p == port,
            Port::Range(r) => {
                let (a, b) = r.split_once(':').unwrap_or((r, r));
                a.parse().unwrap_or(0) <= port && port <= b.parse().unwrap_or(u16::MAX)
            }
        }
    }
}

fn port(value: &str) -> Result<Port> {
    let value = value.trim();
    let number = |s: &str| {
        s.trim()
            .parse::<u16>()
            .map_err(|_| anyhow!("{:?} is not a port, a range or a comparison", value))
    };
    for (op, f) in [
        (
            ">=",
            (|n: u16| Some(format!("{}:", n))) as fn(u16) -> Option<String>,
        ),
        ("<=", |n| Some(format!(":{}", n))),
        (">", |n| n.checked_add(1).map(|n| format!("{}:", n))),
        ("<", |n| n.checked_sub(1).map(|n| format!(":{}", n))),
    ] {
        if let Some(rest) = value.strip_prefix(op) {
            return f(number(rest)?)
                .map(Port::Range)
                .ok_or_else(|| anyhow!("{:?}: no port is so", value));
        }
    }
    match value.split_once('-') {
        Some((a, b)) => {
            let (a, b) = (number(a)?, number(b)?);
            if a > b {
                return Err(anyhow!("{:?}: a range from high to low", value));
            }
            Ok(Port::Range(format!("{}:{}", a, b)))
        }
        None => Ok(Port::One(number(value)?)),
    }
}

/// `DOMAIN-WILDCARD`: `*` any run of characters, dots too, `?` one, and
/// `[...]` a class, without case.
fn wildcard(pattern: &str) -> String {
    let mut regex = String::from("^");
    let mut class = false;
    for c in pattern.to_ascii_lowercase().chars() {
        match c {
            _ if class => {
                if c == ']' {
                    class = false;
                }
                if c == '\\' {
                    regex.push('\\');
                }
                regex.push(c);
            }
            '[' => {
                class = true;
                regex.push('[');
            }
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            c => regex.push_str(&escape(c)),
        }
    }
    regex.push('$');
    regex
}

fn escape(c: char) -> String {
    if "\\.+*?()|[]{}^$#&-~".contains(c) {
        format!("\\{}", c)
    } else {
        c.to_string()
    }
}

/// `PROCESS-NAME`: a name, a full path (from `/`), or a bundle, a path
/// ending with `/` that holds the program; `*` and `?` in the first two.
fn process(value: &str) -> (&'static str, String) {
    let wild = value.contains(['*', '?']);
    if !value.starts_with('/') {
        if !wild {
            return ("process_name", value.to_string());
        }
        let name = glob(value).trim_start_matches('^').to_string();
        return ("process_path_regex", format!("(^|/){}", name));
    }
    if value.ends_with('/') && value.len() > 1 {
        let prefix: String = value.chars().map(escape).collect();
        return ("process_path_regex", format!("^{}", prefix));
    }
    if wild {
        return ("process_path_regex", glob(value));
    }
    ("process_path", value.to_string())
}

/// A glob as a regular expression, with case, `*` and `?` within a part
/// of a path or across parts alike, as Surge's.
fn glob(pattern: &str) -> String {
    let mut regex = String::from("^");
    for c in pattern.chars() {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            c => regex.push_str(&escape(c)),
        }
    }
    regex.push('$');
    regex
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(re: &str, s: &str) -> bool {
        fancy_regex::Regex::new(re).unwrap().is_match(s).unwrap()
    }

    #[test]
    fn ports_and_comparisons() {
        assert_eq!(port("80").unwrap(), Port::One(80));
        assert_eq!(port("8000-9000").unwrap(), Port::Range("8000:9000".into()));
        assert_eq!(port(">=50000").unwrap(), Port::Range("50000:".into()));
        assert_eq!(port(">1023").unwrap(), Port::Range("1024:".into()));
        assert_eq!(port("<1024").unwrap(), Port::Range(":1023".into()));
        assert_eq!(port("<=1023").unwrap(), Port::Range(":1023".into()));
        assert!(port("<0").is_err());
        assert!(port("9-1").is_err());
        assert!(port("http").is_err());
        assert!(Port::Range("6000:7000".into()).holds(6152));
    }

    #[test]
    fn wildcards_cross_dots() {
        let re = wildcard("api-*.Example.com");
        assert!(matches(&re, "api-a.b.example.com"));
        assert!(!matches(&re, "api.example.com"));
        let re = wildcard("cdn?.[ab]x.com");
        assert!(matches(&re, "cdn1.ax.com"));
        assert!(!matches(&re, "cdn1.cx.com"));
    }

    #[test]
    fn processes_by_name_path_or_bundle() {
        assert_eq!(process("Telegram"), ("process_name", "Telegram".into()));
        assert_eq!(
            process("/usr/bin/ssh"),
            ("process_path", "/usr/bin/ssh".into())
        );
        let (key, re) = process("Google*");
        assert_eq!(key, "process_path_regex");
        assert!(matches(
            &re,
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        ));
        assert!(!matches(&re, "/usr/bin/NotGoogle"));
        let (_, re) = process("/Applications/ChatGPT.app/");
        assert!(matches(
            &re,
            "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"
        ));
        assert_eq!(prefix("8.8.8.8").unwrap(), "8.8.8.8/32");
        assert_eq!(prefix("2404:6800::").unwrap(), "2404:6800::/128");
        assert!(prefix("1.2.3.4/33").is_err());
    }
}
