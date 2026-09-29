//! `[Rule]`: `TYPE,VALUE,POLICY[,parameter...]`, matched top-down, to the
//! `FINAL` rule every list ends with. A domain goes to its addresses at the
//! first IP rule without `no-resolve`, where Surge resolves it; one that
//! does not resolve fails its connection, as in Surge, unless `FINAL` has
//! `dns-failed`.
//!
//! A logical rule, `AND,((TYPE,value),(TYPE,value)),POLICY`, `OR` or
//! `NOT,((TYPE,value))`, is sail's logical rule; its rules are written as
//! a rule-set's, without a policy, and nest ten deep at most.
//!
//! `USER-AGENT` and `URL-REGEX` match the plain HTTP Surge reads without
//! MITM: the connection is sniffed for HTTP before the first of them, and
//! for any protocol before the first `PROTOCOL` rule. `extended-matching`
//! sniffs the TLS SNI and HTTP Host before the rule that has it; from
//! there on the domain sniffed, where there is one, is what every domain
//! rule matches, as sail matches a sniffed domain, where Surge matches it
//! besides the one asked for, and only in those rules.
//!
//! A REJECT rule with `pre-matching` is matched before every other, as
//! Surge matches it, for TCP; UDP, which Surge does not match early, meets
//! it where it stands. It matches addresses without resolving a domain,
//! as Surge's early matching, which sees only the address a connection
//! is made to.
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

/// How deep logical rules nest, as Surge has it.
const MAX_LOGICAL_DEPTH: usize = 10;

/// The rule types sail does not implement, or not yet.
fn later(kind: &str) -> Option<&'static str> {
    match kind {
        "RULE-SET" | "DOMAIN-SET" => Some(" yet (C.5b)"),
        "SUBNET" | "CELLULAR-RADIO" | "CELLULAR-CARRIER" | "DEVICE-NAME" | "MAC-ADDRESS"
        | "SCRIPT" => Some(""),
        _ => None,
    }
}

/// Whether a condition matches the destination's addresses, which a domain
/// is resolved to first.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Resolve {
    /// It does not.
    #[default]
    No,
    /// It may: a rule-set, whose rules are not known before it is read.
    Maybe,
    /// It does.
    Yes,
}

/// What must be known of a connection before a condition is matched.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Needs {
    pub resolve: Resolve,
    /// The plain HTTP request, sniffed: `USER-AGENT`, `URL-REGEX`.
    pub http: bool,
    /// The protocol, sniffed: `PROTOCOL`.
    pub protocol: bool,
    /// The TLS SNI or HTTP Host, sniffed: `extended-matching`.
    pub extended: bool,
}

impl Needs {
    pub(super) fn and(self, other: Needs) -> Needs {
        Needs {
            resolve: self.resolve.max(other.resolve),
            http: self.http || other.http,
            protocol: self.protocol || other.protocol,
            extended: self.extended || other.extended,
        }
    }
}

/// A condition, and what it needs.
pub(super) type Cond = (Map<String, Value>, Needs);

/// A rule's parameters, read.
#[derive(Debug, Default, Clone)]
pub(super) struct Flags {
    pub no_resolve: bool,
    pub extended: bool,
    pub pre_matching: bool,
    /// `update-interval`, in seconds: negative for never.
    pub update_interval: Option<i64>,
}

impl Flags {
    /// Reads `params`; those Surge does not take are warned of, at `at`.
    pub(super) fn read(
        params: &[String],
        kind: &str,
        at: &str,
        warnings: &mut Vec<String>,
    ) -> Result<Flags> {
        let mut flags = Flags::default();
        for param in params {
            let param = text::unquote(param);
            // `"update-interval=86400`, a stray quote some profiles have.
            let param = param.trim_matches('"');
            let (key, value) = match param.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim())),
                None => (param.trim().to_ascii_lowercase(), None),
            };
            match key.as_str() {
                "no-resolve" => flags.no_resolve = true,
                "extended-matching" => flags.extended = true,
                "pre-matching" => flags.pre_matching = true,
                "dns-failed" if kind == "FINAL" => {}
                "update-interval" => {
                    flags.update_interval = Some(
                        value
                            .and_then(|v| v.parse().ok())
                            .ok_or_else(|| anyhow!("{}: update-interval: not seconds", at))?,
                    )
                }
                "notification-text"
                | "notification-interval"
                | "always-capture"
                | "force-remote-dns" => {}
                key => warnings.push(format!(
                    "{}: {}: not a parameter Surge takes; ignored, as by Surge",
                    at, key
                )),
            }
        }
        Ok(flags)
    }
}

/// A rule without its policy, as a rule-set or a logical rule holds it:
/// its type, value and parameters.
pub(super) struct Headless {
    pub kind: String,
    pub value: String,
    pub params: Vec<String>,
}

impl Headless {
    pub(super) fn split(line: &str) -> Headless {
        let parts = text::split_rule(line);
        Headless {
            kind: parts[0].to_ascii_uppercase(),
            value: parts.get(1).map(|p| text::unquote(p)).unwrap_or_default(),
            params: parts.iter().skip(2).cloned().collect(),
        }
    }
}

/// What conditions may name besides themselves: the listeners, and the
/// rule-sets the rules name. A line of a rule-set's file has neither.
pub(super) struct Scope<'a> {
    pub general: Option<&'a General>,
    pub sets: Option<&'a mut Sets>,
    pub warnings: &'a mut Vec<String>,
}

/// A condition no connection meets.
fn never() -> Map<String, Value> {
    all(vec![network("tcp"), network("udp")])
}

/// What lowering the rules keeps track of.
struct Walk<'a> {
    policies: &'a Policies,
    general: &'a General,
    out: &'a mut Lowered,
    /// How far a rule before resolves the domain already.
    resolved: Resolve,
    /// Whether a domain that does not resolve goes on, `FINAL,dns-failed`.
    dns_failed: bool,
    /// What a rule before sniffs already.
    sniffed: Needs,
    /// The rules of `pre-matching`, matched first.
    early: Vec<Value>,
}

impl Walk<'_> {
    /// Adds a rule of `condition` to `target`, with what it needs before.
    fn push(&mut self, condition: Map<String, Value>, needs: Needs, target: Target) {
        self.prepare(needs);
        self.fallback(&condition, &target);
        let mut rule = condition;
        apply(&target, &mut rule);
        self.out.rules.push(Value::Object(rule));
    }

    /// Sniffs and resolves as `needs` says, where no rule before has.
    fn prepare(&mut self, needs: Needs) {
        let protocol = needs.protocol && !self.sniffed.protocol;
        let extended = needs.extended && !self.sniffed.extended;
        if protocol || extended {
            let sniffer = if needs.protocol {
                json!(["http", "tls", "quic", "stun"])
            } else {
                json!(["http", "tls", "quic"])
            };
            self.out
                .rules
                .push(json!({ "action": "sniff", "sniffer": sniffer }));
            self.sniffed.protocol |= needs.protocol;
            self.sniffed.extended = true;
            self.sniffed.http = true;
        }
        if needs.http && !self.sniffed.http {
            self.out
                .rules
                .push(json!({ "action": "sniff", "sniffer": ["http"] }));
            self.sniffed.http = true;
        }
        if needs.resolve > self.resolved {
            let mut resolve = json!({ "action": "resolve" });
            // A rule-set that may hold no IP rules is not worth failing
            // for: where the domain does not resolve, its IP rules do not
            // match. An IP rule after resolves again, and fails.
            if self.dns_failed || needs.resolve == Resolve::Maybe {
                resolve["ignore_failure"] = json!(true);
            }
            self.out.rules.push(resolve);
            self.resolved = needs.resolve;
        }
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
            _ if logical => all(vec![condition.clone(), network("udp")]),
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

    /// A `pre-matching` rule's, matched first for TCP.
    fn early(&mut self, condition: &Map<String, Value>, target: &Target) {
        let logical = condition.get("type").and_then(Value::as_str) == Some("logical");
        let mut rule = match condition.get("network") {
            Some(network) if !network.to_string().contains("tcp") => return,
            Some(_) => condition.clone(),
            None if logical => all(vec![condition.clone(), network("tcp")]),
            None => {
                let mut rule = condition.clone();
                rule.insert("network".into(), json!(["tcp"]));
                rule
            }
        };
        apply(target, &mut rule);
        self.early.push(Value::Object(rule));
    }
}

fn network(name: &str) -> Map<String, Value> {
    let mut rule = Map::new();
    rule.insert("network".into(), json!(name));
    rule
}

/// A rule that holds where all of `conditions` do.
fn all(conditions: Vec<Map<String, Value>>) -> Map<String, Value> {
    let mut rule = Map::new();
    rule.insert("type".into(), json!("logical"));
    rule.insert("mode".into(), json!("and"));
    rule.insert(
        "rules".into(),
        Value::Array(conditions.into_iter().map(Value::Object).collect()),
    );
    rule
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
    let parts = text::split_rule(line);
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
        resolved: Resolve::No,
        dns_failed,
        sniffed: Needs::default(),
        early: Vec::new(),
    };
    let mut scope = Scope {
        general: Some(general),
        sets: Some(sets),
        warnings,
    };
    let mut ended = false;
    for (at, s) in &rules {
        if ended {
            scope.warnings.push(format!(
                "{}: after FINAL, where no connection gets; ignored",
                at
            ));
            continue;
        }
        let target = policies
            .target(&s.policy)
            .map_err(|e| anyhow!("{}: {}", at, e))?;
        let flags = Flags::read(&s.params, &s.kind, at, scope.warnings)?;
        if s.kind == "FINAL" {
            ended = true;
            match target {
                Target::Outbound(tag) => {
                    // Its UDP, when it carries none.
                    walk.fallback(&Map::new(), &Target::Outbound(tag.clone()));
                    walk.out.route.insert("final".into(), json!(tag));
                }
                other => {
                    // A condition every connection meets.
                    let mut rule = Map::new();
                    rule.insert("network".into(), json!(["tcp", "udp"]));
                    apply(&other, &mut rule);
                    walk.out.rules.push(Value::Object(rule));
                }
            }
            continue;
        }
        let found = condition(&s.kind, &s.value, &flags, &mut scope, 0)
            .map_err(|e| anyhow!("{}: {}", at, e))?;
        let Some((condition, needs)) = found else {
            scope.warnings.push(format!(
                "{}: {},{}: no connection sail sees matches it; ignored",
                at, s.kind, s.value
            ));
            continue;
        };
        if flags.pre_matching {
            match &target {
                Target::Reject(_) => walk.early(&condition, &target),
                Target::Outbound(_) => scope.warnings.push(format!(
                    "{}: pre-matching: only a REJECT policy's rule is matched early; matched \
                     where it stands, as by Surge",
                    at
                )),
            }
        }
        walk.push(condition, needs, target);
    }
    if !ended {
        return Err(anyhow!(
            "[Rule]: no FINAL rule, which Surge requires at the end"
        ));
    }
    let early = std::mem::take(&mut walk.early);
    walk.out.rules.splice(0..0, early);
    Ok(())
}

/// The condition of a line of a rule-set's file, a rule without its
/// policy. What it needs sniffed or resolved is the rule's that names the
/// set.
#[cfg(feature = "rule-set")]
pub(super) fn headless(line: &str) -> Result<Map<String, Value>> {
    let h = Headless::split(text::strip_comment(line));
    let mut warnings = Vec::new();
    let flags = Flags::read(&h.params, &h.kind, &h.kind, &mut warnings)?;
    if h.kind == "FINAL" || flags.pre_matching {
        return Err(anyhow!("FINAL and pre-matching are not for a rule-set"));
    }
    let mut scope = Scope {
        general: None,
        sets: None,
        warnings: &mut warnings,
    };
    match condition(&h.kind, &h.value, &flags, &mut scope, 0)? {
        Some((condition, _)) => Ok(condition),
        None => Err(anyhow!(
            "{},{}: no connection sail sees matches it",
            h.kind,
            h.value
        )),
    }
}

/// The condition of a rule of `kind` and `value`, and what it needs; none
/// for a rule that never matches in sail. `depth` is how deep in logical
/// rules it is.
pub(super) fn condition(
    kind: &str,
    value: &str,
    flags: &Flags,
    scope: &mut Scope,
    depth: usize,
) -> Result<Option<Cond>> {
    let mut rule = Map::new();
    let mut needs = Needs::default();
    let resolves = |needs: &mut Needs| {
        if !flags.no_resolve {
            needs.resolve = Resolve::Yes;
        }
    };
    if value.is_empty() {
        return Err(anyhow!("{}: no value", kind));
    }
    let key = match kind {
        "AND" | "OR" | "NOT" => return logical(kind, value, scope, depth).map(Some),
        "DOMAIN" => "domain",
        "DOMAIN-SUFFIX" => "domain_suffix",
        "DOMAIN-KEYWORD" => "domain_keyword",
        "DOMAIN-WILDCARD" => {
            rule.insert("domain_regex".into(), json!([wildcard(value)]));
            needs.extended = flags.extended;
            return Ok(Some((rule, needs)));
        }
        "IP-CIDR" | "IP-CIDR6" => {
            rule.insert("ip_cidr".into(), json!([prefix(value)?]));
            resolves(&mut needs);
            return Ok(Some((rule, needs)));
        }
        "SRC-IP" => {
            rule.insert("source_ip_cidr".into(), json!([prefix(value)?]));
            return Ok(Some((rule, needs)));
        }
        "GEOIP" => {
            if value.eq_ignore_ascii_case("UNKNOWN") {
                return Err(anyhow!(
                    "GEOIP,UNKNOWN: sail does not implement addresses of no country yet"
                ));
            }
            let sets = scope
                .sets
                .as_deref_mut()
                .ok_or_else(|| anyhow!("GEOIP: sail reads no GEOIP rule in a rule-set"))?;
            rule.insert("rule_set".into(), json!([sets.geoip(value)?]));
            resolves(&mut needs);
            return Ok(Some((rule, needs)));
        }
        "IP-ASN" => {
            if value.eq_ignore_ascii_case("UNKNOWN") {
                return Err(anyhow!(
                    "IP-ASN,UNKNOWN: sail does not implement addresses of no system yet"
                ));
            }
            let digits = value
                .strip_prefix("AS")
                .or_else(|| value.strip_prefix("as"))
                .unwrap_or(value);
            let number: u32 = digits
                .parse()
                .map_err(|_| anyhow!("IP-ASN: {:?} is not a system's number", value))?;
            rule.insert("ip_asn".into(), json!([number]));
            resolves(&mut needs);
            return Ok(Some((rule, needs)));
        }
        "PROCESS-NAME" => {
            let (key, pattern) = process(value);
            rule.insert(key.into(), json!([pattern]));
            return Ok(Some((rule, needs)));
        }
        "USER-AGENT" => {
            rule.insert("http_user_agent".into(), json!([value]));
            needs.http = true;
            return Ok(Some((rule, needs)));
        }
        "URL-REGEX" => {
            #[cfg(feature = "regex")]
            regex::Regex::new(value).map_err(|e| anyhow!("URL-REGEX: {:?}: {}", value, e))?;
            rule.insert("url_regex".into(), json!([value]));
            needs.http = true;
            return Ok(Some((rule, needs)));
        }
        "HOSTNAME-TYPE" => {
            // As Surge writes them, in its case: the form of the name the
            // connection asks for, or of the one sniffed.
            match value {
                "IPv4" => rule.insert("ip_version".into(), json!(4)),
                "IPv6" => rule.insert("ip_version".into(), json!(6)),
                "DOMAIN" => rule.insert("domain_regex".into(), json!(["\\."])),
                "SIMPLE" => rule.insert("domain_regex".into(), json!(["^[^.]+$"])),
                other => {
                    return Err(anyhow!(
                        "HOSTNAME-TYPE: {:?} is none of IPv4, IPv6, DOMAIN and SIMPLE",
                        other
                    ))
                }
            };
            return Ok(Some((rule, needs)));
        }
        "DEST-PORT" | "SRC-PORT" => {
            let (one, many) = if kind == "DEST-PORT" {
                ("port", "port_range")
            } else {
                ("source_port", "source_port_range")
            };
            match port(value)? {
                Port::One(p) => rule.insert(one.into(), json!([p])),
                Port::Range(r) => rule.insert(many.into(), json!([r])),
            };
            return Ok(Some((rule, needs)));
        }
        "IN-PORT" => {
            let general = scope
                .general
                .ok_or_else(|| anyhow!("IN-PORT: sail reads no IN-PORT rule in a rule-set"))?;
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
            return Ok(Some((rule, needs)));
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
                needs.protocol = true;
                rule.insert("protocol".into(), json!([protocol]));
            }
            return Ok(Some((rule, needs)));
        }
        other => {
            return Err(match later(other) {
                Some(when) => anyhow!("sail does not implement {} rules{}", other, when),
                None => anyhow!("{} is not a rule type Surge takes", other),
            })
        }
    };
    needs.extended = flags.extended;
    rule.insert(key.into(), json!([value.to_ascii_lowercase()]));
    Ok(Some((rule, needs)))
}

/// A logical rule's condition: its rules, `((TYPE,value),...)`, each
/// written as a rule-set's.
fn logical(kind: &str, value: &str, scope: &mut Scope, depth: usize) -> Result<Cond> {
    if depth >= MAX_LOGICAL_DEPTH {
        return Err(anyhow!(
            "{}: logical rules nest {} deep at most",
            kind,
            MAX_LOGICAL_DEPTH
        ));
    }
    let inner = value
        .trim()
        .strip_prefix('(')
        .and_then(|v| v.strip_suffix(')'))
        .ok_or_else(|| anyhow!("{}: its rules are written ((TYPE,value),...)", kind))?;
    let mut rules = Vec::new();
    let mut needs = Needs::default();
    for part in text::split(inner, true) {
        let line = part
            .trim()
            .strip_prefix('(')
            .and_then(|p| p.strip_suffix(')'))
            .ok_or_else(|| anyhow!("{}: {:?} is not (TYPE,value)", kind, part))?;
        let h = Headless::split(line);
        let flags = Flags::read(&h.params, &h.kind, kind, scope.warnings)?;
        if h.kind == "FINAL" || flags.pre_matching {
            return Err(anyhow!("{}: FINAL and pre-matching are not within", kind));
        }
        let (condition, n) = condition(&h.kind, &h.value, &flags, scope, depth + 1)?
            .unwrap_or((never(), Needs::default()));
        rules.push(Value::Object(condition));
        needs = needs.and(n);
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
    Ok((rule, needs))
}

/// An address or a prefix, a bare address a prefix of it alone; the bits
/// past the prefix are dropped, as Surge drops them.
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
    let network = cidr::IpInet::new(ip, len)
        .map_err(|_| anyhow!("{:?} is not an address or a prefix", value))?
        .network();
    Ok(format!(
        "{}/{}",
        network.first_address(),
        network.network_length()
    ))
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
pub(super) fn wildcard(pattern: &str) -> String {
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
        assert_eq!(prefix("104.244.42.0/21").unwrap(), "104.244.40.0/21");
    }

    #[test]
    fn logical_rules_nest_and_say_what_they_need() {
        let mut warnings = Vec::new();
        let mut scope = Scope {
            general: None,
            sets: None,
            warnings: &mut warnings,
        };
        let (rule, needs) = condition(
            "AND",
            "((NOT,((SRC-IP,192.168.1.110))),(OR,((DOMAIN-SUFFIX,example.com,extended-matching),\
             (IP-CIDR,10.0.0.0/8))),(USER-AGENT,\"a,b*\"))",
            &Flags::default(),
            &mut scope,
            0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            Value::Object(rule),
            json!({ "type": "logical", "mode": "and", "rules": [
                { "type": "logical", "mode": "and", "invert": true, "rules": [
                    { "source_ip_cidr": ["192.168.1.110/32"] },
                ] },
                { "type": "logical", "mode": "or", "rules": [
                    { "domain_suffix": ["example.com"] },
                    { "ip_cidr": ["10.0.0.0/8"] },
                ] },
                { "http_user_agent": ["a,b*"] },
            ] })
        );
        assert_eq!(needs.resolve, Resolve::Yes);
        assert!(needs.http && needs.extended && !needs.protocol);
        // no-resolve within holds for its rule.
        let (_, needs) = condition(
            "OR",
            "((IP-ASN,AS13335,no-resolve),(DOMAIN,a))",
            &Flags::default(),
            &mut scope,
            0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(needs.resolve, Resolve::No);
        let deep = format!("{}(DOMAIN,a){}", "(NOT,(".repeat(11), "))".repeat(11));
        let err = condition(
            "NOT",
            &format!("({})", deep),
            &Flags::default(),
            &mut scope,
            0,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("nest 10 deep at most"), "{}", err);
        for (kind, value, expected) in [
            (
                "NOT",
                "((DOMAIN,a),(DOMAIN,b))",
                "NOT: one rule within, not 2",
            ),
            ("AND", "(DOMAIN,a)", "is not (TYPE,value)"),
            (
                "AND",
                "((FINAL,a))",
                "FINAL and pre-matching are not within",
            ),
            (
                "AND",
                "((SCRIPT,a))",
                "sail does not implement SCRIPT rules",
            ),
        ] {
            let err = condition(kind, value, &Flags::default(), &mut scope, 0)
                .unwrap_err()
                .to_string();
            assert!(err.contains(expected), "{}: {}", expected, err);
        }
    }

    #[cfg(feature = "rule-set")]
    #[test]
    fn a_rule_set_s_lines() {
        assert_eq!(
            Value::Object(headless("IP-ASN,13335,no-resolve").unwrap()),
            json!({ "ip_asn": [13335] })
        );
        assert_eq!(
            Value::Object(headless("HOSTNAME-TYPE,SIMPLE").unwrap()),
            json!({ "domain_regex": ["^[^.]+$"] })
        );
        assert_eq!(
            Value::Object(headless("URL-REGEX,\"^http://a\\.com/(x|y),z\"").unwrap()),
            json!({ "url_regex": ["^http://a\\.com/(x|y),z"] })
        );
        for (line, expected) in [
            ("GEOIP,CN", "no GEOIP rule in a rule-set"),
            ("IN-PORT,6152", "no IN-PORT rule in a rule-set"),
            ("DOMAIN,a,pre-matching", "not for a rule-set"),
            ("HOSTNAME-TYPE,ipv4", "none of IPv4"),
            ("IP-ASN,UNKNOWN", "no system yet"),
        ] {
            let err = headless(line).unwrap_err().to_string();
            assert!(err.contains(expected), "{}: {}", line, err);
        }
    }
}
