//! The rules of a rule-set, compiled: what they match, as sing-box matches
//! them.

use std::net::IpAddr;

use anyhow::{anyhow, Result};
use regex::Regex;

use super::succinct::Succinct;
use crate::app::router::matcher::{port_range, CidrIndex, DomainIndex, Facts, Groups};
use crate::config::external_rule::DomainKind;
use crate::config::rule_set::HeadlessRule;
use crate::session::Network;

pub(crate) enum Rule {
    Plain(Box<Plain>),
    Logical {
        /// `and`; `or` otherwise.
        all: bool,
        rules: Vec<Rule>,
        invert: bool,
    },
}

/// A plain rule. As in a routing rule, the conditions on one thing (the
/// destination's address, its port, the source's address, its port) match
/// when any of them does; the rule when each thing it has conditions on
/// matches, and the other conditions do.
#[derive(Default)]
pub(crate) struct Plain {
    domains: DomainIndex,
    /// The domains and suffixes of a binary rule-set.
    succinct: Option<Succinct>,
    domain_regex: Vec<Regex>,
    ip_cidr: CidrIndex,
    source_ip_cidr: CidrIndex,
    ports: Vec<(u16, u16)>,
    source_ports: Vec<(u16, u16)>,
    query_types: Vec<u16>,
    networks: Vec<Network>,
    process_names: Vec<String>,
    invert: bool,
}

/// What a plain rule is made of, before it is compiled: the conditions of
/// a source rule, and those a binary one gives in forms of its own.
#[derive(Default)]
pub(crate) struct Parts {
    pub rule: HeadlessRule,
    pub succinct: Option<Succinct>,
    pub ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub source_ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub query_types: Vec<u16>,
}

/// Rules nested deeper than this are refused, as sing-box refuses them.
const MAX_DEPTH: usize = 100;

impl Rule {
    /// Compiles a rule of the source format.
    pub(crate) fn from_source(rule: &HeadlessRule) -> Result<Self> {
        Self::compile(rule, 0)
    }

    fn compile(rule: &HeadlessRule, depth: usize) -> Result<Self> {
        if depth > MAX_DEPTH {
            return Err(anyhow!("logical rules nested too deep"));
        }
        match rule.kind.as_deref() {
            None | Some("default") => {
                if rule.mode.is_some() || !rule.rules.is_empty() {
                    return Err(anyhow!("mode and rules are for a logical rule"));
                }
                let query_types = rule
                    .query_type
                    .iter()
                    .map(query_type)
                    .collect::<Result<_>>()?;
                Ok(Rule::Plain(Box::new(Plain::compile(Parts {
                    rule: rule.clone(),
                    query_types,
                    ..Default::default()
                })?)))
            }
            Some("logical") => {
                let all = match rule.mode.as_deref() {
                    Some("and") => true,
                    Some("or") => false,
                    Some(other) => return Err(anyhow!("mode: unknown mode \"{}\"", other)),
                    None => return Err(anyhow!("mode: missing")),
                };
                if rule.rules.is_empty() {
                    return Err(anyhow!("rules: a logical rule needs some"));
                }
                let rules = rule
                    .rules
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        Self::compile(r, depth + 1).map_err(|e| anyhow!("rules[{}]: {}", i, e))
                    })
                    .collect::<Result<_>>()?;
                Ok(Rule::Logical {
                    all,
                    rules,
                    invert: rule.invert,
                })
            }
            Some(other) => Err(anyhow!("type: unknown rule type \"{}\"", other)),
        }
    }

    pub(crate) fn matches(&self, facts: &Facts, ip_match_source: bool) -> bool {
        match self {
            Rule::Plain(plain) => plain.matches(facts, ip_match_source),
            Rule::Logical { all, rules, invert } => {
                let matched = if *all {
                    rules.iter().all(|r| r.matches(facts, ip_match_source))
                } else {
                    rules.iter().any(|r| r.matches(facts, ip_match_source))
                };
                matched != *invert
            }
        }
    }

    /// The rule a rule-set of this rule alone merges into the rule that
    /// names it: a plain one, not inverted.
    pub(crate) fn mergeable(&self) -> Option<&Plain> {
        match self {
            Rule::Plain(plain) if !plain.invert => Some(plain),
            _ => None,
        }
    }
}

impl Plain {
    pub(crate) fn compile(parts: Parts) -> Result<Self> {
        let rule = &parts.rule;
        if let Some(field) = rule.unsupported() {
            return Err(anyhow!("{}: sail does not match it yet", field));
        }
        let mut domains = DomainIndex::default();
        for d in &rule.domain {
            domains.insert(DomainKind::Full, d);
        }
        for d in &rule.domain_suffix {
            domains.insert(DomainKind::Suffix, d);
        }
        for d in &rule.domain_keyword {
            domains.insert(DomainKind::Keyword, d);
        }
        let domain_regex = rule
            .domain_regex
            .iter()
            .map(|r| Regex::new(r).map_err(|e| anyhow!("domain_regex: \"{}\": {}", r, e)))
            .collect::<Result<_>>()?;
        let cidrs = |strings: &[String], ranges: &Option<Vec<(IpAddr, IpAddr)>>, field: &str| {
            match ranges {
                Some(ranges) => CidrIndex::from_ranges(ranges),
                None => CidrIndex::new(strings),
            }
            .map_err(|e| anyhow!("{}: {}", field, e))
        };
        let ports = |ports: &[u16], ranges: &[String]| {
            ports
                .iter()
                .map(|&p| Ok((p, p)))
                .chain(ranges.iter().map(|r| port_range(r)))
                .collect::<Result<Vec<_>>>()
        };
        let networks = rule
            .network
            .iter()
            .map(|n| match n.as_str() {
                "tcp" => Ok(Network::Tcp),
                "udp" => Ok(Network::Udp),
                other => Err(anyhow!("network: unknown network \"{}\"", other)),
            })
            .collect::<Result<_>>()?;
        Ok(Plain {
            domains,
            succinct: parts.succinct,
            domain_regex,
            ip_cidr: cidrs(&rule.ip_cidr, &parts.ip_ranges, "ip_cidr")?,
            source_ip_cidr: cidrs(
                &rule.source_ip_cidr,
                &parts.source_ip_ranges,
                "source_ip_cidr",
            )?,
            ports: ports(&rule.port, &rule.port_range)?,
            source_ports: ports(&rule.source_port, &rule.source_port_range)?,
            query_types: parts.query_types,
            networks,
            process_names: rule.process_name.clone(),
            invert: rule.invert,
        })
    }

    /// Whether it has conditions on a destination address given as IPs.
    pub(crate) fn has_ip_cidr(&self) -> bool {
        !self.ip_cidr.is_empty()
    }

    fn has_domains(&self) -> bool {
        !self.domains.is_empty() || self.succinct.is_some() || !self.domain_regex.is_empty()
    }

    /// Which things it has conditions on, and which of them match; `None`
    /// when a condition on anything else does not.
    pub(crate) fn evaluate(&self, facts: &Facts, ip_match_source: bool) -> Option<Groups> {
        let mut groups = Groups::default();
        let source_ip = facts.source().map(|s| s.ip());
        if !self.source_ip_cidr.is_empty() {
            groups.require(
                Groups::SOURCE_ADDRESS,
                source_ip.is_some_and(|ip| self.source_ip_cidr.contains(ip)),
            );
        }
        if ip_match_source && self.has_ip_cidr() {
            groups.require(
                Groups::SOURCE_ADDRESS,
                source_ip.is_some_and(|ip| self.ip_cidr.contains(ip)),
            );
        }
        if !self.source_ports.is_empty() {
            let port = facts.source().map(|s| s.port());
            groups.require(
                Groups::SOURCE_PORT,
                port.is_some_and(|p| within(&self.source_ports, p)),
            );
        }
        if self.has_domains() {
            let matched = facts.domain().is_some_and(|d| {
                self.domains.matches(d)
                    || self.succinct.as_ref().is_some_and(|s| s.matches(d))
                    || self.domain_regex.iter().any(|r| r.is_match(d))
            });
            groups.require(Groups::DESTINATION_ADDRESS, matched);
        }
        if !ip_match_source && self.has_ip_cidr() {
            groups.require(
                Groups::DESTINATION_ADDRESS,
                facts.ips().iter().any(|&ip| self.ip_cidr.contains(ip)),
            );
        }
        if !self.ports.is_empty() {
            groups.require(Groups::DESTINATION_PORT, within(&self.ports, facts.port()));
        }
        if !self.query_types.is_empty()
            && !facts
                .query_type()
                .is_some_and(|t| self.query_types.contains(&t))
        {
            return None;
        }
        if !self.networks.is_empty() && !self.networks.contains(&facts.network()) {
            return None;
        }
        if !self.process_names.is_empty()
            && !facts
                .process_name()
                .is_some_and(|name| self.process_names.iter().any(|p| p == name))
        {
            return None;
        }
        Some(groups)
    }

    fn matches(&self, facts: &Facts, ip_match_source: bool) -> bool {
        let matched = self
            .evaluate(facts, ip_match_source)
            .is_some_and(|groups| groups.done());
        matched != self.invert
    }
}

fn within(ranges: &[(u16, u16)], port: u16) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| (start..=end).contains(&port))
}

/// A record type as sing-box writes one: its name, or its number.
pub(crate) fn query_type(value: &serde_json::Value) -> Result<u16> {
    use std::str::FromStr;
    match value {
        serde_json::Value::String(name) => {
            hickory_proto::rr::RecordType::from_str(&name.to_ascii_uppercase())
                .map(u16::from)
                .map_err(|_| anyhow!("query_type: unknown record type \"{}\"", name))
        }
        serde_json::Value::Number(n) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| anyhow!("query_type: invalid record type {}", n)),
        other => Err(anyhow!("query_type: invalid record type {}", other)),
    }
}
