//! The conditions of a rule, compiled into indexes: a domain is looked up
//! in hash sets, an address is binary-searched in sorted ranges. Routing
//! rules, DNS rules and the rules of rule-sets all compile to the same
//! [`Condition`], and match as sing-box's `DefaultRule` and `LogicalRule`
//! do.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use cidr::IpCidr;
use maxminddb::geoip2::Country;

use super::rule_set::succinct::Succinct;
use crate::config::external_rule::{self, DomainKind, External};
use crate::config::model::{self, LogicalMode, RuleType};
use crate::runtime::RuntimeEnv;
use crate::session::{Network, Session, SniffedProtocol};

/// What rules are matched against: what is known about a connection at
/// the time.
pub(crate) struct Facts {
    /// The domain, sniffed or asked for, in lowercase.
    domain: Option<String>,
    /// The address asked for, and those the domain resolved to.
    ips: Vec<IpAddr>,
    port: u16,
    /// 4 or 6, when the destination is an address.
    ip_version: Option<u8>,
    network: Network,
    inbound: String,
    user: Option<std::sync::Arc<str>>,
    /// The protocol sniffing found.
    protocol: Option<SniffedProtocol>,
    /// The path of the program the connection comes from.
    process_path: Option<String>,
    source: std::net::SocketAddr,
    /// The record type, for a DNS query.
    query_type: Option<u16>,
    /// The code of the DNS response matched.
    rcode: Option<u16>,
}

impl Facts {
    pub fn new(sess: &Session, resolved: &[IpAddr]) -> Self {
        let domain = sess
            .sniffed_domain()
            .or_else(|| sess.destination.domain().map(String::as_str))
            .map(str::to_ascii_lowercase);
        let destination = sess.destination.ip().map(|ip| ip.to_canonical());
        let mut ips: Vec<IpAddr> = destination.into_iter().collect();
        ips.extend_from_slice(resolved);
        Facts {
            domain,
            ips,
            port: sess.destination.port(),
            ip_version: destination.map(|ip| if ip.is_ipv4() { 4 } else { 6 }),
            network: sess.network,
            inbound: sess.inbound_tag.clone(),
            user: sess.user.clone(),
            protocol: sess.sniffed_protocol,
            process_path: sess.process_name.clone(),
            source: sess.source,
            query_type: None,
            rcode: None,
        }
    }

    /// The facts of a DNS response with code `rcode`, whose addresses
    /// are those resolved.
    pub fn with_rcode(mut self, rcode: u16) -> Self {
        self.rcode = Some(rcode);
        self
    }

    /// The facts of a DNS query of `query_type`.
    pub fn with_query_type(mut self, query_type: u16) -> Self {
        self.query_type = Some(query_type);
        self
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Where the connection came from; none for the DNS client's own
    /// queries.
    pub fn source(&self) -> Option<std::net::SocketAddr> {
        Some(self.source).filter(|s| !s.ip().is_unspecified() || s.port() != 0)
    }

    pub fn ips(&self) -> &[IpAddr] {
        &self.ips
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The name of the program the connection comes from: its path's last
    /// part.
    pub fn process_name(&self) -> Option<&str> {
        self.process_path
            .as_deref()
            .map(|path| path.rsplit(['/', '\\']).next().unwrap_or(path))
    }

    pub fn query_type(&self) -> Option<u16> {
        self.query_type
    }
}

/// The things a rule has conditions on, as sing-box groups them: of the
/// conditions on one thing, any matching will do.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Groups {
    required: u8,
    satisfied: u8,
}

impl Groups {
    pub const SOURCE_ADDRESS: u8 = 1;
    pub const SOURCE_PORT: u8 = 2;
    pub const DESTINATION_ADDRESS: u8 = 4;
    pub const DESTINATION_PORT: u8 = 8;

    /// Conditions on `group`, which match or not.
    pub fn require(&mut self, group: u8, matched: bool) {
        self.required |= group;
        if matched {
            self.satisfied |= group;
        }
    }

    /// Whether every thing with conditions matches.
    pub fn done(self) -> bool {
        self.required & !self.satisfied == 0
    }

    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub fn merge(self, other: Groups) -> Groups {
        Groups {
            required: self.required | other.required,
            satisfied: self.satisfied | other.satisfied,
        }
    }
}

/// Domains by how they are compared.
#[derive(Default)]
pub(crate) struct DomainIndex {
    full: HashSet<String>,
    /// A domain matches when it is one of these or a subdomain of one.
    suffix: HashSet<String>,
    /// A domain matches when it is a subdomain of one of these: a suffix
    /// written with a leading dot, as sing-box reads it.
    subdomain: HashSet<String>,
    keyword: Vec<String>,
}

impl DomainIndex {
    pub(crate) fn insert(&mut self, kind: DomainKind, value: &str) {
        let value = value.to_ascii_lowercase();
        match kind {
            DomainKind::Full => {
                self.full.insert(value);
            }
            DomainKind::Suffix => match value.strip_prefix('.') {
                Some(parent) => {
                    self.subdomain.insert(parent.to_string());
                }
                None => {
                    self.suffix.insert(value);
                }
            },
            DomainKind::Keyword => self.keyword.push(value),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.full.is_empty()
            && self.suffix.is_empty()
            && self.subdomain.is_empty()
            && self.keyword.is_empty()
    }

    pub(crate) fn matches(&self, domain: &str) -> bool {
        if self.full.contains(domain) {
            return true;
        }
        if !self.suffix.is_empty() || !self.subdomain.is_empty() {
            let mut rest = domain;
            let mut is_parent = false;
            loop {
                if self.suffix.contains(rest) || (is_parent && self.subdomain.contains(rest)) {
                    return true;
                }
                match rest.find('.') {
                    Some(dot) => rest = &rest[dot + 1..],
                    None => break,
                }
                is_parent = true;
            }
        }
        self.keyword.iter().any(|k| domain.contains(k.as_str()))
    }
}

/// Address ranges, sorted and merged, per family.
#[derive(Default)]
pub(crate) struct CidrIndex {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrIndex {
    /// CIDRs, or plain addresses, which stand for themselves.
    pub(crate) fn new(cidrs: &[String]) -> Result<Self> {
        let mut index = CidrIndex::default();
        for value in cidrs {
            let cidr = value
                .parse::<IpCidr>()
                .or_else(|e| value.parse::<IpAddr>().map(IpCidr::new_host).map_err(|_| e))
                .map_err(|e| anyhow!("invalid CIDR \"{}\": {}", value, e))?;
            match (cidr.first_address(), cidr.last_address()) {
                (IpAddr::V4(first), IpAddr::V4(last)) => index.v4.push((first.into(), last.into())),
                (IpAddr::V6(first), IpAddr::V6(last)) => index.v6.push((first.into(), last.into())),
                _ => unreachable!("a CIDR is of one family"),
            }
        }
        merge(&mut index.v4);
        merge(&mut index.v6);
        Ok(index)
    }

    /// Inclusive ranges of addresses, each of one family.
    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub(crate) fn from_ranges(ranges: &[(IpAddr, IpAddr)]) -> Result<Self> {
        let mut index = CidrIndex::default();
        for &(first, last) in ranges {
            match (first.to_canonical(), last.to_canonical()) {
                (IpAddr::V4(first), IpAddr::V4(last)) if first <= last => {
                    index.v4.push((first.into(), last.into()))
                }
                (IpAddr::V6(first), IpAddr::V6(last)) if first <= last => {
                    index.v6.push((first.into(), last.into()))
                }
                _ => return Err(anyhow!("invalid address range {} - {}", first, last)),
            }
        }
        merge(&mut index.v4);
        merge(&mut index.v6);
        Ok(index)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(ip) => within(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => within(&self.v6, u128::from(ip)),
        }
    }
}

fn merge<T: Ord + Copy>(ranges: &mut Vec<(T, T)>) {
    ranges.sort();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges.iter() {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    *ranges = merged;
}

fn within<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let after = ranges.partition_point(|r| r.0 <= x);
    after > 0 && ranges[after - 1].1 >= x
}

/// Whether `ip` is not a public address, as sing's `IsPublicAddr` says:
/// private, loopback, link-local, multicast or unspecified.
pub(crate) fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_link_local()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            (first & 0xfe00) == 0xfc00
                || ip.is_loopback()
                || ip.is_multicast()
                || (first & 0xffc0) == 0xfe80
                || ip.is_unspecified()
        }
    }
}

struct Mmdb {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
    /// Uppercase, as the databases have them.
    country_code: String,
}

impl Mmdb {
    fn contains(&self, ip: IpAddr) -> bool {
        self.reader
            .lookup(ip)
            .and_then(|result| result.decode::<Country>())
            .is_ok_and(|country| {
                country.is_some_and(|country| {
                    country.country.iso_code == Some(self.country_code.as_str())
                })
            })
    }
}

/// Mmdb readers by file, shared by the rules that use the same database.
pub(crate) type Readers = HashMap<String, Arc<maxminddb::Reader<Vec<u8>>>>;

/// A regular expression, when sail is built with them.
#[cfg(feature = "regex")]
type Pattern = regex::Regex;

/// Without regular expressions, there are none to match.
#[cfg(not(feature = "regex"))]
enum Pattern {}

#[cfg(not(feature = "regex"))]
impl Pattern {
    fn is_match(&self, _: &str) -> bool {
        match *self {}
    }
}

fn patterns(field: &str, values: &[String]) -> Result<Vec<Pattern>> {
    #[cfg(feature = "regex")]
    {
        values
            .iter()
            .map(|v| Pattern::new(v).map_err(|e| anyhow!("{}: \"{}\": {}", field, v, e)))
            .collect()
    }
    #[cfg(not(feature = "regex"))]
    match values.first() {
        Some(_) => Err(anyhow!(
            "{}: not supported, sail is built without regular expressions",
            field
        )),
        None => Ok(Vec::new()),
    }
}

/// Whether sail can tell which program a connection comes from: the
/// NetFilter inbound on Windows says. Tests match as if it could.
const PROCESS_KNOWN: bool = cfg!(any(test, all(feature = "inbound-nf", windows)));
/// Whether process conditions are compiled in.
const PROCESS_COMPILED: bool = cfg!(any(test, feature = "rule-process-name"));

/// Refuses a condition on the program a connection comes from, where it is
/// never known: it would never match.
fn process_known(field: &str, compiled: bool, known: bool) -> Result<()> {
    if !compiled {
        return Err(anyhow!(
            "{}: not supported, rule-process-name is not compiled in",
            field
        ));
    }
    if !known {
        return Err(anyhow!(
            "{}: sail cannot tell which program a connection comes from on this platform",
            field
        ));
    }
    Ok(())
}

/// The protocol sing-box names `name`, as `field` gives it: one sail
/// sniffs, or a condition that could never match is refused.
pub(crate) fn sniffed_protocol(field: &str, name: &str) -> Result<SniffedProtocol> {
    match SniffedProtocol::ALL.into_iter().find(|p| p.name() == name) {
        Some(SniffedProtocol::Quic) if !cfg!(feature = "btls") => Err(anyhow!(
            "{}: quic is never sniffed, sail is built without btls",
            field
        )),
        Some(protocol) => Ok(protocol),
        None if ["ssh", "rdp", "ntp"].contains(&name) => {
            Err(anyhow!("{}: sail does not sniff {} yet", field, name))
        }
        None => Err(anyhow!("{}: unknown protocol \"{}\"", field, name)),
    }
}

/// What building a condition needs from outside it.
pub(crate) struct Context<'a> {
    pub readers: &'a mut Readers,
    pub env: &'a RuntimeEnv,
    pub rule_sets: &'a super::rule_set::RuleSets,
}

/// What the rules of a binary rule-set give in forms of their own.
#[derive(Default)]
pub(crate) struct Extras {
    pub succinct: Option<Succinct>,
    pub ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub source_ip_ranges: Option<Vec<(IpAddr, IpAddr)>>,
    pub query_types: Vec<u16>,
}

/// `field` of the rule at `path`, as errors name it.
fn at(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{}.{}", path, field)
    }
}

/// Rules nested deeper than this are refused, as sing-box refuses them.
pub(crate) const MAX_DEPTH: usize = 100;

/// A rule's conditions, compiled.
pub(crate) enum Condition {
    /// A default rule: conditions of its own.
    Default(Box<Conditions>),
    /// A logical rule: others, combined.
    Logical {
        /// `and`; `or` otherwise.
        all: bool,
        rules: Vec<Condition>,
        invert: bool,
    },
}

impl Condition {
    /// Compiles the conditions of `rule`, found at `path`, and of the
    /// rules nested in it.
    pub(crate) fn compile(rule: &model::Rule, path: &str, ctx: &mut Context) -> Result<Self> {
        Self::compile_at(rule, path, ctx, 0)
    }

    fn compile_at(rule: &model::Rule, path: &str, ctx: &mut Context, depth: usize) -> Result<Self> {
        if depth > MAX_DEPTH {
            return Err(anyhow!("{}: logical rules nested too deep", path));
        }
        match rule.kind {
            RuleType::Default => Ok(Condition::Default(Box::new(Conditions::compile(
                rule,
                Extras::default(),
                path,
                ctx,
            )?))),
            RuleType::Logical => {
                let all = match rule.mode {
                    Some(LogicalMode::And) => true,
                    Some(LogicalMode::Or) => false,
                    None => return Err(anyhow!("{}: missing", at(path, "mode"))),
                };
                if rule.rules.is_empty() {
                    return Err(anyhow!("{}: a logical rule needs some", at(path, "rules")));
                }
                let rules = rule
                    .rules
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        Self::compile_at(r, &at(path, &format!("rules[{}]", i)), ctx, depth + 1)
                    })
                    .collect::<Result<_>>()?;
                Ok(Condition::Logical {
                    all,
                    rules,
                    invert: rule.invert,
                })
            }
        }
    }

    /// Whether the connection `facts` tells of matches; a rule-set's
    /// `ip_cidr` matches the source when `ip_match_source`.
    pub(crate) fn matches(&self, facts: &Facts, ip_match_source: bool) -> bool {
        match self {
            Condition::Default(conditions) => conditions.matches(facts, ip_match_source),
            Condition::Logical { all, rules, invert } => {
                let matched = if *all {
                    rules.iter().all(|r| r.matches(facts, ip_match_source))
                } else {
                    rules.iter().any(|r| r.matches(facts, ip_match_source))
                };
                matched != *invert
            }
        }
    }

    /// The conditions a rule-set of this rule alone merges into the rule
    /// that names it: a default rule's, not inverted, naming no rule-set.
    #[cfg_attr(not(feature = "rule-set"), allow(dead_code))]
    pub(crate) fn mergeable(&self) -> Option<&Conditions> {
        match self {
            Condition::Default(c) if !c.invert && !c.has_rule_sets() => Some(c),
            _ => None,
        }
    }
}

/// The conditions of a default rule. Those on one thing (the source's
/// address, its port, the destination's address, its port) match when any
/// of them does; the rule when each thing it has conditions on matches,
/// and every other condition does.
#[derive(Default)]
pub(crate) struct Conditions {
    /// The mode wanted, and the instance's.
    clash_mode: Option<(String, crate::app::clash_mode::ClashMode)>,
    inbounds: Vec<String>,
    ip_version: Option<u8>,
    networks: Vec<Network>,
    auth_users: Vec<String>,
    protocols: Vec<SniffedProtocol>,
    domains: DomainIndex,
    /// The domains and suffixes of a binary rule-set.
    succinct: Option<Succinct>,
    domain_regex: Vec<Pattern>,
    source_ip_cidr: CidrIndex,
    source_ip_is_private: bool,
    ip_cidr: CidrIndex,
    mmdbs: Vec<Mmdb>,
    ip_is_private: bool,
    /// Any address matches, of a DNS response.
    ip_accept_any: bool,
    response_rcode: Option<u16>,
    source_ports: Vec<(u16, u16)>,
    ports: Vec<(u16, u16)>,
    process_names: Vec<String>,
    process_paths: Vec<String>,
    process_path_regex: Vec<Pattern>,
    query_types: Vec<u16>,
    #[cfg(feature = "rule-set")]
    rule_sets: Vec<super::rule_set::SharedRuleSet>,
    #[cfg(feature = "rule-set")]
    ip_match_source: bool,
    invert: bool,
    /// Whether it has no conditions at all, and so matches everything,
    /// inverted or not, as in sing-box.
    empty: bool,
}

impl Conditions {
    /// Compiles the conditions of the default rule `rule`, found at
    /// `path`, with what a binary rule-set gives in `extras`.
    pub(crate) fn compile(
        rule: &model::Rule,
        extras: Extras,
        path: &str,
        ctx: &mut Context,
    ) -> Result<Self> {
        let field = |f: &str| at(path, f);
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
        for code in &rule.geosite {
            for (kind, d) in external_rule::geosite(code, ctx.env)
                .map_err(|e| anyhow!("{}: {}", field("geosite"), e))?
            {
                domains.insert(kind, &d);
            }
        }
        let mut mmdbs: Vec<external_rule::Mmdb> = rule
            .geoip
            .iter()
            .map(|c| external_rule::geoip(c, ctx.env))
            .collect();
        for filter in &rule.external {
            match external_rule::load(filter, ctx.env)
                .map_err(|e| anyhow!("{}: {}", field("external"), e))?
            {
                External::Mmdb(mmdb) => mmdbs.push(mmdb),
                External::Domains(list) => {
                    for (kind, d) in list {
                        domains.insert(kind, &d);
                    }
                }
            }
        }
        let mmdbs = mmdbs
            .into_iter()
            .map(|mmdb| {
                let reader = match ctx.readers.get(&mmdb.file) {
                    Some(r) => r.clone(),
                    None => {
                        let r = Arc::new(maxminddb::Reader::open_readfile(&mmdb.file).map_err(
                            |e| anyhow!("{}: open {} failed: {}", field("geoip"), mmdb.file, e),
                        )?);
                        ctx.readers.insert(mmdb.file.clone(), r.clone());
                        r
                    }
                };
                Ok(Mmdb {
                    reader,
                    country_code: mmdb.country_code.to_ascii_uppercase(),
                })
            })
            .collect::<Result<_>>()?;

        #[cfg(feature = "rule-set")]
        let rule_sets = rule
            .rule_set
            .iter()
            .map(|tag| ctx.rule_sets.get(tag))
            .collect::<Result<_>>()
            .map_err(|e| anyhow!("{}: {}", field("rule_set"), e))?;
        #[cfg(not(feature = "rule-set"))]
        if let Some(tag) = rule.rule_set.first() {
            ctx.rule_sets
                .get(tag)
                .map_err(|e| anyhow!("{}: {}", field("rule_set"), e))?;
        }

        for (name, set) in [
            ("process_name", !rule.process_name.is_empty()),
            ("process_path", !rule.process_path.is_empty()),
            ("process_path_regex", !rule.process_path_regex.is_empty()),
        ] {
            if set {
                process_known(&field(name), PROCESS_COMPILED, PROCESS_KNOWN)?;
            }
        }
        for (name, set) in [
            ("package_name", !rule.package_name.is_empty()),
            ("package_name_regex", !rule.package_name_regex.is_empty()),
        ] {
            if set {
                return Err(anyhow!(
                    "{}: sail cannot tell which Android package a connection comes from yet",
                    field(name)
                ));
            }
        }
        for (name, set) in [
            ("user", !rule.user.is_empty()),
            ("user_id", !rule.user_id.is_empty()),
        ] {
            if set {
                return Err(anyhow!(
                    "{}: sail cannot tell which user a connection's program runs as yet",
                    field(name)
                ));
            }
        }
        let ip_version = match rule.ip_version {
            None => None,
            Some(v @ (4 | 6)) => Some(v),
            Some(v) => return Err(anyhow!("{}: 4 or 6, not {}", field("ip_version"), v)),
        };

        let cidrs = |strings: &[String], ranges: &Option<Vec<(IpAddr, IpAddr)>>, name: &str| {
            match ranges {
                Some(ranges) => CidrIndex::from_ranges(ranges),
                None => CidrIndex::new(strings),
            }
            .map_err(|e| anyhow!("{}: {}", field(name), e))
        };
        let ports = |ports: &[u16], ranges: &[String], name: &str| {
            ports
                .iter()
                .map(|&p| Ok((p, p)))
                .chain(ranges.iter().map(|r| port_range(r)))
                .collect::<Result<Vec<_>>>()
                .map_err(|e| anyhow!("{}: {}", field(name), e))
        };
        let conditions = Conditions {
            inbounds: rule.inbound.clone(),
            ip_version,
            networks: rule
                .network
                .iter()
                .map(|net| match net.to_ascii_lowercase().as_str() {
                    "tcp" => Ok(Network::Tcp),
                    "udp" => Ok(Network::Udp),
                    _ => Err(anyhow!("{}: unknown network \"{}\"", field("network"), net)),
                })
                .collect::<Result<_>>()?,
            auth_users: rule.auth_user.clone(),
            protocols: rule
                .protocol
                .iter()
                .map(|name| sniffed_protocol(&field("protocol"), name))
                .collect::<Result<_>>()?,
            domains,
            succinct: extras.succinct,
            domain_regex: patterns(&field("domain_regex"), &rule.domain_regex)?,
            source_ip_cidr: cidrs(
                &rule.source_ip_cidr,
                &extras.source_ip_ranges,
                "source_ip_cidr",
            )?,
            source_ip_is_private: rule.source_ip_is_private,
            ip_cidr: cidrs(&rule.ip_cidr, &extras.ip_ranges, "ip_cidr")?,
            mmdbs,
            ip_is_private: rule.ip_is_private,
            ip_accept_any: rule.ip_accept_any,
            response_rcode: rule.response_rcode,
            source_ports: ports(
                &rule.source_port,
                &rule.source_port_range,
                "source_port_range",
            )?,
            ports: ports(&rule.port, &rule.port_range, "port_range")?,
            process_names: rule.process_name.clone(),
            process_paths: rule.process_path.clone(),
            process_path_regex: patterns(&field("process_path_regex"), &rule.process_path_regex)?,
            clash_mode: rule
                .clash_mode
                .clone()
                .map(|mode| (mode, ctx.env.clash_mode.clone())),
            query_types: if extras.query_types.is_empty() {
                rule.query_type
                    .iter()
                    .map(query_type)
                    .collect::<Result<_>>()
                    .map_err(|e| anyhow!("{}: {}", field("query_type"), e))?
            } else {
                extras.query_types
            },
            #[cfg(feature = "rule-set")]
            rule_sets,
            #[cfg(feature = "rule-set")]
            ip_match_source: rule.rule_set_ip_cidr_match_source,
            invert: rule.invert,
            empty: false,
        };
        Ok(Conditions {
            empty: conditions.is_empty(),
            ..conditions
        })
    }

    fn is_empty(&self) -> bool {
        self.inbounds.is_empty()
            && self.ip_version.is_none()
            && self.networks.is_empty()
            && self.auth_users.is_empty()
            && self.protocols.is_empty()
            && !self.has_domains()
            && self.source_ip_cidr.is_empty()
            && !self.source_ip_is_private
            && !self.has_ip_cidr()
            && self.source_ports.is_empty()
            && self.ports.is_empty()
            && self.process_names.is_empty()
            && self.process_paths.is_empty()
            && self.process_path_regex.is_empty()
            && self.query_types.is_empty()
            && self.response_rcode.is_none()
            && self.clash_mode.is_none()
            && !self.has_rule_sets()
    }

    fn has_rule_sets(&self) -> bool {
        #[cfg(feature = "rule-set")]
        return !self.rule_sets.is_empty();
        #[cfg(not(feature = "rule-set"))]
        false
    }

    /// Whether it has conditions on a destination address given as IPs.
    pub(crate) fn has_ip_cidr(&self) -> bool {
        !self.ip_cidr.is_empty()
            || !self.mmdbs.is_empty()
            || self.ip_is_private
            || self.ip_accept_any
    }

    fn has_domains(&self) -> bool {
        !self.domains.is_empty() || self.succinct.is_some() || !self.domain_regex.is_empty()
    }

    /// Which things it has conditions on, and which of them match; `None`
    /// when a condition on anything else does not. A rule-set's `ip_cidr`
    /// matches the source when `ip_match_source`.
    pub(crate) fn evaluate(&self, facts: &Facts, ip_match_source: bool) -> Option<Groups> {
        let mut groups = Groups::default();
        let source_ip = facts.source().map(|s| s.ip());
        if !self.source_ip_cidr.is_empty() || self.source_ip_is_private {
            groups.require(
                Groups::SOURCE_ADDRESS,
                source_ip.is_some_and(|ip| {
                    self.source_ip_cidr.contains(ip)
                        || (self.source_ip_is_private && is_private(ip))
                }),
            );
        }
        let by_ip = |ip: IpAddr| {
            self.ip_cidr.contains(ip)
                || self.mmdbs.iter().any(|m| m.contains(ip))
                || (self.ip_is_private && is_private(ip))
                || self.ip_accept_any
        };
        if ip_match_source && self.has_ip_cidr() {
            // Only `ip_cidr` looks at the source; the others still look at
            // the destination.
            let matched = source_ip.is_some_and(|ip| self.ip_cidr.contains(ip))
                || facts.ips().iter().any(|&ip| {
                    self.mmdbs.iter().any(|m| m.contains(ip))
                        || (self.ip_is_private && is_private(ip))
                });
            groups.require(Groups::SOURCE_ADDRESS, matched);
        }
        if !self.source_ports.is_empty() {
            let port = facts.source().map(|s| s.port());
            groups.require(
                Groups::SOURCE_PORT,
                port.is_some_and(|p| in_ranges(&self.source_ports, p)),
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
                facts.ips().iter().any(|&ip| by_ip(ip)),
            );
        }
        if !self.ports.is_empty() {
            groups.require(
                Groups::DESTINATION_PORT,
                in_ranges(&self.ports, facts.port()),
            );
        }
        let holds = (self.inbounds.is_empty() || self.inbounds.contains(&facts.inbound))
            && self.ip_version.is_none_or(|v| facts.ip_version == Some(v))
            && (self.networks.is_empty() || self.networks.contains(&facts.network()))
            && (self.auth_users.is_empty()
                || facts
                    .user
                    .as_ref()
                    .is_some_and(|user| self.auth_users.iter().any(|u| **u == **user)))
            && (self.protocols.is_empty()
                || facts.protocol.is_some_and(|p| self.protocols.contains(&p)))
            && (self.process_names.is_empty()
                || facts
                    .process_name()
                    .is_some_and(|name| self.process_names.iter().any(|p| p == name)))
            && (self.process_paths.is_empty()
                || facts
                    .process_path
                    .as_deref()
                    .is_some_and(|path| self.process_paths.iter().any(|p| p == path)))
            && (self.process_path_regex.is_empty()
                || facts
                    .process_path
                    .as_deref()
                    .is_some_and(|path| self.process_path_regex.iter().any(|r| r.is_match(path))))
            && (self.query_types.is_empty()
                || facts
                    .query_type()
                    .is_some_and(|t| self.query_types.contains(&t)))
            && self.response_rcode.is_none_or(|c| facts.rcode == Some(c))
            && self
                .clash_mode
                .as_ref()
                .is_none_or(|(wanted, mode)| mode.is(wanted));
        holds.then_some(groups)
    }

    pub(crate) fn matches(&self, facts: &Facts, ip_match_source: bool) -> bool {
        if self.empty {
            return true;
        }
        let matched = match self.evaluate(facts, ip_match_source) {
            None => false,
            #[cfg(feature = "rule-set")]
            Some(groups) if !self.rule_sets.is_empty() => self
                .rule_sets
                .iter()
                .any(|set| set.load().matches_with(groups, facts, self.ip_match_source)),
            Some(groups) => groups.done(),
        };
        matched != self.invert
    }
}

fn in_ranges(ranges: &[(u16, u16)], port: u16) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| (start..=end).contains(&port))
}

/// The conditions of a routing or DNS rule, as they match.
pub(crate) struct Matcher(Condition);

impl Matcher {
    /// Compiles the conditions of `rule`; errors name the field at fault.
    #[cfg(test)]
    pub fn new(
        rule: &model::Rule,
        readers: &mut Readers,
        env: &RuntimeEnv,
        rule_sets: &super::rule_set::RuleSets,
    ) -> Result<Self> {
        Self::at(rule, "", readers, env, rule_sets)
    }

    /// Compiles the conditions of `rule`, found at `path`, which errors
    /// name.
    pub fn at(
        rule: &model::Rule,
        path: &str,
        readers: &mut Readers,
        env: &RuntimeEnv,
        rule_sets: &super::rule_set::RuleSets,
    ) -> Result<Self> {
        let mut ctx = Context {
            readers,
            env,
            rule_sets,
        };
        Condition::compile(rule, path, &mut ctx).map(Matcher)
    }

    pub fn matches(&self, facts: &Facts) -> bool {
        self.0.matches(facts, false)
    }
}

/// A record type as sing-box writes one: its name, or its number.
pub(crate) fn query_type(value: &serde_json::Value) -> Result<u16> {
    use std::str::FromStr;
    match value {
        serde_json::Value::String(name) => {
            hickory_proto::rr::RecordType::from_str(&name.to_ascii_uppercase())
                .map(u16::from)
                .map_err(|_| anyhow!("unknown record type \"{}\"", name))
        }
        serde_json::Value::Number(n) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| anyhow!("invalid record type {}", n)),
        other => Err(anyhow!("invalid record type {}", other)),
    }
}

/// An inclusive range as sing-box writes it: `1000:2000`, or open at one
/// end, `:1024`, `8000:`.
pub(crate) fn port_range(value: &str) -> Result<(u16, u16)> {
    let invalid = || anyhow!("invalid port range \"{}\"", value);
    let (start, end) = value.split_once(':').ok_or_else(invalid)?;
    let bound = |s: &str, open: u16| match s.trim() {
        "" => Ok(open),
        s => s.parse::<u16>().map_err(|_| invalid()),
    };
    let (start, end) = (bound(start, 0)?, bound(end, u16::MAX)?);
    if start > end || value.trim() == ":" {
        return Err(invalid());
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;

    fn matcher(rule: model::Rule) -> Matcher {
        Matcher::new(
            &rule,
            &mut Readers::new(),
            &RuntimeEnv::default(),
            &Default::default(),
        )
        .unwrap()
    }

    fn to(destination: SocksAddr) -> Facts {
        Facts::new(
            &Session {
                destination,
                ..Default::default()
            },
            &[],
        )
    }

    fn domain(d: &str, port: u16) -> Facts {
        to(SocksAddr::Domain(d.to_string(), port))
    }

    fn ip(ip: &str, port: u16) -> Facts {
        to(SocksAddr::from((ip.parse::<IpAddr>().unwrap(), port)))
    }

    #[test]
    fn domains_match_by_kind() {
        let m = matcher(model::Rule {
            domain: vec!["exact.org".into()],
            domain_suffix: vec!["google.com".into(), ".cn".into()],
            domain_keyword: vec!["tube".into()],
            ..Default::default()
        });
        assert!(m.matches(&domain("exact.org", 80)));
        assert!(!m.matches(&domain("www.exact.org", 80)));
        assert!(m.matches(&domain("google.com", 80)));
        assert!(m.matches(&domain("video.GOOGLE.com", 80)));
        assert!(!m.matches(&domain("gle.com", 80)));
        assert!(!m.matches(&domain("agoogle.com", 80)));
        assert!(m.matches(&domain("baidu.cn", 80)));
        assert!(m.matches(&domain("youtube.com", 80)));
        assert!(!m.matches(&ip("1.1.1.1", 80)));
    }

    #[test]
    fn addresses_match_merged_ranges() {
        let m = matcher(model::Rule {
            ip_cidr: vec![
                "192.168.1.0/24".into(),
                "192.168.0.0/16".into(),
                "10.0.0.1/32".into(),
                "fd00::/8".into(),
            ],
            ..Default::default()
        });
        assert!(m.matches(&ip("192.168.1.100", 80)));
        assert!(m.matches(&ip("192.168.200.1", 80)));
        assert!(!m.matches(&ip("192.169.0.1", 80)));
        assert!(m.matches(&ip("10.0.0.1", 80)));
        assert!(!m.matches(&ip("10.0.0.2", 80)));
        assert!(m.matches(&ip("fd12::1", 80)));
        assert!(m.matches(&ip("::ffff:10.0.0.1", 80)));
        assert!(!m.matches(&domain("example.com", 80)));
    }

    /// As in sing-box: `example.com` matches it and its subdomains,
    /// `.example.com` its subdomains alone.
    #[test]
    fn a_suffix_with_a_leading_dot_matches_subdomains_only() {
        let m = matcher(model::Rule {
            domain_suffix: vec![".dot.example".into(), "plain.example".into()],
            ..Default::default()
        });
        assert!(!m.matches(&domain("dot.example", 80)));
        assert!(m.matches(&domain("a.dot.example", 80)));
        assert!(m.matches(&domain("plain.example", 80)));
        assert!(m.matches(&domain("a.plain.example", 80)));
        assert!(!m.matches(&domain("xplain.example", 80)));
    }

    /// As in sing-box: a domain condition and an address condition are
    /// alternatives, not both required.
    #[test]
    fn destination_conditions_are_alternatives() {
        let m = matcher(model::Rule {
            domain_suffix: vec!["example.com".into()],
            ip_cidr: vec!["10.0.0.0/8".into()],
            port: vec![443],
            ..Default::default()
        });
        assert!(m.matches(&domain("example.com", 443)));
        assert!(m.matches(&ip("10.1.2.3", 443)));
        assert!(!m.matches(&ip("10.1.2.3", 80)));
        let resolved = Facts::new(
            &Session {
                destination: SocksAddr::Domain("other.org".into(), 443),
                ..Default::default()
            },
            &["10.0.0.9".parse().unwrap()],
        );
        assert!(m.matches(&resolved));
    }

    #[test]
    fn ports_networks_and_inbounds() {
        let m = matcher(model::Rule {
            port: vec![22],
            port_range: vec!["1024:5000".into()],
            network: vec!["tcp".into()],
            inbound: vec!["socks".into()],
            ..Default::default()
        });
        let mut sess = Session {
            destination: SocksAddr::Domain("a.com".into(), 2000),
            inbound_tag: "socks".into(),
            ..Default::default()
        };
        assert!(m.matches(&Facts::new(&sess, &[])));
        sess.destination = SocksAddr::Domain("a.com".into(), 22);
        assert!(m.matches(&Facts::new(&sess, &[])));
        sess.destination = SocksAddr::Domain("a.com".into(), 5001);
        assert!(!m.matches(&Facts::new(&sess, &[])));
        sess.destination = SocksAddr::Domain("a.com".into(), 22);
        sess.network = Network::Udp;
        assert!(!m.matches(&Facts::new(&sess, &[])));
        sess.network = Network::Tcp;
        sess.inbound_tag = "http".into();
        assert!(!m.matches(&Facts::new(&sess, &[])));
    }

    #[test]
    fn users_match_by_name() {
        let m = matcher(model::Rule {
            auth_user: vec!["alice".into()],
            ..Default::default()
        });
        let mut sess = Session::default();
        assert!(!m.matches(&Facts::new(&sess, &[])));
        sess.user = Some("bob".into());
        assert!(!m.matches(&Facts::new(&sess, &[])));
        sess.user = Some("alice".into());
        assert!(m.matches(&Facts::new(&sess, &[])));
    }

    #[test]
    fn invalid_values_are_errors() {
        for (rule, message) in [
            (
                model::Rule {
                    ip_cidr: vec!["10.0.0.0/33".into()],
                    ..Default::default()
                },
                "ip_cidr: invalid CIDR",
            ),
            (
                model::Rule {
                    network: vec!["sctp".into()],
                    ..Default::default()
                },
                "network: unknown network",
            ),
        ] {
            let err = Matcher::new(
                &rule,
                &mut Readers::new(),
                &RuntimeEnv::default(),
                &Default::default(),
            )
            .err()
            .unwrap();
            assert!(err.to_string().starts_with(message), "{}", err);
        }
        for bad in ["22", "22:21", ":", "22-23", "22:abc", "22:23:24"] {
            assert!(port_range(bad).is_err(), "{}", bad);
        }
        assert_eq!(port_range("22:22").unwrap(), (22, 22));
        assert_eq!(port_range(":1024").unwrap(), (0, 1024));
        assert_eq!(port_range("8000:").unwrap(), (8000, u16::MAX));
    }

    /// A rule written as sing-box's JSON.
    fn json(rule: serde_json::Value) -> Matcher {
        let rule: model::Rule = serde_json::from_value(rule).unwrap();
        matcher(rule)
    }

    fn compile_err(rule: serde_json::Value) -> String {
        let rule: model::Rule = serde_json::from_value(rule).unwrap();
        let err = Matcher::at(
            &rule,
            "route.rules[3]",
            &mut Readers::new(),
            &RuntimeEnv::default(),
            &Default::default(),
        )
        .err()
        .unwrap();
        err.to_string()
    }

    /// A connection from `source` to `destination`.
    fn conn(source: &str, destination: &str) -> Facts {
        let destination = match destination.parse::<std::net::SocketAddr>() {
            Ok(addr) => SocksAddr::Ip(addr),
            Err(_) => {
                let (host, port) = destination.rsplit_once(':').unwrap();
                SocksAddr::Domain(host.into(), port.parse().unwrap())
            }
        };
        Facts::new(
            &Session {
                source: source.parse().unwrap(),
                destination,
                ..Default::default()
            },
            &[],
        )
    }

    #[test]
    fn source_conditions() {
        let m = json(serde_json::json!({
            "source_ip_cidr": "192.168.0.0/16", "source_port_range": "1000:2000"
        }));
        assert!(m.matches(&conn("192.168.1.2:1500", "1.1.1.1:80")));
        assert!(!m.matches(&conn("192.168.1.2:999", "1.1.1.1:80")));
        assert!(!m.matches(&conn("10.0.0.1:1500", "1.1.1.1:80")));
        let m = json(serde_json::json!({ "source_port": [53, 5353] }));
        assert!(m.matches(&conn("10.0.0.1:5353", "1.1.1.1:80")));
        assert!(!m.matches(&conn("10.0.0.1:5354", "1.1.1.1:80")));
        // Without a source, as for the DNS client's own queries, none
        // matches.
        assert!(!m.matches(&domain("a.com", 80)));
    }

    /// As sing's `IsPublicAddr` has it.
    #[test]
    fn private_addresses() {
        for (ip, private) in [
            ("10.1.2.3", true),
            ("172.16.0.1", true),
            ("192.168.9.9", true),
            ("127.0.0.1", true),
            ("169.254.1.1", true),
            ("224.0.0.1", true),
            ("0.0.0.0", true),
            ("100.64.0.1", false),
            ("8.8.8.8", false),
            ("fd00::1", true),
            ("fe80::1", true),
            ("::1", true),
            ("ff02::1", true),
            ("::ffff:10.0.0.1", true),
            ("2001:4860::8888", false),
        ] {
            assert_eq!(is_private(ip.parse().unwrap()), private, "{}", ip);
        }
        let m = json(serde_json::json!({ "ip_is_private": true }));
        assert!(m.matches(&conn("8.8.8.8:1", "192.168.1.1:80")));
        assert!(!m.matches(&conn("192.168.1.1:1", "8.8.8.8:80")));
        // An address a domain resolved to counts.
        let resolved = Facts::new(
            &Session {
                destination: SocksAddr::Domain("lan.example".into(), 80),
                ..Default::default()
            },
            &["10.0.0.9".parse().unwrap()],
        );
        assert!(m.matches(&resolved));
        let m = json(serde_json::json!({ "source_ip_is_private": true }));
        assert!(m.matches(&conn("192.168.1.1:1", "8.8.8.8:80")));
        assert!(!m.matches(&conn("8.8.8.8:1", "192.168.1.1:80")));
    }

    #[test]
    fn ip_version_is_the_destination_s() {
        let v6 = json(serde_json::json!({ "ip_version": 6 }));
        let v4 = json(serde_json::json!({ "ip_version": 4 }));
        assert!(v6.matches(&conn("1.1.1.1:1", "[2001:db8::1]:80")));
        assert!(!v4.matches(&conn("1.1.1.1:1", "[2001:db8::1]:80")));
        assert!(v4.matches(&conn("1.1.1.1:1", "1.2.3.4:80")));
        assert!(v4.matches(&conn("1.1.1.1:1", "[::ffff:1.2.3.4]:80")));
        // A domain has no version.
        assert!(!v4.matches(&domain("a.com", 80)));
        assert!(!v6.matches(&domain("a.com", 80)));
    }

    #[cfg(feature = "regex")]
    #[test]
    fn domain_regex_is_a_destination_address_condition() {
        let m = json(serde_json::json!({
            "domain_regex": "^ads?\\.", "ip_cidr": "10.0.0.0/8"
        }));
        assert!(m.matches(&domain("ad.example.com", 80)));
        assert!(m.matches(&domain("ADS.example.com", 80)));
        assert!(!m.matches(&domain("bad.example.com", 80)));
        assert!(m.matches(&ip("10.0.0.1", 80)));
        assert!(compile_err(serde_json::json!({ "domain_regex": "(" }))
            .starts_with("route.rules[3].domain_regex: \"(\""));
    }

    #[test]
    fn processes_match_as_sing_box_does() {
        let from = |path: &str| {
            Facts::new(
                &Session {
                    process_name: Some(path.into()),
                    ..Default::default()
                },
                &[],
            )
        };
        let m = json(serde_json::json!({ "process_name": "curl" }));
        assert!(m.matches(&from("/usr/bin/curl")));
        assert!(m.matches(&from("C:\\Tools\\curl")));
        assert!(!m.matches(&from("/usr/bin/curl2")));
        assert!(!m.matches(&Facts::new(&Session::default(), &[])));
        // An exact name, not a pattern.
        assert!(!json(serde_json::json!({ "process_name": "cu.l" })).matches(&from("/bin/curl")));
        let m = json(serde_json::json!({ "process_path": "/usr/bin/curl" }));
        assert!(m.matches(&from("/usr/bin/curl")));
        assert!(!m.matches(&from("/bin/curl")));
        if cfg!(feature = "regex") {
            let m = json(serde_json::json!({ "process_path_regex": "^/usr/(local/)?bin/" }));
            assert!(m.matches(&from("/usr/local/bin/curl")));
            assert!(!m.matches(&from("/opt/curl")));
        }
    }

    #[test]
    fn what_the_platform_cannot_tell_is_refused() {
        assert_eq!(
            process_known("process_name", false, true)
                .unwrap_err()
                .to_string(),
            "process_name: not supported, rule-process-name is not compiled in"
        );
        assert!(process_known("rules[0].process_path", true, false)
            .unwrap_err()
            .to_string()
            .starts_with("rules[0].process_path: sail cannot tell which program"));
        for (rule, message) in [
            (
                serde_json::json!({ "package_name": "com.android.chrome" }),
                "route.rules[3].package_name: sail cannot tell",
            ),
            (
                serde_json::json!({ "package_name_regex": "^com\\." }),
                "route.rules[3].package_name_regex: sail cannot tell",
            ),
            (
                serde_json::json!({ "user": "root" }),
                "route.rules[3].user: sail cannot tell",
            ),
            (
                serde_json::json!({ "user_id": [0, 1000] }),
                "route.rules[3].user_id: sail cannot tell",
            ),
            (
                serde_json::json!({ "type": "logical", "mode": "or", "rules": [
                    { "port": 1 }, { "type": "logical", "mode": "and", "rules": [
                        { "port": 2 }, { "source_ip_cidr": "10.0.0.0/33" }
                    ] }
                ] }),
                "route.rules[3].rules[1].rules[1].source_ip_cidr: invalid CIDR",
            ),
            (
                serde_json::json!({ "source_port_range": "2:1" }),
                "route.rules[3].source_port_range: invalid port range",
            ),
        ] {
            let err = compile_err(rule.clone());
            assert!(err.starts_with(message), "{}: {}", rule, err);
        }
    }

    #[test]
    fn invert_turns_a_default_rule_around() {
        let m = json(serde_json::json!({ "domain_suffix": "example.com", "invert": true }));
        assert!(!m.matches(&domain("www.example.com", 80)));
        assert!(m.matches(&domain("example.org", 80)));
        // A rule of no conditions matches everything, inverted or not, as
        // in sing-box.
        assert!(json(serde_json::json!({ "invert": true })).matches(&domain("a.com", 80)));
    }

    #[test]
    fn logical_rules_nest() {
        // (port 443 and not (udp or domain a.com)) or source 10.0.0.0/8
        let m = json(
            serde_json::json!({ "type": "logical", "mode": "or", "rules": [
            { "type": "logical", "mode": "and", "rules": [
                { "port": 443 },
                { "type": "logical", "mode": "or", "invert": true, "rules": [
                    { "network": "udp" }, { "domain": "a.com" }
                ] }
            ] },
            { "source_ip_cidr": "10.0.0.0/8" }
        ] }),
        );
        assert!(m.matches(&conn("1.1.1.1:1", "b.com:443")));
        assert!(!m.matches(&conn("1.1.1.1:1", "a.com:443")));
        assert!(!m.matches(&conn("1.1.1.1:1", "b.com:80")));
        assert!(m.matches(&conn("10.1.1.1:1", "a.com:80")));
        let mut udp = conn("1.1.1.1:1", "b.com:443");
        udp.network = Network::Udp;
        assert!(!m.matches(&udp));
        // A logical rule inverted, and a rule inverted inside one.
        let m = json(
            serde_json::json!({ "type": "logical", "mode": "and", "invert": true,
            "rules": [{ "port": 80 }, { "domain": "a.com", "invert": true }] }),
        );
        assert!(!m.matches(&domain("b.com", 80)));
        assert!(m.matches(&domain("a.com", 80)));
        assert!(m.matches(&domain("b.com", 443)));
    }

    /// Rules and connections checked against sing-box 1.14: what its
    /// `DefaultRule` and `LogicalRule` say for each, by reading
    /// rule_abstract.go and the rule items.
    #[test]
    fn a_table_of_rules_as_sing_box_matches_them() {
        /// A source, a destination, and whether the rule matches.
        type Case<'a> = (&'a str, &'a str, bool);
        let table: &[(serde_json::Value, &[Case])] = &[
            // The conditions on one thing are alternatives; the things
            // are all required.
            (
                serde_json::json!({ "domain": "a.com", "ip_cidr": "10.0.0.0/8",
                                    "port": 443, "source_port": 1 }),
                &[
                    ("1.1.1.1:1", "a.com:443", true),
                    ("1.1.1.1:1", "10.0.0.1:443", true),
                    ("1.1.1.1:2", "a.com:443", false),
                    ("1.1.1.1:1", "a.com:80", false),
                    ("1.1.1.1:1", "b.com:443", false),
                ],
            ),
            // source_ip_cidr and source_ip_is_private are one thing.
            (
                serde_json::json!({ "source_ip_cidr": "8.8.8.0/24",
                                    "source_ip_is_private": true }),
                &[
                    ("8.8.8.8:1", "a.com:1", true),
                    ("192.168.0.1:1", "a.com:1", true),
                    ("1.1.1.1:1", "a.com:1", false),
                ],
            ),
            // ip_cidr and ip_is_private are one thing, apart from the
            // domain's only in that either will do.
            (
                serde_json::json!({ "ip_cidr": "8.8.8.0/24", "ip_is_private": true }),
                &[
                    ("1.1.1.1:1", "8.8.8.8:53", true),
                    ("1.1.1.1:1", "192.168.1.1:53", true),
                    ("1.1.1.1:1", "1.1.1.1:53", false),
                    ("1.1.1.1:1", "a.com:53", false),
                ],
            ),
            // port and port_range are one thing, as are the source's.
            (
                serde_json::json!({ "port": 22, "port_range": "8000:", "source_port_range": ":1024",
                                    "source_port": 5000 }),
                &[
                    ("1.1.1.1:5000", "a.com:22", true),
                    ("1.1.1.1:80", "a.com:9000", true),
                    ("1.1.1.1:2000", "a.com:22", false),
                    ("1.1.1.1:80", "a.com:7999", false),
                ],
            ),
            // Other conditions each must hold.
            (
                serde_json::json!({ "domain_keyword": "exa", "network": "tcp", "ip_version": 4 }),
                &[
                    ("1.1.1.1:1", "example.com:1", false),
                    ("1.1.1.1:1", "1.2.3.4:1", false),
                ],
            ),
            // invert of the whole.
            (
                serde_json::json!({ "domain": "a.com", "port": 443, "invert": true }),
                &[
                    ("1.1.1.1:1", "a.com:443", false),
                    ("1.1.1.1:1", "a.com:80", true),
                    ("1.1.1.1:1", "b.com:443", true),
                ],
            ),
            // and / or over nested rules, each grouping on its own.
            (
                serde_json::json!({ "type": "logical", "mode": "and", "rules": [
                    { "domain": "a.com" }, { "ip_cidr": "10.0.0.0/8", "invert": true }
                ] }),
                &[
                    ("1.1.1.1:1", "a.com:1", true),
                    ("1.1.1.1:1", "10.0.0.1:1", false),
                ],
            ),
            (
                serde_json::json!({ "type": "logical", "mode": "or", "invert": true, "rules": [
                    { "domain": "a.com" }, { "port": 22 }
                ] }),
                &[
                    ("1.1.1.1:1", "a.com:1", false),
                    ("1.1.1.1:1", "b.com:22", false),
                    ("1.1.1.1:1", "b.com:23", true),
                ],
            ),
        ];
        for (rule, cases) in table {
            let m = json(rule.clone());
            for &(source, destination, expected) in *cases {
                assert_eq!(
                    m.matches(&conn(source, destination)),
                    expected,
                    "{} from {} to {}",
                    rule,
                    source,
                    destination
                );
            }
        }
    }

    #[test]
    fn a_plain_address_is_a_cidr_of_itself() {
        let m = json(serde_json::json!({ "ip_cidr": ["1.2.3.4", "2001:db8::1"] }));
        assert!(m.matches(&ip("1.2.3.4", 1)));
        assert!(!m.matches(&ip("1.2.3.5", 1)));
        assert!(m.matches(&ip("2001:db8::1", 1)));
    }
}
