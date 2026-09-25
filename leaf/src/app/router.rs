use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Result;
use async_recursion::async_recursion;
use cidr::IpCidr;
use futures::TryFutureExt;
use maxminddb::geoip2::Country;
use maxminddb::Mmap;
#[cfg(feature = "rule-process-name")]
use regex::Regex;
use tracing::debug;

use crate::app::SyncDnsClient;
use crate::config::external_rule::{self, DomainKind, External, Mmdb};
use crate::config::model;
use crate::runtime::RuntimeEnv;
use crate::session::{Network, Session, SocksAddr};

pub trait Condition: Send + Sync + Unpin {
    fn apply(&self, sess: &Session) -> bool;
}

struct Rule {
    target: String,
    condition: Box<dyn Condition>,
}

impl Rule {
    fn new(target: String, condition: Box<dyn Condition>) -> Self {
        Rule { target, condition }
    }
}

impl Condition for Rule {
    fn apply(&self, sess: &Session) -> bool {
        self.condition.apply(sess)
    }
}

struct MmdbMatcher {
    reader: Arc<maxminddb::Reader<Mmap>>,
    country_code: String,
}

impl MmdbMatcher {
    fn new(reader: Arc<maxminddb::Reader<Mmap>>, country_code: String) -> Self {
        MmdbMatcher {
            reader,
            country_code,
        }
    }
}

impl Condition for MmdbMatcher {
    fn apply(&self, sess: &Session) -> bool {
        let destination = sess
            .destination_for_routing()
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&sess.destination));
        if !destination.is_domain() {
            if let Some(ip) = destination.ip() {
                if let Ok(country) = self.reader.lookup::<Country>(ip) {
                    if let Some(country) = country.country {
                        if let Some(iso_code) = country.iso_code {
                            if iso_code.to_lowercase() == self.country_code.to_lowercase() {
                                debug!("[{}] matches geoip code [{}]", ip, &self.country_code);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}

struct IpCidrMatcher {
    values: Vec<IpCidr>,
}

impl IpCidrMatcher {
    fn new(ips: &[String]) -> Result<Self> {
        let values = ips
            .iter()
            .map(|ip| {
                ip.parse::<IpCidr>()
                    .map_err(|e| anyhow!("ip_cidr: invalid CIDR \"{}\": {}", ip, e))
            })
            .collect::<Result<_>>()?;
        Ok(IpCidrMatcher { values })
    }
}

impl Condition for IpCidrMatcher {
    fn apply(&self, sess: &Session) -> bool {
        let destination = sess
            .destination_for_routing()
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&sess.destination));
        if !destination.is_domain() {
            for cidr in &self.values {
                if let Some(ip) = destination.ip() {
                    if cidr.contains(&ip) {
                        debug!("[{}] matches ip-cidr [{}]", ip, &cidr);
                        return true;
                    }
                }
            }
        }
        false
    }
}

struct InboundTagMatcher {
    values: Vec<String>,
}

impl InboundTagMatcher {
    fn new(tags: &[String]) -> Self {
        Self {
            values: tags.to_vec(),
        }
    }
}

impl Condition for InboundTagMatcher {
    fn apply(&self, sess: &Session) -> bool {
        for v in &self.values {
            if v == &sess.inbound_tag {
                debug!("[{}] matches inbound tag [{}]", &sess.inbound_tag, v);
                return true;
            }
        }
        false
    }
}

struct NetworkMatcher {
    values: Vec<Network>,
}

impl NetworkMatcher {
    fn new(networks: &[String]) -> Result<Self> {
        let values = networks
            .iter()
            .map(|net| match net.to_lowercase().as_str() {
                "tcp" => Ok(Network::Tcp),
                "udp" => Ok(Network::Udp),
                _ => Err(anyhow!("network: unknown network \"{}\"", net)),
            })
            .collect::<Result<_>>()?;
        Ok(Self { values })
    }
}

impl Condition for NetworkMatcher {
    fn apply(&self, sess: &Session) -> bool {
        for v in &self.values {
            if v == &sess.network {
                debug!("[{}] matches network [{}]", &sess.network, v);
                return true;
            }
        }
        false
    }
}

struct PortMatcher {
    condition: Box<dyn Condition>,
}

impl PortMatcher {
    fn new(port_ranges: &[String]) -> Result<Self> {
        let mut cond_or = ConditionOr::new();
        for pr in port_ranges.iter() {
            cond_or.add(Box::new(PortRangeMatcher::new(pr)?));
        }
        Ok(PortMatcher {
            condition: Box::new(cond_or),
        })
    }
}

impl Condition for PortMatcher {
    fn apply(&self, sess: &Session) -> bool {
        self.condition.apply(sess)
    }
}

struct PortRangeMatcher {
    start: u16,
    end: u16,
}

impl PortRangeMatcher {
    /// A single port, `443`, or an inclusive range, `1000-2000`.
    fn new(port_range: &str) -> Result<Self> {
        let invalid = || anyhow!("port_range: invalid port range \"{}\"", port_range);
        let (start, end) = match port_range.split_once('-') {
            Some((start, end)) => (start, end),
            None => (port_range, port_range),
        };
        let start = start.trim().parse::<u16>().map_err(|_| invalid())?;
        let end = end.trim().parse::<u16>().map_err(|_| invalid())?;
        if start > end {
            return Err(invalid());
        }
        Ok(PortRangeMatcher { start, end })
    }
}

impl Condition for PortRangeMatcher {
    fn apply(&self, sess: &Session) -> bool {
        let port = sess
            .destination_for_routing()
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&sess.destination))
            .port();
        if port >= self.start && port <= self.end {
            debug!(
                "[{}] matches port range [{}-{}]",
                port, self.start, self.end
            );
            true
        } else {
            false
        }
    }
}

struct DomainKeywordMatcher {
    value: String,
}

impl DomainKeywordMatcher {
    fn new(value: String) -> Self {
        DomainKeywordMatcher { value }
    }
}

impl Condition for DomainKeywordMatcher {
    fn apply(&self, sess: &Session) -> bool {
        let destination = sess
            .destination_for_routing()
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&sess.destination));
        if destination.is_domain() {
            if let Some(domain) = destination.domain() {
                if domain.contains(&self.value) {
                    debug!("[{}] matches domain keyword [{}]", domain, &self.value);
                    return true;
                }
            }
        }
        false
    }
}

struct DomainSuffixMatcher {
    value: String,
}

impl DomainSuffixMatcher {
    fn new(value: String) -> Self {
        DomainSuffixMatcher { value }
    }
}

// test if domain1 is a subdomain of domain2
// examples:
//   video.google.com vs google.com -> true
//   video.google.com vs gle.com -> false
//   google.com vs video.google.com -> false
fn is_sub_domain(d1: &str, d2: &str) -> bool {
    let d1_parts: Vec<&str> = d1.split('.').rev().collect();
    let d2_parts: Vec<&str> = d2.split('.').rev().collect();
    if d1_parts.len() < d2_parts.len() {
        return false;
    }
    let d2_enum = d2_parts.iter().enumerate();
    for (i, v) in d2_enum {
        if &d1_parts[i] != v {
            return false;
        }
    }
    true
}

impl Condition for DomainSuffixMatcher {
    fn apply(&self, sess: &Session) -> bool {
        let destination = sess
            .destination_for_routing()
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&sess.destination));
        if destination.is_domain() {
            if let Some(domain) = destination.domain() {
                if is_sub_domain(domain, &self.value) {
                    debug!("[{}] matches domain suffix [{}]", domain, &self.value);
                    return true;
                }
            }
        }
        false
    }
}

struct DomainFullMatcher {
    value: String,
}

impl DomainFullMatcher {
    fn new(value: String) -> Self {
        DomainFullMatcher { value }
    }
}

impl Condition for DomainFullMatcher {
    fn apply(&self, sess: &Session) -> bool {
        let destination = sess
            .destination_for_routing()
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&sess.destination));
        if destination.is_domain() {
            if let Some(domain) = destination.domain() {
                if domain == &self.value {
                    debug!("{} matches domain [{}]", domain, &self.value);
                    return true;
                }
            }
        }
        false
    }
}

struct DomainMatcher {
    condition: Box<dyn Condition>,
}

impl DomainMatcher {
    fn new(domains: Vec<(DomainKind, String)>) -> Self {
        let mut cond_or = ConditionOr::new();
        for (kind, filter) in domains {
            match kind {
                DomainKind::Keyword => {
                    cond_or.add(Box::new(DomainKeywordMatcher::new(filter)));
                }
                DomainKind::Suffix => {
                    cond_or.add(Box::new(DomainSuffixMatcher::new(filter)));
                }
                DomainKind::Full => {
                    cond_or.add(Box::new(DomainFullMatcher::new(filter)));
                }
            }
        }
        DomainMatcher {
            condition: Box::new(cond_or),
        }
    }
}

impl Condition for DomainMatcher {
    fn apply(&self, sess: &Session) -> bool {
        self.condition.apply(sess)
    }
}

#[cfg(feature = "rule-process-name")]
pub struct ProcessNameMatcher {
    regexes: Vec<Regex>,
}

#[cfg(feature = "rule-process-name")]
impl ProcessNameMatcher {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let regexes = patterns
            .iter()
            .map(|p| {
                Regex::new(p).map_err(|e| anyhow!("process_name: invalid pattern \"{}\": {}", p, e))
            })
            .collect::<Result<_>>()?;
        Ok(Self { regexes })
    }
}

#[cfg(feature = "rule-process-name")]
impl Condition for ProcessNameMatcher {
    fn apply(&self, sess: &Session) -> bool {
        if let Some(process_name) = sess.process_name.as_ref() {
            for regex in &self.regexes {
                if regex.is_match(process_name) {
                    debug!("Matched process_name={} with regex", process_name);
                    return true;
                }
            }
        }
        false
    }
}

struct ConditionAnd {
    conditions: Vec<Box<dyn Condition>>,
}

impl ConditionAnd {
    fn new() -> Self {
        ConditionAnd {
            conditions: Vec::new(),
        }
    }

    fn add(&mut self, cond: Box<dyn Condition>) {
        self.conditions.push(cond)
    }

    fn is_empty(&self) -> bool {
        self.conditions.len() == 0
    }
}

impl Condition for ConditionAnd {
    fn apply(&self, sess: &Session) -> bool {
        for cond in &self.conditions {
            if !cond.apply(sess) {
                return false;
            }
        }
        true
    }
}

struct ConditionOr {
    conditions: Vec<Box<dyn Condition>>,
}

impl ConditionOr {
    fn new() -> Self {
        ConditionOr {
            conditions: Vec::new(),
        }
    }

    fn add(&mut self, cond: Box<dyn Condition>) {
        self.conditions.push(cond)
    }
}

impl Condition for ConditionOr {
    fn apply(&self, sess: &Session) -> bool {
        for cond in &self.conditions {
            if cond.apply(sess) {
                return true;
            }
        }
        false
    }
}

pub struct Router {
    rules: Vec<Rule>,
    final_outbound: Option<String>,
    domain_resolve: bool,
    dns_client: SyncDnsClient,
}

/// Compiles one configured rule into its conditions.
fn compile_rule(
    rule: &model::Rule,
    mmdb_readers: &mut HashMap<String, Arc<maxminddb::Reader<Mmap>>>,
    env: &RuntimeEnv,
) -> Result<Rule> {
    let mut cond_and = ConditionAnd::new();

    let mut domains: Vec<(DomainKind, String)> = Vec::new();
    domains.extend(rule.domain.iter().map(|d| (DomainKind::Full, d.clone())));
    domains.extend(
        rule.domain_suffix
            .iter()
            .map(|d| (DomainKind::Suffix, d.clone())),
    );
    domains.extend(
        rule.domain_keyword
            .iter()
            .map(|d| (DomainKind::Keyword, d.clone())),
    );
    let mut mmdbs: Vec<Mmdb> = rule
        .geoip
        .iter()
        .map(|c| external_rule::geoip(c, env))
        .collect();
    for code in &rule.geosite {
        domains.extend(external_rule::geosite(code, env)?);
    }
    for filter in &rule.external {
        match external_rule::load(filter, env)? {
            External::Mmdb(mmdb) => mmdbs.push(mmdb),
            External::Domains(d) => domains.extend(d),
        }
    }

    if !domains.is_empty() {
        cond_and.add(Box::new(DomainMatcher::new(domains)));
    }
    if !rule.ip_cidr.is_empty() {
        cond_and.add(Box::new(IpCidrMatcher::new(&rule.ip_cidr)?));
    }
    for mmdb in mmdbs {
        let reader = match mmdb_readers.get(&mmdb.file) {
            Some(r) => r.clone(),
            None => {
                let r = Arc::new(
                    maxminddb::Reader::open_mmap(&mmdb.file)
                        .map_err(|e| anyhow!("geoip: open {} failed: {}", mmdb.file, e))?,
                );
                mmdb_readers.insert(mmdb.file.clone(), r.clone());
                r
            }
        };
        cond_and.add(Box::new(MmdbMatcher::new(reader, mmdb.country_code)));
    }
    if !rule.port_range.is_empty() {
        cond_and.add(Box::new(PortMatcher::new(&rule.port_range)?));
    }
    if !rule.network.is_empty() {
        cond_and.add(Box::new(NetworkMatcher::new(&rule.network)?));
    }
    if !rule.inbound.is_empty() {
        cond_and.add(Box::new(InboundTagMatcher::new(&rule.inbound)));
    }
    if !rule.process_name.is_empty() {
        #[cfg(feature = "rule-process-name")]
        cond_and.add(Box::new(ProcessNameMatcher::new(&rule.process_name)?));
        #[cfg(not(feature = "rule-process-name"))]
        return Err(anyhow!(
            "process_name: not supported, rule-process-name is not compiled in"
        ));
    }

    if cond_and.is_empty() {
        return Err(anyhow!("the rule has no conditions"));
    }
    Ok(Rule::new(rule.outbound.clone(), Box::new(cond_and)))
}

impl Router {
    fn load_rules(route: &model::Route, env: &RuntimeEnv) -> Result<Vec<Rule>> {
        let mut mmdb_readers = HashMap::new();
        route
            .rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                compile_rule(rule, &mut mmdb_readers, env)
                    .map_err(|e| anyhow!("route.rules[{}]: {}", i, e))
            })
            .collect()
    }

    pub fn new(route: &model::Route, dns_client: SyncDnsClient, env: &RuntimeEnv) -> Result<Self> {
        Ok(Router {
            rules: Self::load_rules(route, env)?,
            final_outbound: route.final_outbound.clone(),
            domain_resolve: route.domain_resolve,
            dns_client,
        })
    }

    pub fn reload(&mut self, route: &model::Route, env: &RuntimeEnv) -> Result<()> {
        self.rules = Self::load_rules(route, env)?;
        self.final_outbound = route.final_outbound.clone();
        self.domain_resolve = route.domain_resolve;
        Ok(())
    }

    #[async_recursion]
    pub async fn pick_route<'a>(&'a self, sess: &'a Session) -> Result<Option<&'a String>> {
        let effective_dest = &sess.destination;
        for rule in &self.rules {
            if rule.apply(sess) {
                return Ok(Some(&rule.target));
            }
        }
        if effective_dest.is_domain() && self.domain_resolve && !sess.skip_resolve {
            debug!("resolve routing domain={:?}", effective_dest.domain());
            let ips = {
                self.dns_client
                    .read()
                    .await
                    .lookup(
                        effective_dest
                            .domain()
                            .ok_or_else(|| anyhow!("illegal domain name"))?,
                    )
                    .map_err(|e| anyhow!("lookup failed: {}", e))
                    .await?
            };
            if !ips.is_empty() {
                let mut new_sess = sess.clone();
                new_sess.destination = SocksAddr::from((ips[0], effective_dest.port()));
                new_sess.dns_sniffed_domain = None;
                new_sess.tls_sniffed_domain = None;
                new_sess.http_sniffed_domain = None;
                debug!("re-matching with resolved ip={}", ips[0]);
                for rule in &self.rules {
                    if rule.apply(&new_sess) {
                        return Ok(Some(&rule.target));
                    }
                }
            }
        }
        Ok(self.final_outbound.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use crate::session::SocksAddr;

    use super::*;

    #[test]
    fn test_is_sub_domain() {
        let d1 = "video.google.com".to_string();
        let d2 = "google.com".to_string();
        assert!(is_sub_domain(&d1, &d2));

        let d1 = "video.google.com".to_string();
        let d2 = "gle.com".to_string();
        assert!(!is_sub_domain(&d1, &d2));
    }

    #[test]
    fn test_port_matcher() {
        let mut sess = Session {
            destination: SocksAddr::Domain("www.google.com".to_string(), 22),
            ..Default::default()
        };

        // test port range
        let m = PortMatcher::new(&["1024-5000".to_string(), "6000-7000".to_string()]).unwrap();
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 2000);
        assert!(m.apply(&sess));
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 5001);
        assert!(!m.apply(&sess));
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 6001);
        assert!(m.apply(&sess));

        // test single port range
        let m = PortMatcher::new(&["22-22".to_string()]).unwrap();
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 22);
        assert!(m.apply(&sess));

        // a single port
        let m = PortMatcher::new(&["22".to_string()]).unwrap();
        assert!(m.apply(&sess));
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 23);
        assert!(!m.apply(&sess));

        // test invalid port ranges
        let m = PortRangeMatcher::new("22-21");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("22-");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("-22");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("22-abc");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("22-23-24");
        assert!(m.is_err());
    }

    #[test]
    fn test_domain_matchers() {
        let sess = Session {
            destination: SocksAddr::Domain("www.google.com".to_string(), 80),
            ..Default::default()
        };

        // Keyword matcher
        let m = DomainKeywordMatcher::new("google".to_string());
        assert!(m.apply(&sess));
        let m = DomainKeywordMatcher::new("baidu".to_string());
        assert!(!m.apply(&sess));

        // Suffix matcher
        let m = DomainSuffixMatcher::new("google.com".to_string());
        assert!(m.apply(&sess));
        let m = DomainSuffixMatcher::new("com".to_string());
        assert!(m.apply(&sess));
        let m = DomainSuffixMatcher::new("www.google.com".to_string());
        assert!(m.apply(&sess));
        let m = DomainSuffixMatcher::new("gle.com".to_string());
        assert!(!m.apply(&sess));

        // Full matcher
        let m = DomainFullMatcher::new("www.google.com".to_string());
        assert!(m.apply(&sess));
        let m = DomainFullMatcher::new("google.com".to_string());
        assert!(!m.apply(&sess));
    }

    #[test]
    fn test_ip_cidr_matcher() {
        use std::net::IpAddr;

        let mut sess = Session::default();

        let ips = vec!["192.168.1.0/24".to_string(), "10.0.0.1/32".to_string()];
        let m = IpCidrMatcher::new(&ips).unwrap();

        sess.destination = SocksAddr::from(("192.168.1.100".parse::<IpAddr>().unwrap(), 80));
        assert!(m.apply(&sess));

        sess.destination = SocksAddr::from(("192.168.2.1".parse::<IpAddr>().unwrap(), 80));
        assert!(!m.apply(&sess));

        sess.destination = SocksAddr::from(("10.0.0.1".parse::<IpAddr>().unwrap(), 80));
        assert!(m.apply(&sess));

        sess.destination = SocksAddr::from(("10.0.0.2".parse::<IpAddr>().unwrap(), 80));
        assert!(!m.apply(&sess));
    }

    #[test]
    fn an_invalid_cidr_is_an_error() {
        let err = IpCidrMatcher::new(&["10.0.0.0/33".to_string()])
            .err()
            .unwrap();
        assert!(
            err.to_string().starts_with("ip_cidr: invalid CIDR"),
            "{}",
            err
        );
    }

    #[test]
    fn a_rule_without_conditions_is_an_error() {
        let rule = model::Rule {
            outbound: "direct".to_string(),
            ..Default::default()
        };
        let err = compile_rule(&rule, &mut HashMap::new(), &RuntimeEnv::default())
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "the rule has no conditions");
    }
}
