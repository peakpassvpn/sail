//! The conditions of one rule, compiled into indexes: a domain is looked up
//! in hash sets, an address is binary-searched in sorted ranges.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use cidr::IpCidr;
use maxminddb::geoip2::Country;
use maxminddb::Mmap;
#[cfg(feature = "rule-process-name")]
use regex::Regex;

use crate::config::external_rule::{self, DomainKind, External};
use crate::config::model;
use crate::runtime::RuntimeEnv;
use crate::session::{Network, Session};

/// What rules are matched against: what is known about a connection at
/// the time.
pub(super) struct Facts {
    /// The domain, sniffed or asked for, in lowercase.
    domain: Option<String>,
    /// The address asked for, and those the domain resolved to.
    ips: Vec<IpAddr>,
    port: u16,
    network: Network,
    inbound: String,
    #[cfg_attr(not(feature = "rule-process-name"), allow(dead_code))]
    process_name: Option<String>,
}

impl Facts {
    pub fn new(sess: &Session, resolved: &[IpAddr]) -> Self {
        let domain = sess
            .sniffed_domain()
            .or_else(|| sess.destination.domain().map(String::as_str))
            .map(str::to_ascii_lowercase);
        let mut ips: Vec<IpAddr> = sess.destination.ip().into_iter().collect();
        ips.extend_from_slice(resolved);
        Facts {
            domain,
            ips,
            port: sess.destination.port(),
            network: sess.network,
            inbound: sess.inbound_tag.clone(),
            process_name: sess.process_name.clone(),
        }
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

/// Domains by how they are compared.
#[derive(Default)]
struct DomainIndex {
    full: HashSet<String>,
    /// A domain matches when it is one of these or a subdomain of one.
    suffix: HashSet<String>,
    keyword: Vec<String>,
}

impl DomainIndex {
    fn insert(&mut self, kind: DomainKind, value: &str) {
        let value = value.to_ascii_lowercase();
        match kind {
            DomainKind::Full => {
                self.full.insert(value);
            }
            DomainKind::Suffix => {
                self.suffix
                    .insert(value.trim_start_matches('.').to_string());
            }
            DomainKind::Keyword => self.keyword.push(value),
        }
    }

    fn is_empty(&self) -> bool {
        self.full.is_empty() && self.suffix.is_empty() && self.keyword.is_empty()
    }

    fn matches(&self, domain: &str) -> bool {
        if self.full.contains(domain) {
            return true;
        }
        if !self.suffix.is_empty() {
            let mut rest = domain;
            loop {
                if self.suffix.contains(rest) {
                    return true;
                }
                match rest.find('.') {
                    Some(dot) => rest = &rest[dot + 1..],
                    None => break,
                }
            }
        }
        self.keyword.iter().any(|k| domain.contains(k.as_str()))
    }
}

/// Address ranges, sorted and merged, per family.
#[derive(Default)]
struct CidrIndex {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl CidrIndex {
    fn new(cidrs: &[String]) -> Result<Self> {
        let mut index = CidrIndex::default();
        for value in cidrs {
            let cidr = value
                .parse::<IpCidr>()
                .map_err(|e| anyhow!("ip_cidr: invalid CIDR \"{}\": {}", value, e))?;
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

    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn contains(&self, ip: IpAddr) -> bool {
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

struct Mmdb {
    reader: Arc<maxminddb::Reader<Mmap>>,
    /// Uppercase, as the databases have them.
    country_code: String,
}

impl Mmdb {
    fn contains(&self, ip: IpAddr) -> bool {
        matches!(
            self.reader.lookup::<Country>(ip),
            Ok(Country { country: Some(country), .. })
                if country.iso_code == Some(self.country_code.as_str())
        )
    }
}

/// Mmdb readers by file, shared by the rules that use the same database.
pub(super) type Readers = HashMap<String, Arc<maxminddb::Reader<Mmap>>>;

/// The conditions of one rule.
pub(super) struct Matcher {
    domains: DomainIndex,
    cidrs: CidrIndex,
    mmdbs: Vec<Mmdb>,
    ports: Vec<(u16, u16)>,
    networks: Vec<Network>,
    inbounds: Vec<String>,
    #[cfg(feature = "rule-process-name")]
    process_names: Vec<Regex>,
}

impl Matcher {
    pub fn new(rule: &model::Rule, readers: &mut Readers, env: &RuntimeEnv) -> Result<Self> {
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
            for (kind, d) in external_rule::geosite(code, env)? {
                domains.insert(kind, &d);
            }
        }
        let mut mmdbs: Vec<external_rule::Mmdb> = rule
            .geoip
            .iter()
            .map(|c| external_rule::geoip(c, env))
            .collect();
        for filter in &rule.external {
            match external_rule::load(filter, env)? {
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
                let reader = match readers.get(&mmdb.file) {
                    Some(r) => r.clone(),
                    None => {
                        let r = Arc::new(
                            maxminddb::Reader::open_mmap(&mmdb.file)
                                .map_err(|e| anyhow!("geoip: open {} failed: {}", mmdb.file, e))?,
                        );
                        readers.insert(mmdb.file.clone(), r.clone());
                        r
                    }
                };
                Ok(Mmdb {
                    reader,
                    country_code: mmdb.country_code.to_ascii_uppercase(),
                })
            })
            .collect::<Result<_>>()?;

        #[cfg(not(feature = "rule-process-name"))]
        if !rule.process_name.is_empty() {
            return Err(anyhow!(
                "process_name: not supported, rule-process-name is not compiled in"
            ));
        }

        Ok(Matcher {
            domains,
            cidrs: CidrIndex::new(&rule.ip_cidr)?,
            mmdbs,
            ports: rule
                .port_range
                .iter()
                .map(|p| port_range(p))
                .collect::<Result<_>>()?,
            networks: rule
                .network
                .iter()
                .map(|net| match net.to_ascii_lowercase().as_str() {
                    "tcp" => Ok(Network::Tcp),
                    "udp" => Ok(Network::Udp),
                    _ => Err(anyhow!("network: unknown network \"{}\"", net)),
                })
                .collect::<Result<_>>()?,
            inbounds: rule.inbound.clone(),
            #[cfg(feature = "rule-process-name")]
            process_names: rule
                .process_name
                .iter()
                .map(|p| {
                    Regex::new(p)
                        .map_err(|e| anyhow!("process_name: invalid pattern \"{}\": {}", p, e))
                })
                .collect::<Result<_>>()?,
        })
    }

    pub fn matches(&self, facts: &Facts) -> bool {
        let destination_set =
            !self.domains.is_empty() || !self.cidrs.is_empty() || !self.mmdbs.is_empty();
        if destination_set {
            let by_domain = facts.domain().is_some_and(|d| self.domains.matches(d));
            let by_ip = || {
                facts
                    .ips
                    .iter()
                    .any(|&ip| self.cidrs.contains(ip) || self.mmdbs.iter().any(|m| m.contains(ip)))
            };
            if !by_domain && !by_ip() {
                return false;
            }
        }
        if !self.ports.is_empty()
            && !self
                .ports
                .iter()
                .any(|&(start, end)| (start..=end).contains(&facts.port))
        {
            return false;
        }
        if !self.networks.is_empty() && !self.networks.contains(&facts.network) {
            return false;
        }
        if !self.inbounds.is_empty() && !self.inbounds.contains(&facts.inbound) {
            return false;
        }
        #[cfg(feature = "rule-process-name")]
        if !self.process_names.is_empty()
            && !facts
                .process_name
                .as_deref()
                .is_some_and(|name| self.process_names.iter().any(|r| r.is_match(name)))
        {
            return false;
        }
        true
    }
}

/// A single port, `443`, or an inclusive range, `1000-2000`.
fn port_range(value: &str) -> Result<(u16, u16)> {
    let invalid = || anyhow!("port_range: invalid port range \"{}\"", value);
    let (start, end) = value.split_once('-').unwrap_or((value, value));
    let start = start.trim().parse::<u16>().map_err(|_| invalid())?;
    let end = end.trim().parse::<u16>().map_err(|_| invalid())?;
    if start > end {
        return Err(invalid());
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;

    fn matcher(rule: model::Rule) -> Matcher {
        Matcher::new(&rule, &mut Readers::new(), &RuntimeEnv::default()).unwrap()
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

    /// As in sing-box: a domain condition and an address condition are
    /// alternatives, not both required.
    #[test]
    fn destination_conditions_are_alternatives() {
        let m = matcher(model::Rule {
            domain_suffix: vec!["example.com".into()],
            ip_cidr: vec!["10.0.0.0/8".into()],
            port_range: vec!["443".into()],
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
            port_range: vec!["1024-5000".into(), "22".into()],
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
            let err = Matcher::new(&rule, &mut Readers::new(), &RuntimeEnv::default())
                .err()
                .unwrap();
            assert!(err.to_string().starts_with(message), "{}", err);
        }
        for bad in ["22-21", "22-", "-22", "22-abc", "22-23-24"] {
            assert!(port_range(bad).is_err(), "{}", bad);
        }
        assert_eq!(port_range("22").unwrap(), (22, 22));
    }
}
