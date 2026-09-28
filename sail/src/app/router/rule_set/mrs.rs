//! Mihomo's binary rule-set format, MRS: zstd, and within it `MRS\x01`, the
//! behavior, the count, reserved bytes, and the set: a succinct trie of the
//! domains (Mihomo's `DomainSet`), or the IP ranges.
//!
//! The domains stay in their trie, matched as it is (see [`DomainSet`]).

use std::io::Read;
use std::net::{IpAddr, Ipv6Addr};

use anyhow::{anyhow, Result};

use super::domain_set::DomainSet;
use crate::config::rule_set::ClashBehavior;

const MAGIC: &[u8; 4] = b"MRS\x01";

/// The most an MRS file may hold once decompressed: what a download of a
/// rule-set may be.
pub(crate) const MAX_DECOMPRESSED: usize = super::http::MAX_BODY;

/// What an MRS file holds.
pub(crate) enum Set {
    /// Domains.
    Domains(DomainSet),
    /// IP ranges, their ends included.
    Ranges(Vec<(IpAddr, IpAddr)>),
}

/// Reads an MRS file of `behavior`.
pub(crate) fn read(data: &[u8], behavior: ClashBehavior) -> Result<Set> {
    let decoder = ruzstd::decoding::StreamingDecoder::new(data)
        .map_err(|e| anyhow!("mrs: not zstd: {}", e))?;
    let mut raw = Vec::new();
    decoder
        .take(MAX_DECOMPRESSED as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| anyhow!("mrs: zstd: {}", e))?;
    if raw.len() > MAX_DECOMPRESSED {
        return Err(anyhow!(
            "mrs: more than {} bytes decompressed",
            MAX_DECOMPRESSED
        ));
    }
    let mut r = Reader { data: &raw, at: 0 };
    if r.bytes(4)? != MAGIC {
        return Err(anyhow!("mrs: not an MRS v1 file"));
    }
    let wanted = match behavior {
        ClashBehavior::Domain => 0,
        ClashBehavior::Ipcidr => 1,
        ClashBehavior::Classical => {
            return Err(anyhow!("mrs: a classical rule-set has no MRS form"))
        }
    };
    let found = r.u8()?;
    if found != wanted {
        return Err(anyhow!(
            "mrs: a {} set, not {:?}",
            match found {
                0 => "domain",
                1 => "ipcidr",
                2 => "classical",
                _ => "unknown",
            },
            behavior
        ));
    }
    let _count = r.i64()?;
    let extra = r.len()?;
    r.bytes(extra)?;
    match behavior {
        ClashBehavior::Domain => domains(&mut r).map(Set::Domains),
        _ => ranges(&mut r).map(Set::Ranges),
    }
}

/// The domains of Mihomo's `DomainSet`, kept as they are.
fn domains(r: &mut Reader) -> Result<DomainSet> {
    if r.u8()? != 1 {
        return Err(anyhow!("mrs: an unknown domain set version"));
    }
    let leaves = r.u64s()?;
    let bitmap = r.u64s()?;
    let n = r.len()?;
    let labels = r.bytes(n)?.to_vec();
    DomainSet::new(leaves, bitmap, labels)
}

/// The ranges of Mihomo's `IpCidrSet`.
fn ranges(r: &mut Reader) -> Result<Vec<(IpAddr, IpAddr)>> {
    if r.u8()? != 1 {
        return Err(anyhow!("mrs: an unknown IP set version"));
    }
    let n = r.len()?;
    if n > r.left() / 32 {
        return Err(anyhow!("mrs: {} ranges, more than it holds", n));
    }
    let mut ranges = Vec::with_capacity(n);
    for _ in 0..n {
        let from = address(r.bytes(16)?);
        let to = address(r.bytes(16)?);
        ranges.push((from, to));
    }
    Ok(ranges)
}

fn address(bytes: &[u8]) -> IpAddr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(bytes);
    let ip = Ipv6Addr::from(octets);
    match ip.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip),
    }
}

/// Big-endian reads, each checked against what is left.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn left(&self) -> usize {
        self.data.len() - self.at
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.left() {
            return Err(anyhow!("mrs: cut short"));
        }
        let bytes = &self.data[self.at..self.at + n];
        self.at += n;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(
            self.bytes(8)?.try_into().expect("8 bytes"),
        ))
    }

    /// A length, which what is left must be able to hold.
    fn len(&mut self) -> Result<usize> {
        let n = self.i64()?;
        usize::try_from(n)
            .ok()
            .filter(|n| *n <= self.left())
            .ok_or_else(|| anyhow!("mrs: a length of {}, more than it holds", n))
    }

    fn u64s(&mut self) -> Result<Vec<u64>> {
        let n = self.len()?;
        if n > self.left() / 8 {
            return Err(anyhow!("mrs: {} words, more than it holds", n));
        }
        (0..n)
            .map(|_| {
                Ok(u64::from_be_bytes(
                    self.bytes(8)?.try_into().expect("8 bytes"),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rule_set");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/{}", FIXTURES, name)).unwrap()
    }

    /// The domains Mihomo's own text of a set holds, as MRS keeps them:
    /// `+.x` is `x` and `.x`.
    fn listed_domains(text: &str) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            match line.strip_prefix("+.") {
                Some(base) => {
                    set.insert(base.to_string());
                    set.insert(format!(".{}", base));
                }
                None => {
                    set.insert(line.to_string());
                }
            }
        }
        set
    }

    /// Ranges, sorted, and those that touch joined, as Mihomo's set keeps
    /// them.
    fn merged(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
        ranges.sort();
        let mut out: Vec<(u128, u128)> = Vec::new();
        for (a, b) in ranges {
            match out.last_mut() {
                Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
                _ => out.push((a, b)),
            }
        }
        out
    }

    fn number(ip: IpAddr) -> u128 {
        match ip {
            IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
            IpAddr::V6(v6) => u128::from(v6),
        }
    }

    #[test]
    fn a_domain_set_holds_what_mihomo_s_text_of_it_does() {
        let Set::Domains(domains) =
            read(&fixture("geosite-telegram.mrs"), ClashBehavior::Domain).unwrap()
        else {
            panic!("not domains");
        };
        let decoded: BTreeSet<String> = domains.domains().into_iter().collect();
        let listed = listed_domains(&String::from_utf8(fixture("geosite-telegram.list")).unwrap());
        assert_eq!(decoded, listed);
    }

    #[test]
    fn an_ip_set_holds_what_mihomo_s_text_of_it_does() {
        let Set::Ranges(ranges) =
            read(&fixture("geoip-telegram.mrs"), ClashBehavior::Ipcidr).unwrap()
        else {
            panic!("not ranges");
        };
        let decoded = merged(
            ranges
                .into_iter()
                .map(|(a, b)| (number(a), number(b)))
                .collect(),
        );
        let listed = merged(
            String::from_utf8(fixture("geoip-telegram.list"))
                .unwrap()
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let net: cidr::IpCidr = l.trim().parse().unwrap();
                    (number(net.first_address()), number(net.last_address()))
                })
                .collect(),
        );
        assert_eq!(decoded, listed);
    }

    /// The domains to ask a set about: each entry's own, one and two
    /// labels under it, and a stranger.
    fn queries(list: &str) -> Vec<String> {
        let mut queries = vec!["stranger.invalid".to_string()];
        for line in list
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let base = line
                .trim_start_matches("+.")
                .trim_start_matches('.')
                .replace('*', "w");
            queries.push(base.clone());
            queries.push(format!("a.{}", base));
            queries.push(format!("a.b.{}", base));
            queries.push(format!("x{}", base));
        }
        queries
    }

    /// Whether the set matches each query as the domain index matches the
    /// set's text.
    fn matches_as_its_text(set: &DomainSet, list: &str) {
        let lines: Vec<String> = list
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect();
        let index = super::super::clash::from_lines(&lines, ClashBehavior::Domain).unwrap();
        for query in queries(list) {
            let facts = crate::app::router::matcher::Facts::new(
                &crate::session::Session {
                    destination: crate::session::SocksAddr::Domain(query.clone(), 443),
                    ..Default::default()
                },
                &[],
            );
            let want = index.iter().any(|r| r.matches(&facts, false));
            assert_eq!(set.matches(&query), want, "{}", query);
        }
    }

    #[test]
    fn a_domain_set_matches_as_its_text_does() {
        let Set::Domains(set) =
            read(&fixture("geosite-telegram.mrs"), ClashBehavior::Domain).unwrap()
        else {
            panic!("not domains");
        };
        matches_as_its_text(
            &set,
            &String::from_utf8(fixture("geosite-telegram.list")).unwrap(),
        );
    }

    /// Made by Mihomo's `convert-ruleset` from `wildcards.list`.
    #[test]
    fn wildcards_match_as_mihomo_writes_them() {
        let Set::Domains(set) = read(&fixture("wildcards.mrs"), ClashBehavior::Domain).unwrap()
        else {
            panic!("not domains");
        };
        let list = String::from_utf8(fixture("wildcards.list")).unwrap();
        let decoded: BTreeSet<String> = set.domains().into_iter().collect();
        assert_eq!(decoded, listed_domains(&list));
        matches_as_its_text(&set, &list);
        for (domain, want) in [
            ("a.example", true),
            ("deep.sub.a.example", true),
            ("b.example", false),
            ("www.b.example", true),
            ("one.c.example", true),
            ("two.one.c.example", false),
            ("x.any.e.example", true),
            ("x.e.example", false),
            ("D.EXAMPLE", true),
        ] {
            assert_eq!(set.matches(domain), want, "{}", domain);
        }
    }

    #[test]
    fn a_broken_file_is_an_error() {
        let data = fixture("geosite-telegram.mrs");
        assert!(read(&data[..data.len() / 2], ClashBehavior::Domain).is_err());
        assert!(read(&data, ClashBehavior::Ipcidr).is_err());
        assert!(read(b"not zstd", ClashBehavior::Domain).is_err());
        for i in (0..data.len()).step_by(7) {
            let mut bad = data.clone();
            bad[i] ^= 0x55;
            let _ = read(&bad, ClashBehavior::Domain);
        }
    }

    /// Mihomo's published sets, against their own text, where
    /// `SAIL_MRS_DIR` holds `geosite-*.mrs` and `.list` pairs: a check of
    /// large sets, not run by default.
    #[test]
    #[ignore]
    fn published_sets_hold_what_their_text_does() {
        let dir = std::env::var("SAIL_MRS_DIR").unwrap();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let Some(stem) = name.strip_suffix(".mrs") else {
                continue;
            };
            let list = std::fs::read_to_string(format!("{}/{}.list", dir, stem)).unwrap();
            let data = std::fs::read(&path).unwrap();
            let start = std::time::Instant::now();
            if stem.starts_with("geosite-") {
                let Set::Domains(domains) = read(&data, ClashBehavior::Domain).unwrap() else {
                    panic!()
                };
                matches_as_its_text(&domains, &list);
                let decoded: BTreeSet<String> = domains.domains().into_iter().collect();
                assert_eq!(decoded, listed_domains(&list), "{}", stem);
                println!(
                    "{}: {} domains in {:?}",
                    stem,
                    decoded.len(),
                    start.elapsed()
                );
            } else {
                let Set::Ranges(ranges) = read(&data, ClashBehavior::Ipcidr).unwrap() else {
                    panic!()
                };
                let n = ranges.len();
                let decoded = merged(
                    ranges
                        .into_iter()
                        .map(|(a, b)| (number(a), number(b)))
                        .collect(),
                );
                let listed = merged(
                    list.lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| {
                            let net: cidr::IpCidr = l.trim().parse().unwrap();
                            (number(net.first_address()), number(net.last_address()))
                        })
                        .collect(),
                );
                assert_eq!(decoded, listed, "{}", stem);
                println!("{}: {} ranges in {:?}", stem, n, start.elapsed());
            }
        }
    }
}
