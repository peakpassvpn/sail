//! Sites, and which member each connection is tried through.
//!
//! A site is what a destination belongs to: the narrow rule-set its rule
//! matched by, else its registrable domain, else its network (or, with
//! `prefer_asn`, its autonomous system). The group keeps each site on one
//! member while that member works for it, so that a site sees one
//! address, and remembers how each member it tried did for it.

use std::net::IpAddr;

use rand::Rng;
use tokio::time::Instant;

use super::score::Ewma;
use crate::protocol::group::domain::registrable_domain;
use crate::protocol::group::members::MemberKey;
use crate::session::{Session, SocksAddr};

/// How many members one connection is tried through at most.
pub const MAX_ATTEMPTS: usize = 3;

/// How many members a site remembers; after this many tried the site
/// itself is taken to be the problem, and the group stops switching.
pub const MAX_TRIED: usize = 3;

/// How long a member that failed a site is not tried for it first.
pub const SITE_FAILED_FOR: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// A site's first response through its member is this many times the
/// member's average, or its member's average this many times the best
/// member's, and the site tries another.
const SLOWER: f64 = 2.0;

/// Autonomous systems that are CDNs, whose addresses serve unrelated
/// sites: an address in one is keyed by its network rather than by its
/// AS. Cloudflare, Akamai, Fastly, Amazon (CloudFront), Google,
/// Microsoft, Alibaba, Tencent.
const CDN_ASNS: &[u32] = &[
    13335, 209242, 20940, 16625, 54113, 16509, 14618, 15169, 396982, 8075, 45102, 132203,
];

/// The site a connection's destination belongs to; `asn` looks up an
/// address's autonomous system, with `prefer_asn`.
pub fn key(sess: &Session, asn: Option<&dyn Fn(IpAddr) -> Option<u32>>) -> String {
    if let Some(tag) = &sess.matched_rule_set {
        return format!("rule_set:{}", tag);
    }
    let domain = match &sess.destination {
        SocksAddr::Domain(domain, _) if domain.parse::<IpAddr>().is_err() => Some(domain.as_str()),
        _ => sess.sniffed_domain(),
    };
    if let Some(domain) = domain {
        return registrable_domain(domain);
    }
    let ip = match &sess.destination {
        SocksAddr::Ip(addr) => addr.ip(),
        SocksAddr::Domain(domain, _) => domain.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
    }
    .to_canonical();
    if let Some(asn) = asn.and_then(|lookup| lookup(ip)) {
        if !CDN_ASNS.contains(&asn) {
            return format!("AS{}", asn);
        }
    }
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            format!("{}.{}.{}.0/24", a, b, c)
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// How one member did for a site.
#[derive(Clone, Debug)]
struct Tried {
    member: MemberKey,
    /// Its first responses for the site, with connecting.
    latency: Option<Ewma>,
    failed_until: Option<Instant>,
    at: Instant,
}

/// What the group remembers of one site.
#[derive(Clone, Debug, Default)]
pub struct Site {
    /// The member its connections go to while it works for it.
    pinned: Option<MemberKey>,
    /// The members tried for it, at most `MAX_TRIED + 1`.
    tried: Vec<Tried>,
    /// Its member was much slower for it than usual: the next connection
    /// tries another.
    switch: bool,
    /// Enough members were tried: it stays on the best of them.
    settled: bool,
}

impl Site {
    fn tried(&self, member: &MemberKey) -> Option<&Tried> {
        self.tried.iter().find(|t| t.member == *member)
    }

    fn tried_mut(&mut self, member: &MemberKey, now: Instant) -> &mut Tried {
        let i = match self.tried.iter().position(|t| t.member == *member) {
            Some(i) => i,
            None => {
                if self.tried.len() > MAX_TRIED {
                    // The oldest goes, unless pinned.
                    let oldest = self
                        .tried
                        .iter()
                        .enumerate()
                        .filter(|(_, t)| Some(&t.member) != self.pinned.as_ref())
                        .min_by_key(|(_, t)| t.at)
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.tried.remove(oldest);
                }
                self.tried.push(Tried {
                    member: member.clone(),
                    latency: None,
                    failed_until: None,
                    at: now,
                });
                self.tried.len() - 1
            }
        };
        let t = &mut self.tried[i];
        t.at = now;
        t
    }

    fn failed_for(&self, member: &MemberKey, now: Instant) -> bool {
        self.tried(member)
            .and_then(|t| t.failed_until)
            .is_some_and(|until| now < until)
    }

    /// The member it is pinned to, if any.
    #[cfg(test)]
    pub fn pinned(&self) -> Option<&MemberKey> {
        self.pinned.as_ref()
    }

    #[cfg(test)]
    pub fn is_settled(&self) -> bool {
        self.settled
    }

    /// A connection to it through `member` was answered after `latency`
    /// ms, which is the member's average `usual` for all sites.
    pub fn answered(&mut self, member: &MemberKey, latency: f64, usual: Option<f64>, now: Instant) {
        let t = self.tried_mut(member, now);
        t.failed_until = None;
        Ewma::add(&mut t.latency, latency, 1.0, now);
        let site_latency = t.latency.map(|l| l.mean()).unwrap_or(latency);
        if self.pinned.is_none() {
            self.pinned = Some(member.clone());
        }
        if !self.settled
            && self.pinned.as_ref() == Some(member)
            && usual.is_some_and(|usual| super::score::slower(site_latency, usual, SLOWER))
        {
            self.switch = true;
        }
    }

    /// A connection to it through `member` succeeded without a latency to
    /// tell: it is pinned to it, if to none yet.
    pub fn connected(&mut self, member: &MemberKey, now: Instant) {
        self.tried_mut(member, now);
        if self.pinned.is_none() {
            self.pinned = Some(member.clone());
        }
    }

    /// A connection to it through `member` failed.
    pub fn failed(&mut self, member: &MemberKey, now: Instant) {
        self.tried_mut(member, now).failed_until = Some(now + SITE_FAILED_FOR);
        if self.pinned.as_ref() == Some(member) {
            self.pinned = None;
        }
    }

    /// Forgets the members `keep` does not keep: those that left the
    /// group.
    pub fn retain(&mut self, keep: impl Fn(&MemberKey) -> bool) {
        self.tried.retain(|t| keep(&t.member));
        if self.pinned.as_ref().is_some_and(|p| !keep(p)) {
            self.pinned = None;
        }
    }
}

/// A member as the choice sees it.
#[derive(Clone, Debug)]
pub struct Rank {
    pub key: MemberKey,
    /// `None` while unknown.
    pub score: Option<f64>,
    pub failed: bool,
}

/// How close to the best a member must be to be picked.
#[derive(Clone, Copy, Debug)]
pub struct Tolerance {
    pub ms: f64,
    pub ratio: f64,
}

impl Tolerance {
    /// Whether `score` is close enough to `best`.
    fn admits(&self, score: f64, best: f64) -> bool {
        score <= (best * (1.0 + self.ratio)).max(best + self.ms)
    }
}

/// The members, by index into `ranks`, a connection to `site` is tried
/// through, in turn, `MAX_ATTEMPTS` at most:
///
/// 1. the site's member, while it has not failed, and is not more than
///    twice as slow for the site as the best member is for all;
/// 2. else one picked at random among the members up whose score is
///    within `tolerance` of the best (a member tried more than
///    `MAX_TRIED` times for a site settles it on the best of them);
/// 3. then the others up by score, the unknown in order, and the failed
///    by score.
pub fn order(
    ranks: &[Rank],
    site: Option<&mut Site>,
    tolerance: Tolerance,
    now: Instant,
    rng: &mut impl Rng,
) -> Vec<usize> {
    let mut up: Vec<usize> = (0..ranks.len())
        .filter(|&i| !ranks[i].failed && ranks[i].score.is_some())
        .collect();
    up.sort_by(|&a, &b| ranks[a].score.partial_cmp(&ranks[b].score).unwrap());
    let unknown: Vec<usize> = (0..ranks.len())
        .filter(|&i| !ranks[i].failed && ranks[i].score.is_none())
        .collect();
    let mut failed: Vec<usize> = (0..ranks.len()).filter(|&i| ranks[i].failed).collect();
    failed.sort_by(|&a, &b| {
        let score = |i: usize| ranks[i].score.unwrap_or(f64::INFINITY);
        score(a).partial_cmp(&score(b)).unwrap()
    });
    let best = up.first().and_then(|&i| ranks[i].score);
    let position = |key: &MemberKey| ranks.iter().position(|r| r.key == *key);

    let site_failed: Vec<usize> = match &site {
        Some(site) => (0..ranks.len())
            .filter(|&i| site.failed_for(&ranks[i].key, now))
            .collect(),
        None => Vec::new(),
    };
    let failed_for_site = |i: usize| site_failed.contains(&i);
    let mut first = None;
    if let Some(site) = site {
        first = pinned(ranks, site, best, now, &position);
        if first.is_none() && site.switch && !site.settled {
            site.switch = false;
            // Another member it has not tried, the best there is.
            let untried = up
                .iter()
                .chain(&unknown)
                .copied()
                .find(|&i| site.tried(&ranks[i].key).is_none() && !failed_for_site(i));
            if site.tried.len() >= MAX_TRIED || untried.is_none() {
                settle(site, ranks, &position);
                first = pinned(ranks, site, best, now, &position);
            } else {
                first = untried;
                site.pinned = None;
            }
        }
    }
    let first = first.or_else(|| {
        // The best of those that did not fail the site.
        let usable: Vec<usize> = up
            .iter()
            .copied()
            .filter(|&i| !failed_for_site(i))
            .collect();
        let candidates: Vec<usize> = match usable.first().and_then(|&i| ranks[i].score) {
            Some(best) => usable
                .iter()
                .copied()
                .filter(|&i| tolerance.admits(ranks[i].score.unwrap_or(f64::INFINITY), best))
                .collect(),
            None => Vec::new(),
        };
        match candidates.len() {
            0 => None,
            n => Some(candidates[rng.gen_range(0..n)]),
        }
    });
    let mut order: Vec<usize> = Vec::with_capacity(MAX_ATTEMPTS);
    let rest = up.iter().chain(&unknown).chain(&failed).copied();
    // Those that failed for the site go after the others.
    let (for_site, not_for_site): (Vec<usize>, Vec<usize>) =
        rest.partition(|&i| !failed_for_site(i));
    for i in first.into_iter().chain(for_site).chain(not_for_site) {
        if order.len() == MAX_ATTEMPTS {
            break;
        }
        if !order.contains(&i) {
            order.push(i);
        }
    }
    order
}

/// The site's pinned member, if it is to be kept; unpins it if not.
fn pinned(
    ranks: &[Rank],
    site: &mut Site,
    best: Option<f64>,
    now: Instant,
    position: &impl Fn(&MemberKey) -> Option<usize>,
) -> Option<usize> {
    let key = site.pinned.clone()?;
    let keep = match position(&key) {
        Some(i) if ranks[i].failed || site.failed_for(&key, now) => None,
        // A site that settled keeps its member, however slow.
        Some(i) if site.settled => Some(i),
        Some(_) if site.switch => None,
        Some(i) => {
            let for_site = site
                .tried(&key)
                .and_then(|t| t.latency)
                .map(|l| l.mean())
                .or(ranks[i].score);
            match (for_site, best) {
                (Some(latency), Some(best)) if super::score::slower(latency, best, SLOWER) => None,
                _ => Some(i),
            }
        }
        None => None,
    };
    if keep.is_none() {
        site.pinned = None;
    }
    keep
}

/// Pins the site to the member that was fastest for it, and stops it
/// switching.
fn settle(site: &mut Site, ranks: &[Rank], position: &impl Fn(&MemberKey) -> Option<usize>) {
    site.settled = true;
    site.switch = false;
    let best = site
        .tried
        .iter()
        .filter(|t| position(&t.member).is_some_and(|i| !ranks[i].failed))
        .filter_map(|t| t.latency.map(|l| (t.member.clone(), l.mean())))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    if let Some((member, _)) = best {
        site.pinned = Some(member);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rank(name: &str, score: Option<f64>, failed: bool) -> Rank {
        Rank {
            key: MemberKey::outbound(name),
            score,
            failed,
        }
    }

    fn up(name: &str, score: f64) -> Rank {
        rank(name, Some(score), false)
    }

    fn tolerance(ms: f64, ratio: f64) -> Tolerance {
        Tolerance { ms, ratio }
    }

    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(7)
    }

    fn key(name: &str) -> MemberKey {
        MemberKey::outbound(name)
    }

    #[tokio::test(start_paused = true)]
    async fn the_best_is_first_then_the_others_up_the_unknown_and_the_failed() {
        let now = Instant::now();
        let ranks = [
            rank("failed", Some(10.0), true),
            rank("unknown", None, false),
            up("slow", 300.0),
            up("fast", 50.0),
        ];
        let t = tolerance(0.0, 0.0);
        assert_eq!(order(&ranks, None, t, now, &mut rng()), [3, 2, 1]);
        // Nothing known: the unknown in order, then the failed.
        let ranks = [
            rank("a", None, true),
            rank("b", None, false),
            rank("c", None, false),
        ];
        assert_eq!(order(&ranks, None, t, now, &mut rng()), [1, 2, 0]);
    }

    #[tokio::test(start_paused = true)]
    async fn one_within_the_tolerance_is_picked_at_random() {
        let now = Instant::now();
        let ranks = [
            up("a", 100.0),
            up("b", 115.0),
            up("c", 125.0),
            up("d", 300.0),
        ];
        let picked = |t: Tolerance| {
            let mut rng = rng();
            let mut seen = std::collections::BTreeSet::new();
            for _ in 0..200 {
                seen.insert(order(&ranks, None, t, now, &mut rng)[0]);
            }
            seen.into_iter().collect::<Vec<_>>()
        };
        // 20% of 100 ms.
        assert_eq!(picked(tolerance(0.0, 0.2)), [0, 1]);
        // The floor in milliseconds, when it is the wider.
        assert_eq!(picked(tolerance(30.0, 0.2)), [0, 1, 2]);
        assert_eq!(picked(tolerance(0.0, 0.0)), [0]);
        assert_eq!(picked(tolerance(1000.0, 0.0)), [0, 1, 2, 3]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_site_keeps_its_member() {
        let now = Instant::now();
        let ranks = [up("a", 100.0), up("b", 105.0)];
        let t = tolerance(30.0, 0.2);
        let mut site = Site::default();
        let mut rng = rng();
        let first = order(&ranks, Some(&mut site), t, now, &mut rng)[0];
        site.answered(&ranks[first].key, 100.0, Some(100.0), now);
        for _ in 0..50 {
            assert_eq!(order(&ranks, Some(&mut site), t, now, &mut rng)[0], first);
        }
        assert_eq!(site.pinned(), Some(&ranks[first].key));
    }

    #[tokio::test(start_paused = true)]
    async fn a_site_leaves_its_member_when_it_failed() {
        let now = Instant::now();
        let t = tolerance(0.0, 0.0);
        let mut site = Site::default();
        site.answered(&key("a"), 100.0, Some(100.0), now);
        let ranks = [up("a", 100.0), up("b", 120.0)];
        assert_eq!(order(&ranks, Some(&mut site), t, now, &mut rng()), [0, 1]);
        // Failed for everyone.
        let failed = [rank("a", Some(100.0), true), up("b", 120.0)];
        assert_eq!(order(&failed, Some(&mut site), t, now, &mut rng()), [1, 0]);
        assert_eq!(site.pinned(), None);

        // Failed for the site alone: tried last, for a while.
        let mut site = Site::default();
        site.answered(&key("a"), 100.0, Some(100.0), now);
        site.failed(&key("a"), now);
        let ranks = [up("a", 100.0), up("b", 120.0), up("c", 130.0)];
        assert_eq!(
            order(&ranks, Some(&mut site), t, now, &mut rng()),
            [1, 2, 0]
        );
        let later = now + SITE_FAILED_FOR;
        assert_eq!(order(&ranks, Some(&mut site), t, later, &mut rng())[0], 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_site_leaves_its_member_when_twice_as_slow_as_the_best() {
        let now = Instant::now();
        let t = tolerance(0.0, 0.0);
        let mut site = Site::default();
        site.answered(&key("a"), 150.0, Some(150.0), now);
        let ranks = [up("a", 150.0), up("b", 100.0)];
        assert_eq!(order(&ranks, Some(&mut site), t, now, &mut rng())[0], 0);
        let ranks = [up("a", 250.0), up("b", 100.0)];
        let mut far = site.clone();
        far.tried[0].latency = Some(Ewma::new(201.0, 1.0, now));
        assert_eq!(order(&ranks, Some(&mut far), t, now, &mut rng())[0], 1);
        assert_eq!(far.pinned(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_site_slow_on_its_member_tries_others_then_settles() {
        let now = Instant::now();
        let t = tolerance(0.0, 0.0);
        let ranks = [
            up("a", 100.0),
            up("b", 110.0),
            up("c", 120.0),
            up("d", 130.0),
        ];
        let mut site = Site::default();
        let mut rng = rng();
        let mut tried = Vec::new();
        for _ in 0..3 {
            let i = order(&ranks, Some(&mut site), t, now, &mut rng)[0];
            tried.push(i);
            // The site is slow whichever member it goes through; b the
            // least so.
            let latency = if i == 1 { 400.0 } else { 500.0 };
            site.answered(&ranks[i].key, latency, ranks[i].score, now);
        }
        assert_eq!(tried, [0, 1, 2]);
        assert!(site.switch);
        // Three tried: it settles on the fastest of them for it, and stays.
        for _ in 0..5 {
            let i = order(&ranks, Some(&mut site), t, now, &mut rng)[0];
            assert_eq!(i, 1);
            site.answered(&ranks[i].key, 400.0, ranks[i].score, now);
        }
        assert!(site.is_settled());
        // But leaves it when it fails.
        site.failed(&key("b"), now);
        assert_ne!(order(&ranks, Some(&mut site), t, now, &mut rng)[0], 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_member_gone_is_not_the_site_s() {
        let now = Instant::now();
        let t = tolerance(0.0, 0.0);
        let mut site = Site::default();
        site.answered(&key("gone"), 100.0, Some(100.0), now);
        let ranks = [up("a", 100.0)];
        assert_eq!(order(&ranks, Some(&mut site), t, now, &mut rng()), [0]);
        site.answered(&key("a"), 100.0, Some(100.0), now);
        assert_eq!(site.pinned(), Some(&key("a")));
        site.retain(|k| *k != key("a"));
        assert_eq!(site.pinned(), None);
        assert!(site.tried(&key("a")).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_are_bounded() {
        let now = Instant::now();
        let ranks: Vec<Rank> = (0..10).map(|i| up(&i.to_string(), i as f64)).collect();
        assert_eq!(
            order(&ranks, None, tolerance(0.0, 0.0), now, &mut rng()).len(),
            MAX_ATTEMPTS
        );
    }

    #[test]
    fn site_keys() {
        let sess = |destination: SocksAddr| Session {
            destination,
            ..Default::default()
        };
        let domain = |d: &str| sess(SocksAddr::Domain(d.to_string(), 443));
        let ip = |ip: &str| sess(SocksAddr::Ip((ip.parse::<IpAddr>().unwrap(), 443).into()));
        assert_eq!(super::key(&domain("www.example.com"), None), "example.com");
        assert_eq!(super::key(&domain("192.0.2.9"), None), "192.0.2.0/24");
        assert_eq!(super::key(&ip("192.0.2.9"), None), "192.0.2.0/24");
        assert_eq!(super::key(&ip("::ffff:192.0.2.9"), None), "192.0.2.0/24");
        assert_eq!(
            super::key(&ip("2001:db8:1:2:3::4"), None),
            "2001:db8:1:2::/64"
        );
        // A narrow rule-set's sites are one.
        let mut s = domain("www.example.com");
        s.matched_rule_set = Some("netflix".into());
        assert_eq!(super::key(&s, None), "rule_set:netflix");
        // A sniffed domain names the site of an address.
        let mut s = ip("192.0.2.9");
        s.set_sniffed_domain(
            crate::session::SniffedFrom::Tls,
            "api.example.org".to_string(),
        );
        assert_eq!(super::key(&s, None), "example.org");
        // By AS, but not a CDN's.
        let asn = |ip: IpAddr| match ip.to_string().as_str() {
            "192.0.2.9" => Some(64500),
            _ => Some(13335),
        };
        assert_eq!(super::key(&ip("192.0.2.9"), Some(&asn)), "AS64500");
        assert_eq!(
            super::key(&ip("198.51.100.1"), Some(&asn)),
            "198.51.100.0/24"
        );
        assert_eq!(
            super::key(&domain("example.com"), Some(&asn)),
            "example.com"
        );
    }
}
