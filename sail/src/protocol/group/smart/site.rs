//! Sites, and which member each connection is tried through.
//!
//! A site is what a destination belongs to: the narrow rule-set its rule
//! matched by, else its registrable domain, else its network (or, with
//! `prefer_asn`, its autonomous system). The group keeps each site on one
//! member while that member works for it, so that a site sees one
//! address, and remembers how each member it tried did for it.

use std::net::IpAddr;
use std::time::Duration;

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

/// A bulk site goes over to another member it tried once that member's
/// rate for it is this many times its own member's. A judgment: above
/// the run-to-run noise of one transfer, well below `SLOWER`.
const RATE_MARGIN: f64 = 1.25;

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
    /// Its rate for the site's transfers, in bytes a second, each sample
    /// weighing its seconds. Not kept across restarts: a bulk site goes
    /// by latency again until its first transfer of 1 MiB.
    rate: Option<Ewma>,
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
                    rate: None,
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

    /// Whether a transfer of it was big enough to have a rate: its
    /// members are then ranked by rate for it rather than by latency.
    fn is_bulk(&self) -> bool {
        self.tried.iter().any(|t| t.rate.is_some())
    }

    fn rate(&self, member: &MemberKey) -> Option<f64> {
        self.tried(member).and_then(|t| t.rate).map(|r| r.mean())
    }

    /// Of the members tried for it, the one with the best rate, of those
    /// that did not fail it and `usable` keeps.
    fn best_rate(
        &self,
        now: Instant,
        usable: impl Fn(&MemberKey) -> bool,
    ) -> Option<(MemberKey, f64)> {
        self.tried
            .iter()
            .filter(|t| usable(&t.member) && !self.failed_for(&t.member, now))
            .filter_map(|t| t.rate.map(|r| (t.member.clone(), r.mean())))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
    }

    /// A transfer of it through `member` moved `rate` bytes a second for
    /// `time`; `others` are the group's other members that carry it, with
    /// their capacity if known. It goes over to a member it tried that is
    /// much faster for it; and, unless settled, tries next a member it has
    /// not tried whose capacity is unknown or more than twice its rate.
    ///
    /// A sample weighs its time, so a member's rate is the bytes it moved
    /// over the time it took: on a lossy member one stream may run at
    /// 300 Mbit/s while three others crawl at 10, and the transfer takes
    /// as long as the crawling ones.
    pub fn rated(
        &mut self,
        member: &MemberKey,
        rate: f64,
        time: Duration,
        others: &[(MemberKey, Option<f64>)],
        now: Instant,
    ) {
        let t = self.tried_mut(member, now);
        Ewma::add(&mut t.rate, rate, time.as_secs_f64().max(1e-3), now);
        let site_rate = t.rate.map_or(rate, |r| r.mean());
        if let Some((best, best_rate)) = self.best_rate(now, |_| true) {
            // A member pinned without a rate yet is being tried: it keeps
            // the site until it has one.
            let pinned_rate = self.pinned.as_ref().and_then(|p| self.rate(p));
            let go = match pinned_rate {
                Some(pinned_rate) => best_rate > pinned_rate * RATE_MARGIN,
                None => self.pinned.is_none(),
            };
            if go {
                self.pinned = Some(best);
            }
        }
        if !self.settled
            && self.pinned.as_ref() == Some(member)
            && others.iter().any(|(k, capacity)| {
                k != member
                    && self.tried(k).is_none()
                    && capacity.is_none_or(|c| c > site_rate * SLOWER)
            })
        {
            self.switch = true;
        }
    }

    /// Whether it is pinned to `member`: its connections then go to that
    /// member alone, not raced, so that it keeps one exit.
    pub fn is_pinned_to(&self, member: &MemberKey) -> bool {
        self.pinned.as_ref() == Some(member)
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

/// A site as the cache file keeps it (memory.rs): its key hashed, its
/// times as Unix milliseconds.
#[derive(Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct StoredSite {
    pub key: String,
    #[serde(default)]
    pub pinned: Option<StoredMember>,
    #[serde(default)]
    pub settled: bool,
    #[serde(default)]
    pub tried: Vec<StoredTried>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct StoredMember {
    #[serde(default)]
    pub provider: Option<String>,
    pub name: String,
}

impl StoredMember {
    fn of(key: &MemberKey) -> Self {
        StoredMember {
            provider: key.source.as_deref().map(String::from),
            name: key.name.to_string(),
        }
    }

    fn key(&self) -> MemberKey {
        MemberKey {
            source: self.provider.as_deref().map(Into::into),
            name: self.name.as_str().into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct StoredTried {
    pub member: StoredMember,
    #[serde(default)]
    pub mean: Option<f64>,
    #[serde(default)]
    pub weight: f64,
    #[serde(default)]
    pub failed_until_ms: Option<u64>,
    pub at_ms: u64,
}

/// `instant` as Unix milliseconds, `now` being both `now_ms` and `now`.
fn to_ms(instant: Instant, now: Instant, now_ms: u64) -> u64 {
    if instant <= now {
        now_ms.saturating_sub(now.duration_since(instant).as_millis() as u64)
    } else {
        now_ms.saturating_add(instant.duration_since(now).as_millis() as u64)
    }
}

impl Site {
    /// What the cache file keeps of it, under `key` (hashed).
    pub fn stored(&self, key: String, now: Instant, now_ms: u64) -> StoredSite {
        StoredSite {
            key,
            pinned: self.pinned.as_ref().map(StoredMember::of),
            settled: self.settled,
            tried: self
                .tried
                .iter()
                .map(|t| StoredTried {
                    member: StoredMember::of(&t.member),
                    mean: t.latency.map(|l| l.mean()),
                    weight: t.latency.map_or(0.0, |l| l.weight(now)),
                    failed_until_ms: t
                        .failed_until
                        .filter(|until| *until > now)
                        .map(|until| to_ms(until, now, now_ms)),
                    at_ms: to_ms(t.at, now, now_ms),
                })
                .collect(),
        }
    }

    /// The site `stored` keeps, as of `now` (`now_ms`): none if its last
    /// use is longer than `ttl` ago, or none of its members is `kept`.
    pub fn restored(
        stored: &StoredSite,
        ttl: std::time::Duration,
        kept: impl Fn(&MemberKey) -> bool,
        now: Instant,
        now_ms: u64,
    ) -> Option<Site> {
        let ago = |ms: u64| std::time::Duration::from_millis(now_ms.saturating_sub(ms));
        let last = stored.tried.iter().map(|t| t.at_ms).max()?;
        if ago(last) >= ttl {
            return None;
        }
        let tried: Vec<Tried> = stored
            .tried
            .iter()
            .filter(|t| kept(&t.member.key()))
            .take(MAX_TRIED + 1)
            .map(|t| Tried {
                rate: None,
                member: t.member.key(),
                latency: t
                    .mean
                    .and_then(|mean| Ewma::restored(mean, t.weight, ago(t.at_ms), now)),
                failed_until: t
                    .failed_until_ms
                    .filter(|until| *until > now_ms)
                    .map(|until| now + std::time::Duration::from_millis(until - now_ms)),
                at: now.checked_sub(ago(t.at_ms)).unwrap_or(now),
            })
            .collect();
        if tried.is_empty() {
            return None;
        }
        let pinned = stored
            .pinned
            .as_ref()
            .map(StoredMember::key)
            .filter(|p| tried.iter().any(|t| t.member == *p));
        Some(Site {
            pinned,
            tried,
            switch: false,
            settled: stored.settled,
        })
    }
}

/// A member as the choice sees it.
#[derive(Clone, Debug)]
pub struct Rank {
    pub key: MemberKey,
    /// `None` while unknown.
    pub score: Option<f64>,
    pub failed: bool,
    /// The most it carried, in bytes a second, if known.
    pub capacity: Option<f64>,
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
///    twice as slow for the site as the best member is for all, or is
///    within `tolerance` of it;
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
        first = pinned(ranks, site, best, tolerance, now, &position);
        if first.is_none() && site.switch && !site.settled {
            site.switch = false;
            // Another member it has not tried, the best there is: for a
            // bulk site, the one that carried the most, if more than twice
            // its best rate, else the first whose capacity is unknown.
            let mut untried: Vec<usize> = up
                .iter()
                .chain(&unknown)
                .copied()
                .filter(|&i| site.tried(&ranks[i].key).is_none() && !failed_for_site(i))
                .collect();
            if site.is_bulk() {
                let rate = site.best_rate(now, |_| true).map_or(0.0, |(_, r)| r);
                let class = |i: usize| match ranks[i].capacity {
                    Some(c) if c > rate * SLOWER => (0, -c),
                    None => (1, 0.0),
                    Some(_) => (2, 0.0),
                };
                untried.sort_by(|&a, &b| class(a).partial_cmp(&class(b)).unwrap());
            }
            let untried = untried.first().copied();
            if site.tried.len() >= MAX_TRIED || untried.is_none() {
                settle(site, ranks, now, &position);
                first = pinned(ranks, site, best, tolerance, now, &position);
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
    tolerance: Tolerance,
    now: Instant,
    position: &impl Fn(&MemberKey) -> Option<usize>,
) -> Option<usize> {
    let key = site.pinned.clone()?;
    let keep = match position(&key) {
        Some(i) if ranks[i].failed || site.failed_for(&key, now) => None,
        // A site that settled keeps its member, however slow.
        Some(i) if site.settled => Some(i),
        Some(_) if site.switch => None,
        // A bulk site's member is the one with the best rate for it
        // (`rated`), or one being tried: latency does not move it.
        Some(i) if site.is_bulk() => Some(i),
        Some(i) => {
            let for_site = site
                .tried(&key)
                .and_then(|t| t.latency)
                .map(|l| l.mean())
                .or(ranks[i].score);
            // Within the tolerance it would be picked as likely as any:
            // leaving it would only move the site at random.
            match (for_site, best) {
                (Some(latency), Some(best))
                    if super::score::slower(latency, best, SLOWER)
                        && !tolerance.admits(latency, best) =>
                {
                    None
                }
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

/// Pins the site to the member that was fastest for it (by rate, for a
/// bulk site), and stops it
/// switching.
fn settle(
    site: &mut Site,
    ranks: &[Rank],
    now: Instant,
    position: &impl Fn(&MemberKey) -> Option<usize>,
) {
    site.settled = true;
    site.switch = false;
    if site.is_bulk() {
        let usable = |key: &MemberKey| position(key).is_some_and(|i| !ranks[i].failed);
        if let Some((member, _)) = site.best_rate(now, usable) {
            site.pinned = Some(member);
        }
        return;
    }
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
            capacity: None,
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

    /// Bytes a second of `mbit` Mbit/s.
    fn mbit(mbit: f64) -> f64 {
        mbit * 1e6 / 8.0
    }

    /// One connection to `site`: the member it goes through, which then
    /// moves `rate` for it; `capacity` is each member's.
    fn transfer(
        site: &mut Site,
        ranks: &[Rank],
        rate: impl Fn(&str) -> f64,
        now: Instant,
    ) -> String {
        let first = order(ranks, Some(site), tolerance(0.0, 0.0), now, &mut rng())[0];
        let member = ranks[first].key.clone();
        site.connected(&member, now);
        let others: Vec<(MemberKey, Option<f64>)> = ranks
            .iter()
            .filter(|r| r.key != member)
            .map(|r| (r.key.clone(), r.capacity))
            .collect();
        site.rated(
            &member,
            rate(&member.name),
            Duration::from_secs(1),
            &others,
            now,
        );
        member.name.to_string()
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_bulk_site_tries_a_member_of_unknown_capacity_and_keeps_the_faster() {
        let now = Instant::now();
        // a answers first; b carries more.
        let ranks = [up("a", 20.0), up("b", 40.0)];
        let rate = |m: &str| if m == "a" { mbit(8.0) } else { mbit(300.0) };
        let mut site = Site::default();
        let went: Vec<String> = (0..5)
            .map(|_| transfer(&mut site, &ranks, rate, now))
            .collect();
        assert_eq!(went, ["a", "b", "b", "b", "b"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_bulk_site_tries_the_member_that_carried_most_elsewhere() {
        let now = Instant::now();
        let mut ranks = [up("a", 20.0), up("b", 40.0), up("c", 60.0)];
        ranks[1].capacity = Some(mbit(10.0));
        ranks[2].capacity = Some(mbit(300.0));
        let rate = |m: &str| if m == "c" { mbit(250.0) } else { mbit(8.0) };
        let mut site = Site::default();
        let went: Vec<String> = (0..3)
            .map(|_| transfer(&mut site, &ranks, rate, now))
            .collect();
        assert_eq!(went, ["a", "c", "c"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_bulk_site_whose_server_is_the_limit_tries_three_members_and_stays() {
        let now = Instant::now();
        let ranks = [up("a", 20.0), up("b", 40.0), up("c", 60.0), up("d", 80.0)];
        // 20 Mbit/s whatever the member, give or take.
        let rate = |m: &str| mbit(if m == "b" { 21.0 } else { 19.0 });
        let mut site = Site::default();
        let went: Vec<String> = (0..10)
            .map(|_| transfer(&mut site, &ranks, rate, now))
            .collect();
        let mut tried = went.clone();
        tried.sort();
        tried.dedup();
        assert!(tried.len() <= 3, "{:?}", went);
        assert!(went[3..].windows(2).all(|w| w[0] == w[1]), "{:?}", went);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lossy_member_s_one_fast_stream_does_not_hide_its_slow_ones() {
        let now = Instant::now();
        let mut site = Site::default();
        let b_unknown = [(key("b"), None)];
        // Four streams of 8 MiB through a, lossy: one fast, three slow.
        site.connected(&key("a"), now);
        for mbit_s in [300.0, 11.0, 10.0, 9.0] {
            let rate = mbit(mbit_s);
            let time = Duration::from_secs_f64((8 << 20) as f64 / rate);
            site.rated(&key("a"), rate, time, &b_unknown, now);
        }
        // One stream of 8 MiB through b, clean: slower than a's fast one
        // and than the mean of a's four rates, but the transfer is done
        // far sooner.
        site.connected(&key("b"), now);
        let rate = mbit(100.0);
        let time = Duration::from_secs_f64((8 << 20) as f64 / rate);
        site.rated(&key("b"), rate, time, &[(key("a"), Some(mbit(300.0)))], now);
        assert_eq!(site.pinned, Some(key("b")));
    }

    #[tokio::test(start_paused = true)]
    async fn latency_does_not_move_a_bulk_site() {
        let now = Instant::now();
        let mut site = Site::default();
        site.connected(&key("b"), now);
        site.rated(
            &key("b"),
            mbit(300.0),
            Duration::from_secs(1),
            &[(key("a"), Some(mbit(10.0)))],
            now,
        );
        // b ten times as slow to answer as a.
        let ranks = [up("a", 20.0), up("b", 200.0)];
        assert_eq!(
            order(
                &ranks,
                Some(&mut site),
                tolerance(0.0, 0.0),
                now,
                &mut rng()
            )[0],
            1
        );
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
        // Twice as slow but within the tolerance: it stays.
        let mut near = site.clone();
        near.tried[0].latency = Some(Ewma::new(201.0, 1.0, now));
        let wide = tolerance(10000.0, 0.0);
        assert_eq!(order(&ranks, Some(&mut near), wide, now, &mut rng())[0], 0);
        assert_eq!(near.pinned(), Some(&key("a")));
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
