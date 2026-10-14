//! `load-balance`: spreads connections over its members, as Mihomo's
//! load-balance group does, skipping those that failed their last URL
//! test, and those that do not carry the connection's network: one that
//! carries TCP alone, or UDP alone (an outbound with sing-box's
//! `network`).
//!
//! - `consistent-hashing`: a destination's registrable domain, or its IP,
//!   always goes to the same member, so a site sees one address. Members
//!   are weighed per site (rendezvous hashing), so that a member that
//!   comes or goes moves only the sites it takes or had.
//! - `round-robin`: each connection goes to the next member.
//! - `sticky-sessions`: a source and destination pair goes to the member
//!   it went to last, picked at random at first, until the pair is left
//!   unused for a while; its TCP and its UDP apart, as the members that
//!   carry each may differ.
//!
//! `hash_key: "user"`, a sail extension (Mihomo's `hash-key: in-user`),
//! has consistent-hashing and sticky-sessions key on the user the inbound
//! authenticated instead: a user's connections go to one member wherever
//! they go. A connection of no user is keyed as without it.

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use lru_time_cache::LruCache;
use rand::Rng;
use serde_derive::Deserialize;
use tracing::debug;

use super::domain::registrable_domain;
use super::health::{self, Checker};
use super::members::{Member, MemberKey, Members, Snapshot};
use super::merge;
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::app::healthcheck::{HttpProbe, StatusRanges};
use crate::app::SyncDnsClient;
use crate::config::model::GroupProviders;
use crate::session::{Network, Session, SocksAddr};

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "load-balance",
        OutboundFactory::composite(dependencies, build),
    );
}

#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum StrategyKind {
    #[default]
    ConsistentHashing,
    RoundRobin,
    StickySessions,
}

/// What consistent-hashing and sticky-sessions key on in place of the
/// destination, and the source.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum HashKey {
    /// The user the inbound authenticated, as Mihomo's `in-user`.
    User,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadBalanceOutboundOptions {
    /// Its members; none may be when its providers give others.
    #[serde(default)]
    outbounds: Vec<String>,
    /// Members from outbound providers too, a sail extension.
    #[serde(flatten)]
    providers: GroupProviders,
    #[serde(default)]
    strategy: StrategyKind,
    /// `user`: a connection's user is its key, not its destination (and
    /// source); a sail extension. Unset, or a connection of no user, as
    /// without it. round-robin keys on nothing, and refuses it.
    #[serde(default)]
    hash_key: Option<HashKey>,
    /// What is requested through each member to test it.
    #[serde(default = "default_url")]
    url: String,
    #[serde(default, with = "crate::config::model::duration")]
    interval: Option<Duration>,
    /// The HTTP statuses a test must be answered with to pass, as
    /// urltest's; any when unset.
    #[serde(default)]
    expected_status: Option<String>,
    /// The latency of a second request on the connection the first
    /// opened, without the connect and handshakes, as Mihomo's
    /// `unified-delay`; a sail extension.
    #[serde(default)]
    unified_delay: bool,
    /// How long a test may take before its member counts as failed; 5s.
    /// Also how close together `max_failed_times` failures must come, as
    /// urltest's.
    #[serde(default, with = "crate::config::model::duration")]
    timeout: Option<Duration>,
    /// How many failed connections, within `timeout` of the first, have
    /// the members tested again; 5, as urltest's.
    #[serde(default)]
    max_failed_times: Option<u32>,
    /// Tests only while the group is in use: not when it was not used
    /// since the last ones.
    #[serde(default = "default_lazy")]
    lazy: bool,
}

fn default_url() -> String {
    health::DEFAULT_URL.to_string()
}

fn default_lazy() -> bool {
    true
}

/// How long a sticky session is kept unused, as in Mihomo.
const STICKY_TTL: Duration = Duration::from_secs(10 * 60);
/// How many sticky sessions are kept at most; the least recently used
/// goes first.
const STICKY_CAPACITY: usize = 4096;
fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: LoadBalanceOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.providers.dependencies(options.outbounds))
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: LoadBalanceOutboundOptions = ctx.options()?;
    // As Mihomo: a key asked for would give no stickiness.
    if options.hash_key.is_some() && options.strategy == StrategyKind::RoundRobin {
        return Err(anyhow!(
            "[{}] outbound: hash_key: round-robin keys on nothing",
            ctx.tag
        ));
    }
    let merged = merge::members(ctx, &options.outbounds, &options.providers)?;
    let members = merged.members.clone();
    let interval = options.interval.unwrap_or(health::DEFAULT_INTERVAL);
    if interval.is_zero() {
        return Err(anyhow!(
            "[{}] outbound: interval: must not be zero",
            ctx.tag
        ));
    }
    let expected = StatusRanges::parse(options.expected_status.as_deref().unwrap_or_default())
        .map_err(|e| anyhow!("[{}] outbound: expected_status: {}", ctx.tag, e))?;
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone(), ctx.env)
        .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))?
        .expecting(expected)
        .unified(options.unified_delay);
    let timeout = options.timeout.unwrap_or(health::DEFAULT_TIMEOUT);
    if timeout.is_zero() {
        return Err(anyhow!("[{}] outbound: timeout: must not be zero", ctx.tag));
    }
    let max_failed_times = options
        .max_failed_times
        .unwrap_or(health::DEFAULT_MAX_FAILED_TIMES);
    if max_failed_times == 0 {
        return Err(anyhow!(
            "[{}] outbound: max_failed_times: must not be zero",
            ctx.tag
        ));
    }
    let (checker, abort_handle) = Checker::new(
        ctx.tag,
        members.clone(),
        probe.into(),
        ctx.dns_client.clone(),
        ctx.env.network.clone(),
        interval,
        timeout,
        max_failed_times,
        options.lazy.then_some(interval),
        Default::default(),
        Box::new(|_, _, _| ()),
    );
    ctx.abort_handles.push(abort_handle);
    ctx.checkers.insert(ctx.tag.to_owned(), checker.clone());
    merged.on_merged({
        let checker = checker.clone();
        // The new members are tested soon rather than an interval on.
        Box::new(move |_, added| {
            if added {
                checker.retest();
            }
        })
    });
    let group = Arc::new(Group {
        balancer: Balancer::new(options.strategy, STICKY_TTL).keyed_by(options.hash_key),
        members,
        checker,
        dns_client: ctx.dns_client.clone(),
    });
    Ok(HandlerBuilder::default()
        .is_group(true)
        .tag(ctx.tag.to_owned())
        .stream_handler(group.clone())
        .datagram_handler(group)
        .build())
}

/// Picks a member per connection.
struct Balancer {
    strategy: Strategy,
    hash_key: Option<HashKey>,
}

enum Strategy {
    ConsistentHashing,
    RoundRobin(AtomicUsize),
    /// By source and destination, or by `hash_key`, and network.
    StickySessions(Mutex<LruCache<u64, MemberKey>>),
}

impl Balancer {
    fn new(kind: StrategyKind, sticky_ttl: Duration) -> Self {
        let strategy = match kind {
            StrategyKind::ConsistentHashing => Strategy::ConsistentHashing,
            StrategyKind::RoundRobin => Strategy::RoundRobin(AtomicUsize::new(0)),
            StrategyKind::StickySessions => Strategy::StickySessions(Mutex::new(
                LruCache::with_expiry_duration_and_capacity(sticky_ttl, STICKY_CAPACITY),
            )),
        };
        Self {
            strategy,
            hash_key: None,
        }
    }

    /// Keyed by `hash_key` where a connection has it.
    fn keyed_by(mut self, hash_key: Option<HashKey>) -> Self {
        self.hash_key = hash_key;
        self
    }

    /// What `sess` is keyed on in place of its destination (and source):
    /// its user, with `hash_key: "user"`, if it has one. Marked off, so
    /// that no user's name is taken for a destination.
    fn key_of(&self, sess: &Session) -> Option<String> {
        match self.hash_key? {
            HashKey::User => crate::user::name(&sess.user).map(|name| format!("user\0{}", name)),
        }
    }

    /// The member of `members`, which are not none, for `sess` of
    /// `network`, among those `is_up`; when none is, among all, since a
    /// test can be wrong and trying beats refusing.
    fn pick(
        &self,
        sess: &Session,
        network: Network,
        members: &[Member],
        is_up: impl Fn(&Member) -> bool,
    ) -> usize {
        let n = members.len();
        let any_up = members.iter().any(&is_up);
        let is_up = |i: usize| !any_up || is_up(&members[i]);
        match &self.strategy {
            Strategy::ConsistentHashing => {
                let site = fnv1a(
                    self.key_of(sess)
                        .unwrap_or_else(|| destination_key(&sess.destination))
                        .as_bytes(),
                );
                (0..n)
                    .filter(|&i| is_up(i))
                    .max_by_key(|&i| weight(site, &members[i].key))
                    .unwrap_or(0)
            }
            Strategy::RoundRobin(next) => {
                let start = next.fetch_add(1, Ordering::Relaxed);
                (0..n)
                    .map(|i| start.wrapping_add(i) % n)
                    .find(|&i| is_up(i))
                    .unwrap_or(start % n)
            }
            Strategy::StickySessions(cache) => {
                // The network too: the TCP and the UDP of a pair may have
                // different members to go to, and would take each other's
                // member away.
                let pair = self.key_of(sess).unwrap_or_else(|| {
                    format!(
                        "{}|{}",
                        sess.source.ip(),
                        destination_key(&sess.destination)
                    )
                });
                let key = fnv1a(format!("{}|{}", pair, network).as_bytes());
                let Ok(mut cache) = cache.lock() else {
                    return 0;
                };
                if let Some(member) = cache.get(&key) {
                    if let Some(i) = members.iter().position(|m| m.key == *member) {
                        if is_up(i) {
                            return i;
                        }
                    }
                }
                let up: Vec<usize> = (0..n).filter(|&i| is_up(i)).collect();
                let i = up[rand::thread_rng().gen_range(0..up.len())];
                cache.insert(key, members[i].key.clone());
                i
            }
        }
    }
}

/// What a destination is balanced by: its registrable domain, so that
/// the hosts of one site go together, or its IP.
fn destination_key(destination: &SocksAddr) -> String {
    match destination {
        SocksAddr::Ip(addr) => addr.ip().to_string(),
        SocksAddr::Domain(domain, _) => match domain.parse::<IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => registrable_domain(domain),
        },
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}

/// How much the site hashed to `site` weighs `member`: the member that
/// weighs most takes the site. Each weight is the pair's alone, so a
/// member's coming or going moves no site between other members.
fn weight(site: u64, member: &MemberKey) -> u64 {
    let mut bytes = Vec::with_capacity(member.name.len() + 16);
    if let Some(source) = &member.source {
        bytes.extend_from_slice(source.as_bytes());
    }
    bytes.push(0xff);
    bytes.extend_from_slice(member.name.as_bytes());
    mix(site ^ fnv1a(&bytes))
}

/// splitmix64's finalizer: every bit of the result depends on every bit
/// of `x`.
fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

struct Group {
    members: Arc<Members>,
    balancer: Balancer,
    checker: Arc<Checker>,
    dns_client: SyncDnsClient,
}

impl Group {
    /// The member of `snapshot` for `sess` of `network`, of those that
    /// carry it and are up; when none of them is up, of those that carry
    /// it; when none does, of all, and its error tells.
    fn pick<'s>(
        &self,
        sess: &Session,
        snapshot: &'s Snapshot,
        network: Network,
    ) -> io::Result<&'s Member> {
        let carries = |m: &AnyOutboundHandler| match network {
            Network::Tcp => m.stream().is_ok(),
            Network::Udp => m.datagram().is_ok(),
        };
        self.checker.used();
        let members = &snapshot.members;
        if members.is_empty() {
            return Err(io::Error::other("no outbound to balance over"));
        }
        let up = |m: &Member| carries(&m.handler) && self.checker.is_up(&m.key);
        let i = match members.iter().any(up) {
            true => self.balancer.pick(sess, network, members, up),
            false => self
                .balancer
                .pick(sess, network, members, |m| carries(&m.handler)),
        };
        Ok(&members[i])
    }

    /// A failed connection through `member` is reason to test again
    /// rather than wait out the interval; not through a member that is
    /// not tested, see `health::is_tested`, of which the tests would say
    /// nothing.
    fn failed<T>(&self, member: &Member, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() && health::is_tested(&member.handler) {
            self.checker.retest();
        }
        result
    }
}

#[async_trait]
impl OutboundStreamHandler for Group {
    fn connect_addr(&self) -> OutboundConnect {
        // The member is picked, and dialled, per connection.
        OutboundConnect::Unknown
    }

    /// Tests the members again, as sing-box's urltest does on a change of
    /// interface. Heard here only: the datagram side is the same group.
    /// Its members hear of it themselves.
    fn network_changed(&self, _change: &crate::net::network::NetworkChange) {
        self.checker.network_changed();
    }

    /// Tests the members again, as on a change of network. Its members
    /// hear of it themselves.
    fn close_idle(&self) {
        self.checker.network_changed();
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let snapshot = self.members.load();
        let member = self.pick(sess, &snapshot, Network::Tcp)?;
        let a = &member.handler;
        debug!(
            "load-balance handles [{}] to [{}]",
            sess.destination,
            a.tag()
        );
        // In the chain before it is dialled: a failure names it.
        sess.chain.push(&member.key.name);
        self.failed(
            member,
            crate::net::dial_domain::stream(sess, self.dns_client.clone(), a).await,
        )
    }
}

#[async_trait]
impl OutboundDatagramHandler for Group {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let snapshot = self.members.load();
        let member = self.pick(sess, &snapshot, Network::Udp)?;
        let a = &member.handler;
        debug!(
            "load-balance handles [{}] to [{}]",
            sess.destination,
            a.tag()
        );
        sess.chain.push(&member.key.name);
        self.failed(
            member,
            crate::net::dial_domain::datagram_through(sess, self.dns_client.clone(), a).await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::group::members::tests::member;

    fn sess(source: &str, destination: &str) -> Session {
        let destination = match destination.parse::<IpAddr>() {
            Ok(ip) => SocksAddr::Ip((ip, 443).into()),
            Err(_) => SocksAddr::Domain(destination.to_string(), 443),
        };
        Session {
            source: (source.parse::<IpAddr>().unwrap(), 5000).into(),
            destination,
            ..Default::default()
        }
    }

    fn all_up(_: usize) -> bool {
        true
    }

    /// `Balancer::pick` over `n` members, `m0` on, by index.
    fn pick(b: &Balancer, s: &Session, n: usize, is_up: impl Fn(usize) -> bool) -> usize {
        let members: Vec<Member> = (0..n).map(|i| member(None, &format!("m{}", i))).collect();
        b.pick(s, Network::Tcp, &members, |m| {
            is_up(m.key.name[1..].parse().unwrap())
        })
    }

    #[test]
    fn destination_keys() {
        let key = |d: &str| destination_key(&sess("10.0.0.1", d).destination);
        assert_eq!(key("192.0.2.1"), "192.0.2.1");
        assert_eq!(key("2001:db8::1"), "2001:db8::1");
        // An IP given as a domain name.
        let domain_ip = SocksAddr::Domain("192.0.2.1".to_string(), 443);
        assert_eq!(destination_key(&domain_ip), "192.0.2.1");
        assert_eq!(key("cdn.example.co.uk"), "example.co.uk");
        assert_eq!(key("localhost"), "localhost");
        #[cfg(feature = "load-balance-psl")]
        {
            assert_ne!(key("alice.github.io"), key("bob.github.io"));
            assert_ne!(key("a.blogspot.com"), key("b.blogspot.com"));
        }
    }

    #[test]
    fn consistent_hashing_keeps_a_site_on_one_member() {
        let b = Balancer::new(StrategyKind::ConsistentHashing, STICKY_TTL);
        let first = pick(&b, &sess("10.0.0.1", "www.example.com"), 5, all_up);
        for (source, host) in [
            ("10.0.0.2", "api.example.com"),
            ("10.0.0.3", "example.com"),
            ("10.0.0.1", "cdn.static.example.com"),
        ] {
            assert_eq!(pick(&b, &sess(source, host), 5, all_up), first, "{}", host);
        }
        // And a new balancer, as after a restart, agrees.
        let again = Balancer::new(StrategyKind::ConsistentHashing, STICKY_TTL);
        assert_eq!(
            pick(&again, &sess("10.0.0.9", "example.com"), 5, all_up),
            first
        );
    }

    #[test]
    fn consistent_hashing_spreads_sites() {
        let b = Balancer::new(StrategyKind::ConsistentHashing, STICKY_TTL);
        let mut used = [0; 4];
        for i in 0..200 {
            used[pick(&b, &sess("10.0.0.1", &format!("site{}.com", i)), 4, all_up)] += 1;
        }
        assert!(used.iter().all(|&n| n > 20), "{:?}", used);
    }

    #[test]
    fn consistent_hashing_moves_only_the_sites_of_a_member_that_is_down() {
        let b = Balancer::new(StrategyKind::ConsistentHashing, STICKY_TTL);
        for i in 0..100 {
            let s = sess("10.0.0.1", &format!("site{}.com", i));
            let up = pick(&b, &s, 4, all_up);
            let down = if up == 0 { 1 } else { 0 };
            let picked = pick(&b, &s, 4, |i| i != down);
            assert_eq!(picked, up, "site{} moved though its member is up", i);
            let moved = pick(&b, &s, 4, |i| i != up);
            assert_ne!(moved, up);
        }
    }

    #[test]
    fn consistent_hashing_moves_only_the_sites_of_a_member_removed() {
        let b = Balancer::new(StrategyKind::ConsistentHashing, STICKY_TTL);
        let all: Vec<Member> = (0..8)
            .map(|i| member(Some("p"), &format!("HK {:02}", i)))
            .collect();
        let gone = all[3].key.clone();
        let rest: Vec<Member> = all.iter().filter(|m| m.key != gone).cloned().collect();
        let mut moved = 0;
        for i in 0..400 {
            let s = sess("10.0.0.1", &format!("site{}.com", i));
            let before = &all[b.pick(&s, Network::Tcp, &all, |_| true)].key;
            let after = &rest[b.pick(&s, Network::Tcp, &rest, |_| true)].key;
            if *before == gone {
                moved += 1;
            } else {
                assert_eq!(after, before, "site{} moved off a member still there", i);
            }
        }
        // Its share of the sites, give or take.
        assert!((20..=90).contains(&moved), "{}", moved);
    }

    #[test]
    fn a_sticky_session_follows_its_member_wherever_it_moves() {
        let b = Balancer::new(StrategyKind::StickySessions, STICKY_TTL);
        let s = sess("10.0.0.1", "example.com");
        let mut members: Vec<Member> = (0..6)
            .map(|i| member(Some("p"), &format!("m{}", i)))
            .collect();
        let first = members[b.pick(&s, Network::Tcp, &members, |_| true)]
            .key
            .clone();
        members.reverse();
        members.insert(0, member(Some("q"), "new"));
        assert_eq!(
            members[b.pick(&s, Network::Tcp, &members, |_| true)].key,
            first
        );
    }

    #[test]
    fn round_robin_takes_each_member_in_turn_and_skips_one_down() {
        let b = Balancer::new(StrategyKind::RoundRobin, STICKY_TTL);
        let s = sess("10.0.0.1", "example.com");
        let picks: Vec<usize> = (0..6).map(|_| pick(&b, &s, 3, all_up)).collect();
        assert_eq!(picks, [0, 1, 2, 0, 1, 2]);
        let picks: Vec<usize> = (0..4).map(|_| pick(&b, &s, 3, |i| i != 1)).collect();
        assert!(picks.iter().all(|&i| i != 1), "{:?}", picks);
        assert!(picks.contains(&0) && picks.contains(&2), "{:?}", picks);
    }

    #[test]
    fn when_every_member_is_down_one_is_still_tried() {
        for kind in [
            StrategyKind::ConsistentHashing,
            StrategyKind::RoundRobin,
            StrategyKind::StickySessions,
        ] {
            let b = Balancer::new(kind, STICKY_TTL);
            assert!(pick(&b, &sess("10.0.0.1", "example.com"), 3, |_| false) < 3);
        }
    }

    #[test]
    fn a_sticky_session_keeps_its_member_until_it_expires() {
        let ttl = Duration::from_millis(100);
        let b = Balancer::new(StrategyKind::StickySessions, ttl);
        let s = sess("10.0.0.1", "www.example.com");
        let first = pick(&b, &s, 16, all_up);
        for _ in 0..20 {
            assert_eq!(pick(&b, &s, 16, all_up), first);
        }
        // Another host of the same site is the same session.
        assert_eq!(
            pick(&b, &sess("10.0.0.1", "api.example.com"), 16, all_up),
            first
        );

        // Once expired, a member is picked again, at random: out of 16,
        // some of a few tries differ.
        let mut differed = false;
        for _ in 0..5 {
            std::thread::sleep(ttl + Duration::from_millis(50));
            if pick(&b, &s, 16, all_up) != first {
                differed = true;
                break;
            }
        }
        assert!(differed, "the session never expired");
    }

    /// `s`, of the inbound's user `name`.
    fn of(mut s: Session, name: &str) -> Session {
        s.user = Some(crate::user::UserRef::unbound(name));
        s
    }

    #[test]
    fn hash_key_user_keeps_a_user_on_one_member_wherever_it_goes() {
        let b = Balancer::new(StrategyKind::ConsistentHashing, STICKY_TTL)
            .keyed_by(Some(HashKey::User));
        let first = pick(
            &b,
            &of(sess("10.0.0.1", "a.example.com"), "alice"),
            8,
            all_up,
        );
        for (source, host) in [
            ("10.0.0.2", "b.example.org"),
            ("10.0.0.3", "c.example.net"),
            ("10.0.0.1", "192.0.2.1"),
        ] {
            let s = of(sess(source, host), "alice");
            assert_eq!(pick(&b, &s, 8, all_up), first, "{}", host);
        }
        // Users to one destination spread over the members.
        let used: std::collections::HashSet<usize> = (0..40)
            .map(|i| {
                let s = of(sess("10.0.0.1", "a.example.com"), &format!("u{}", i));
                pick(&b, &s, 8, all_up)
            })
            .collect();
        assert!(used.len() > 1, "{:?}", used);
        // A connection of no user is keyed as without hash_key.
        let plain = Balancer::new(StrategyKind::ConsistentHashing, STICKY_TTL);
        for i in 0..50 {
            let s = sess("10.0.0.1", &format!("site{}.com", i));
            assert_eq!(pick(&b, &s, 8, all_up), pick(&plain, &s, 8, all_up));
        }
    }

    #[test]
    fn hash_key_user_keeps_a_sticky_session_per_user() {
        let b =
            Balancer::new(StrategyKind::StickySessions, STICKY_TTL).keyed_by(Some(HashKey::User));
        let first = pick(
            &b,
            &of(sess("10.0.0.1", "a.example.com"), "alice"),
            16,
            all_up,
        );
        for (source, host) in [("10.0.0.2", "b.example.org"), ("10.0.0.3", "192.0.2.1")] {
            let s = of(sess(source, host), "alice");
            assert_eq!(pick(&b, &s, 16, all_up), first, "{}", host);
        }
        // Users of one source and destination are sessions of their own:
        // out of 16, some of a few users' differ.
        assert!(
            (0..8).any(|i| {
                let s = of(sess("10.0.0.1", "a.example.com"), &format!("u{}", i));
                pick(&b, &s, 16, all_up) != first
            }),
            "every user went to the first's member"
        );
        // A connection of no user: its pair is the session, as without
        // hash_key, which another host of the site is too.
        let pair = pick(&b, &sess("10.0.0.9", "example.com"), 16, all_up);
        for _ in 0..5 {
            let s = sess("10.0.0.9", "www.example.com");
            assert_eq!(pick(&b, &s, 16, all_up), pair);
        }
    }

    #[test]
    fn hash_key_is_user_and_not_with_round_robin() {
        use serde_json::json;
        let check = |options: serde_json::Value| {
            let mut lb = json!({ "type": "load-balance", "tag": "lb", "outbounds": ["direct"] });
            lb.as_object_mut()
                .unwrap()
                .extend(options.as_object().unwrap().clone());
            let config = json!({ "outbounds": [{ "type": "direct", "tag": "direct" }, lb] });
            crate::config::from_string(&config.to_string())
                .and_then(|c| crate::check_config(&c, &Default::default()))
                .map_err(|e| format!("{:#}", e))
        };
        assert_eq!(check(json!({ "hash_key": "user" })), Ok(()));
        assert_eq!(
            check(json!({ "hash_key": "user", "strategy": "sticky-sessions" })),
            Ok(())
        );
        assert_eq!(
            check(json!({ "hash_key": "user", "strategy": "round-robin" })),
            Err("[lb] outbound: hash_key: round-robin keys on nothing".into())
        );
        let err = check(json!({ "hash_key": "in-user" })).unwrap_err();
        assert!(
            err.contains("hash_key") && err.contains("unknown variant"),
            "{}",
            err
        );
    }

    #[test]
    fn a_sticky_session_leaves_a_member_that_is_down() {
        let b = Balancer::new(StrategyKind::StickySessions, STICKY_TTL);
        let s = sess("10.0.0.1", "example.com");
        let first = pick(&b, &s, 3, all_up);
        let next = pick(&b, &s, 3, |i| i != first);
        assert_ne!(next, first);
        // And sticks to the new one, even once the old one is back.
        assert_eq!(pick(&b, &s, 3, all_up), next);
    }

    /// A group over `members`, whose rounds are fed by hand.
    fn group(kind: StrategyKind, members: Vec<Member>) -> Group {
        let members = Members::of(members);
        Group {
            balancer: Balancer::new(kind, STICKY_TTL),
            checker: health::tests::checker(
                members.clone(),
                Default::default(),
                Box::new(|_, _, _| ()),
            ),
            members,
            dns_client: health::tests::dns(),
        }
    }

    /// The members the connections to sixty sites through `group` go to,
    /// of `network`, sorted; sites no connection went to before, so that
    /// no session sticks.
    fn taken(group: &Group, network: Network) -> Vec<String> {
        static SITES: AtomicUsize = AtomicUsize::new(0);
        let snapshot = group.members.load();
        let mut taken: Vec<String> = (0..60)
            .map(|_| {
                let site = SITES.fetch_add(1, Ordering::Relaxed);
                let s = sess("10.0.0.1", &format!("site{}.test", site));
                let member = group.pick(&s, &snapshot, network).unwrap();
                member.key.name.to_string()
            })
            .collect();
        taken.sort();
        taken.dedup();
        taken
    }

    const TCP: Network = Network::Tcp;
    const UDP: Network = Network::Udp;

    #[tokio::test]
    async fn connections_go_to_the_members_that_carry_their_network() {
        use crate::protocol::group::members::tests::one;
        let ms = Some(Duration::from_millis(10));
        for kind in [
            StrategyKind::ConsistentHashing,
            StrategyKind::RoundRobin,
            StrategyKind::StickySessions,
        ] {
            let members = vec![
                one("t", true),
                one("u", false),
                member(None, "b"),
                member(None, "c"),
            ];
            let group = group(kind, members);
            assert_eq!(taken(&group, TCP), ["b", "c", "t"], "{:?}", kind);
            assert_eq!(taken(&group, UDP), ["b", "c", "u"], "{:?}", kind);
            // [u] is not tested, and stays up, round after round.
            for _ in 0..3 {
                group.checker.round(&[ms, None, ms, None]);
                assert_eq!(taken(&group, TCP), ["b", "t"], "{:?}", kind);
                assert_eq!(taken(&group, UDP), ["b", "u"], "{:?}", kind);
            }
            group.checker.round(&[ms, None, None, None]);
            assert_eq!(taken(&group, TCP), ["t"], "{:?}", kind);
            assert_eq!(taken(&group, UDP), ["u"], "{:?}", kind);
            // None that carries it is up: one that does is tried.
            group.checker.round(&[None, None, None, None]);
            assert_eq!(taken(&group, TCP), ["b", "c", "t"], "{:?}", kind);
            assert_eq!(taken(&group, UDP), ["u"], "{:?}", kind);
        }
    }

    /// The TCP and the UDP of one pair go to members of their own, which
    /// the other does not take away: here UDP has [u] to go to, which TCP
    /// does not.
    #[tokio::test]
    async fn tcp_and_udp_of_a_pair_keep_their_own_sticky_members() {
        use crate::protocol::group::members::tests::one;
        let members = vec![member(None, "a"), one("u", false), member(None, "b")];
        let group = group(StrategyKind::StickySessions, members);
        let snapshot = group.members.load();
        let mut udp_took = Vec::new();
        for pair in 0..40 {
            let s = sess("10.0.0.1", &format!("pair{}.test", pair));
            let pick = |network| {
                let member = group.pick(&s, &snapshot, network).unwrap();
                member.key.name.to_string()
            };
            // UDP first: its member, when [u], is one TCP cannot take.
            let udp = pick(UDP);
            let tcp = pick(TCP);
            assert_ne!(tcp, "u");
            for _ in 0..5 {
                assert_eq!(pick(TCP), tcp, "{}", pair);
                assert_eq!(pick(UDP), udp, "{}", pair);
            }
            udp_took.push(udp);
        }
        assert!(udp_took.iter().any(|m| m == "u"), "{:?}", udp_took);
    }

    #[test]
    fn sticky_sessions_are_bounded() {
        let b = Balancer::new(StrategyKind::StickySessions, STICKY_TTL);
        for i in 0..(STICKY_CAPACITY + 100) {
            pick(&b, &sess("10.0.0.1", &format!("site{}.com", i)), 2, all_up);
        }
        let Strategy::StickySessions(cache) = &b.strategy else {
            unreachable!()
        };
        assert!(cache.lock().unwrap().len() <= STICKY_CAPACITY);
    }
}
