//! `load-balance`: spreads connections over its members, as Mihomo's
//! load-balance group does, skipping those that failed their last URL
//! test.
//!
//! - `consistent-hashing`: a destination's registrable domain, or its IP,
//!   always goes to the same member, so a site sees one address.
//! - `round-robin`: each connection goes to the next member.
//! - `sticky-sessions`: a source and destination pair goes to the member
//!   it went to last, picked at random at first, until the pair is left
//!   unused for a while.

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

use super::health::{self, Checker};
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::app::healthcheck::HttpProbe;
use crate::app::SyncDnsClient;
use crate::net::{connect_datagram_outbound, connect_stream_outbound};
use crate::session::{Session, SocksAddr};

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadBalanceOutboundOptions {
    outbounds: Vec<String>,
    #[serde(default)]
    strategy: StrategyKind,
    /// What is requested through each member to test it.
    #[serde(default = "default_url")]
    url: String,
    #[serde(default, with = "crate::config::model::duration")]
    interval: Option<Duration>,
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
/// How many hashes consistent hashing tries before it takes any member
/// that is up.
const MAX_REHASH: u64 = 5;

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: LoadBalanceOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.outbounds)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: LoadBalanceOutboundOptions = ctx.options()?;
    let actors = ctx.members(&options.outbounds)?;
    let interval = options.interval.unwrap_or(health::DEFAULT_INTERVAL);
    if interval.is_zero() {
        return Err(anyhow!(
            "[{}] outbound: interval: must not be zero",
            ctx.tag
        ));
    }
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone())
        .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))?;
    let (checker, abort_handle) = Checker::new(
        ctx.tag,
        actors.clone(),
        probe,
        ctx.dns_client.clone(),
        interval,
        health::DEFAULT_TIMEOUT,
        options.lazy.then_some(interval),
        Box::new(|_| ()),
    );
    ctx.abort_handles.push(abort_handle);
    let group = Arc::new(Group {
        balancer: Balancer::new(options.strategy, actors.len(), STICKY_TTL),
        actors,
        checker,
        dns_client: ctx.dns_client.clone(),
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(group.clone())
        .datagram_handler(group)
        .build())
}

/// Picks a member per connection.
struct Balancer {
    members: usize,
    strategy: Strategy,
}

enum Strategy {
    ConsistentHashing,
    RoundRobin(AtomicUsize),
    StickySessions(Mutex<LruCache<u64, usize>>),
}

impl Balancer {
    fn new(kind: StrategyKind, members: usize, sticky_ttl: Duration) -> Self {
        let strategy = match kind {
            StrategyKind::ConsistentHashing => Strategy::ConsistentHashing,
            StrategyKind::RoundRobin => Strategy::RoundRobin(AtomicUsize::new(0)),
            StrategyKind::StickySessions => Strategy::StickySessions(Mutex::new(
                LruCache::with_expiry_duration_and_capacity(sticky_ttl, STICKY_CAPACITY),
            )),
        };
        Self { members, strategy }
    }

    /// The member for `sess`, among those `is_up`; when none is, among
    /// all, since a test can be wrong and trying beats refusing.
    fn pick(&self, sess: &Session, is_up: impl Fn(usize) -> bool) -> usize {
        let n = self.members;
        let any_up = (0..n).any(&is_up);
        let is_up = |i: usize| !any_up || is_up(i);
        match &self.strategy {
            Strategy::ConsistentHashing => {
                let key = fnv1a(destination_key(&sess.destination).as_bytes());
                (0..MAX_REHASH)
                    .map(|i| jump_hash(key.wrapping_add(i), n))
                    .find(|&i| is_up(i))
                    .or_else(|| (0..n).find(|&i| is_up(i)))
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
                let key = fnv1a(
                    format!(
                        "{}|{}",
                        sess.source.ip(),
                        destination_key(&sess.destination)
                    )
                    .as_bytes(),
                );
                let Ok(mut cache) = cache.lock() else {
                    return 0;
                };
                if let Some(&i) = cache.get(&key) {
                    if i < n && is_up(i) {
                        return i;
                    }
                }
                let up: Vec<usize> = (0..n).filter(|&i| is_up(i)).collect();
                let i = up[rand::thread_rng().gen_range(0..up.len())];
                cache.insert(key, i);
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

/// The registrable domain of `domain`, approximately: without the public
/// suffix list, the last two labels, or three under a two-letter country
/// code with a common second level (`example.co.uk`).
fn registrable_domain(domain: &str) -> String {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return domain;
    }
    const SECOND_LEVELS: &[&str] = &["co", "com", "net", "org", "gov", "edu", "ac", "ne", "or"];
    let keep = if labels[n - 1].len() == 2 && SECOND_LEVELS.contains(&labels[n - 2]) {
        3
    } else {
        2
    };
    labels[n - keep..].join(".")
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}

/// Jump consistent hashing (Lamping and Veach): a key keeps its bucket
/// as long as the number of buckets does.
fn jump_hash(mut key: u64, buckets: usize) -> usize {
    let (mut b, mut j) = (-1i64, 0i64);
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * ((1u64 << 31) as f64 / ((key >> 33) + 1) as f64)) as i64;
    }
    b.max(0) as usize
}

struct Group {
    actors: Vec<AnyOutboundHandler>,
    balancer: Balancer,
    checker: Arc<Checker>,
    dns_client: SyncDnsClient,
}

impl Group {
    fn pick(&self, sess: &Session) -> &AnyOutboundHandler {
        self.checker.used();
        &self.actors[self.balancer.pick(sess, |i| self.checker.is_up(i))]
    }

    /// A failed connection is reason to test again rather than wait out
    /// the interval.
    fn failed<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
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

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let a = self.pick(sess);
        debug!(
            "load-balance handles [{}] to [{}]",
            sess.destination,
            a.tag()
        );
        self.failed(
            async {
                let stream = connect_stream_outbound(sess, self.dns_client.clone(), a).await?;
                a.stream()?.handle(sess, None, stream).await
            }
            .await,
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
        let a = self.pick(sess);
        debug!(
            "load-balance handles [{}] to [{}]",
            sess.destination,
            a.tag()
        );
        self.failed(
            async {
                let transport = connect_datagram_outbound(sess, self.dns_client.clone(), a).await?;
                a.datagram()?.handle(sess, transport).await
            }
            .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("www.example.com"), "example.com");
        assert_eq!(registrable_domain("a.b.example.com."), "example.com");
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("news.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }

    #[test]
    fn consistent_hashing_keeps_a_site_on_one_member() {
        let b = Balancer::new(StrategyKind::ConsistentHashing, 5, STICKY_TTL);
        let first = b.pick(&sess("10.0.0.1", "www.example.com"), all_up);
        for (source, host) in [
            ("10.0.0.2", "api.example.com"),
            ("10.0.0.3", "example.com"),
            ("10.0.0.1", "cdn.static.example.com"),
        ] {
            assert_eq!(b.pick(&sess(source, host), all_up), first, "{}", host);
        }
        // And a new balancer, as after a restart, agrees.
        let again = Balancer::new(StrategyKind::ConsistentHashing, 5, STICKY_TTL);
        assert_eq!(again.pick(&sess("10.0.0.9", "example.com"), all_up), first);
    }

    #[test]
    fn consistent_hashing_spreads_sites() {
        let b = Balancer::new(StrategyKind::ConsistentHashing, 4, STICKY_TTL);
        let mut used = [0; 4];
        for i in 0..200 {
            used[b.pick(&sess("10.0.0.1", &format!("site{}.com", i)), all_up)] += 1;
        }
        assert!(used.iter().all(|&n| n > 20), "{:?}", used);
    }

    #[test]
    fn consistent_hashing_moves_only_the_sites_of_a_member_that_is_down() {
        let b = Balancer::new(StrategyKind::ConsistentHashing, 4, STICKY_TTL);
        for i in 0..100 {
            let s = sess("10.0.0.1", &format!("site{}.com", i));
            let up = b.pick(&s, all_up);
            let down = if up == 0 { 1 } else { 0 };
            let picked = b.pick(&s, |i| i != down);
            assert_eq!(picked, up, "site{} moved though its member is up", i);
            let moved = b.pick(&s, |i| i != up);
            assert_ne!(moved, up);
        }
    }

    #[test]
    fn round_robin_takes_each_member_in_turn_and_skips_one_down() {
        let b = Balancer::new(StrategyKind::RoundRobin, 3, STICKY_TTL);
        let s = sess("10.0.0.1", "example.com");
        let picks: Vec<usize> = (0..6).map(|_| b.pick(&s, all_up)).collect();
        assert_eq!(picks, [0, 1, 2, 0, 1, 2]);
        let picks: Vec<usize> = (0..4).map(|_| b.pick(&s, |i| i != 1)).collect();
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
            let b = Balancer::new(kind, 3, STICKY_TTL);
            assert!(b.pick(&sess("10.0.0.1", "example.com"), |_| false) < 3);
        }
    }

    #[test]
    fn a_sticky_session_keeps_its_member_until_it_expires() {
        let ttl = Duration::from_millis(100);
        let b = Balancer::new(StrategyKind::StickySessions, 16, ttl);
        let s = sess("10.0.0.1", "www.example.com");
        let first = b.pick(&s, all_up);
        for _ in 0..20 {
            assert_eq!(b.pick(&s, all_up), first);
        }
        // Another host of the same site is the same session.
        assert_eq!(b.pick(&sess("10.0.0.1", "api.example.com"), all_up), first);

        // Once expired, a member is picked again, at random: out of 16,
        // some of a few tries differ.
        let mut differed = false;
        for _ in 0..5 {
            std::thread::sleep(ttl + Duration::from_millis(50));
            if b.pick(&s, all_up) != first {
                differed = true;
                break;
            }
        }
        assert!(differed, "the session never expired");
    }

    #[test]
    fn a_sticky_session_leaves_a_member_that_is_down() {
        let b = Balancer::new(StrategyKind::StickySessions, 3, STICKY_TTL);
        let s = sess("10.0.0.1", "example.com");
        let first = b.pick(&s, all_up);
        let next = b.pick(&s, |i| i != first);
        assert_ne!(next, first);
        // And sticks to the new one, even once the old one is back.
        assert_eq!(b.pick(&s, all_up), next);
    }

    #[test]
    fn sticky_sessions_are_bounded() {
        let b = Balancer::new(StrategyKind::StickySessions, 2, STICKY_TTL);
        for i in 0..(STICKY_CAPACITY + 100) {
            b.pick(&sess("10.0.0.1", &format!("site{}.com", i)), all_up);
        }
        let Strategy::StickySessions(cache) = &b.strategy else {
            unreachable!()
        };
        assert!(cache.lock().unwrap().len() <= STICKY_CAPACITY);
    }
}
