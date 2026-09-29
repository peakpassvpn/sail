//! Fake IPs, as sing-box's `fakeip` server hands them out: an address of
//! its ranges for each domain asked for, taken in turn, and the domain
//! back for an address, so that a connection to one goes to the domain.
//!
//! As Mihomo's: the first four addresses of a range, its network's, the
//! gateway a TUN device takes and the two after, are never handed out,
//! nor taken for fake ones, so that a device and its DNS address may sit
//! at the start of the range, as Mihomo puts them. sing-box starts handing
//! out at the third.
//!
//! With the cache file's `store_fakeip`, what is handed out is kept there as
//! it is, and a start with the same ranges goes on from it: what apps and
//! systems cached of the addresses before the restart still goes to its
//! domain.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use cidr::IpCidr;
use tracing::warn;

use crate::runtime::cache_file::{CacheFile, CacheFileSlot, FakeIpOp, FakeIps};

/// The addresses at the start of a range that are not fake.
const RESERVED: u128 = 4;

/// The most domains each family keeps: an IPv6 range would otherwise grow
/// without end, never coming round to its first address again.
const CAPACITY: usize = 65536;

/// The addresses of one family, and those handed out.
struct Pool {
    /// The range's first and last addresses, as numbers.
    first: u128,
    last: u128,
    /// The address handed out last.
    current: u128,
    domains: HashMap<String, u128>,
    /// Handed out, oldest first, for when the pool is full. An entry
    /// counts only while its domain still has its address.
    order: VecDeque<(u128, String)>,
    v6: bool,
}

impl Pool {
    fn new(cidr: IpCidr) -> Self {
        let (first, last, v6) = match (cidr.first_address(), cidr.last_address()) {
            (IpAddr::V4(f), IpAddr::V4(l)) => (u32::from(f) as u128, u32::from(l) as u128, false),
            (IpAddr::V6(f), IpAddr::V6(l)) => (u128::from(f), u128::from(l), true),
            _ => unreachable!("a CIDR is of one family"),
        };
        Pool {
            first,
            last,
            // The first handed out is the one after those reserved.
            current: first + RESERVED - 1,
            domains: HashMap::new(),
            order: VecDeque::new(),
            v6,
        }
    }

    /// Whether `n` is of the addresses it may hand out.
    fn contains(&self, n: u128) -> bool {
        (self.first + RESERVED..=self.last).contains(&n)
    }

    fn addr(&self, n: u128) -> IpAddr {
        if self.v6 {
            IpAddr::V6(Ipv6Addr::from(n))
        } else {
            IpAddr::V4(Ipv4Addr::from(n as u32))
        }
    }
}

pub(crate) struct FakeIpStore {
    /// `inet4_range` and `inet6_range`, as configured: a reload with the
    /// same keeps the store, and the addresses handed out.
    pub ranges: (Option<String>, Option<String>),
    /// The instance's cache file, which they are kept in if it stores fake
    /// IPs: the one in place when each is handed out, as a reload may
    /// change it, or a failed one put the old back.
    cache: CacheFileSlot,
    inner: Mutex<Inner>,
}

struct Inner {
    v4: Option<Pool>,
    v6: Option<Pool>,
    by_address: HashMap<IpAddr, String>,
    /// How many were handed out: the order of the next.
    handed_out: u64,
    /// The cache file, and its `cache_id`, the addresses were last written
    /// to; another is first given them all.
    written_to: Option<(u64, String)>,
}

impl Inner {
    fn pool(&mut self, v6: bool) -> Option<&mut Pool> {
        if v6 {
            self.v6.as_mut()
        } else {
            self.v4.as_mut()
        }
    }

    /// Takes back what a cache file kept, oldest first: what is not of the
    /// ranges now is left out.
    fn restore(&mut self, kept: FakeIps) {
        for (order, address, domain) in kept.entries {
            let v6 = address.is_ipv6();
            let n = number(address);
            let pool = if v6 {
                self.v6.as_mut()
            } else {
                self.v4.as_mut()
            };
            let Some(pool) = pool.filter(|p| p.contains(n)) else {
                continue;
            };
            if let Some(old) = pool.domains.insert(domain.clone(), n) {
                self.by_address.remove(&pool.addr(old));
            }
            pool.order.push_back((n, domain.clone()));
            self.by_address.insert(address, domain);
            self.handed_out = self.handed_out.max(order + 1);
        }
        for (v6, cursor) in [(false, kept.cursor4), (true, kept.cursor6)] {
            if let (Some(pool), Some(cursor)) = (self.pool(v6), cursor) {
                if (pool.first + RESERVED - 1..pool.last).contains(&cursor) {
                    pool.current = cursor;
                }
            }
        }
    }

    /// All it holds, for a cache file that holds none of it: in the order
    /// handed out, each family's cursor last.
    fn snapshot(&mut self, ranges: String) -> Vec<FakeIpOp> {
        let mut ops = vec![FakeIpOp::Clear { ranges }];
        let mut order = 0;
        for pool in [self.v4.as_ref(), self.v6.as_ref()].into_iter().flatten() {
            for (n, domain) in &pool.order {
                if pool.domains.get(domain) == Some(n) {
                    ops.push(FakeIpOp::Put {
                        address: pool.addr(*n),
                        domain: domain.clone(),
                        order,
                    });
                    order += 1;
                }
            }
            ops.push(FakeIpOp::Cursor {
                v6: pool.v6,
                current: pool.current,
            });
        }
        self.handed_out = self.handed_out.max(order);
        ops
    }
}

fn number(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// What an address is to the store.
#[derive(Debug, PartialEq, Eq)]
pub enum FakeIp {
    /// Not of its ranges.
    NotFake,
    /// Handed out for this domain.
    Domain(String),
    /// Of its ranges, but for no domain it knows: handed out before a
    /// restart, or forgotten since.
    Unknown,
}

impl FakeIpStore {
    pub(crate) fn new(
        inet4_range: Option<&str>,
        inet6_range: Option<&str>,
        cache: CacheFileSlot,
    ) -> Result<Self> {
        let pool = |range: Option<&str>, v6: bool, field: &str| -> Result<Option<Pool>> {
            let Some(range) = range else { return Ok(None) };
            let cidr: IpCidr = range
                .parse()
                .map_err(|e| anyhow!("{}: invalid range \"{}\": {}", field, range, e))?;
            if cidr.is_ipv6() != v6 {
                return Err(anyhow!("{}: \"{}\" is of the other family", field, range));
            }
            // Those reserved and the last are not handed out: at least one
            // more is needed.
            let size_bits = if v6 { 128 } else { 32 } - cidr.network_length();
            if size_bits < 3 {
                return Err(anyhow!("{}: \"{}\" is too small", field, range));
            }
            Ok(Some(Pool::new(cidr)))
        };
        let v4 = pool(inet4_range, false, "inet4_range")?;
        let v6 = pool(inet6_range, true, "inet6_range")?;
        if v4.is_none() && v6.is_none() {
            return Err(anyhow!("set inet4_range, inet6_range, or both"));
        }
        let store = Self {
            ranges: (inet4_range.map(String::from), inet6_range.map(String::from)),
            cache,
            inner: Mutex::new(Inner {
                v4,
                v6,
                by_address: HashMap::new(),
                handed_out: 0,
                written_to: None,
            }),
        };
        store.restore();
        Ok(store)
    }

    /// The ranges, as the cache file keeps them.
    fn ranges_key(&self) -> String {
        let (v4, v6) = &self.ranges;
        format!(
            "{} {}",
            v4.as_deref().unwrap_or("-"),
            v6.as_deref().unwrap_or("-")
        )
    }

    /// The cache file fake IPs go to, if one stores them.
    fn cache(&self) -> Option<Arc<CacheFile>> {
        self.cache.get().filter(|cache| cache.store_fakeip)
    }

    /// Goes on from what the cache file kept, if it kept them for these
    /// ranges.
    fn restore(&self) {
        let Some(cache) = self.cache() else { return };
        let mut inner = self.inner();
        match cache.load_fake_ips(&self.ranges_key()) {
            Ok(kept) => {
                if let Some(kept) = kept {
                    inner.restore(kept);
                }
                inner.written_to = Some(cache.fake_ip_binding());
            }
            Err(e) => warn!("cache_file: fake IPs not restored: {}", e),
        }
    }

    /// Writes `ops` to the cache file, if one stores fake IPs: after all it
    /// holds, to one it was not written to.
    fn persist(&self, inner: &mut Inner, ops: Vec<FakeIpOp>) {
        let Some(cache) = self.cache() else {
            inner.written_to = None;
            return;
        };
        let binding = cache.fake_ip_binding();
        if inner.written_to.as_ref() == Some(&binding) {
            if !ops.is_empty() {
                cache.write_fake_ips(ops);
            }
            return;
        }
        // All of it; `ops` are in it already.
        cache.write_fake_ips(inner.snapshot(self.ranges_key()));
        inner.written_to = Some(binding);
    }

    /// Writes all it holds to the cache file if it is not the one it was
    /// written to, as after a reload that changed it.
    pub(crate) fn sync(&self) {
        let mut inner = self.inner();
        self.persist(&mut inner, Vec::new());
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether it hands out addresses of this family.
    pub(crate) fn serves(&self, v6: bool) -> bool {
        let inner = self.inner();
        if v6 {
            inner.v6.is_some()
        } else {
            inner.v4.is_some()
        }
    }

    /// The address of `domain`, handed out now if it has none.
    pub(crate) fn create(&self, domain: &str, v6: bool) -> Result<IpAddr> {
        let mut inner = self.inner();
        let Inner {
            v4,
            v6: pool6,
            by_address,
            handed_out,
            ..
        } = &mut *inner;
        let pool = if v6 { pool6.as_mut() } else { v4.as_mut() }
            .ok_or_else(|| anyhow!("no {} range", if v6 { "inet6" } else { "inet4" }))?;
        if let Some(&n) = pool.domains.get(domain) {
            return Ok(pool.addr(n));
        }
        let mut next = pool.current + 1;
        if next >= pool.last {
            next = pool.first + RESERVED;
        }
        pool.current = next;
        // Taken again: its old domain goes, and its entry in `order` when
        // popped.
        let addr = pool.addr(next);
        if let Some(old) = by_address.remove(&addr) {
            pool.domains.remove(&old);
        }
        let mut ops = Vec::new();
        while pool.domains.len() >= CAPACITY || pool.order.len() >= 2 * CAPACITY {
            let Some((oldest, old)) = pool.order.pop_front() else {
                break;
            };
            if pool.domains.get(&old) == Some(&oldest) {
                pool.domains.remove(&old);
                by_address.remove(&pool.addr(oldest));
                ops.push(FakeIpOp::Remove(pool.addr(oldest)));
            }
        }
        pool.domains.insert(domain.to_string(), next);
        pool.order.push_back((next, domain.to_string()));
        by_address.insert(addr, domain.to_string());
        ops.push(FakeIpOp::Put {
            address: addr,
            domain: domain.to_string(),
            order: *handed_out,
        });
        ops.push(FakeIpOp::Cursor { v6, current: next });
        *handed_out += 1;
        self.persist(&mut inner, ops);
        Ok(addr)
    }

    /// What `ip` is to the store.
    pub(crate) fn lookup(&self, ip: IpAddr) -> FakeIp {
        let ip = ip.to_canonical();
        let inner = self.inner();
        let n = number(ip);
        let pool = if ip.is_ipv6() { &inner.v6 } else { &inner.v4 };
        if !pool.as_ref().is_some_and(|p| p.contains(n)) {
            return FakeIp::NotFake;
        }
        match inner.by_address.get(&ip) {
            Some(domain) => FakeIp::Domain(domain.clone()),
            None => FakeIp::Unknown,
        }
    }

    /// The address handed out for `domain`, if one was.
    pub(crate) fn address_of(&self, domain: &str, v6: bool) -> Option<IpAddr> {
        let inner = self.inner();
        let pool = if v6 { &inner.v6 } else { &inner.v4 };
        pool.as_ref()
            .and_then(|p| p.domains.get(domain).map(|&n| p.addr(n)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_handed_out_in_turn_and_come_round() {
        let store = FakeIpStore::new(
            Some("198.18.0.0/29"),
            Some("fc00::/125"),
            Default::default(),
        )
        .unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // 198.18.0.0/29: .0 to .3 are not handed out, nor .7, the last.
        assert_eq!(store.create("a.example", false).unwrap(), ip("198.18.0.4"));
        assert_eq!(store.create("a.example", false).unwrap(), ip("198.18.0.4"));
        assert_eq!(store.create("b.example", false).unwrap(), ip("198.18.0.5"));
        assert_eq!(store.create("c.example", false).unwrap(), ip("198.18.0.6"));
        assert_eq!(store.create("d.example", false).unwrap(), ip("198.18.0.4"));
        // d took a's address: a is forgotten.
        assert_eq!(
            store.lookup(ip("198.18.0.4")),
            FakeIp::Domain("d.example".into())
        );
        assert_eq!(store.address_of("a.example", false), None);
        assert_eq!(store.create("e.example", true).unwrap(), ip("fc00::4"));
        assert_eq!(store.lookup(ip("fc00::5")), FakeIp::Unknown);
        // Those reserved, a device's and its DNS address, are not fake.
        assert_eq!(store.lookup(ip("198.18.0.1")), FakeIp::NotFake);
        assert_eq!(store.lookup(ip("198.18.0.2")), FakeIp::NotFake);
        assert_eq!(store.lookup(ip("fc00::1")), FakeIp::NotFake);
        assert_eq!(store.lookup(ip("10.0.0.1")), FakeIp::NotFake);
        assert_eq!(
            store.lookup(ip("::ffff:198.18.0.5")),
            FakeIp::Domain("b.example".into())
        );
    }

    #[test]
    fn ranges_are_checked() {
        for (v4, v6, message) in [
            (None, None, "set inet4_range"),
            (Some("fc00::/18"), None, "the other family"),
            (Some("198.18.0.0/30"), None, "too small"),
            (Some("198.18.0.0/40"), None, "invalid range"),
        ] {
            let err = FakeIpStore::new(v4, v6, Default::default())
                .err()
                .unwrap()
                .to_string();
            assert!(err.contains(message), "{:?} {:?}: {}", v4, v6, err);
        }
    }

    #[test]
    fn an_ipv6_range_keeps_at_most_its_capacity() {
        let store = FakeIpStore::new(None, Some("fc00::/18"), Default::default()).unwrap();
        for i in 0..CAPACITY + 10 {
            store.create(&format!("d{}.example", i), true).unwrap();
        }
        assert_eq!(store.address_of("d0.example", true), None);
        assert!(store
            .address_of(&format!("d{}.example", CAPACITY + 9), true)
            .is_some());
        assert!(store.inner().by_address.len() <= CAPACITY);
    }

    mod kept {
        use super::*;
        use crate::config::model::CacheFileOptions;
        use crate::runtime::cache_file::tests::env;
        use crate::runtime::RuntimeEnv;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        fn options(store_fakeip: bool, cache_id: Option<&str>) -> CacheFileOptions {
            CacheFileOptions {
                enabled: true,
                store_fakeip,
                cache_id: cache_id.map(String::from),
                ..Default::default()
            }
        }

        /// An instance's start, or reload, with `options`.
        fn start(env: &RuntimeEnv, options: &CacheFileOptions) {
            env.cache_file.replace(Some(options), env).unwrap().keep();
        }

        /// The instance's end: the file closes once what is queued is
        /// written.
        fn stop(env: &RuntimeEnv, store: FakeIpStore) {
            drop(store);
            env.cache_file.replace(None, env).unwrap().keep();
        }

        fn store(env: &RuntimeEnv, v4: &str) -> FakeIpStore {
            FakeIpStore::new(Some(v4), Some("fc00::/125"), env.cache_file.clone()).unwrap()
        }

        fn dir(name: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "sail-fakeip-kept-{}-{}",
                name,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            dir
        }

        #[test]
        fn a_restart_goes_on_from_what_was_handed_out() {
            let dir = dir("restart");
            let env = env(&dir);
            start(&env, &options(true, None));
            let first = store(&env, "198.18.0.0/29");
            assert_eq!(first.create("a.example", false).unwrap(), ip("198.18.0.4"));
            assert_eq!(first.create("b.example", false).unwrap(), ip("198.18.0.5"));
            assert_eq!(first.create("c.example", false).unwrap(), ip("198.18.0.6"));
            // d takes a's address: a is gone for good.
            assert_eq!(first.create("d.example", false).unwrap(), ip("198.18.0.4"));
            assert_eq!(first.create("e.example", true).unwrap(), ip("fc00::4"));
            stop(&env, first);

            start(&env, &options(true, None));
            let again = store(&env, "198.18.0.0/29");
            assert_eq!(
                again.lookup(ip("198.18.0.4")),
                FakeIp::Domain("d.example".into())
            );
            assert_eq!(
                again.lookup(ip("198.18.0.6")),
                FakeIp::Domain("c.example".into())
            );
            assert_eq!(
                again.lookup(ip("fc00::4")),
                FakeIp::Domain("e.example".into())
            );
            assert_eq!(again.address_of("a.example", false), None);
            // The next is after the last handed out, not the first again.
            assert_eq!(again.create("f.example", false).unwrap(), ip("198.18.0.5"));
            assert_eq!(again.address_of("b.example", false), None);
            assert_eq!(again.create("c.example", false).unwrap(), ip("198.18.0.6"));
            stop(&env, again);

            // Other ranges: nothing kept.
            start(&env, &options(true, None));
            let other = store(&env, "198.19.0.0/29");
            assert_eq!(other.lookup(ip("198.19.0.4")), FakeIp::Unknown);
            stop(&env, other);
            start(&env, &options(true, None));
            let back = store(&env, "198.18.0.0/29");
            assert_eq!(back.lookup(ip("198.18.0.4")), FakeIp::Unknown);
            stop(&env, back);
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn without_store_fakeip_nothing_is_kept() {
            let dir = dir("off");
            let env = env(&dir);
            start(&env, &options(false, None));
            let first = store(&env, "198.18.0.0/29");
            first.create("a.example", false).unwrap();
            stop(&env, first);
            start(&env, &options(true, None));
            let again = store(&env, "198.18.0.0/29");
            assert_eq!(again.lookup(ip("198.18.0.4")), FakeIp::Unknown);
            stop(&env, again);
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn a_reload_to_another_cache_id_writes_all_there() {
            let dir = dir("reload");
            let env = env(&dir);
            start(&env, &options(true, None));
            let kept = store(&env, "198.18.0.0/29");
            kept.create("a.example", false).unwrap();
            kept.create("b.example", false).unwrap();
            // A reload with the same ranges keeps the store.
            start(&env, &options(true, Some("other")));
            kept.sync();
            stop(&env, kept);

            start(&env, &options(true, Some("other")));
            let again = store(&env, "198.18.0.0/29");
            assert_eq!(
                again.lookup(ip("198.18.0.4")),
                FakeIp::Domain("a.example".into())
            );
            assert_eq!(
                again.lookup(ip("198.18.0.5")),
                FakeIp::Domain("b.example".into())
            );
            assert_eq!(again.create("c.example", false).unwrap(), ip("198.18.0.6"));
            stop(&env, again);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
