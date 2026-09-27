//! Fake IPs, as sing-box's `fakeip` server hands them out: an address of
//! its ranges for each domain asked for, taken in turn, and the domain
//! back for an address, so that a connection to one goes to the domain.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use cidr::IpCidr;

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
            // As sing-box: the network's address and the next are not
            // handed out, and the first handed out is the one after.
            current: first + 1,
            domains: HashMap::new(),
            order: VecDeque::new(),
            v6,
        }
    }

    fn contains(&self, n: u128) -> bool {
        (self.first..=self.last).contains(&n)
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
    inner: Mutex<Inner>,
}

struct Inner {
    v4: Option<Pool>,
    v6: Option<Pool>,
    by_address: HashMap<IpAddr, String>,
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
    pub(crate) fn new(inet4_range: Option<&str>, inet6_range: Option<&str>) -> Result<Self> {
        let pool = |range: Option<&str>, v6: bool, field: &str| -> Result<Option<Pool>> {
            let Some(range) = range else { return Ok(None) };
            let cidr: IpCidr = range
                .parse()
                .map_err(|e| anyhow!("{}: invalid range \"{}\": {}", field, range, e))?;
            if cidr.is_ipv6() != v6 {
                return Err(anyhow!("{}: \"{}\" is of the other family", field, range));
            }
            // The network's address, the next, and the last are not handed
            // out: at least one more is needed.
            let size_bits = if v6 { 128 } else { 32 } - cidr.network_length();
            if size_bits < 2 {
                return Err(anyhow!("{}: \"{}\" is too small", field, range));
            }
            Ok(Some(Pool::new(cidr)))
        };
        let v4 = pool(inet4_range, false, "inet4_range")?;
        let v6 = pool(inet6_range, true, "inet6_range")?;
        if v4.is_none() && v6.is_none() {
            return Err(anyhow!("set inet4_range, inet6_range, or both"));
        }
        Ok(Self {
            ranges: (inet4_range.map(String::from), inet6_range.map(String::from)),
            inner: Mutex::new(Inner {
                v4,
                v6,
                by_address: HashMap::new(),
            }),
        })
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
        } = &mut *inner;
        let pool = if v6 { pool6.as_mut() } else { v4.as_mut() }
            .ok_or_else(|| anyhow!("no {} range", if v6 { "inet6" } else { "inet4" }))?;
        if let Some(&n) = pool.domains.get(domain) {
            return Ok(pool.addr(n));
        }
        let mut next = pool.current + 1;
        if next >= pool.last {
            next = pool.first + 2;
        }
        pool.current = next;
        // Taken again: its old domain goes, and its entry in `order` when
        // popped.
        let addr = pool.addr(next);
        if let Some(old) = by_address.remove(&addr) {
            pool.domains.remove(&old);
        }
        while pool.domains.len() >= CAPACITY || pool.order.len() >= 2 * CAPACITY {
            let Some((oldest, old)) = pool.order.pop_front() else {
                break;
            };
            if pool.domains.get(&old) == Some(&oldest) {
                pool.domains.remove(&old);
                by_address.remove(&pool.addr(oldest));
            }
        }
        pool.domains.insert(domain.to_string(), next);
        pool.order.push_back((next, domain.to_string()));
        by_address.insert(addr, domain.to_string());
        Ok(addr)
    }

    /// What `ip` is to the store.
    pub(crate) fn lookup(&self, ip: IpAddr) -> FakeIp {
        let ip = ip.to_canonical();
        let inner = self.inner();
        let n = match ip {
            IpAddr::V4(v4) => u32::from(v4) as u128,
            IpAddr::V6(v6) => u128::from(v6),
        };
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
        let store = FakeIpStore::new(Some("198.18.0.0/30"), Some("fc00::/126")).unwrap();
        // 198.18.0.0/30: .0 and .1 are not handed out, nor .3, the last.
        assert_eq!(
            store.create("a.example", false).unwrap(),
            "198.18.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            store.create("a.example", false).unwrap(),
            "198.18.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            store.create("b.example", false).unwrap(),
            "198.18.0.2".parse::<IpAddr>().unwrap()
        );
        // b took a's address: a is forgotten.
        assert_eq!(
            store.lookup("198.18.0.2".parse().unwrap()),
            FakeIp::Domain("b.example".into())
        );
        assert_eq!(store.address_of("a.example", false), None);
        assert_eq!(
            store.create("c.example", true).unwrap(),
            "fc00::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(store.lookup("fc00::1".parse().unwrap()), FakeIp::Unknown);
        assert_eq!(store.lookup("10.0.0.1".parse().unwrap()), FakeIp::NotFake);
        assert_eq!(
            store.lookup("::ffff:198.18.0.2".parse().unwrap()),
            FakeIp::Domain("b.example".into())
        );
    }

    #[test]
    fn ranges_are_checked() {
        for (v4, v6, message) in [
            (None, None, "set inet4_range"),
            (Some("fc00::/18"), None, "the other family"),
            (Some("198.18.0.0/31"), None, "too small"),
            (Some("198.18.0.0/40"), None, "invalid range"),
        ] {
            let err = FakeIpStore::new(v4, v6).err().unwrap().to_string();
            assert!(err.contains(message), "{:?} {:?}: {}", v4, v6, err);
        }
    }

    #[test]
    fn an_ipv6_range_keeps_at_most_its_capacity() {
        let store = FakeIpStore::new(None, Some("fc00::/18")).unwrap();
        for i in 0..CAPACITY + 10 {
            store.create(&format!("d{}.example", i), true).unwrap();
        }
        assert_eq!(store.address_of("d0.example", true), None);
        assert!(store
            .address_of(&format!("d{}.example", CAPACITY + 9), true)
            .is_some());
        assert!(store.inner().by_address.len() <= CAPACITY);
    }
}
