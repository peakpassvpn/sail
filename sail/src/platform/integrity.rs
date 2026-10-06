//! Whether what auto_route set up for a TUN is still as it set it up:
//! its routes there and winning, its address there, and on Windows its
//! DNS servers. Someone else's change
//! is told (`Event::SystemChanged`), once a break, and left as it is: the
//! host restores it or rebuilds the instance.
//!
//! sail compares the system with what it wants, under the lock its own
//! changes are made under, so that a change of its own is never one; see
//! design-notes/tun-integrity.md of the project.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::control::events::{EventHub, SystemChange};
use crate::runtime::teardown::LeftKind;

/// A route of the system's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) dst: IpAddr,
    pub(crate) len: u8,
    /// Its interface's index.
    pub(crate) index: u32,
    /// Bound to its interface (macOS RTF_IFSCOPE): only what is sent on
    /// that interface takes it.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub(crate) scoped: bool,
}

/// What is not as sail set it up: of which kind, what, and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Broken {
    pub(crate) kind: LeftKind,
    /// The resource, the TUN's name first: "route 128.0.0.0/1 into utun9".
    pub(crate) what: String,
    /// "gone", "128.0.0.0/1 on en0 wins".
    pub(crate) how: String,
}

/// Whether `address` is in `dst`/`len`.
fn contains(dst: IpAddr, len: u8, address: IpAddr) -> bool {
    match (dst, address) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// The address an address of `prefix` is looked up by: its first but
/// one, which no route of the network itself takes. 0/0's (Windows') are
/// "this network" and loopback, which have routes of their own: a
/// default route is looked up by the first but one of 1/8 or 2000::/3.
fn probe((address, len): (IpAddr, u8)) -> IpAddr {
    let address = match (address, len) {
        (IpAddr::V4(_), 0) => Ipv4Addr::new(1, 0, 0, 0).into(),
        (IpAddr::V6(_), 0) => Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0).into(),
        _ => address,
    };
    match address {
        IpAddr::V4(a) => Ipv4Addr::from(u32::from(a).wrapping_add(1)).into(),
        IpAddr::V6(a) => Ipv6Addr::from(u128::from(a).wrapping_add(1)).into(),
    }
}

/// The route of `table` that an unbound packet to `address` takes: the
/// longest unscoped one that holds it, the first of equals.
// Windows asks the system (GetBestRoute2).
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) fn longest_match(table: &[Route], address: IpAddr) -> Option<Route> {
    let mut best: Option<Route> = None;
    for route in table
        .iter()
        .filter(|r| !r.scoped && contains(r.dst, r.len, address))
    {
        if best.is_none_or(|b| route.len > b.len) {
            best = Some(*route);
        }
    }
    best
}

/// The routes into the TUN `tun` (index `index`) that are not as sail
/// set them up: each of `wanted` with no route of its own into the TUN,
/// and each of `contested`, those of `wanted` that win over the default
/// route, that another route wins over. `winner` is the route an address
/// takes; `name` an interface's name.
pub(crate) fn routes(
    tun: &str,
    index: u32,
    wanted: &[(IpAddr, u8)],
    contested: &[(IpAddr, u8)],
    table: &[Route],
    winner: impl Fn(IpAddr) -> Option<Route>,
    name: impl Fn(u32) -> String,
) -> Vec<Broken> {
    let mut broken = Vec::new();
    let what = |(address, len): (IpAddr, u8)| format!("route {}/{} into {}", address, len, tun);
    for &prefix in wanted {
        let there = table
            .iter()
            .any(|r| r.dst == prefix.0 && r.len == prefix.1 && r.index == index);
        if !there {
            broken.push(Broken {
                kind: LeftKind::Route,
                what: what(prefix),
                how: "gone".into(),
            });
            continue;
        }
        if !contested.contains(&prefix) {
            continue;
        }
        match winner(probe(prefix)) {
            Some(r) if r.index != index => broken.push(Broken {
                kind: LeftKind::Route,
                what: what(prefix),
                how: format!("{}/{} on {} wins", r.dst, r.len, name(r.index)),
            }),
            _ => {}
        }
    }
    broken
}

/// Whether the TUN `tun` still has `address`, among the addresses of the
/// interfaces up (`up`: interface, address).
pub(crate) fn address(tun: &str, address: IpAddr, up: &[(String, IpAddr)]) -> Option<Broken> {
    let there = up.iter().any(|(name, a)| name == tun && *a == address);
    (!there).then(|| Broken {
        kind: LeftKind::Tun,
        what: format!("{}: its address {}", tun, address),
        how: "gone, or the TUN is down".into(),
    })
}

/// Whether the TUN `tun`'s DNS servers of a family (`family`: "IPv4")
/// are still `wanted`, those sail set: `got`, in any order.
pub(crate) fn dns(tun: &str, family: &str, wanted: &[IpAddr], got: &[IpAddr]) -> Option<Broken> {
    let same = wanted.iter().all(|a| got.contains(a)) && got.iter().all(|a| wanted.contains(a));
    let list = |servers: &[IpAddr]| match servers {
        [] => "none".to_string(),
        servers => servers
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    };
    (!same).then(|| Broken {
        kind: LeftKind::Dns,
        what: format!("the {} DNS servers of {}", family, tun),
        how: format!("{} instead of {}", list(got), list(wanted)),
    })
}

/// What was told broken, so that a break is told once: again only once a
/// check found it right in between.
#[derive(Default)]
pub(crate) struct Told(HashSet<String>);

impl Told {
    /// Tells on `events` what of `found` was not broken at the check
    /// before, and forgets what is no longer.
    pub(crate) fn tell(&mut self, found: Vec<Broken>, events: &EventHub) {
        let now: HashSet<String> = found.iter().map(|b| b.what.clone()).collect();
        for b in found {
            if self.0.contains(&b.what) {
                continue;
            }
            tracing::warn!(
                "{}: {}; changed by someone else, and left as it is",
                b.what,
                b.how
            );
            events.system_changed(SystemChange {
                kind: b.kind,
                resource: format!("{}: {}", b.what, b.how),
            });
        }
        self.0 = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TUN: u32 = 9;
    const EN0: u32 = 4;

    fn route(dst: &str, len: u8, index: u32) -> Route {
        Route {
            dst: dst.parse().unwrap(),
            len,
            index,
            scoped: false,
        }
    }

    fn prefix(dst: &str, len: u8) -> (IpAddr, u8) {
        (dst.parse().unwrap(), len)
    }

    fn name(index: u32) -> String {
        match index {
            TUN => "utun9".into(),
            EN0 => "en0".into(),
            other => format!("interface {}", other),
        }
    }

    fn check(wanted: &[(IpAddr, u8)], table: &[Route]) -> Vec<String> {
        routes(
            "utun9",
            TUN,
            wanted,
            wanted,
            table,
            |a| longest_match(table, a),
            name,
        )
        .into_iter()
        .map(|b| format!("{}: {}", b.what, b.how))
        .collect()
    }

    /// The system as sail set it up: nothing to tell, with the default
    /// route, a LAN's and a scoped one there too.
    #[test]
    fn routes_as_set_up_are_not_broken() {
        let wanted = [prefix("1.0.0.0", 8), prefix("128.0.0.0", 1)];
        let mut scoped = route("0.0.0.0", 0, EN0);
        scoped.scoped = true;
        let table = [
            route("0.0.0.0", 0, EN0),
            scoped,
            route("192.168.1.0", 24, EN0),
            route("1.0.0.0", 8, TUN),
            route("128.0.0.0", 1, TUN),
        ];
        assert!(check(&wanted, &table).is_empty());
    }

    #[test]
    fn a_route_gone_or_on_another_interface_is_told() {
        let wanted = [prefix("1.0.0.0", 8), prefix("128.0.0.0", 1)];
        let table = [route("0.0.0.0", 0, EN0), route("128.0.0.0", 1, EN0)];
        assert_eq!(
            check(&wanted, &table),
            [
                "route 1.0.0.0/8 into utun9: gone",
                "route 128.0.0.0/1 into utun9: gone",
            ]
        );
    }

    /// Another VPN's halves, or a longer route of the same span: sail's
    /// is there and loses.
    #[test]
    fn a_route_that_wins_over_sail_s_is_told() {
        let wanted = [prefix("128.0.0.0", 1), prefix("2000::", 3)];
        let table = [
            route("128.0.0.0", 1, TUN),
            route("128.0.0.0", 2, 12),
            route("2000::", 3, TUN),
            route("2000::", 4, EN0),
        ];
        assert_eq!(
            check(&wanted, &table),
            [
                "route 128.0.0.0/1 into utun9: 128.0.0.0/2 on interface 12 wins",
                "route 2000::/3 into utun9: 2000::/4 on en0 wins",
            ]
        );
    }

    /// Only the default route's halves are looked up: a route sail adds
    /// for a rule-set may well lose to a longer one, as it should.
    #[test]
    fn a_route_not_contested_is_only_looked_for() {
        let wanted = [prefix("10.0.0.0", 8)];
        let table = [route("10.0.0.0", 8, TUN), route("10.0.0.0", 16, EN0)];
        let found = routes(
            "utun9",
            TUN,
            &wanted,
            &[],
            &table,
            |a| longest_match(&table, a),
            name,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn the_longest_unscoped_route_wins() {
        let mut scoped = route("128.0.0.0", 9, EN0);
        scoped.scoped = true;
        let table = [route("0.0.0.0", 0, EN0), route("128.0.0.0", 1, TUN), scoped];
        assert_eq!(
            longest_match(&table, "128.0.0.1".parse().unwrap()),
            Some(route("128.0.0.0", 1, TUN))
        );
        assert_eq!(
            longest_match(&table, "1.2.3.4".parse().unwrap()),
            Some(route("0.0.0.0", 0, EN0))
        );
    }

    #[test]
    fn a_tun_without_its_address_is_told() {
        let address: IpAddr = "172.19.0.1".parse().unwrap();
        let up = [("utun9".to_string(), address)];
        assert_eq!(super::address("utun9", address, &up), None);
        let other = [("utun3".to_string(), address)];
        assert_eq!(
            super::address("utun9", address, &other).map(|b| b.what),
            Some("utun9: its address 172.19.0.1".to_string())
        );
    }

    /// Windows' 0/0 and ::/0 are looked up by a global address: their own
    /// first ones are "this network" and loopback.
    #[test]
    fn a_default_route_is_looked_up_by_a_global_address() {
        assert_eq!(
            probe(prefix("0.0.0.0", 0)),
            "1.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(probe(prefix("::", 0)), "2000::1".parse::<IpAddr>().unwrap());
        assert_eq!(
            probe(prefix("128.0.0.0", 1)),
            "128.0.0.1".parse::<IpAddr>().unwrap()
        );
        let table = [route("0.0.0.0", 0, EN0), route("0.0.0.0", 0, TUN)];
        let wanted = [prefix("0.0.0.0", 0)];
        let found = routes(
            "tun0",
            TUN,
            &wanted,
            &wanted,
            &table,
            |_| Some(route("0.0.0.0", 0, EN0)),
            name,
        );
        assert_eq!(found[0].how, "0.0.0.0/0 on en0 wins");
    }

    #[test]
    fn dns_servers_not_sail_s_are_told() {
        let ours: IpAddr = "172.19.0.2".parse().unwrap();
        let other: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(dns("tun0", "IPv4", &[ours], &[ours]), None);
        let told = |got: &[IpAddr]| {
            dns("tun0", "IPv4", &[ours], got).map(|b| format!("{}: {}", b.what, b.how))
        };
        assert_eq!(
            told(&[other]).as_deref(),
            Some("the IPv4 DNS servers of tun0: 1.1.1.1 instead of 172.19.0.2")
        );
        assert_eq!(
            told(&[]).as_deref(),
            Some("the IPv4 DNS servers of tun0: none instead of 172.19.0.2")
        );
        assert!(told(&[ours, other]).is_some());
    }

    /// Once a break: told again only after a check found it right.
    #[tokio::test]
    async fn a_break_is_told_once() {
        let hub = EventHub::default();
        let mut events = hub.system_changes();
        let gone = |p: &str| Broken {
            kind: LeftKind::Route,
            what: format!("route {} into utun9", p),
            how: "gone".into(),
        };
        let mut told = Told::default();
        told.tell(vec![gone("1.0.0.0/8")], &hub);
        told.tell(vec![gone("1.0.0.0/8"), gone("2.0.0.0/7")], &hub);
        told.tell(vec![], &hub);
        told.tell(vec![gone("1.0.0.0/8")], &hub);
        let mut seen = Vec::new();
        while let Ok(change) = events.try_recv() {
            seen.push(change.resource);
        }
        assert_eq!(
            seen,
            [
                "route 1.0.0.0/8 into utun9: gone",
                "route 2.0.0.0/7 into utun9: gone",
                "route 1.0.0.0/8 into utun9: gone",
            ]
        );
    }
}
