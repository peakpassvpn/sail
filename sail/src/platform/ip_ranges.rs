//! Sets of addresses as the routing and firewall code needs them: ranges of
//! one family merged, taken from one another, and cut into prefixes.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Addresses of one family, as numbers, in merged inclusive ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RangeSet {
    v6: bool,
    ranges: Vec<(u128, u128)>,
}

impl RangeSet {
    pub(crate) fn new(v6: bool) -> RangeSet {
        RangeSet {
            v6,
            ranges: Vec::new(),
        }
    }

    fn bits(&self) -> u32 {
        if self.v6 {
            128
        } else {
            32
        }
    }

    /// Adds a prefix of this set's family; one of the other is ignored.
    pub(crate) fn add(&mut self, (address, len): (IpAddr, u8)) {
        if let Some(range) = self.range_of(address, len) {
            self.ranges.push(range);
            self.normalize();
        }
    }

    /// Takes a prefix out; one of the other family is ignored.
    pub(crate) fn remove(&mut self, (address, len): (IpAddr, u8)) {
        let Some((start, end)) = self.range_of(address, len) else {
            return;
        };
        self.ranges = self
            .ranges
            .iter()
            .flat_map(|&(a, b)| {
                if b < start || a > end {
                    return vec![(a, b)];
                }
                let mut kept = Vec::new();
                if a < start {
                    kept.push((a, start - 1));
                }
                if b > end {
                    kept.push((end + 1, b));
                }
                kept
            })
            .collect();
    }

    /// The fewest prefixes that cover the set, in order.
    pub(crate) fn prefixes(&self) -> Vec<(IpAddr, u8)> {
        self.ranges
            .iter()
            .flat_map(|&(first, last)| range_prefixes(self.address(first), self.address(last)))
            .collect()
    }

    fn address(&self, n: u128) -> IpAddr {
        if self.v6 {
            Ipv6Addr::from(n).into()
        } else {
            Ipv4Addr::from(n as u32).into()
        }
    }

    fn range_of(&self, address: IpAddr, len: u8) -> Option<(u128, u128)> {
        let (v6, n) = match address {
            IpAddr::V4(a) => (false, u128::from(u32::from(a))),
            IpAddr::V6(a) => (true, u128::from(a)),
        };
        if v6 != self.v6 || u32::from(len) > self.bits() {
            return None;
        }
        let host_bits = self.bits() - u32::from(len);
        let host = if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        let start = n & !host;
        Some((start, start | host))
    }

    fn normalize(&mut self) {
        self.ranges.sort();
        let mut merged: Vec<(u128, u128)> = Vec::new();
        for &(start, end) in &self.ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        self.ranges = merged;
    }
}

/// The fewest prefixes that cover the inclusive range `first..=last` of
/// one family.
pub(crate) fn range_prefixes(first: IpAddr, last: IpAddr) -> Vec<(IpAddr, u8)> {
    let (v6, mut first, last) = match (first, last) {
        _ if first > last => return Vec::new(),
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            (false, u128::from(u32::from(a)), u128::from(u32::from(b)))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => (true, u128::from(a), u128::from(b)),
        _ => return Vec::new(),
    };
    let bits: u32 = if v6 { 128 } else { 32 };
    let address = |n: u128| -> IpAddr {
        if v6 {
            Ipv6Addr::from(n).into()
        } else {
            Ipv4Addr::from(n as u32).into()
        }
    };
    // The last address of the block of 2^`size` from `first`, which is
    // aligned to it.
    let block_end = |first: u128, size: u32| {
        if size >= 128 {
            u128::MAX
        } else {
            first + ((1u128 << size) - 1)
        }
    };
    let mut prefixes = Vec::new();
    loop {
        // The largest aligned block from `first` that ends by `last`.
        let mut size = first.trailing_zeros().min(bits);
        while block_end(first, size) > last {
            size -= 1;
        }
        prefixes.push((address(first), (bits - size) as u8));
        let end = block_end(first, size);
        if end >= last {
            break;
        }
        first = end + 1;
    }
    prefixes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn show(prefixes: Vec<(IpAddr, u8)>) -> Vec<String> {
        prefixes
            .into_iter()
            .map(|(ip, len)| format!("{}/{}", ip, len))
            .collect()
    }

    fn prefixes(first: &str, last: &str) -> Vec<String> {
        show(range_prefixes(
            first.parse().unwrap(),
            last.parse().unwrap(),
        ))
    }

    fn prefix(s: &str) -> (IpAddr, u8) {
        let (address, len) = s.split_once('/').unwrap();
        (address.parse().unwrap(), len.parse().unwrap())
    }

    #[test]
    fn ranges_become_the_fewest_prefixes() {
        assert_eq!(prefixes("10.0.0.0", "10.255.255.255"), ["10.0.0.0/8"]);
        assert_eq!(prefixes("1.1.1.1", "1.1.1.1"), ["1.1.1.1/32"]);
        assert_eq!(
            prefixes("10.0.0.1", "10.0.0.6"),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]
        );
        assert_eq!(prefixes("0.0.0.0", "255.255.255.255"), ["0.0.0.0/0"]);
        assert_eq!(
            prefixes("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ["::/0"]
        );
        assert_eq!(
            prefixes("255.255.255.254", "255.255.255.255"),
            ["255.255.255.254/31"]
        );
        assert_eq!(
            prefixes("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
            ["2001:db8::/32"]
        );
    }

    #[test]
    fn sets_merge_and_subtract() {
        let mut set = RangeSet::new(false);
        set.add(prefix("0.0.0.0/0"));
        set.remove(prefix("192.168.0.0/16"));
        set.remove(prefix("10.0.0.0/8"));
        set.remove(prefix("fc00::/7"));
        assert_eq!(
            show(set.prefixes()),
            [
                "0.0.0.0/5",
                "8.0.0.0/7",
                "11.0.0.0/8",
                "12.0.0.0/6",
                "16.0.0.0/4",
                "32.0.0.0/3",
                "64.0.0.0/2",
                "128.0.0.0/2",
                "192.0.0.0/9",
                "192.128.0.0/11",
                "192.160.0.0/13",
                "192.169.0.0/16",
                "192.170.0.0/15",
                "192.172.0.0/14",
                "192.176.0.0/12",
                "192.192.0.0/10",
                "193.0.0.0/8",
                "194.0.0.0/7",
                "196.0.0.0/6",
                "200.0.0.0/5",
                "208.0.0.0/4",
                "224.0.0.0/3",
            ]
        );
        let mut dup = RangeSet::new(true);
        dup.add(prefix("2001:db8::/32"));
        dup.add(prefix("2001:db8:1::/48"));
        dup.add(prefix("2001:db9::/32"));
        assert_eq!(show(dup.prefixes()), ["2001:db8::/31"]);
    }
}
