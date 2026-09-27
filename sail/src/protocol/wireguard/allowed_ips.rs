//! Cryptokey routing: prefixes to peers, by longest-prefix match.
//!
//! One hash map per prefix length present, probed from the longest length
//! down, so a lookup costs one probe per distinct length. Host bits of an
//! inserted prefix are masked off; inserting a prefix another peer holds
//! moves it, as `wg set ... allowed-ips` does.

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct AllowedIps<T> {
    v4: Table<T>,
    v6: Table<T>,
}

#[derive(Debug, Clone)]
struct Table<T> {
    /// (prefix length, prefixes of that length), longest first.
    by_len: Vec<(u8, HashMap<u128, T>)>,
}

impl<T> Default for Table<T> {
    fn default() -> Self {
        Table { by_len: Vec::new() }
    }
}

impl<T> Default for AllowedIps<T> {
    fn default() -> Self {
        AllowedIps {
            v4: Table::default(),
            v6: Table::default(),
        }
    }
}

fn mask(bits: u128, len: u8, width: u8) -> u128 {
    if len == 0 {
        0
    } else {
        let shift = width - len;
        let m = (u128::MAX >> (128 - width as u32)) >> shift << shift;
        bits & m
    }
}

fn split(ip: IpAddr) -> (u128, u8) {
    match ip {
        IpAddr::V4(v4) => (u32::from(v4) as u128, 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    }
}

impl<T: Clone + PartialEq> Table<T> {
    fn insert(&mut self, bits: u128, len: u8, width: u8, value: T) {
        let key = mask(bits, len, width);
        match self.by_len.binary_search_by(|(l, _)| len.cmp(l)) {
            Ok(i) => {
                self.by_len[i].1.insert(key, value);
            }
            Err(i) => {
                let mut m = HashMap::new();
                m.insert(key, value);
                self.by_len.insert(i, (len, m));
            }
        }
    }

    fn lookup(&self, bits: u128, width: u8) -> Option<&T> {
        self.by_len
            .iter()
            .find_map(|(len, m)| m.get(&mask(bits, *len, width)))
    }

    fn remove_value(&mut self, value: &T) {
        for (_, m) in &mut self.by_len {
            m.retain(|_, v| v != value);
        }
        self.by_len.retain(|(_, m)| !m.is_empty());
    }

    fn entries(&self, width: u8) -> impl Iterator<Item = (u128, u8, &T)> {
        let _ = width;
        self.by_len
            .iter()
            .flat_map(|(len, m)| m.iter().map(move |(k, v)| (*k, *len, v)))
    }
}

impl<T: Clone + PartialEq> AllowedIps<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `ip/len` for `value`. False if `len` is too long for the family.
    pub fn insert(&mut self, ip: IpAddr, len: u8, value: T) -> bool {
        let (bits, width) = split(ip);
        if len > width {
            return false;
        }
        match ip {
            IpAddr::V4(_) => self.v4.insert(bits, len, width, value),
            IpAddr::V6(_) => self.v6.insert(bits, len, width, value),
        }
        true
    }

    /// The value of the longest prefix containing `ip`.
    pub fn lookup(&self, ip: IpAddr) -> Option<&T> {
        let (bits, width) = split(ip);
        match ip {
            IpAddr::V4(_) => self.v4.lookup(bits, width),
            IpAddr::V6(_) => self.v6.lookup(bits, width),
        }
    }

    /// Removes every prefix of `value`.
    pub fn remove(&mut self, value: &T) {
        self.v4.remove_value(value);
        self.v6.remove_value(value);
    }

    /// The prefixes of `value`.
    pub fn prefixes_of(&self, value: &T) -> Vec<(IpAddr, u8)> {
        let v4 = self
            .v4
            .entries(32)
            .filter(|e| e.2 == value)
            .map(|(k, l, _)| (IpAddr::V4((k as u32).into()), l));
        let v6 = self
            .v6
            .entries(128)
            .filter(|e| e.2 == value)
            .map(|(k, l, _)| (IpAddr::V6(k.into()), l));
        v4.chain(v6).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let mut t = AllowedIps::new();
        assert!(t.insert(ip("0.0.0.0"), 0, 'a'));
        assert!(t.insert(ip("10.0.0.0"), 8, 'b'));
        assert!(t.insert(ip("10.1.0.0"), 16, 'c'));
        assert!(t.insert(ip("10.1.2.3"), 32, 'd'));
        assert!(t.insert(ip("::"), 0, 'e'));
        assert!(t.insert(ip("fd00::"), 8, 'f'));
        assert!(t.insert(ip("fd00:1::5"), 128, 'g'));
        assert!(!t.insert(ip("10.0.0.0"), 33, 'x'));

        assert_eq!(t.lookup(ip("192.0.2.1")), Some(&'a'));
        assert_eq!(t.lookup(ip("10.200.0.1")), Some(&'b'));
        assert_eq!(t.lookup(ip("10.1.9.9")), Some(&'c'));
        assert_eq!(t.lookup(ip("10.1.2.3")), Some(&'d'));
        assert_eq!(t.lookup(ip("2001:db8::1")), Some(&'e'));
        assert_eq!(t.lookup(ip("fd12::1")), Some(&'f'));
        assert_eq!(t.lookup(ip("fd00:1::5")), Some(&'g'));
        assert_eq!(t.lookup(ip("fd00:1::6")), Some(&'f'));
    }

    #[test]
    fn host_bits_masked_and_moves() {
        let mut t = AllowedIps::new();
        t.insert(ip("10.1.2.3"), 24, 1u32);
        assert_eq!(t.lookup(ip("10.1.2.200")), Some(&1));
        assert_eq!(t.prefixes_of(&1), vec![(ip("10.1.2.0"), 24)]);
        // Another peer takes the same prefix.
        t.insert(ip("10.1.2.0"), 24, 2);
        assert_eq!(t.lookup(ip("10.1.2.200")), Some(&2));
        assert!(t.prefixes_of(&1).is_empty());
        t.remove(&2);
        assert_eq!(t.lookup(ip("10.1.2.200")), None);
    }

    #[test]
    fn families_are_separate() {
        let mut t = AllowedIps::new();
        t.insert(ip("0.0.0.0"), 0, 1u8);
        assert_eq!(t.lookup(ip("::1")), None);
        assert_eq!(t.lookup(ip("::ffff:10.0.0.1")), None);
    }
}
