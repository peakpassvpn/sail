//! Addresses and uids as interval sets hold them: merged into the fewest
//! ranges, in order -- the kernel refuses overlapping intervals, and nft(8)
//! merges them before sending -- and written as nft(8) writes them.

use std::net::IpAddr;
use std::ops::RangeInclusive;

use crate::platform::nft::SetElem;

/// Addresses `first..=last` of one family, as numbers: an IPv4 address in
/// the low 32 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Range {
    pub v6: bool,
    pub first: u128,
    pub last: u128,
}

fn bits(v6: bool) -> u32 {
    if v6 {
        128
    } else {
        32
    }
}

fn top(v6: bool) -> u128 {
    if v6 {
        u128::MAX
    } else {
        u128::from(u32::MAX)
    }
}

pub(super) fn number(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

pub(super) fn address(v6: bool, n: u128) -> IpAddr {
    if v6 {
        IpAddr::from(n.to_be_bytes())
    } else {
        IpAddr::from((n as u32).to_be_bytes())
    }
}

/// The prefixes of one family, host bits masked off, as the fewest ranges
/// that cover them, in order. Prefixes of the other family are left out.
pub(super) fn ranges(prefixes: &[(IpAddr, u8)], v6: bool) -> Vec<Range> {
    let mut all: Vec<Range> = prefixes
        .iter()
        .filter(|(addr, _)| addr.is_ipv6() == v6)
        .map(|&(addr, len)| {
            let len = u32::from(len).min(bits(v6));
            let host = top(v6).checked_shr(len).unwrap_or(0) & top(v6);
            let first = number(addr) & !host;
            Range {
                v6,
                first,
                last: first | host,
            }
        })
        .collect();
    all.sort_by_key(|r| r.first);
    let mut merged: Vec<Range> = Vec::with_capacity(all.len());
    for r in all {
        match merged.last_mut() {
            // Overlapping or adjacent.
            Some(m) if m.last == top(v6) || r.first <= m.last + 1 => {
                m.last = m.last.max(r.last);
            }
            _ => merged.push(r),
        }
    }
    merged
}

/// The ranges as an interval set's elements.
pub(super) fn elems(ranges: &[Range]) -> Vec<SetElem> {
    ranges
        .iter()
        .flat_map(|r| SetElem::ip_range(address(r.v6, r.first), address(r.v6, r.last)))
        .collect()
}

/// A range as nft(8) writes an interval: an address, a prefix, or
/// `first-last`.
pub(super) fn text(r: &Range) -> String {
    let span = r.last - r.first;
    if span == 0 {
        return address(r.v6, r.first).to_string();
    }
    // A power of two long, and aligned to it: a prefix.
    if span & span.wrapping_add(1) == 0 && r.first & span == 0 {
        let len = bits(r.v6) - span.count_ones();
        return format!("{}/{}", address(r.v6, r.first), len);
    }
    format!("{}-{}", address(r.v6, r.first), address(r.v6, r.last))
}

/// Uid ranges merged into the fewest, in order.
pub(super) fn uid_ranges(uids: &[RangeInclusive<u32>]) -> Vec<(u32, u32)> {
    let mut all: Vec<(u32, u32)> = uids.iter().map(|r| (*r.start(), *r.end())).collect();
    all.sort();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(all.len());
    for (first, last) in all {
        match merged.last_mut() {
            Some(m) if m.1 == u32::MAX || first <= m.1 + 1 => m.1 = m.1.max(last),
            _ => merged.push((first, last)),
        }
    }
    merged
}

/// Uid ranges as the elements of an interval set looked up after a
/// `byteorder hton`: big-endian, so the kernel's byte order is numeric
/// order. An end past the last uid is left out, as for addresses.
pub(super) fn uid_elems(ranges: &[(u32, u32)]) -> Vec<SetElem> {
    let mut elems = Vec::with_capacity(ranges.len() * 2);
    for &(first, last) in ranges {
        elems.push(SetElem::new(first.to_be_bytes()));
        if let Some(end) = last.checked_add(1) {
            elems.push(SetElem::end(end.to_be_bytes()));
        }
    }
    elems
}

pub(super) fn uid_text(&(first, last): &(u32, u32)) -> String {
    if first == last {
        first.to_string()
    } else {
        format!("{}-{}", first, last)
    }
}

#[cfg(test)]
// A uid range is one element of a list of them.
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    fn p(s: &str) -> (IpAddr, u8) {
        let (addr, len) = s.split_once('/').unwrap();
        (addr.parse().unwrap(), len.parse().unwrap())
    }

    fn texts(prefixes: &[&str], v6: bool) -> Vec<String> {
        let prefixes: Vec<_> = prefixes.iter().map(|s| p(s)).collect();
        ranges(&prefixes, v6).iter().map(text).collect()
    }

    #[test]
    fn masks_merges_and_orders() {
        assert_eq!(
            texts(
                &[
                    "192.168.1.10/24",
                    "127.0.0.1/8",
                    "172.18.0.1/30",
                    "10.0.0.0/8",
                    "11.0.0.0/8",
                    "10.1.2.3/16",
                    "::1/128",
                ],
                false
            ),
            [
                "10.0.0.0/7",
                "127.0.0.0/8",
                "172.18.0.0/30",
                "192.168.1.0/24"
            ]
        );
        assert_eq!(
            texts(&["10.0.0.0/8", "12.0.0.0/8", "11.0.0.0/8"], false),
            ["10.0.0.0-12.255.255.255"]
        );
        assert_eq!(texts(&["127.0.0.1/32"], false), ["127.0.0.1"]);
        assert_eq!(texts(&["0.0.0.0/0", "10.0.0.0/8"], false), ["0.0.0.0/0"]);
        assert_eq!(
            texts(&["::1/128", "fdfe:dcba:9876::1/126", "::/0"], true),
            ["::/0"]
        );
        assert_eq!(
            texts(&["fdfe:dcba:9876::1/126", "::1/128"], true),
            ["::1", "fdfe:dcba:9876::/126"]
        );
        // Everything but the top of the space runs to its last address;
        // the top has no end element.
        let r = ranges(&[p("255.255.255.0/24"), p("255.255.254.0/24")], false);
        assert_eq!(text(&r[0]), "255.255.254.0/23");
        assert_eq!(elems(&r), [SetElem::new([255, 255, 254, 0])]);
        let r = ranges(&[p("10.0.0.0/8")], false);
        assert_eq!(
            elems(&r),
            [SetElem::new([10, 0, 0, 0]), SetElem::end([11, 0, 0, 0])]
        );
    }

    #[test]
    fn uids() {
        let r = uid_ranges(&[3000..=3000, 1000..=1999, 1500..=2500, 2501..=2600]);
        assert_eq!(r, [(1000, 2600), (3000, 3000)]);
        assert_eq!(
            r.iter().map(uid_text).collect::<Vec<_>>(),
            ["1000-2600", "3000"]
        );
        assert_eq!(
            uid_elems(&r),
            [
                SetElem::new(1000u32.to_be_bytes()),
                SetElem::end(2601u32.to_be_bytes()),
                SetElem::new(3000u32.to_be_bytes()),
                SetElem::end(3001u32.to_be_bytes()),
            ]
        );
        assert_eq!(
            uid_elems(&uid_ranges(&[5..=u32::MAX])),
            [SetElem::new(5u32.to_be_bytes())]
        );
    }
}
