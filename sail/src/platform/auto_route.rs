//! The ip rules of a TUN with `auto_route` on Linux, without auto_redirect:
//! sing-tun's (v0.9.6, `rules()` in tun_linux.go), priority for priority.
//! The TUN's routes are in a table of their own; these rules send into it
//! what is to go into the TUN, and leave the main table alone: nothing of
//! the system's routing is changed, and what the kernel drops with the
//! device is all that points at it.
//!
//! A pure builder: options in, rules out, in the order they are added.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

use super::ip_ranges::RangeSet;

/// What a rule does with a packet it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Lookup(u32),
    Goto(u32),
    Nop,
    Unreachable,
}

/// One ip rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    pub v6: bool,
    pub priority: u32,
    pub invert: bool,
    pub action: Action,
    pub src: Option<(IpAddr, u8)>,
    pub dst: Option<(IpAddr, u8)>,
    pub iif: Option<String>,
    pub uid_range: Option<(u32, u32)>,
    pub dport: Option<(u16, u16)>,
    pub suppress_prefixlength: Option<u32>,
}

impl Rule {
    fn new(v6: bool, priority: u32, action: Action) -> Rule {
        Rule {
            v6,
            priority,
            invert: false,
            action,
            src: None,
            dst: None,
            iif: None,
            uid_range: None,
            dport: None,
            suppress_prefixlength: None,
        }
    }
}

/// The main routing table.
pub(crate) const MAIN_TABLE: u32 = 254;

/// What the rules are made of.
#[derive(Clone, Debug, Default)]
pub(crate) struct RuleOptions {
    pub tun: String,
    pub table: u32,
    pub rule_index: u32,
    /// The TUN's addresses with their prefix lengths, of each family.
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub ipv6: Vec<(Ipv6Addr, u8)>,
    pub strict_route: bool,
    pub include_uid: Vec<RangeInclusive<u32>>,
    pub exclude_uid: Vec<RangeInclusive<u32>>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
}

/// How many priorities from `rule_index` are the rules'; the last one is
/// where excluded traffic lands.
pub(crate) const RULE_SPAN: u32 = 10;

/// The uid ranges whose traffic is left out: with `include_uid`, every uid
/// outside it (less what `exclude_uid` takes out of it too), otherwise
/// `exclude_uid`; merged and in order (sing-tun's `ExcludedRanges`).
pub(crate) fn excluded_uids(
    include: &[RangeInclusive<u32>],
    exclude: &[RangeInclusive<u32>],
) -> Vec<(u32, u32)> {
    let merge = |mut ranges: Vec<(u32, u32)>| {
        ranges.sort();
        let mut merged: Vec<(u32, u32)> = Vec::new();
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        merged
    };
    let exclude = merge(exclude.iter().map(|r| (*r.start(), *r.end())).collect());
    if include.is_empty() {
        return exclude;
    }
    // The uids included, less the excluded, then the rest of 0..=MAX-1.
    let mut kept = merge(include.iter().map(|r| (*r.start(), *r.end())).collect());
    for &(start, end) in &exclude {
        kept = kept
            .into_iter()
            .flat_map(|(a, b)| {
                let mut parts = Vec::new();
                if a < start {
                    parts.push((a, b.min(start - 1)));
                }
                if b > end {
                    parts.push((a.max(end + 1), b));
                }
                if b < start || a > end {
                    return vec![(a, b)];
                }
                parts
            })
            .collect();
    }
    const TOP: u32 = 0xFFFF_FFFE;
    let mut complement = Vec::new();
    let mut next = 0u32;
    for (start, end) in kept {
        if start > next {
            complement.push((next, start - 1));
        }
        next = end.saturating_add(1);
    }
    if next <= TOP {
        complement.push((next, TOP));
    }
    complement
}

/// The rules, in the order they are added: within a priority, the order
/// the kernel tries them in.
pub(crate) fn rules(o: &RuleOptions) -> Vec<Rule> {
    let p4 = !o.ipv4.is_empty();
    let p6 = !o.ipv6.is_empty();
    if !p4 && !p6 {
        return Vec::new();
    }
    let mut rules = Vec::new();
    let nop = o.rule_index + RULE_SPAN;
    let mut priority = o.rule_index;
    let mut priority6 = o.rule_index;
    let families = |p4: bool, p6: bool| {
        [(false, p4), (true, p6)]
            .into_iter()
            .filter_map(|(v6, on)| on.then_some(v6))
    };

    let excluded = excluded_uids(&o.include_uid, &o.exclude_uid);
    for &range in &excluded {
        for v6 in families(p4, p6) {
            let at = if v6 { priority6 } else { priority };
            rules.push(Rule {
                uid_range: Some(range),
                ..Rule::new(v6, at, Action::Goto(nop))
            });
        }
    }
    if !excluded.is_empty() {
        priority += u32::from(p4);
        priority6 += u32::from(p6);
    }

    if !o.include_interface.is_empty() {
        let (matched, matched6) = (priority + 2, priority6 + 2);
        for name in &o.include_interface {
            for v6 in families(p4, p6) {
                let (at, to) = if v6 {
                    (priority6, matched6)
                } else {
                    (priority, matched)
                };
                rules.push(Rule {
                    iif: Some(name.clone()),
                    ..Rule::new(v6, at, Action::Goto(to))
                });
            }
        }
        priority += u32::from(p4);
        priority6 += u32::from(p6);
        for v6 in families(p4, p6) {
            let (at, to) = if v6 {
                (&mut priority6, matched6)
            } else {
                (&mut priority, matched)
            };
            rules.push(Rule::new(v6, *at, Action::Goto(nop)));
            *at += 1;
            rules.push(Rule::new(v6, to, Action::Nop));
            *at += 1;
        }
    } else if !o.exclude_interface.is_empty() {
        for name in &o.exclude_interface {
            for v6 in families(p4, p6) {
                let at = if v6 { priority6 } else { priority };
                rules.push(Rule {
                    iif: Some(name.clone()),
                    ..Rule::new(v6, at, Action::Goto(nop))
                });
            }
        }
        priority += u32::from(p4);
        priority6 += u32::from(p6);
    }

    if o.strict_route {
        if !p4 {
            rules.push(Rule::new(false, priority, Action::Unreachable));
            priority += 1;
        }
        if !p6 {
            rules.push(Rule::new(true, priority6, Action::Unreachable));
            priority6 += 1;
        }
    }

    let masked4 = |&(address, len): &(Ipv4Addr, u8)| -> (IpAddr, u8) {
        let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
        (Ipv4Addr::from(u32::from(address) & mask).into(), len)
    };
    let masked6 = |&(address, len): &(Ipv6Addr, u8)| -> (IpAddr, u8) {
        let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
        (Ipv6Addr::from(u128::from(address) & mask).into(), len)
    };
    if p4 {
        for address in &o.ipv4 {
            rules.push(Rule {
                dst: Some(masked4(address)),
                ..Rule::new(false, priority, Action::Lookup(o.table))
            });
        }
        priority += 1;
        rules.push(Rule {
            suppress_prefixlength: Some(0),
            ..Rule::new(false, priority, Action::Lookup(o.table))
        });
        priority += 1;
    }
    if p6 {
        rules.push(Rule {
            suppress_prefixlength: Some(0),
            ..Rule::new(true, priority6, Action::Lookup(o.table))
        });
        priority6 += 1;
    }
    for v6 in families(p4, p6) {
        let at = if v6 { priority6 } else { priority };
        rules.push(Rule {
            invert: true,
            dport: Some((53, 53)),
            suppress_prefixlength: Some(0),
            ..Rule::new(v6, at, Action::Lookup(MAIN_TABLE))
        });
    }

    if p4 {
        rules.push(Rule {
            iif: Some(o.tun.clone()),
            ..Rule::new(false, priority, Action::Goto(nop))
        });
        priority += 1;
        rules.push(Rule {
            invert: true,
            iif: Some("lo".into()),
            ..Rule::new(false, priority, Action::Lookup(o.table))
        });
        rules.push(Rule {
            iif: Some("lo".into()),
            src: Some((Ipv4Addr::UNSPECIFIED.into(), 32)),
            ..Rule::new(false, priority, Action::Lookup(o.table))
        });
        for address in &o.ipv4 {
            rules.push(Rule {
                iif: Some("lo".into()),
                src: Some(masked4(address)),
                ..Rule::new(false, priority, Action::Lookup(o.table))
            });
        }
    }
    if p6 {
        for address in &o.ipv6 {
            rules.push(Rule {
                iif: Some("lo".into()),
                src: Some(masked6(address)),
                ..Rule::new(true, priority6, Action::Lookup(o.table))
            });
        }
        priority6 += 1;
        rules.push(Rule {
            iif: Some(o.tun.clone()),
            ..Rule::new(true, priority6, Action::Goto(nop))
        });
        // These match only a flow with a source already: an unbound
        // socket's first lookup passes them and reaches the table below,
        // as IPv4's `from 0.0.0.0/32` catches it.
        for half in [Ipv6Addr::UNSPECIFIED, Ipv6Addr::from(1u128 << 127)] {
            rules.push(Rule {
                iif: Some("lo".into()),
                src: Some((half.into(), 1)),
                ..Rule::new(true, priority6, Action::Goto(nop))
            });
        }
        priority6 += 1;
        rules.push(Rule::new(true, priority6, Action::Lookup(o.table)));
    }
    for v6 in families(p4, p6) {
        rules.push(Rule::new(v6, nop, Action::Nop));
    }
    rules
}

/// The prefixes of one family routed into the TUN's table: `include`
/// (`route_address` and the rule-sets of `route_address_set`), or all
/// addresses without it, less `exclude`; merged, so a prefix twice is
/// routed once.
pub(crate) fn routes(
    v6: bool,
    include: &[(IpAddr, u8)],
    exclude: &[(IpAddr, u8)],
) -> Vec<(IpAddr, u8)> {
    let mut set = RangeSet::new(v6);
    let of_family = |&&(address, _): &&(IpAddr, u8)| address.is_ipv6() == v6;
    let mut included = include.iter().filter(of_family).peekable();
    if included.peek().is_none() {
        let all: IpAddr = if v6 {
            Ipv6Addr::UNSPECIFIED.into()
        } else {
            Ipv4Addr::UNSPECIFIED.into()
        };
        set.add((all, 0));
    }
    for &prefix in included {
        set.add(prefix);
    }
    for &prefix in exclude.iter().filter(of_family) {
        set.remove(prefix);
    }
    set.prefixes()
}

/// A rule as `ip rule show` prints it, for logs and tests.
pub(crate) fn render(rule: &Rule) -> String {
    let mut out = format!("{}: ", rule.priority);
    if rule.invert {
        out.push_str("not ");
    }
    match rule.src {
        Some((address, len)) if !(len == 0) => {
            let full = if address.is_ipv4() { 32 } else { 128 };
            if len == full {
                out.push_str(&format!("from {} ", address));
            } else {
                out.push_str(&format!("from {}/{} ", address, len));
            }
        }
        _ => out.push_str("from all "),
    }
    if let Some((address, len)) = rule.dst {
        out.push_str(&format!("to {}/{} ", address, len));
    }
    if let Some(iif) = &rule.iif {
        out.push_str(&format!("iif {} ", iif));
    }
    if let Some((start, end)) = rule.uid_range {
        out.push_str(&format!("uidrange {}-{} ", start, end));
    }
    if let Some((start, end)) = rule.dport {
        if start == end {
            out.push_str(&format!("dport {} ", start));
        } else {
            out.push_str(&format!("dport {}-{} ", start, end));
        }
    }
    match rule.action {
        Action::Lookup(MAIN_TABLE) => out.push_str("lookup main "),
        Action::Lookup(table) => out.push_str(&format!("lookup {} ", table)),
        Action::Goto(to) => out.push_str(&format!("goto {} ", to)),
        Action::Nop => out.push_str("nop "),
        Action::Unreachable => out.push_str("unreachable "),
    }
    if let Some(len) = rule.suppress_prefixlength {
        out.push_str(&format!("suppress_prefixlength {} ", len));
    }
    out.trim_end().to_string()
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    fn options() -> RuleOptions {
        RuleOptions {
            tun: "tun0".into(),
            table: 2022,
            rule_index: 9000,
            ipv4: vec![("172.18.0.1".parse().unwrap(), 30)],
            ipv6: vec![("fdfe:dcba:9876::1".parse().unwrap(), 126)],
            ..Default::default()
        }
    }

    fn listing(o: &RuleOptions, v6: bool) -> Vec<String> {
        rules(o)
            .iter()
            .filter(|rule| rule.v6 == v6)
            .map(render)
            .collect()
    }

    /// sing-tun's rules for the default dual-stack TUN, in the order they
    /// are added.
    #[test]
    fn the_default_rules_are_sing_tun_s() {
        assert_eq!(
            listing(&options(), false),
            [
                "9000: from all to 172.18.0.0/30 lookup 2022",
                "9001: from all lookup 2022 suppress_prefixlength 0",
                "9002: not from all dport 53 lookup main suppress_prefixlength 0",
                "9002: from all iif tun0 goto 9010",
                "9003: not from all iif lo lookup 2022",
                "9003: from 0.0.0.0 iif lo lookup 2022",
                "9003: from 172.18.0.0/30 iif lo lookup 2022",
                "9010: from all nop",
            ]
        );
        assert_eq!(
            listing(&options(), true),
            [
                "9000: from all lookup 2022 suppress_prefixlength 0",
                "9001: not from all dport 53 lookup main suppress_prefixlength 0",
                "9001: from fdfe:dcba:9876::/126 iif lo lookup 2022",
                "9002: from all iif tun0 goto 9010",
                "9002: from ::/1 iif lo goto 9010",
                "9002: from 8000::/1 iif lo goto 9010",
                "9003: from all lookup 2022",
                "9010: from all nop",
            ]
        );
    }

    #[test]
    fn strict_route_makes_the_missing_family_unreachable() {
        let o = RuleOptions {
            ipv6: Vec::new(),
            strict_route: true,
            ..options()
        };
        assert_eq!(listing(&o, true), ["9000: from all unreachable"]);
        // With both families, it adds nothing.
        let both = RuleOptions {
            strict_route: true,
            ..options()
        };
        assert_eq!(rules(&both), rules(&options()));
    }

    #[test]
    fn uids_and_interfaces_come_first() {
        let o = RuleOptions {
            ipv6: Vec::new(),
            exclude_uid: vec![1000..=1999],
            include_interface: vec!["lo".into(), "br-lan".into()],
            ..options()
        };
        assert_eq!(
            listing(&o, false)[..6],
            [
                "9000: from all uidrange 1000-1999 goto 9010",
                "9001: from all iif lo goto 9003",
                "9001: from all iif br-lan goto 9003",
                "9002: from all goto 9010",
                "9003: from all nop",
                "9004: from all to 172.18.0.0/30 lookup 2022",
            ]
        );
        let excluded = RuleOptions {
            ipv6: Vec::new(),
            exclude_interface: vec!["eth1".into()],
            ..options()
        };
        assert_eq!(
            listing(&excluded, false)[0],
            "9000: from all iif eth1 goto 9010"
        );
    }

    #[test]
    fn routes_are_all_or_the_included_less_the_excluded() {
        let p = |s: &str| {
            let (address, len) = s.split_once('/').unwrap();
            (
                address.parse::<IpAddr>().unwrap(),
                len.parse::<u8>().unwrap(),
            )
        };
        let show = |prefixes: Vec<(IpAddr, u8)>| {
            prefixes
                .into_iter()
                .map(|(a, l)| format!("{}/{}", a, l))
                .collect::<Vec<_>>()
        };
        assert_eq!(show(routes(false, &[], &[])), ["0.0.0.0/0"]);
        assert_eq!(show(routes(true, &[p("10.0.0.0/8")], &[])), ["::/0"]);
        assert_eq!(
            show(routes(
                false,
                &[p("10.0.0.0/8"), p("10.1.0.0/16"), p("2001:db8::/32")],
                &[p("10.128.0.0/9")]
            )),
            ["10.0.0.0/9"]
        );
    }

    #[test]
    fn included_uids_exclude_the_others() {
        assert_eq!(
            excluded_uids(&[1000..=1999], &[]),
            [(0, 999), (2000, 0xFFFF_FFFE)]
        );
        assert_eq!(
            excluded_uids(&[1000..=1999], &[1500..=1500]),
            [(0, 999), (1500, 1500), (2000, 0xFFFF_FFFE)]
        );
        assert_eq!(excluded_uids(&[], &[5..=6, 1..=2, 3..=4]), [(1, 6)]);
        assert_eq!(excluded_uids(&[0..=0xFFFF_FFFE], &[]), []);
    }
}
