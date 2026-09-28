//! The nftables ruleset of Linux `auto_redirect`: sing-tun's (v0.9.6, the
//! version whose NFQUEUE pre-match works), with the same chains, sets,
//! marks and rule order, as one `inet` table.
//!
//! TCP that is not excluded is redirected to sail's redirect listener;
//! UDP and ICMP get the input mark, which an ip rule routes into the TUN;
//! sail's own sockets carry the output mark and are left alone. With
//! NFQUEUE, the first packet of a flow is first handed to sail, whose
//! verdict marks it: output mark to bypass, reset mark to reject, input
//! mark to take it; the pre-match chains copy the mark into the conntrack
//! entry, so the flow's later packets follow it.
//!
//! This is a pure builder: options in, an `nft::Batch` out, which the
//! caller commits. It knows nothing of sail's configuration; the caller
//! finds the interfaces' addresses, the redirect port and whether NFQUEUE
//! can be bound.
//!
//! What it leaves out of sing-tun: the iptables and Android paths, the mode
//! without marks, the OpenWrt fw4 drop-in and the Docker rules, and the
//! MAC address lists.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod addr;
mod ruleset;
#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

use crate::platform::nft;

/// What the ruleset is built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulesetOptions {
    /// The `inet` table's name.
    pub table: String,
    pub tun_name: String,
    /// The TUN's IPv4 address and prefix length; `None` leaves IPv4 alone.
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// The TUN's IPv6 address and prefix length; `None` leaves IPv6 alone.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// Routes a packet into the TUN.
    pub input_mark: u32,
    /// sail's own traffic, and flows sail bypassed: left alone.
    pub output_mark: u32,
    /// A flow sail rejected: answered with a TCP reset.
    pub reset_mark: u32,
    /// The NFQUEUE the pre-match chains queue to. `None` when it cannot be
    /// bound: then there is no pre-match, and every flow is taken.
    pub nfqueue: Option<u16>,
    /// The redirect listener's port.
    pub redirect_port: u16,
    /// DNAT DNS (port 53) to the address after the TUN's own, when that is
    /// inside its prefix.
    pub dns_hijack: bool,
    /// Leave MPTCP alone rather than drop it (so it falls back to TCP).
    pub exclude_mptcp: bool,
    /// With one family only, reject the other.
    pub strict_route: bool,
    /// TCP to these is routed into the TUN rather than redirected.
    pub loopback_address: Vec<IpAddr>,
    /// Only these destinations are taken...
    pub route_address: Vec<(IpAddr, u8)>,
    /// ...and not these.
    pub route_exclude_address: Vec<(IpAddr, u8)>,
    /// The rule-sets' destinations, in named sets `update_route_address_sets`
    /// refills; `None` when no rule-set was configured.
    pub route_address_set: Option<AddressSet>,
    pub route_exclude_address_set: Option<AddressSet>,
    /// Forwarded traffic is taken only from these interfaces...
    pub include_interface: Vec<String>,
    /// ...and not from these. Naming `lo` in either leaves out the host's
    /// own traffic.
    pub exclude_interface: Vec<String>,
    /// The host's traffic is taken only from these users...
    pub include_uid: Vec<RangeInclusive<u32>>,
    /// ...and not from these.
    pub exclude_uid: Vec<RangeInclusive<u32>>,
    /// The prefixes of the host's interfaces -- `lo`'s, and the global
    /// unicast ones of the others. Their subnets are local destinations,
    /// never taken, and the LAN whose DNS is hijacked.
    pub local_prefixes: Vec<(IpAddr, u8)>,
}

/// The destinations of rule-sets, for one of the named sets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressSet {
    pub prefixes: Vec<(IpAddr, u8)>,
}

/// Options the ruleset cannot be built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidOptions(pub String);

impl std::fmt::Display for InvalidOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "auto_redirect: {}", self.0)
    }
}

impl std::error::Error for InvalidOptions {}

/// A batch that deletes the table if it is there, left from an earlier
/// run, and creates it with everything in it, as one transaction.
pub fn setup(o: &RulesetOptions) -> Result<nft::Batch, InvalidOptions> {
    check(o)?;
    Ok(ruleset::build(o).batch)
}

/// A batch that refills the local address sets with the interfaces'
/// prefixes as they are now. The chains stay.
pub fn update_local_prefixes(o: &RulesetOptions, prefixes: &[(IpAddr, u8)]) -> nft::Batch {
    ruleset::update_local_prefixes(o, prefixes)
}

/// A batch that refills the rule-set sets: each given one, of those `o`
/// has (a set not made at setup cannot be filled later).
pub fn update_route_address_sets(
    o: &RulesetOptions,
    include: Option<&AddressSet>,
    exclude: Option<&AddressSet>,
) -> nft::Batch {
    ruleset::update_route_address_sets(o, include, exclude)
}

/// A batch that deletes the table, if it is there.
pub fn cleanup(table: &str) -> nft::Batch {
    let mut batch = nft::Batch::new();
    batch.del_table_if_exists(&nft::Table::new(nft::Family::Inet, table));
    batch
}

/// The ruleset `setup` builds, written about as nft(8) lists it, for logs
/// and tests: the sets, then the chains, each rule on its line.
pub fn render(o: &RulesetOptions) -> Result<String, InvalidOptions> {
    check(o)?;
    Ok(ruleset::build(o).text())
}

/// Whether the ruleset is not what it is meant to be.
fn check(o: &RulesetOptions) -> Result<(), InvalidOptions> {
    let bad = |s: String| Err(InvalidOptions(s));
    if o.table.is_empty() {
        return bad("the table has no name".into());
    }
    if o.ipv4.is_none() && o.ipv6.is_none() {
        return bad("the TUN has no address".into());
    }
    let names = std::iter::once(&o.tun_name)
        .chain(&o.include_interface)
        .chain(&o.exclude_interface);
    for name in names {
        if name.is_empty() || nft::ifname(name).is_none() {
            return bad(format!("\"{}\" is not an interface name", name));
        }
    }
    if o.tun_name == "lo" {
        return bad("the TUN cannot be lo".into());
    }
    let marks = [
        ("input", o.input_mark),
        ("output", o.output_mark),
        ("reset", o.reset_mark),
    ];
    for (i, (name, mark)) in marks.iter().enumerate() {
        if *mark == 0 {
            return bad(format!("the {} mark is 0", name));
        }
        if let Some((other, _)) = marks[..i].iter().find(|(_, m)| m == mark) {
            return bad(format!(
                "the {} and {} marks are the same, {:#x}",
                other, name, mark
            ));
        }
    }
    if o.redirect_port == 0 {
        return bad("the redirect port is 0".into());
    }
    let tun = o
        .ipv4
        .map(|(a, len)| (IpAddr::V4(a), len))
        .into_iter()
        .chain(o.ipv6.map(|(a, len)| (IpAddr::V6(a), len)));
    let sets = [&o.route_address_set, &o.route_exclude_address_set];
    let prefixes = tun
        .chain(o.route_address.iter().copied())
        .chain(o.route_exclude_address.iter().copied())
        .chain(o.local_prefixes.iter().copied())
        .chain(
            sets.into_iter()
                .flatten()
                .flat_map(|s| s.prefixes.iter().copied()),
        );
    for (addr, len) in prefixes {
        if len > if addr.is_ipv4() { 32 } else { 128 } {
            return bad(format!("{}/{} is not a prefix", addr, len));
        }
    }
    for r in o.include_uid.iter().chain(&o.exclude_uid) {
        if r.start() > r.end() {
            return bad(format!("uid range {}-{} is empty", r.start(), r.end()));
        }
    }
    Ok(())
}
