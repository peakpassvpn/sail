//! The requests, as bytes, and the reading of what the kernel answers.
//!
//! Every request here is the one iproute2 6.15 sends for the matching ip(8)
//! command: the same fixed header, the same attributes in the same order,
//! the same flags. The tests hold iproute2's bytes, captured with an
//! `nlmon` device in a network namespace (`tcpdump -i nlmon0`), and the
//! commands they came from. Values inside rtnetlink attributes are in the
//! host's byte order.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::super::nft::netlink::{attr_ne32, attr_str, attrs, Attrs};
use super::super::nft::sys::*;
use super::sys::*;
use super::{invalid, DefaultRoute, Family, Prefix, Route, RouteKind, Rule, RuleAction};

/// One request: the message type, its flags (without `NLM_F_REQUEST`,
/// which every request has), its body, and what it does, for errors.
#[derive(Debug)]
pub(super) struct Request {
    pub ty: u16,
    pub flags: u16,
    pub body: Vec<u8>,
    pub what: String,
}

/// The flags of a request that makes something, as `ip ... add` sends
/// them: fail if it is there already.
const CREATE: u16 = NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

fn addr_bytes(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// Checks `prefix` is of `family` and not longer than its addresses.
fn check_prefix(prefix: &Prefix, family: Family, what: &str) -> io::Result<()> {
    if prefix.family() != family {
        return Err(invalid(format!(
            "{}: {} is not an {} prefix",
            what, prefix, family
        )));
    }
    if prefix.len > family.max_len() {
        return Err(invalid(format!("{}: {}: prefix too long", what, prefix)));
    }
    Ok(())
}

// ---- routes ----

/// `ip route add` (`del`: `ip route del`) of `route`.
///
/// The header: iproute2 (`iproute_modify`) gives an added route protocol
/// `boot` and the scope `link` when it is an IPv4 unicast route without a
/// gateway -- on the link itself -- and `universe` otherwise, IPv6 always.
/// A deleted route has protocol 0 and scope `nowhere`, which match any,
/// and type 0 for a unicast route, which matches any type. A table past
/// 255 does not fit `rtm_table`: it goes in `RTA_TABLE`, the header's
/// table left unspecified. A default route (length 0) has no `RTA_DST`,
/// as `ip route add default` sends it.
pub(super) fn route(route: &Route, add: bool) -> io::Result<Request> {
    let family = route.family();
    let what = format!(
        "{} {}route {} in table {}",
        if add { "adding" } else { "deleting" },
        match route.kind {
            RouteKind::Unicast => "",
            RouteKind::Throw => "throw ",
            RouteKind::Unreachable => "unreachable ",
            RouteKind::Blackhole => "blackhole ",
            RouteKind::Prohibit => "prohibit ",
        },
        route.dst,
        route.table
    );
    check_prefix(&route.dst, family, &what)?;
    if let Some(gateway) = &route.gateway {
        if Family::of(gateway) != family {
            return Err(invalid(format!(
                "{}: gateway {} is not {}",
                what, gateway, family
            )));
        }
    }
    let (protocol, scope, rtn) = if add {
        let scope = if family == Family::V4
            && route.kind == RouteKind::Unicast
            && route.gateway.is_none()
        {
            RT_SCOPE_LINK
        } else {
            RT_SCOPE_UNIVERSE
        };
        (RTPROT_BOOT, scope, route.kind.rtn())
    } else {
        let rtn = match route.kind {
            RouteKind::Unicast => 0,
            kind => kind.rtn(),
        };
        (0, RT_SCOPE_NOWHERE, rtn)
    };
    let small_table = route.table < 256;
    let header = rtmsg(
        family.af(),
        route.dst.len,
        if small_table {
            route.table as u8
        } else {
            RT_TABLE_UNSPEC
        },
        protocol,
        scope,
        rtn,
    );
    let mut a = Attrs::with_header(&header);
    if route.dst.len > 0 {
        a.bytes(RTA_DST, &addr_bytes(&route.dst.addr));
    }
    if let Some(gateway) = &route.gateway {
        a.bytes(RTA_GATEWAY, &addr_bytes(gateway));
    }
    if !small_table {
        a.ne32(RTA_TABLE, route.table);
    }
    if let Some(metric) = route.metric {
        a.ne32(RTA_PRIORITY, metric);
    }
    if let Some(oif) = route.oif {
        a.ne32(RTA_OIF, oif);
    }
    Ok(Request {
        ty: if add { RTM_NEWROUTE } else { RTM_DELROUTE },
        flags: if add { CREATE } else { NLM_F_ACK },
        body: a.into_bytes(),
        what,
    })
}

/// A `struct rtmsg`: family, dst_len, src_len, tos, table, protocol,
/// scope, type, flags.
fn rtmsg(af: u8, dst_len: u8, table: u8, protocol: u8, scope: u8, rtn: u8) -> [u8; RTMSG_LEN] {
    [af, dst_len, 0, 0, table, protocol, scope, rtn, 0, 0, 0, 0]
}

/// A dump of the routes of `family`, of every table: the kernel filters
/// them by table only when asked strictly, so the caller does.
pub(super) fn dump_routes(family: Family, what: String) -> Request {
    Request {
        ty: RTM_GETROUTE,
        flags: NLM_F_DUMP,
        body: rtmsg(family.af(), 0, 0, 0, 0, 0).to_vec(),
        what,
    }
}

/// A route as the kernel dumps it (`RTM_NEWROUTE`), before filtering.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DumpedRoute {
    pub family: Family,
    pub dst: Prefix,
    pub table: u32,
    /// `rtm_type`, which may be a kind `RouteKind` does not have (local,
    /// broadcast...).
    pub rtn: u8,
    pub gateway: Option<IpAddr>,
    pub oif: Option<u32>,
    pub metric: Option<u32>,
    /// It has several next hops (`RTA_MULTIPATH`); the first one's
    /// gateway and interface are those above.
    pub multipath: bool,
}

fn parse_addr(family: Family, payload: &[u8]) -> Option<IpAddr> {
    match family {
        Family::V4 => {
            let b: [u8; 4] = payload.get(..4)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(b)))
        }
        Family::V6 => {
            let b: [u8; 16] = payload.get(..16)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
    }
}

/// Reads an `RTM_NEWROUTE` body. None for another family, or one too
/// short to be a route.
pub(super) fn parse_route(body: &[u8]) -> Option<DumpedRoute> {
    let header = body.get(..RTMSG_LEN)?;
    let family = Family::from_af(header[0])?;
    let mut route = DumpedRoute {
        family,
        dst: Prefix::new(family.unspecified(), header[1]),
        table: header[4] as u32,
        rtn: header[7],
        gateway: None,
        oif: None,
        metric: None,
        multipath: false,
    };
    for (ty, payload) in attrs(&body[RTMSG_LEN..]) {
        match ty {
            RTA_DST => route.dst.addr = parse_addr(family, payload)?,
            RTA_GATEWAY => route.gateway = parse_addr(family, payload),
            RTA_OIF => route.oif = attr_ne32(payload),
            RTA_PRIORITY => route.metric = attr_ne32(payload),
            RTA_TABLE => route.table = attr_ne32(payload)?,
            RTA_MULTIPATH => {
                route.multipath = true;
                // struct rtnexthop: len (u16), flags, hops, ifindex (i32),
                // then the hop's attributes. The first hop only.
                if route.oif.is_none() && route.gateway.is_none() {
                    if let Some(hop) = payload.get(..RTNEXTHOP_LEN) {
                        let len = u16::from_ne_bytes([hop[0], hop[1]]) as usize;
                        route.oif = attr_ne32(&hop[4..8]);
                        let hop_attrs = payload.get(RTNEXTHOP_LEN..len).unwrap_or_default();
                        route.gateway = attrs(hop_attrs)
                            .find(|(ty, _)| *ty == RTA_GATEWAY)
                            .and_then(|(_, p)| parse_addr(family, p));
                    }
                }
            }
            _ => {}
        }
    }
    Some(route)
}

/// The main table's default routes among `dumped`, lowest metric first. A
/// multipath route counts as its first hop; one with no interface -- an
/// unreachable default, say -- is not a way out and is left out.
pub(super) fn default_routes(dumped: impl IntoIterator<Item = DumpedRoute>) -> Vec<DefaultRoute> {
    let mut routes: Vec<DefaultRoute> = dumped
        .into_iter()
        .filter(|r| r.table == RT_TABLE_MAIN && r.dst.len == 0 && r.rtn == RTN_UNICAST)
        .filter_map(|r| {
            Some(DefaultRoute {
                family: r.family,
                oif: r.oif?,
                gateway: r.gateway,
                metric: r.metric.unwrap_or(0),
                table: r.table,
            })
        })
        .collect();
    routes.sort_by_key(|r| r.metric);
    routes
}

/// The routes of `table` among `dumped`, as `Route`s that delete them. A
/// multipath route is given without its hops, which deletes it whole; one
/// of a type `RouteKind` does not have is left out (the kernel puts only
/// local and broadcast routes, in the local table, of those).
pub(super) fn routes_in(dumped: impl IntoIterator<Item = DumpedRoute>, table: u32) -> Vec<Route> {
    dumped
        .into_iter()
        .filter(|r| r.table == table)
        .filter_map(|r| {
            let kind = RouteKind::from_rtn(r.rtn)?;
            Some(Route {
                dst: r.dst,
                gateway: if r.multipath { None } else { r.gateway },
                oif: if r.multipath { None } else { r.oif },
                table: r.table,
                kind,
                metric: r.metric,
            })
        })
        .collect()
}

// ---- rules ----

/// `ip rule add` (`del`: `ip rule del`) of `rule`.
///
/// The header is a `struct fib_rule_hdr` (family, dst_len, src_len, tos,
/// table, res1, res2, action, flags). As iproute2 (`iprule_modify`) has
/// it: a table below 256 goes in the header's `table`, a larger one in
/// `FRA_TABLE` with the header's unspecified; `lookup` is action
/// `FR_ACT_TO_TBL` when adding and left unspecified (0, any) when
/// deleting; `not` is `FIB_RULE_INVERT` in the flags. The attributes
/// follow in the order ip(8) writes them in the tests' commands:
/// priority, selectors, then the action's.
///
/// `FRA_IP_PROTO` is a u8, as iproute2 sends it (`addattr8`) and the
/// kernel's policy has it (`NLA_U8`); vishvananda/netlink sends 4 bytes
/// (rule_linux.go, `FRA_IP_PROTO`), which the kernel reads the first of.
pub(super) fn rule(rule: &Rule, add: bool) -> io::Result<Request> {
    let what = format!(
        "{} rule {} ({})",
        if add { "adding" } else { "deleting" },
        rule.priority,
        rule.family
    );
    for prefix in rule.src.iter().chain(&rule.dst) {
        check_prefix(prefix, rule.family, &what)?;
    }
    let (action, table) = match rule.action {
        RuleAction::Lookup(table) => (if add { FR_ACT_TO_TBL } else { FR_ACT_UNSPEC }, Some(table)),
        RuleAction::Goto(_) => (FR_ACT_GOTO, None),
        RuleAction::Nop => (FR_ACT_NOP, None),
        RuleAction::Unreachable => (FR_ACT_UNREACHABLE, None),
    };
    let header_table = match table {
        Some(t) if t < 256 => t as u8,
        _ => RT_TABLE_UNSPEC,
    };
    let flags = if rule.invert { FIB_RULE_INVERT } else { 0 };
    let mut header = [0u8; RTMSG_LEN];
    header[0] = rule.family.af();
    header[1] = rule.dst.map_or(0, |p| p.len);
    header[2] = rule.src.map_or(0, |p| p.len);
    header[4] = header_table;
    header[7] = action;
    header[8..12].copy_from_slice(&flags.to_ne_bytes());

    let mut a = Attrs::with_header(&header);
    a.ne32(FRA_PRIORITY, rule.priority);
    if let Some(src) = &rule.src {
        a.bytes(FRA_SRC, &addr_bytes(&src.addr));
    }
    if let Some(dst) = &rule.dst {
        a.bytes(FRA_DST, &addr_bytes(&dst.addr));
    }
    if let Some(iif) = &rule.iif {
        a.str(FRA_IIFNAME, iif);
    }
    if let Some(oif) = &rule.oif {
        a.str(FRA_OIFNAME, oif);
    }
    if let Some((mark, mask)) = rule.fwmark {
        a.ne32(FRA_FWMARK, mark);
        a.ne32(FRA_FWMASK, mask);
    }
    if let Some((start, end)) = rule.uid_range {
        // struct fib_rule_uid_range { __u32 start; __u32 end; }
        let mut b = start.to_ne_bytes().to_vec();
        b.extend_from_slice(&end.to_ne_bytes());
        a.bytes(FRA_UID_RANGE, &b);
    }
    if let Some(proto) = rule.ip_proto {
        a.u8(FRA_IP_PROTO, proto);
    }
    // struct fib_rule_port_range { __u16 start; __u16 end; }
    let port_range = |(start, end): (u16, u16)| {
        let mut b = start.to_ne_bytes().to_vec();
        b.extend_from_slice(&end.to_ne_bytes());
        b
    };
    if let Some(sport) = rule.sport {
        a.bytes(FRA_SPORT_RANGE, &port_range(sport));
    }
    if let Some(dport) = rule.dport {
        a.bytes(FRA_DPORT_RANGE, &port_range(dport));
    }
    match (rule.action, table) {
        (_, Some(t)) if t >= 256 => {
            a.ne32(FRA_TABLE, t);
        }
        (RuleAction::Goto(priority), _) => {
            a.ne32(FRA_GOTO, priority);
        }
        _ => {}
    }
    if let Some(len) = rule.suppress_prefixlength {
        a.ne32(FRA_SUPPRESS_PREFIXLEN, len);
    }
    Ok(Request {
        ty: if add { RTM_NEWRULE } else { RTM_DELRULE },
        flags: if add { CREATE } else { NLM_F_ACK },
        body: a.into_bytes(),
        what,
    })
}

/// `ip rule del priority <priority>`: deletes the first rule of `family`
/// at `priority`, whatever it is -- the kernel matches only on what a
/// deletion gives.
pub(super) fn del_rule_at(family: Family, priority: u32) -> Request {
    let mut header = [0u8; RTMSG_LEN];
    header[0] = family.af();
    let mut a = Attrs::with_header(&header);
    a.ne32(FRA_PRIORITY, priority);
    Request {
        ty: RTM_DELRULE,
        flags: NLM_F_ACK,
        body: a.into_bytes(),
        what: format!("deleting the rules at {} ({})", priority, family),
    }
}

// ---- links and addresses ----

/// A `struct ifinfomsg`: family, pad, type (u16), index (i32), flags,
/// change.
fn ifinfomsg(index: u32, flags: u32, change: u32) -> [u8; IFINFOMSG_LEN] {
    let mut h = [0u8; IFINFOMSG_LEN];
    h[0] = AF_UNSPEC;
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    h
}

/// `ip link show <name>`, and `ip link show` of an index: the link, its
/// statistics left out (`IFLA_EXT_MASK`). iproute2 also asks for VF
/// information (`RTEXT_FILTER_VF`), which is not needed here.
pub(super) fn get_link(link: Result<&str, u32>) -> Request {
    let index = link.err().unwrap_or(0);
    let mut a = Attrs::with_header(&ifinfomsg(index, 0, 0));
    a.ne32(IFLA_EXT_MASK, RTEXT_FILTER_SKIP_STATS);
    if let Ok(name) = link {
        a.str(IFLA_IFNAME, name);
    }
    Request {
        ty: RTM_GETLINK,
        flags: NLM_F_ACK,
        body: a.into_bytes(),
        what: match link {
            Ok(name) => format!("looking up link {}", name),
            Err(index) => format!("looking up link {}", index),
        },
    }
}

/// An `RTM_NEWLINK` body's index and name.
pub(super) fn parse_link(body: &[u8]) -> Option<(u32, String)> {
    let header = body.get(..IFINFOMSG_LEN)?;
    let index = attr_ne32(&header[4..8])?;
    let name = attrs(&body[IFINFOMSG_LEN..])
        .find(|(ty, _)| *ty == IFLA_IFNAME)
        .map(|(_, p)| attr_str(p))?;
    Some((index, name))
}

/// `ip link set <link> up [mtu <mtu>]`.
pub(super) fn set_link_up(index: u32, mtu: Option<u32>) -> Request {
    let mut a = Attrs::with_header(&ifinfomsg(index, IFF_UP, IFF_UP));
    if let Some(mtu) = mtu {
        a.ne32(IFLA_MTU, mtu);
    }
    Request {
        ty: RTM_NEWLINK,
        flags: NLM_F_ACK,
        body: a.into_bytes(),
        what: format!("setting link {} up", index),
    }
}

/// `ip addr add <addr> [peer <peer>] dev <link>`: `IFA_LOCAL` is the
/// address, `IFA_ADDRESS` the peer or, without one, the address again.
pub(super) fn add_address(index: u32, addr: Prefix, peer: Option<IpAddr>) -> io::Result<Request> {
    let family = addr.family();
    let what = format!("adding address {} to link {}", addr, index);
    check_prefix(&addr, family, &what)?;
    if let Some(peer) = &peer {
        if Family::of(peer) != family {
            return Err(invalid(format!(
                "{}: peer {} is not {}",
                what, peer, family
            )));
        }
    }
    // struct ifaddrmsg: family, prefixlen, flags, scope, index (u32).
    let mut header = [0u8; IFADDRMSG_LEN];
    header[0] = family.af();
    header[1] = addr.len;
    header[4..8].copy_from_slice(&index.to_ne_bytes());
    let mut a = Attrs::with_header(&header);
    a.bytes(IFA_LOCAL, &addr_bytes(&addr.addr));
    a.bytes(IFA_ADDRESS, &addr_bytes(&peer.unwrap_or(addr.addr)));
    Ok(Request {
        ty: RTM_NEWADDR,
        flags: CREATE,
        body: a.into_bytes(),
        what,
    })
}

#[cfg(test)]
mod tests {
    //! The expected bytes are iproute2 6.15's (Debian 13, x86_64, so the
    //! host-order values are little-endian), captured from an `nlmon`
    //! device in a throwaway network namespace in which `lo` is link 1
    //! and a dummy link, `dummy0`, link 2:
    //!
    //! ```text
    //! ip netns exec NS sh -c 'ip link add nlmon0 type nlmon; ip link set nlmon0 up;
    //!     tcpdump -U -i nlmon0 -w cap.pcap & ...; <the command>'
    //! ```
    //!
    //! Each test names its command. The body is what follows the 16-byte
    //! `nlmsghdr`; the header's flags are given with `NLM_F_REQUEST` (1).

    use std::net::IpAddr;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn prefix(s: &str) -> Prefix {
        let (addr, len) = s.split_once('/').unwrap();
        Prefix::new(ip(addr), len.parse().unwrap())
    }

    /// Checks `req` against what iproute2 sent: the type, the flags with
    /// `NLM_F_REQUEST`, and the body in hex.
    #[track_caller]
    fn same(req: &Request, ty: u16, flags: u16, body: &str) {
        if !cfg!(target_endian = "little") {
            return;
        }
        assert_eq!(req.ty, ty, "type of {}", req.what);
        assert_eq!(req.flags | NLM_F_REQUEST, flags, "flags of {}", req.what);
        assert_eq!(
            req.body
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            body,
            "body of {}",
            req.what
        );
    }

    fn lookup(family: Family, priority: u32, table: u32) -> Rule {
        Rule::new(family, priority, RuleAction::Lookup(table))
    }

    // ---- rules ----

    #[test]
    fn rule_lookup_big_table_uses_fra_table() {
        // ip rule add priority 9000 lookup 2022
        let r = rule(&lookup(Family::V4, 9000, 2022), true).unwrap();
        same(
            &r,
            RTM_NEWRULE,
            0x605,
            "020000000000000100000000080006002823000008000f00e6070000",
        );
        assert_eq!(r.what, "adding rule 9000 (v4)");
    }

    #[test]
    fn rule_delete_leaves_the_lookup_action_unspecified() {
        // ip rule del priority 9000 lookup 2022
        let r = rule(&lookup(Family::V4, 9000, 2022), false).unwrap();
        same(
            &r,
            RTM_DELRULE,
            0x5,
            "020000000000000000000000080006002823000008000f00e6070000",
        );
    }

    #[test]
    fn rule_goto() {
        // ip rule add priority 9001 goto 9010
        let r = Rule::new(Family::V4, 9001, RuleAction::Goto(9010));
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "02000000000000020000000008000600292300000800040032230000",
        );
    }

    #[test]
    fn rule_nop() {
        // ip rule add priority 9002 nop
        let r = Rule::new(Family::V4, 9002, RuleAction::Nop);
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "020000000000000300000000080006002a230000",
        );
    }

    #[test]
    fn rule_unreachable() {
        // ip rule add priority 9003 unreachable
        let r = Rule::new(Family::V4, 9003, RuleAction::Unreachable);
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "020000000000000700000000080006002b230000",
        );
    }

    #[test]
    fn rule_invert_dport_suppress_prefixlength() {
        // ip rule add not priority 9004 dport 53 lookup main
        //     suppress_prefixlength 0
        let mut r = lookup(Family::V4, 9004, 254);
        r.invert = true;
        r.dport = Some((53, 53));
        r.suppress_prefixlength = Some(0);
        // The main table fits the header: no FRA_TABLE.
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "02000000fe00000102000000080006002c230000080018003500350008000e0000000000",
        );
    }

    #[test]
    fn rule_from_and_iif() {
        // ip rule add priority 9005 from 0.0.0.0/32 iif lo lookup 2022
        let mut r = lookup(Family::V4, 9005, 2022);
        r.src = Some(prefix("0.0.0.0/32"));
        r.iif = Some("lo".into());
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "020020000000000100000000080006002d2300000800020000000000\
             070003006c6f000008000f00e6070000",
        );
    }

    #[test]
    fn rule_uid_range() {
        // ip rule add priority 9006 uidrange 1000-2000 lookup 2022
        let mut r = lookup(Family::V4, 9006, 2022);
        r.uid_range = Some((1000, 2000));
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "020000000000000100000000080006002e2300000c001400e8030000d0070000\
             08000f00e6070000",
        );
    }

    #[test]
    fn rule_fwmark_and_mask() {
        // ip rule add priority 9007 fwmark 0x2023/0xffff lookup 2022
        let mut r = lookup(Family::V4, 9007, 2022);
        r.fwmark = Some((0x2023, 0xffff));
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "020000000000000100000000080006002f23000008000a0023200000\
             08001000ffff000008000f00e6070000",
        );
    }

    #[test]
    fn rule_v6_from() {
        // ip -6 rule add priority 9008 from ::/1 lookup 2022
        let mut r = lookup(Family::V6, 9008, 2022);
        r.src = Some(prefix("::/1"));
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "0a00010000000001000000000800060030230000\
             1400020000000000000000000000000000000000\
             08000f00e6070000",
        );
    }

    #[test]
    fn rule_to_oif_ipproto_sport_small_table() {
        // ip rule add priority 9009 to 10.0.0.0/8 oif dummy0 ipproto tcp
        //     sport 1000-2000 lookup 100
        let mut r = lookup(Family::V4, 9009, 100);
        r.dst = Some(prefix("10.0.0.0/8"));
        r.oif = Some("dummy0".into());
        r.ip_proto = Some(6);
        r.sport = Some((1000, 2000));
        same(
            &rule(&r, true).unwrap(),
            RTM_NEWRULE,
            0x605,
            "0208000064000001000000000800060031230000080001000a000000\
             0b00110064756d6d79300000050016000600000008001700e803d007",
        );
    }

    #[test]
    fn rule_prefix_of_the_wrong_family_is_refused() {
        let mut r = lookup(Family::V6, 9000, 2022);
        r.src = Some(prefix("10.0.0.0/8"));
        let e = rule(&r, true).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("adding rule 9000 (v6)"), "{}", e);
        let mut r = lookup(Family::V4, 9000, 2022);
        r.dst = Some(prefix("10.0.0.0/33"));
        assert!(rule(&r, true).is_err());
    }

    #[test]
    fn rule_delete_by_priority_only() {
        let r = del_rule_at(Family::V6, 9001);
        // ip -6 rule del priority 9001 (not captured; laid out as the
        // deletion above, the table and action left unspecified)
        same(
            &r,
            RTM_DELRULE,
            0x5,
            "0a00000000000000000000000800060029230000",
        );
    }

    // ---- routes ----

    #[test]
    fn route_default_dev_big_table() {
        // ip route add default dev dummy0 table 2022
        let r = Route::new(prefix("0.0.0.0/0"), 2022).oif(2);
        let req = route(&r, true).unwrap();
        // Scope link: no gateway.
        same(
            &req,
            RTM_NEWROUTE,
            0x605,
            "020000000003fd010000000008000f00e60700000800040002000000",
        );
        assert_eq!(req.what, "adding route 0.0.0.0/0 in table 2022");
    }

    #[test]
    fn route_via_gateway_with_metric() {
        // ip route add 10.0.0.0/8 via 10.1.0.1 table 2022 metric 5
        let r = Route::new(prefix("10.0.0.0/8"), 2022)
            .gateway(ip("10.1.0.1"))
            .metric(5);
        same(
            &route(&r, true).unwrap(),
            RTM_NEWROUTE,
            0x605,
            "020800000003000100000000080001000a000000080005000a010001\
             08000f00e60700000800060005000000",
        );
        // ip route del 10.0.0.0/8 via 10.1.0.1 table 2022 metric 5
        same(
            &route(&r, false).unwrap(),
            RTM_DELROUTE,
            0x5,
            "020800000000ff0000000000080001000a000000080005000a010001\
             08000f00e60700000800060005000000",
        );
    }

    #[test]
    fn route_throw() {
        // ip route add throw 192.168.0.0/16 table 2022
        let r = Route::new(prefix("192.168.0.0/16"), 2022).kind(RouteKind::Throw);
        same(
            &route(&r, true).unwrap(),
            RTM_NEWROUTE,
            0x605,
            "02100000000300090000000008000100c0a8000008000f00e6070000",
        );
        // ip route del throw 192.168.0.0/16 table 2022
        same(
            &route(&r, false).unwrap(),
            RTM_DELROUTE,
            0x5,
            "021000000000ff090000000008000100c0a8000008000f00e6070000",
        );
    }

    #[test]
    fn route_unreachable() {
        // ip route add unreachable 1.2.3.0/24 table 2022
        let r = Route::new(prefix("1.2.3.0/24"), 2022).kind(RouteKind::Unreachable);
        same(
            &route(&r, true).unwrap(),
            RTM_NEWROUTE,
            0x605,
            "021800000003000700000000080001000102030008000f00e6070000",
        );
    }

    #[test]
    fn route_v6_default_dev() {
        // ip -6 route add ::/0 dev dummy0 table 2022, less the RTA_DST of
        // 16 zero bytes iproute2 sends for "::/0" (and not for "default"):
        // a default route here never has one. The scope is universe, as
        // for any IPv6 route.
        let r = Route::new(prefix("::/0"), 2022).oif(2);
        same(
            &route(&r, true).unwrap(),
            RTM_NEWROUTE,
            0x605,
            "0a0000000003000100000000\
             08000f00e60700000800040002000000",
        );
    }

    #[test]
    fn route_v6_unreachable_with_metric() {
        // ip -6 route add unreachable 2001:db8::/32 table 2022 metric 7
        let r = Route::new(prefix("2001:db8::/32"), 2022)
            .kind(RouteKind::Unreachable)
            .metric(7);
        same(
            &route(&r, true).unwrap(),
            RTM_NEWROUTE,
            0x605,
            "0a20000000030007000000001400010020010db8000000000000000000000000\
             08000f00e60700000800060007000000",
        );
    }

    #[test]
    fn route_small_table_in_the_header() {
        // ip route add 10.9.0.0/16 dev dummy0 table 100
        let r = Route::new(prefix("10.9.0.0/16"), 100).oif(2);
        same(
            &route(&r, true).unwrap(),
            RTM_NEWROUTE,
            0x605,
            "021000006403fd0100000000080001000a0900000800040002000000",
        );
    }

    #[test]
    fn route_gateway_of_the_wrong_family_is_refused() {
        let r = Route::new(prefix("::/0"), 2022).gateway(ip("10.0.0.1"));
        assert_eq!(
            route(&r, true).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn dumped_routes_read_back() {
        // What the kernel dumps is laid out as what is added: the added
        // routes read back as themselves.
        let routes = [
            Route::new(prefix("10.0.0.0/8"), 2022)
                .gateway(ip("10.1.0.1"))
                .metric(5),
            Route::new(prefix("0.0.0.0/0"), 2022).oif(2),
            Route::new(prefix("2001:db8::/32"), 100)
                .kind(RouteKind::Unreachable)
                .metric(7),
        ];
        let dumped: Vec<_> = routes
            .iter()
            .map(|r| parse_route(&route(r, true).unwrap().body).unwrap())
            .collect();
        assert_eq!(dumped[1].rtn, RTN_UNICAST);
        assert_eq!(routes_in(dumped, 2022), routes[..2].to_vec());
    }

    #[test]
    fn dumped_multipath_route_is_its_first_hop() {
        // 0.0.0.0/0 table main, nexthop via 10.1.0.1 dev 3, nexthop via
        // 10.2.0.1 dev 4.
        let mut a = Attrs::with_header(&rtmsg(AF_INET, 0, 254, 3, 0, RTN_UNICAST));
        let mut hops = Vec::new();
        for (gw, dev) in [([10, 1, 0, 1], 3u32), ([10, 2, 0, 1], 4)] {
            hops.extend_from_slice(&16u16.to_ne_bytes());
            hops.extend_from_slice(&[0, 0]);
            hops.extend_from_slice(&dev.to_ne_bytes());
            hops.extend_from_slice(&8u16.to_ne_bytes());
            hops.extend_from_slice(&RTA_GATEWAY.to_ne_bytes());
            hops.extend_from_slice(&gw);
        }
        a.bytes(RTA_MULTIPATH, &hops);
        let dumped = parse_route(&a.into_bytes()).unwrap();
        assert!(dumped.multipath);
        assert_eq!(dumped.oif, Some(3));
        assert_eq!(dumped.gateway, Some(ip("10.1.0.1")));
        let defaults = default_routes([dumped]);
        assert_eq!(
            defaults,
            vec![DefaultRoute {
                family: Family::V4,
                oif: 3,
                gateway: Some(ip("10.1.0.1")),
                metric: 0,
                table: 254,
            }]
        );
    }

    #[test]
    fn default_routes_are_the_main_tables_by_metric() {
        let dumped =
            |dst: &str, table: u32, oif: Option<u32>, metric: Option<u32>, rtn: u8| DumpedRoute {
                family: Family::V4,
                dst: prefix(dst),
                table,
                rtn,
                gateway: None,
                oif,
                metric,
                multipath: false,
            };
        let routes = default_routes([
            dumped("0.0.0.0/0", 254, Some(2), Some(600), RTN_UNICAST),
            dumped("0.0.0.0/0", 254, Some(3), None, RTN_UNICAST),
            dumped("0.0.0.0/0", 2022, Some(4), Some(1), RTN_UNICAST),
            dumped("10.0.0.0/8", 254, Some(5), Some(1), RTN_UNICAST),
            dumped("0.0.0.0/0", 254, None, Some(1), RTN_UNREACHABLE),
        ]);
        let got: Vec<_> = routes.iter().map(|r| (r.oif, r.metric)).collect();
        assert_eq!(got, vec![(3, 0), (2, 600)]);
    }

    // ---- links and addresses ----

    #[test]
    fn address_with_peer() {
        // ip addr add 10.2.0.1/32 peer 10.2.0.2 dev dummy0
        let r = add_address(2, prefix("10.2.0.1/32"), Some(ip("10.2.0.2"))).unwrap();
        same(
            &r,
            RTM_NEWADDR,
            0x605,
            "0220000002000000080002000a020001080001000a020002",
        );
    }

    #[test]
    fn address_without_peer() {
        // ip addr add 172.19.0.1/30 dev dummy0
        let r = add_address(2, prefix("172.19.0.1/30"), None).unwrap();
        same(
            &r,
            RTM_NEWADDR,
            0x605,
            "021e00000200000008000200ac13000108000100ac130001",
        );
        // ip -6 addr add fdfe::1/126 dev dummy0
        let r = add_address(2, prefix("fdfe::1/126"), None).unwrap();
        same(
            &r,
            RTM_NEWADDR,
            0x605,
            "0a7e00000200000014000200fdfe000000000000000000000000000114000100\
             fdfe0000000000000000000000000001",
        );
    }

    #[test]
    fn link_up_with_mtu() {
        // ip link set dummy0 up mtu 1400
        same(
            &set_link_up(2, Some(1400)),
            RTM_NEWLINK,
            0x5,
            "000000000200000001000000010000000800040078050000",
        );
    }

    #[test]
    fn link_by_name() {
        // ip link show dummy0 asks with IFLA_EXT_MASK 9 (VF and skip
        // stats) and without NLM_F_ACK:
        // 0000000000000000000000000000000008001d00090000000b00030064756d6d79300000
        // This asks without VF information, and with an ack, so an answer
        // and an error are read alike.
        same(
            &get_link(Ok("dummy0")),
            RTM_GETLINK,
            0x5,
            "0000000000000000000000000000000008001d00080000000b00030064756d6d79300000",
        );
        let reply = {
            let mut a = Attrs::with_header(&ifinfomsg(2, 0, 0));
            a.str(IFLA_IFNAME, "dummy0");
            a.into_bytes()
        };
        assert_eq!(parse_link(&reply), Some((2, "dummy0".to_owned())));
    }
}
