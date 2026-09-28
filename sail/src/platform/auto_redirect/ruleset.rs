//! The ruleset, rule by rule, as sing-tun v0.9.6 builds it
//! (redirect_nftables.go, redirect_nftables_rules.go). Each piece of a
//! rule is built with the words nft(8) lists it with -- none for a check
//! nft leaves out as implied by the next, such as the family before `ip
//! daddr` -- so `render` shows what the batch holds, as the kernel will.

use std::net::IpAddr;

use super::addr;
use super::{AddressSet, RulesetOptions};
use crate::platform::nft::*;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// `IPS_DST_NAT`: the connection's destination was NATed -- redirected.
const IPS_DST_NAT: u32 = 1 << 5;
const DNS_PORT: u16 = 53;

// Standard priorities.
const MANGLE: i32 = -150;
const DSTNAT: i32 = -100;
const FILTER: i32 = 0;

const PREROUTING_PREMATCH: &str = "prerouting_prematch";
const OUTPUT_PREMATCH: &str = "output_prematch";

/// The families, as the ruleset tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fam {
    V4,
    V6,
}

use Fam::*;

impl Fam {
    fn nfproto(self) -> Family {
        match self {
            V4 => Family::Ipv4,
            V6 => Family::Ipv6,
        }
    }

    fn is_v6(self) -> bool {
        self == V6
    }

    fn of(addr: &IpAddr) -> Fam {
        if addr.is_ipv6() {
            V6
        } else {
            V4
        }
    }

    /// `meta nfproto`'s word.
    fn word(self) -> &'static str {
        match self {
            V4 => "ipv4",
            V6 => "ipv6",
        }
    }

    /// The header's word: `ip daddr`, `ip6 daddr`.
    fn ip(self) -> &'static str {
        match self {
            V4 => "ip",
            V6 => "ip6",
        }
    }

    fn key(self) -> KeyType {
        match self {
            V4 => KeyType::IPV4_ADDR,
            V6 => KeyType::IPV6_ADDR,
        }
    }

    /// (offset, length) of the source address in the network header; the
    /// destination follows it.
    fn saddr(self) -> (u32, u32) {
        match self {
            V4 => (12, 4),
            V6 => (8, 16),
        }
    }

    fn local_set(self) -> &'static str {
        match self {
            V4 => "inet4_local_address_set",
            V6 => "inet6_local_address_set",
        }
    }

    fn route_set(self) -> &'static str {
        match self {
            V4 => "inet4_route_address_set",
            V6 => "inet6_route_address_set",
        }
    }

    fn route_exclude_set(self) -> &'static str {
        match self {
            V4 => "inet4_route_exclude_address_set",
            V6 => "inet6_route_exclude_address_set",
        }
    }

    fn loopback_set(self) -> &'static str {
        match self {
            V4 => "inet4_local_redirect_address_set",
            V6 => "inet6_local_redirect_address_set",
        }
    }
}

/// One of the named sets, by family.
type SetName = fn(Fam) -> &'static str;

/// A piece of a rule: its expressions, and nft(8)'s words for them.
struct Part {
    exprs: Vec<Expr>,
    text: String,
}

fn part(exprs: impl Into<Vec<Expr>>, text: impl Into<String>) -> Part {
    Part {
        exprs: exprs.into(),
        text: text.into(),
    }
}

/// A check nft(8) leaves out of its listing, the next piece implying it.
fn implied(mut p: Part) -> Part {
    p.text.clear();
    p
}

fn not(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "",
        CmpOp::Neq => "!= ",
    }
}

fn mark_text(mark: u32) -> String {
    format!("{:#010x}", mark)
}

fn counter() -> Part {
    part([Expr::Counter], "counter")
}

fn then(v: Verdict) -> Part {
    let word = match &v {
        Verdict::Accept => "accept",
        Verdict::Drop => "drop",
        Verdict::Return => "return",
        Verdict::Jump(_) | Verdict::Goto(_) => unreachable!("the ruleset has one level"),
    };
    part([verdict(v)], word)
}

fn ret() -> Part {
    then(Verdict::Return)
}

fn nfproto(fam: Fam) -> Part {
    part(
        meta_cmp(MetaKey::NfProto, CmpOp::Eq, vec![fam.nfproto() as u8]),
        format!("meta nfproto {}", fam.word()),
    )
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        TCP => "tcp",
        UDP => "udp",
        ICMP => "icmp",
        ICMPV6 => "ipv6-icmp",
        _ => unreachable!("not a protocol of the ruleset"),
    }
}

fn l4proto(proto: u8) -> Part {
    part(
        meta_cmp(MetaKey::L4Proto, CmpOp::Eq, vec![proto]),
        format!("meta l4proto {}", proto_name(proto)),
    )
}

/// `iifname`, or `oifname` when `key` says so.
fn ifname_is(key: MetaKey, op: CmpOp, name: &str) -> Part {
    let word = if key == MetaKey::OifName {
        "oifname"
    } else {
        "iifname"
    };
    // The names were checked.
    part(
        meta_cmp(key, op, ifname(name).expect("a checked interface name")),
        format!("{} {}\"{}\"", word, not(op), name),
    )
}

fn mark_is(op: CmpOp, mark: u32) -> Part {
    part(
        meta_cmp(MetaKey::Mark, op, host_u32(mark)),
        format!("meta mark {}{}", not(op), mark_text(mark)),
    )
}

fn ct_mark_is(op: CmpOp, mark: u32) -> Part {
    part(
        ct_cmp(CtKey::Mark, op, host_u32(mark)),
        format!("ct mark {}{}", not(op), mark_text(mark)),
    )
}

/// `meta mark set <mark>`.
fn set_mark(mark: u32) -> Part {
    part(
        [
            Expr::Immediate {
                dreg: Reg::R1,
                data: host_u32(mark),
            },
            Expr::MetaSet {
                key: MetaKey::Mark,
                sreg: Reg::R1,
            },
        ],
        format!("meta mark set {}", mark_text(mark)),
    )
}

fn ct_mark_set_meta_mark() -> Part {
    part(
        [
            meta(MetaKey::Mark),
            Expr::CtSet {
                key: CtKey::Mark,
                sreg: Reg::R1,
            },
        ],
        "ct mark set meta mark",
    )
}

fn meta_mark_set_ct_mark() -> Part {
    part(
        [
            ct(CtKey::Mark),
            Expr::MetaSet {
                key: MetaKey::Mark,
                sreg: Reg::R1,
            },
        ],
        "meta mark set ct mark",
    )
}

fn payload(base: PayloadBase, offset: u32, len: u32) -> Expr {
    Expr::Payload {
        base,
        offset,
        len,
        dreg: Reg::R1,
    }
}

/// `th dport <port>`, or `tcp dport` after the protocol's check.
fn dport(proto: &str, port_: u16) -> Part {
    part(
        [
            payload(PayloadBase::Transport, 2, 2),
            cmp(CmpOp::Eq, port(port_)),
        ],
        format!("{} dport {}", proto, port_),
    )
}

/// `ip daddr` (or `saddr`) in a set, or not. The family must have been
/// checked before.
fn addr_in(fam: Fam, source: bool, set: &SetRef, invert: bool, set_text: &str) -> Part {
    let (offset, len) = fam.saddr();
    let (offset, word) = if source {
        (offset, "saddr")
    } else {
        (offset + len, "daddr")
    };
    part(
        [
            payload(PayloadBase::Network, offset, len),
            lookup(set, invert),
        ],
        format!(
            "{} {} {}{}",
            fam.ip(),
            word,
            if invert { "!= " } else { "" },
            set_text
        ),
    )
}

/// `tcp option mptcp exists`.
fn mptcp() -> Part {
    let mut p = implied(l4proto(TCP));
    p.exprs.extend([
        Expr::Exthdr {
            op: ExthdrOp::TcpOpt,
            ty: 30,
            offset: 0,
            len: 1,
            flags: EXTHDR_F_PRESENT,
            dreg: Reg::R1,
        },
        cmp(CmpOp::Eq, vec![1]),
    ]);
    p.text = "tcp option mptcp exists".into();
    p
}

fn queue(num: u16) -> Part {
    part(
        [Expr::Queue {
            num,
            total: 0,
            flags: QUEUE_FLAG_BYPASS,
        }],
        format!("queue flags bypass to {}", num),
    )
}

/// The TUN's address after its own, where DNS goes: sing-tun's
/// `Inet{4,6}DNSAddress` without a DNS address of its own. None when it
/// falls outside the prefix.
fn dns_target(addr: IpAddr, len: u8) -> Option<IpAddr> {
    let prefix = addr::ranges(&[(addr, len)], addr.is_ipv6())[0];
    let next = addr::number(addr).checked_add(1)?;
    (next <= prefix.last).then(|| addr::address(prefix.v6, next))
}

/// A priority as nft(8) writes it: by the standard one it is near.
fn priority_text(prio: i32) -> String {
    for (name, standard) in [("mangle", MANGLE), ("dstnat", DSTNAT), ("filter", FILTER)] {
        let offset = prio - standard;
        if offset.abs() <= 10 {
            return match offset {
                0 => name.to_string(),
                o if o > 0 => format!("{} + {}", name, o),
                o => format!("{} - {}", name, -o),
            };
        }
    }
    prio.to_string()
}

/// One chain being filled: what the shared rules need to know of it.
#[derive(Clone, Copy)]
struct ChainInfo {
    name: &'static str,
    ty: ChainType,
    hook: Hook,
}

/// A ruleset as it is built: the batch, and its text.
pub(super) struct Built {
    pub batch: Batch,
    table: String,
    sets: Vec<String>,
    chains: Vec<(String, Vec<String>)>,
}

impl Built {
    pub fn text(&self) -> String {
        let mut out = format!("table inet {} {{\n", self.table);
        for set in &self.sets {
            out += set;
        }
        for (header, rules) in &self.chains {
            out += header;
            for rule in rules {
                out += "\t\t";
                out += rule;
                out += "\n";
            }
            out += "\t}\n";
        }
        out += "}\n";
        out
    }
}

struct Builder<'a> {
    o: &'a RulesetOptions,
    table: Table,
    built: Built,
    /// The named sets made so far, which rules look up by the batch's id.
    named: Vec<SetRef>,
}

pub(super) fn build(o: &RulesetOptions) -> Built {
    let mut b = Builder {
        o,
        table: Table::new(Family::Inet, o.table.as_str()),
        built: Built {
            batch: Batch::new(),
            table: o.table.clone(),
            sets: Vec::new(),
            chains: Vec::new(),
        },
        named: Vec::new(),
    };
    b.build();
    b.built
}

impl Builder<'_> {
    fn families(&self) -> Vec<Fam> {
        families(self.o)
    }

    /// The family left out when only one is there.
    fn missing(&self) -> Option<Fam> {
        match (self.o.ipv4.is_some(), self.o.ipv6.is_some()) {
            (true, false) => Some(V6),
            (false, true) => Some(V4),
            _ => None,
        }
    }

    fn loopback(&self, fam: Fam) -> Vec<IpAddr> {
        self.o
            .loopback_address
            .iter()
            .filter(|a| Fam::of(a) == fam)
            .copied()
            .collect()
    }

    /// sing-tun's `shouldSkipOutputChain`: the host's own traffic is left
    /// alone when `lo` is not among the included interfaces, or is
    /// excluded.
    fn skip_output(&self) -> bool {
        let lo = |names: &[String]| names.iter().any(|n| n == "lo");
        (!self.o.include_interface.is_empty() && !lo(&self.o.include_interface))
            || lo(&self.o.exclude_interface)
    }

    fn build(&mut self) {
        let o = self.o;
        self.built.batch.del_table_if_exists(&self.table);
        self.built.batch.add_table(&self.table);

        // Named sets, in sing-tun's order (its ids 1 to 8).
        for (set, name) in [
            (&o.route_address_set, Fam::route_set as SetName),
            (&o.route_exclude_address_set, Fam::route_exclude_set),
        ] {
            if let Some(set) = set {
                for fam in self.families() {
                    let ranges = addr::ranges(&set.prefixes, fam.is_v6());
                    self.named_interval_set(name(fam), fam, &ranges);
                }
            }
        }
        for fam in self.families() {
            let ranges = addr::ranges(&o.local_prefixes, fam.is_v6());
            self.named_interval_set(fam.local_set(), fam, &ranges);
        }
        for fam in self.families() {
            let addrs = self.loopback(fam);
            if !addrs.is_empty() {
                self.loopback_set(fam, &addrs);
            }
        }

        let nfqueue = o.nfqueue.is_some();
        if let Some(num) = o.nfqueue {
            let c = self.chain(
                PREROUTING_PREMATCH,
                ChainType::Filter,
                Hook::Prerouting,
                DSTNAT - 1,
            );
            self.prematch_rules(c, num);
            if !self.skip_output() {
                // A route chain, below the NAT hook, so that the mark a
                // verdict sets reroutes the packet.
                let c = self.chain(OUTPUT_PREMATCH, ChainType::Route, Hook::Output, MANGLE + 1);
                self.prematch_rules(c, num);
            }
        }

        let has_loopback = !o.loopback_address.is_empty();
        if !self.skip_output() {
            // After output_prematch when it is there.
            let prio = if nfqueue { MANGLE + 2 } else { MANGLE };
            let c = self.chain("output", ChainType::Nat, Hook::Output, prio);
            self.exclude_rules(c);
            self.unreachable(c);
            self.redirect(c);
            if has_loopback {
                let c = self.chain("output_route", ChainType::Route, Hook::Output, prio);
                self.loopback_reroute(c);
            }
            let c = self.chain("output_udp_icmp", ChainType::Route, Hook::Output, prio);
            self.exclude_rules(c);
            self.unreachable(c);
            self.mark(c);
        }

        let c = self.chain("input", ChainType::Filter, Hook::Input, FILTER);
        self.redirect_port_reject(c);

        let (nat_prio, udp_prio) = if nfqueue {
            (DSTNAT + 2, DSTNAT + 3)
        } else {
            (DSTNAT + 1, DSTNAT + 2)
        };
        let c = self.chain("prerouting", ChainType::Nat, Hook::Prerouting, nat_prio);
        self.exclude_rules(c);
        self.unreachable(c);
        self.redirect(c);
        self.mark(c);
        if has_loopback {
            let c = self.chain(
                "prerouting_filter",
                ChainType::Filter,
                Hook::Prerouting,
                nat_prio,
            );
            self.loopback_reroute(c);
        }
        let c = self.chain(
            "prerouting_udp_icmp",
            ChainType::Filter,
            Hook::Prerouting,
            udp_prio,
        );
        self.prerouting_udp_icmp(c);
    }

    // -- Sets.

    fn named_interval_set(&mut self, name: &'static str, fam: Fam, ranges: &[addr::Range]) {
        let set =
            self.built
                .batch
                .add_set(&self.table, &Set::named(name, fam.key()).interval(), &[]);
        let elems = addr::elems(ranges);
        if !elems.is_empty() {
            self.built.batch.add_elements(&self.table, &set, &elems);
        }
        self.named.push(set);
        let texts: Vec<String> = ranges.iter().map(addr::text).collect();
        self.set_text(name, fam, "interval", &texts);
    }

    fn loopback_set(&mut self, fam: Fam, addrs: &[IpAddr]) {
        let name = fam.loopback_set();
        let elems: Vec<SetElem> = addrs
            .iter()
            .map(|a| match a {
                IpAddr::V4(a) => SetElem::new(a.octets()),
                IpAddr::V6(a) => SetElem::new(a.octets()),
            })
            .collect();
        let set =
            self.built
                .batch
                .add_set(&self.table, &Set::named(name, fam.key()).constant(), &elems);
        self.named.push(set);
        let texts: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
        self.set_text(name, fam, "constant", &texts);
    }

    fn set_text(&mut self, name: &str, fam: Fam, flags: &str, elems: &[String]) {
        let ty = match fam {
            V4 => "ipv4_addr",
            V6 => "ipv6_addr",
        };
        let mut text = format!("\tset {} {{\n\t\ttype {}\n\t\tflags {}\n", name, ty, flags);
        if !elems.is_empty() {
            text += &format!("\t\telements = {{ {} }}\n", elems.join(", "));
        }
        text += "\t}\n";
        self.built.sets.push(text);
    }

    /// A named set made in this batch, by the id the batch gave it.
    fn named(&self, name: &str) -> SetRef {
        self.named
            .iter()
            .find(|s| s.name() == name)
            .cloned()
            .unwrap_or_else(|| SetRef::named(name))
    }

    /// An anonymous set, which one rule can look up: a new one each time.
    fn anon(&mut self, key: KeyType, interval: bool, elems: &[SetElem]) -> SetRef {
        let mut set = Set::anonymous(key);
        if interval {
            set = set.interval();
        }
        self.built.batch.add_set(&self.table, &set, elems)
    }

    /// `meta l4proto { ... }`, or not in it.
    fn l4proto_in(&mut self, protos: &[u8], invert: bool) -> Part {
        let elems: Vec<SetElem> = protos.iter().map(|p| SetElem::new([*p])).collect();
        let set = self.anon(KeyType::INET_PROTO, false, &elems);
        // nft(8) lists them in order.
        let mut sorted = protos.to_vec();
        sorted.sort();
        let names: Vec<&str> = sorted.iter().map(|p| proto_name(*p)).collect();
        part(
            [meta(MetaKey::L4Proto), lookup(&set, invert)],
            format!(
                "meta l4proto {}{{ {} }}",
                if invert { "!= " } else { "" },
                names.join(", ")
            ),
        )
    }

    /// `iifname { ... }`, or not in it.
    fn iifname_in(&mut self, names: &[String], invert: bool) -> Part {
        let elems: Vec<SetElem> = names
            .iter()
            .map(|n| SetElem::new(ifname(n).expect("a checked interface name")))
            .collect();
        let set = self.anon(KeyType::IFNAME, false, &elems);
        let quoted: Vec<String> = names.iter().map(|n| format!("\"{}\"", n)).collect();
        part(
            [meta(MetaKey::IifName), lookup(&set, invert)],
            format!(
                "iifname {}{{ {} }}",
                if invert { "!= " } else { "" },
                quoted.join(", ")
            ),
        )
    }

    /// `meta skuid` is, or is not, among `uids`: one uid compares, more
    /// or a range look up an interval set -- of big-endian keys, so the
    /// uid is converted first, as nft(8) does. (sing-tun's set holds
    /// host-order keys, which the kernel orders wrongly on little-endian
    /// hosts.)
    fn uid_in(&mut self, uids: &[std::ops::RangeInclusive<u32>], invert: bool) -> Part {
        let op = if invert { CmpOp::Neq } else { CmpOp::Eq };
        if let [one] = uids {
            if one.start() == one.end() {
                return part(
                    meta_cmp(MetaKey::SkUid, op, host_u32(*one.start())),
                    format!("meta skuid {}{}", not(op), one.start()),
                );
            }
        }
        let ranges = addr::uid_ranges(uids);
        let key = KeyType {
            byteorder: ByteOrder::Big,
            ..KeyType::UID
        };
        let set = self.anon(key, true, &addr::uid_elems(&ranges));
        let texts: Vec<String> = ranges.iter().map(addr::uid_text).collect();
        part(
            [
                meta(MetaKey::SkUid),
                Expr::Byteorder {
                    sreg: Reg::R1,
                    dreg: Reg::R1,
                    op: ByteorderOp::Hton,
                    len: 4,
                    size: 4,
                },
                lookup(&set, invert),
            ],
            format!("meta skuid {}{{ {} }}", not(op), texts.join(", ")),
        )
    }

    /// `meta nfproto <fam> ip daddr { prefixes }`, or not in it, in an
    /// anonymous set.
    fn daddr_in_prefixes(&mut self, fam: Fam, ranges: &[addr::Range], invert: bool) -> Vec<Part> {
        let set = self.anon(fam.key(), true, &addr::elems(ranges));
        let texts: Vec<String> = ranges.iter().map(addr::text).collect();
        let text = format!("{{ {} }}", texts.join(", "));
        vec![
            implied(nfproto(fam)),
            addr_in(fam, false, &set, invert, &text),
        ]
    }

    /// `meta nfproto <fam> ip daddr @set`, or not in it.
    fn daddr_in_named(&self, fam: Fam, name: &str, invert: bool) -> Vec<Part> {
        let text = format!("@{}", name);
        vec![
            implied(nfproto(fam)),
            addr_in(fam, false, &self.named(name), invert, &text),
        ]
    }

    // -- Chains and rules.

    fn chain(&mut self, name: &'static str, ty: ChainType, hook: Hook, prio: i32) -> ChainInfo {
        self.built
            .batch
            .add_chain(&self.table, &Chain::base(name, ty, hook, prio));
        let ty_word = match ty {
            ChainType::Filter => "filter",
            ChainType::Nat => "nat",
            ChainType::Route => "route",
        };
        let hook_word = match hook {
            Hook::Prerouting => "prerouting",
            Hook::Input => "input",
            Hook::Forward => "forward",
            Hook::Output => "output",
            Hook::Postrouting => "postrouting",
        };
        self.built.chains.push((
            format!(
                "\tchain {} {{\n\t\ttype {} hook {} priority {}; policy accept;\n",
                name,
                ty_word,
                hook_word,
                priority_text(prio)
            ),
            Vec::new(),
        ));
        ChainInfo { name, ty, hook }
    }

    fn rule(&mut self, c: ChainInfo, parts: Vec<Part>) {
        let mut exprs = Vec::new();
        let mut words = Vec::new();
        for p in parts {
            exprs.extend(p.exprs);
            if !p.text.is_empty() {
                words.push(p.text);
            }
        }
        self.built.batch.add_rule(&self.table, c.name, &exprs);
        let (_, rules) = self.built.chains.last_mut().expect("a chain");
        rules.push(words.join(" "));
    }

    /// sing-tun's `nftablesCreateExcludeRules`: what a chain leaves alone,
    /// shared by the NAT, route and pre-match chains, each taking the
    /// rules that apply to it.
    fn exclude_rules(&mut self, c: ChainInfo) {
        let o = self.o;
        // sail's own traffic.
        if c.hook == Hook::Output && c.ty != ChainType::Filter && c.name != OUTPUT_PREMATCH {
            if c.ty == ChainType::Route {
                let p = self.l4proto_in(&[UDP, ICMP, ICMPV6], true);
                self.rule(c, vec![p, ret()]);
            }
            self.rule(c, vec![mark_is(CmpOp::Eq, o.output_mark), counter(), ret()]);
            if c.ty == ChainType::Route {
                self.rule(
                    c,
                    vec![ct_mark_is(CmpOp::Eq, o.output_mark), counter(), ret()],
                );
            }
        }
        // Flows the pre-match judged, bypassed or taken already.
        if o.nfqueue.is_some() && c.ty == ChainType::Nat {
            for mark in [o.output_mark, o.input_mark] {
                self.rule(c, vec![ct_mark_is(CmpOp::Eq, mark), counter(), ret()]);
            }
        }

        if c.hook == Hook::Prerouting {
            self.rule(
                c,
                vec![
                    ifname_is(MetaKey::IifName, CmpOp::Eq, &o.tun_name),
                    counter(),
                    ret(),
                ],
            );
            match o.include_interface.as_slice() {
                [] => {}
                [one] => self.rule(
                    c,
                    vec![
                        ifname_is(MetaKey::IifName, CmpOp::Neq, one),
                        counter(),
                        ret(),
                    ],
                ),
                names => {
                    let p = self.iifname_in(names, true);
                    self.rule(c, vec![p, counter(), ret()]);
                }
            }
            match o.exclude_interface.as_slice() {
                [] => {}
                [one] => self.rule(
                    c,
                    vec![
                        ifname_is(MetaKey::IifName, CmpOp::Eq, one),
                        counter(),
                        ret(),
                    ],
                ),
                names => {
                    let p = self.iifname_in(names, false);
                    self.rule(c, vec![p, counter(), ret()]);
                }
            }
        } else {
            if !o.include_uid.is_empty() {
                let p = self.uid_in(&o.include_uid, true);
                self.rule(c, vec![p, counter(), ret()]);
            }
            if !o.exclude_uid.is_empty() {
                let p = self.uid_in(&o.exclude_uid, false);
                self.rule(c, vec![p, counter(), ret()]);
            }
        }

        // route_address and route_exclude_address, of whichever family
        // they name.
        for (prefixes, invert) in [(&o.route_address, true), (&o.route_exclude_address, false)] {
            for fam in [V4, V6] {
                let ranges = addr::ranges(prefixes, fam.is_v6());
                if !ranges.is_empty() {
                    let mut p = self.daddr_in_prefixes(fam, &ranges, invert);
                    p.extend([counter(), ret()]);
                    self.rule(c, p);
                }
            }
        }

        if o.dns_hijack
            && (c.ty == ChainType::Nat || c.ty == ChainType::Filter || c.name == OUTPUT_PREMATCH)
            && matches!(c.hook, Hook::Prerouting | Hook::Output)
        {
            for fam in self.families() {
                self.dns_hijack(c, fam);
            }
        }

        // Local destinations, then the rule-sets.
        // (the set of a family, whether it is the ones not in it that
        // return)
        let mut named: Vec<(SetName, bool)> = vec![(Fam::local_set, false)];
        if o.route_address_set.is_some() {
            named.push((Fam::route_set, true));
        }
        if o.route_exclude_address_set.is_some() {
            named.push((Fam::route_exclude_set, false));
        }
        for (set, invert) in named {
            for fam in self.families() {
                let mut p = self.daddr_in_named(fam, set(fam), invert);
                p.extend([counter(), ret()]);
                self.rule(c, p);
            }
        }

        // MPTCP cannot be redirected: dropped, so it falls back to TCP, or
        // left alone.
        if c.ty == ChainType::Nat || o.exclude_mptcp {
            let v = if o.exclude_mptcp {
                Verdict::Return
            } else {
                Verdict::Drop
            };
            self.rule(c, vec![mptcp(), counter(), then(v)]);
        }
    }

    /// DNS to the TUN's next address: DNAT in a NAT chain; elsewhere --
    /// the pre-match chains -- only returns, so DNS is not judged there.
    /// In prerouting, only from the local subnets; in output, not over
    /// `lo`, which cannot be DNATed away.
    fn dns_hijack(&mut self, c: ChainInfo, fam: Fam) {
        let tun = match fam {
            V4 => self.o.ipv4.map(|(a, len)| (IpAddr::V4(a), len)),
            V6 => self.o.ipv6.map(|(a, len)| (IpAddr::V6(a), len)),
        };
        let Some(target) = tun.and_then(|(a, len)| dns_target(a, len)) else {
            return;
        };
        let mut parts = Vec::new();
        if c.hook == Hook::Output {
            parts.push(nfproto(fam));
            parts.push(ifname_is(MetaKey::OifName, CmpOp::Neq, "lo"));
        } else {
            let set = fam.local_set();
            let text = format!("@{}", set);
            parts.push(implied(nfproto(fam)));
            parts.push(addr_in(fam, true, &self.named(set), false, &text));
        }
        parts.push(self.l4proto_in(&[TCP, UDP], false));
        parts.push(dport("th", DNS_PORT));
        parts.push(counter());
        if c.ty == ChainType::Nat {
            let data = match target {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            parts.push(part(
                [
                    Expr::Immediate {
                        dreg: Reg::R1,
                        data,
                    },
                    Expr::Nat {
                        kind: NatKind::Dnat,
                        family: fam.nfproto(),
                        addr_min: Some(Reg::R1),
                        proto_min: None,
                        flags: 0,
                    },
                ],
                format!("dnat {} to {}", fam.ip(), target),
            ));
        } else {
            parts.push(ret());
        }
        self.rule(c, parts);
    }

    /// With `strict_route` and one family, the other is refused.
    fn unreachable(&mut self, c: ChainInfo) {
        let Some(fam) = self.missing() else { return };
        if !self.o.strict_route {
            return;
        }
        // Type 0 code 0: net-unreachable for IPv4, no-route for IPv6.
        let text = match fam {
            V4 => "reject with icmp net-unreachable",
            V6 => "reject with icmpv6 no-route",
        };
        let reject = part(
            [Expr::Reject {
                kind: RejectKind::Icmp,
                code: 0,
            }],
            text,
        );
        self.rule(c, vec![nfproto(fam), counter(), reject]);
    }

    /// TCP to the redirect listener. With loopback addresses, a rule per
    /// family, leaving those addresses to the reroute rules.
    fn redirect(&mut self, c: ChainInfo) {
        let port_ = self.o.redirect_port;
        let redirect = || {
            let mut p = l4proto(TCP);
            p.exprs.extend([
                Expr::Counter,
                Expr::Immediate {
                    dreg: Reg::R1,
                    data: port(port_),
                },
                Expr::Redir {
                    proto_min: Some(Reg::R1),
                    flags: NAT_RANGE_PROTO_SPECIFIED,
                },
                verdict(Verdict::Return),
            ]);
            p.text += &format!(" counter redirect to :{} return", port_);
            p
        };
        if self.o.loopback_address.is_empty() {
            // With one family, only that one.
            let mut parts = Vec::new();
            if self.missing().is_some() {
                parts.push(nfproto(self.families()[0]));
            }
            parts.push(redirect());
            self.rule(c, parts);
            return;
        }
        for fam in self.families() {
            let mut parts = if self.loopback(fam).is_empty() {
                vec![nfproto(fam)]
            } else {
                self.daddr_in_named(fam, fam.loopback_set(), true)
            };
            parts.push(redirect());
            self.rule(c, parts);
        }
    }

    /// The input mark, into the conntrack entry too, so the flow's later
    /// packets get it back.
    fn mark(&mut self, c: ChainInfo) {
        let p = vec![
            set_mark(self.o.input_mark),
            ct_mark_set_meta_mark(),
            counter(),
            ret(),
        ];
        self.rule(c, p);
    }

    /// TCP to a loopback address goes into the TUN, by mark, rather than
    /// to the redirect listener.
    fn loopback_reroute(&mut self, c: ChainInfo) {
        for fam in self.families() {
            if self.loopback(fam).is_empty() {
                continue;
            }
            let mut parts = vec![l4proto(TCP), mark_is(CmpOp::Neq, self.o.input_mark)];
            parts.extend(self.daddr_in_named(fam, fam.loopback_set(), false));
            parts.push(set_mark(self.o.input_mark));
            if c.hook == Hook::Output {
                parts.push(ct_mark_set_meta_mark());
            }
            parts.push(counter());
            self.rule(c, parts);
        }
    }

    /// Connections to the redirect listener that were not redirected there
    /// -- straight from the LAN, say -- are reset.
    fn redirect_port_reject(&mut self, c: ChainInfo) {
        let status = part(
            [
                ct(CtKey::Status),
                Expr::Bitwise {
                    sreg: Reg::R1,
                    dreg: Reg::R1,
                    len: 4,
                    mask: host_u32(IPS_DST_NAT),
                    xor: vec![0; 4],
                },
                cmp(CmpOp::Eq, vec![0; 4]),
            ],
            "ct status ! dnat",
        );
        let reject = part(
            [Expr::Reject {
                kind: RejectKind::TcpRst,
                code: 0,
            }],
            "reject with tcp reset",
        );
        self.rule(
            c,
            vec![
                implied(l4proto(TCP)),
                dport("tcp", self.o.redirect_port),
                status,
                counter(),
                reject,
            ],
        );
    }

    /// Forwarded UDP and ICMP: the input mark back from the conntrack
    /// entry; a flow without it is left alone, with the output mark.
    fn prerouting_udp_icmp(&mut self, c: ChainInfo) {
        let o = self.o;
        let p = self.l4proto_in(&[UDP, ICMP, ICMPV6], true);
        self.rule(c, vec![p, ret()]);
        self.rule(
            c,
            vec![
                ifname_is(MetaKey::IifName, CmpOp::Eq, &o.tun_name),
                counter(),
                ret(),
            ],
        );
        self.rule(
            c,
            vec![
                ifname_is(MetaKey::IifName, CmpOp::Neq, &o.tun_name),
                ct_mark_is(CmpOp::Eq, o.input_mark),
                meta_mark_set_ct_mark(),
                counter(),
            ],
        );
        self.rule(
            c,
            vec![
                ct_mark_is(CmpOp::Neq, o.input_mark),
                set_mark(o.output_mark),
                ct_mark_set_meta_mark(),
                counter(),
            ],
        );
    }

    /// The pre-match chain (sing-tun v0.9.6 `nftablesAddPreMatchRules`).
    /// A verdict comes back with NF_REPEAT and its mark, so the chain runs
    /// again from the top and the mark rules take it.
    fn prematch_rules(&mut self, c: ChainInfo, num: u16) {
        let o = self.o;
        if c.hook == Hook::Prerouting {
            self.rule(
                c,
                vec![ifname_is(MetaKey::IifName, CmpOp::Eq, &o.tun_name), ret()],
            );
        }
        self.rule(
            c,
            vec![
                part(
                    ct_cmp(CtKey::Direction, CmpOp::Eq, vec![1]),
                    "ct direction reply",
                ),
                ret(),
            ],
        );
        // A judged packet or flow: the mark and the conntrack mark agree.
        for mark in [o.output_mark, o.input_mark] {
            self.rule(
                c,
                vec![
                    mark_is(CmpOp::Eq, mark),
                    ct_mark_set_meta_mark(),
                    counter(),
                    ret(),
                ],
            );
            self.rule(
                c,
                vec![
                    ct_mark_is(CmpOp::Eq, mark),
                    meta_mark_set_ct_mark(),
                    counter(),
                    ret(),
                ],
            );
        }
        if let Some(fam) = self.missing() {
            self.rule(c, vec![nfproto(fam), ret()]);
        }
        let p = self.l4proto_in(&[TCP, UDP, ICMP, ICMPV6], true);
        self.rule(c, vec![p, ret()]);
        // Of TCP, only a SYN without ACK.
        let mut syn = implied(l4proto(TCP));
        syn.exprs.extend([
            payload(PayloadBase::Transport, 13, 1),
            Expr::Bitwise {
                sreg: Reg::R1,
                dreg: Reg::R1,
                len: 1,
                mask: vec![0x12],
                xor: vec![0],
            },
            cmp(CmpOp::Neq, vec![0x02]),
        ]);
        syn.text = "tcp flags & (syn | ack) != syn".into();
        self.rule(c, vec![syn, ret()]);
        self.rule(
            c,
            vec![
                l4proto(TCP),
                mark_is(CmpOp::Eq, o.reset_mark),
                counter(),
                part(
                    [Expr::Reject {
                        kind: RejectKind::TcpRst,
                        code: 0,
                    }],
                    "reject with tcp reset",
                ),
            ],
        );

        self.exclude_rules(c);

        self.rule(c, vec![l4proto(TCP), counter(), queue(num)]);
        self.rule(c, vec![l4proto(UDP), counter(), queue(num)]);
        for (proto, ty, word) in [
            (ICMP, ICMP_ECHO_REQUEST, "icmp"),
            (ICMPV6, ICMPV6_ECHO_REQUEST, "icmpv6"),
        ] {
            let mut echo = implied(l4proto(proto));
            echo.exprs.extend([
                payload(PayloadBase::Transport, 0, 2),
                cmp(CmpOp::Eq, vec![ty, 0]),
            ]);
            echo.text = format!("{} type echo-request {} code 0", word, word);
            self.rule(c, vec![echo, counter(), queue(num)]);
        }
    }
}

/// Flushes and refills the local address sets.
pub(super) fn update_local_prefixes(o: &RulesetOptions, prefixes: &[(IpAddr, u8)]) -> Batch {
    let table = Table::new(Family::Inet, o.table.as_str());
    let mut batch = Batch::new();
    for fam in families(o) {
        refill(&mut batch, &table, fam.local_set(), prefixes, fam);
    }
    batch
}

/// Flushes and refills the rule-set sets given, of those the ruleset has.
pub(super) fn update_route_address_sets(
    o: &RulesetOptions,
    include: Option<&AddressSet>,
    exclude: Option<&AddressSet>,
) -> Batch {
    let table = Table::new(Family::Inet, o.table.as_str());
    let mut batch = Batch::new();
    for (set, made, name) in [
        (
            include,
            o.route_address_set.is_some(),
            Fam::route_set as SetName,
        ),
        (
            exclude,
            o.route_exclude_address_set.is_some(),
            Fam::route_exclude_set,
        ),
    ] {
        let Some(set) = set.filter(|_| made) else {
            continue;
        };
        for fam in families(o) {
            refill(&mut batch, &table, name(fam), &set.prefixes, fam);
        }
    }
    batch
}

fn families(o: &RulesetOptions) -> Vec<Fam> {
    let mut fams = Vec::new();
    if o.ipv4.is_some() {
        fams.push(V4);
    }
    if o.ipv6.is_some() {
        fams.push(V6);
    }
    fams
}

fn refill(batch: &mut Batch, table: &Table, name: &str, prefixes: &[(IpAddr, u8)], fam: Fam) {
    batch.flush_set(table, name);
    let elems = addr::elems(&addr::ranges(prefixes, fam.is_v6()));
    if !elems.is_empty() {
        batch.add_elements(table, &SetRef::named(name), &elems);
    }
}

#[cfg(test)]
// A uid range is one element of a list of them.
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    #[test]
    fn uid_ranges_are_looked_up_big_endian() {
        let o = super::super::tests::default_options();
        let mut b = Builder {
            o: &o,
            table: Table::new(Family::Inet, "t"),
            built: Built {
                batch: Batch::new(),
                table: "t".into(),
                sets: Vec::new(),
                chains: Vec::new(),
            },
            named: Vec::new(),
        };
        // One uid: a host-order compare, as `meta skuid` loads it.
        let p = b.uid_in(&[1000..=1000], true);
        assert_eq!(
            p.exprs,
            [
                meta(MetaKey::SkUid),
                cmp(CmpOp::Neq, 1000u32.to_ne_bytes().to_vec())
            ]
        );
        assert_eq!(p.text, "meta skuid != 1000");
        // A range: converted, then looked up in a set of its own.
        let p = b.uid_in(&[1000..=1999], false);
        assert_eq!(
            p.exprs[..2],
            [
                meta(MetaKey::SkUid),
                Expr::Byteorder {
                    sreg: Reg::R1,
                    dreg: Reg::R1,
                    op: ByteorderOp::Hton,
                    len: 4,
                    size: 4
                }
            ]
        );
        let Expr::Lookup { set, invert, .. } = &p.exprs[2] else {
            panic!("{:?}", p.exprs[2]);
        };
        assert!(!invert);
        assert_eq!(set.id(), Some(1));
        assert_eq!(p.text, "meta skuid { 1000-1999 }");
        assert_eq!(
            b.built.batch.descriptions().collect::<Vec<_>>(),
            [
                "creating anonymous set 1",
                "adding elements to anonymous set 1"
            ]
        );
    }

    #[test]
    fn dns_goes_to_the_next_address() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(dns_target(a("172.18.0.1"), 30), Some(a("172.18.0.2")));
        assert_eq!(dns_target(a("172.18.0.3"), 30), None);
        assert_eq!(dns_target(a("172.18.0.1"), 32), None);
        assert_eq!(dns_target(a("10.0.0.0"), 31), Some(a("10.0.0.1")));
        assert_eq!(
            dns_target(a("fdfe:dcba:9876::1"), 126),
            Some(a("fdfe:dcba:9876::2"))
        );
        assert_eq!(
            dns_target(a("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 0),
            None
        );
    }

    #[test]
    fn priorities_as_nft_writes_them() {
        assert_eq!(priority_text(-101), "dstnat - 1");
        assert_eq!(priority_text(-150), "mangle");
        assert_eq!(priority_text(-148), "mangle + 2");
        assert_eq!(priority_text(-97), "dstnat + 3");
        assert_eq!(priority_text(0), "filter");
        assert_eq!(priority_text(-120), "-120");
    }
}
