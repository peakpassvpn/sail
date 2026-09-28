//! Rule expressions: the kernel's own, one variant each, with the
//! registers and data they are given on the wire. A rule is a list of
//! them; the helpers at the end spell the common pairs ("meta mark ==
//! X") in one call.
//!
//! The encoding follows sagernet/nftables v0.3.0-beta.4 (`expr/*.go`),
//! attribute for attribute, which follows what nft(8) sends.

use super::netlink::Attrs;
use super::sys::*;
use super::Family;

/// A 16-byte data register, or the verdict register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reg {
    Verdict = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
}

/// `meta` keys (`enum nft_meta_keys`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaKey {
    Mark = 3,
    IifName = 6,
    OifName = 7,
    SkUid = 10,
    NfProto = 15,
    L4Proto = 16,
}

/// `ct` keys (`enum nft_ct_keys`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtKey {
    Direction = 1,
    /// The `IPS_*` status bits, a host-order u32.
    Status = 2,
    Mark = 3,
}

/// `cmp` operators (`enum nft_cmp_ops`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Eq = 0,
    Neq = 1,
}

/// Where a `payload` offset counts from (`enum nft_payload_bases`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadBase {
    Network = 1,
    Transport = 2,
}

/// Which way `byteorder` converts (`enum nft_byteorder_ops`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteorderOp {
    Ntoh = 0,
    Hton = 1,
}

/// Which extension headers `exthdr` walks (`enum nft_exthdr_op`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExthdrOp {
    Ipv6 = 0,
    TcpOpt = 1,
}

/// `exthdr` flag: load 1 if the option is there, 0 if not, rather than
/// its bytes.
pub const EXTHDR_F_PRESENT: u32 = 0x1;

/// `nat` and `redir` flag: the proto registers hold a port range.
pub const NAT_RANGE_PROTO_SPECIFIED: u32 = 0x2;

/// `queue` flag: accept rather than drop when no one listens.
pub const QUEUE_FLAG_BYPASS: u16 = 0x1;
/// `queue` flag: spread over the queues by CPU rather than by flow hash.
pub const QUEUE_FLAG_CPU_FANOUT: u16 = 0x2;

/// The kind of `nat` (`enum nft_nat_types`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    Snat = 0,
    Dnat = 1,
}

/// How `reject` answers (`enum nft_reject_types`). The code is an ICMP
/// code for `Icmp`, an `enum nft_reject_inet_code` for `Icmpx`, and unused
/// for `TcpRst`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectKind {
    Icmp = 0,
    TcpRst = 1,
    Icmpx = 2,
}

/// A verdict, as the `immediate` expression loads it into the verdict
/// register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Return,
    Jump(String),
    Goto(String),
}

/// The set a `lookup` looks in: by name, or, for a set made in the same
/// batch -- an anonymous one has no name of its own yet -- by the id the
/// batch gave it. `Batch::add_set` returns one of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetRef {
    pub(super) name: String,
    pub(super) id: Option<u32>,
}

impl SetRef {
    /// A set that exists already, by name.
    pub fn named(name: impl Into<String>) -> SetRef {
        SetRef {
            name: name.into(),
            id: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> Option<u32> {
        self.id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    /// Loads a `meta` key into `dreg`.
    Meta { key: MetaKey, dreg: Reg },
    /// Sets a `meta` key from `sreg`.
    MetaSet { key: MetaKey, sreg: Reg },
    /// Loads a `ct` key into `dreg`.
    Ct { key: CtKey, dreg: Reg },
    /// Sets a `ct` key from `sreg`.
    CtSet { key: CtKey, sreg: Reg },
    /// Loads `len` bytes of a header at `offset` into `dreg`.
    Payload {
        base: PayloadBase,
        offset: u32,
        len: u32,
        dreg: Reg,
    },
    /// Loads from an extension header -- a TCP option, say -- into `dreg`.
    /// `ty` is the option kind; with `EXTHDR_F_PRESENT` in `flags` it loads
    /// whether the option is there.
    Exthdr {
        op: ExthdrOp,
        ty: u8,
        offset: u32,
        len: u32,
        flags: u32,
        dreg: Reg,
    },
    /// Stops the rule unless `sreg` compares so with `data`.
    Cmp { op: CmpOp, sreg: Reg, data: Vec<u8> },
    /// Converts `len` bytes from `sreg` into `dreg`, as numbers of `size`
    /// bytes each (2, 4 or 8). A lookup in an interval set of host-order
    /// keys -- uids, say -- needs them big-endian first, since the kernel
    /// orders an interval set's keys as bytes; nft(8) puts this before it.
    Byteorder {
        sreg: Reg,
        dreg: Reg,
        op: ByteorderOp,
        len: u32,
        size: u32,
    },
    /// `dreg = (sreg & mask) ^ xor` over `len` bytes.
    Bitwise {
        sreg: Reg,
        dreg: Reg,
        len: u32,
        mask: Vec<u8>,
        xor: Vec<u8>,
    },
    /// Loads `data` into `dreg`.
    Immediate { dreg: Reg, data: Vec<u8> },
    /// Ends the rule with a verdict.
    Verdict(Verdict),
    /// Stops the rule unless `sreg` is in the set -- or, inverted, is not.
    Lookup {
        sreg: Reg,
        set: SetRef,
        invert: bool,
    },
    /// Redirects to the host, to the port in `proto_min` if given.
    Redir { proto_min: Option<Reg>, flags: u32 },
    /// Source or destination NAT to the address in `addr_min` (of
    /// `family`), and the port in `proto_min`, if given.
    Nat {
        kind: NatKind,
        family: Family,
        addr_min: Option<Reg>,
        proto_min: Option<Reg>,
        flags: u32,
    },
    /// Hands the packet to user space on queue `num` (of `total` queues
    /// from there).
    Queue { num: u16, total: u16, flags: u16 },
    /// Rejects the packet.
    Reject { kind: RejectKind, code: u8 },
    /// Counts packets and bytes.
    Counter,
}

impl Expr {
    /// The expression's name, as the kernel knows it.
    pub fn name(&self) -> &'static str {
        match self {
            Expr::Meta { .. } | Expr::MetaSet { .. } => "meta",
            Expr::Ct { .. } | Expr::CtSet { .. } => "ct",
            Expr::Payload { .. } => "payload",
            Expr::Exthdr { .. } => "exthdr",
            Expr::Cmp { .. } => "cmp",
            Expr::Bitwise { .. } => "bitwise",
            Expr::Byteorder { .. } => "byteorder",
            Expr::Immediate { .. } | Expr::Verdict(_) => "immediate",
            Expr::Lookup { .. } => "lookup",
            Expr::Redir { .. } => "redir",
            Expr::Nat { .. } => "nat",
            Expr::Queue { .. } => "queue",
            Expr::Reject { .. } => "reject",
            Expr::Counter => "counter",
        }
    }

    /// Writes the expression as one `NFTA_LIST_ELEM` of a rule's
    /// `NFTA_RULE_EXPRESSIONS`: its name, and its attributes nested in
    /// `NFTA_EXPR_DATA`.
    pub(super) fn encode(&self, a: &mut Attrs) {
        a.nested(NFTA_LIST_ELEM, |a| {
            a.str(NFTA_EXPR_NAME, self.name());
            a.nested(NFTA_EXPR_DATA, |a| self.encode_data(a));
        });
    }

    fn encode_data(&self, a: &mut Attrs) {
        match self {
            // expr/expr.go:218-248: the key, then the register.
            Expr::Meta { key, dreg } => {
                a.be32(NFTA_META_KEY, *key as u32);
                a.be32(NFTA_META_DREG, *dreg as u32);
            }
            Expr::MetaSet { key, sreg } => {
                a.be32(NFTA_META_KEY, *key as u32);
                a.be32(NFTA_META_SREG, *sreg as u32);
            }
            // expr/ct.go:75-107, the same shape.
            Expr::Ct { key, dreg } => {
                a.be32(NFTA_CT_KEY, *key as u32);
                a.be32(NFTA_CT_DREG, *dreg as u32);
            }
            Expr::CtSet { key, sreg } => {
                a.be32(NFTA_CT_KEY, *key as u32);
                a.be32(NFTA_CT_SREG, *sreg as u32);
            }
            // expr/payload.go:67-81 (a load; no checksum fields).
            Expr::Payload {
                base,
                offset,
                len,
                dreg,
            } => {
                a.be32(NFTA_PAYLOAD_DREG, *dreg as u32);
                a.be32(NFTA_PAYLOAD_BASE, *base as u32);
                a.be32(NFTA_PAYLOAD_OFFSET, *offset);
                a.be32(NFTA_PAYLOAD_LEN, *len);
            }
            // expr/exthdr.go:43-67: the flags follow only a load.
            Expr::Exthdr {
                op,
                ty,
                offset,
                len,
                flags,
                dreg,
            } => {
                a.be32(NFTA_EXTHDR_DREG, *dreg as u32);
                a.u8(NFTA_EXTHDR_TYPE, *ty);
                a.be32(NFTA_EXTHDR_OFFSET, *offset);
                a.be32(NFTA_EXTHDR_LEN, *len);
                a.be32(NFTA_EXTHDR_OP, *op as u32);
                a.be32(NFTA_EXTHDR_FLAGS, *flags);
            }
            // expr/expr.go:363-381.
            Expr::Cmp { op, sreg, data } => {
                a.be32(NFTA_CMP_SREG, *sreg as u32);
                a.be32(NFTA_CMP_OP, *op as u32);
                a.nested(NFTA_CMP_DATA, |a| {
                    a.bytes(NFTA_DATA_VALUE, data);
                });
            }
            // expr/bitwise.go:36-60.
            Expr::Bitwise {
                sreg,
                dreg,
                len,
                mask,
                xor,
            } => {
                a.be32(NFTA_BITWISE_SREG, *sreg as u32);
                a.be32(NFTA_BITWISE_DREG, *dreg as u32);
                a.be32(NFTA_BITWISE_LEN, *len);
                a.nested(NFTA_BITWISE_MASK, |a| {
                    a.bytes(NFTA_DATA_VALUE, mask);
                });
                a.nested(NFTA_BITWISE_XOR, |a| {
                    a.bytes(NFTA_DATA_VALUE, xor);
                });
            }
            // expr/byteorder.go:39-54: every attribute, in this order.
            Expr::Byteorder {
                sreg,
                dreg,
                op,
                len,
                size,
            } => {
                a.be32(NFTA_BYTEORDER_SREG, *sreg as u32);
                a.be32(NFTA_BYTEORDER_DREG, *dreg as u32);
                a.be32(NFTA_BYTEORDER_OP, *op as u32);
                a.be32(NFTA_BYTEORDER_LEN, *len);
                a.be32(NFTA_BYTEORDER_SIZE, *size);
            }
            // expr/immediate.go:31-50.
            Expr::Immediate { dreg, data } => {
                a.be32(NFTA_IMMEDIATE_DREG, *dreg as u32);
                a.nested(NFTA_IMMEDIATE_DATA, |a| {
                    a.bytes(NFTA_DATA_VALUE, data);
                });
            }
            // expr/verdict.go:66-99: the code as a big-endian s32, the
            // chain for a jump or goto.
            Expr::Verdict(verdict) => {
                let (code, chain) = match verdict {
                    Verdict::Accept => (NF_ACCEPT, None),
                    Verdict::Drop => (NF_DROP, None),
                    Verdict::Return => (NFT_RETURN, None),
                    Verdict::Jump(chain) => (NFT_JUMP, Some(chain)),
                    Verdict::Goto(chain) => (NFT_GOTO, Some(chain)),
                };
                a.be32(NFTA_IMMEDIATE_DREG, Reg::Verdict as u32);
                a.nested(NFTA_IMMEDIATE_DATA, |a| {
                    a.nested(NFTA_DATA_VERDICT, |a| {
                        a.be32(NFTA_VERDICT_CODE, code as u32);
                        if let Some(chain) = chain {
                            a.str(NFTA_VERDICT_CHAIN, chain);
                        }
                    });
                });
            }
            // expr/lookup.go:43-60. The Go code sends a set id of 0 with a
            // name-only lookup; the kernel only reads the id when the name
            // is not found, so it is left out here.
            Expr::Lookup { sreg, set, invert } => {
                a.be32(NFTA_LOOKUP_SREG, *sreg as u32);
                if *invert {
                    a.be32(NFTA_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
                }
                a.str(NFTA_LOOKUP_SET, &set.name);
                if let Some(id) = set.id {
                    a.be32(NFTA_LOOKUP_SET_ID, id);
                }
            }
            // expr/redirect.go:34-51: every attribute only when set.
            Expr::Redir { proto_min, flags } => {
                if let Some(reg) = proto_min {
                    a.be32(NFTA_REDIR_REG_PROTO_MIN, *reg as u32);
                }
                if *flags != 0 {
                    a.be32(NFTA_REDIR_FLAGS, *flags);
                }
            }
            // expr/nat.go:61-101.
            Expr::Nat {
                kind,
                family,
                addr_min,
                proto_min,
                flags,
            } => {
                a.be32(NFTA_NAT_TYPE, *kind as u32);
                a.be32(NFTA_NAT_FAMILY, *family as u32);
                if let Some(reg) = addr_min {
                    a.be32(NFTA_NAT_REG_ADDR_MIN, *reg as u32);
                }
                if let Some(reg) = proto_min {
                    a.be32(NFTA_NAT_REG_PROTO_MIN, *reg as u32);
                }
                if *flags != 0 {
                    a.be32(NFTA_NAT_FLAGS, *flags);
                }
            }
            // expr/queue.go:44-60: 16-bit fields, a total of 0 sent as 1.
            Expr::Queue { num, total, flags } => {
                a.be16(NFTA_QUEUE_NUM, *num);
                a.be16(NFTA_QUEUE_TOTAL, (*total).max(1));
                a.be16(NFTA_QUEUE_FLAGS, *flags);
            }
            // expr/reject.go:30-41: the code is sent even for a TCP reset.
            Expr::Reject { kind, code } => {
                a.be32(NFTA_REJECT_TYPE, *kind as u32);
                a.u8(NFTA_REJECT_ICMP_CODE, *code);
            }
            // expr/counter.go:30-42: starting counts of zero.
            Expr::Counter => {
                a.be64(NFTA_COUNTER_BYTES, 0);
                a.be64(NFTA_COUNTER_PACKETS, 0);
            }
        }
    }
}

/// Loads a `meta` key into register 1.
pub fn meta(key: MetaKey) -> Expr {
    Expr::Meta { key, dreg: Reg::R1 }
}

/// Loads a `ct` key into register 1.
pub fn ct(key: CtKey) -> Expr {
    Expr::Ct { key, dreg: Reg::R1 }
}

/// Compares register 1 with `data`.
pub fn cmp(op: CmpOp, data: impl Into<Vec<u8>>) -> Expr {
    Expr::Cmp {
        op,
        sreg: Reg::R1,
        data: data.into(),
    }
}

/// `meta <key> ==/!= data`.
pub fn meta_cmp(key: MetaKey, op: CmpOp, data: impl Into<Vec<u8>>) -> [Expr; 2] {
    [meta(key), cmp(op, data)]
}

/// `ct <key> ==/!= data`.
pub fn ct_cmp(key: CtKey, op: CmpOp, data: impl Into<Vec<u8>>) -> [Expr; 2] {
    [ct(key), cmp(op, data)]
}

/// Looks register 1 up in `set`.
pub fn lookup(set: &SetRef, invert: bool) -> Expr {
    Expr::Lookup {
        sreg: Reg::R1,
        set: set.clone(),
        invert,
    }
}

/// A verdict expression.
pub fn verdict(verdict: Verdict) -> Expr {
    Expr::Verdict(verdict)
}

/// A mark or a uid as `meta`, `ct` and set keys hold it: 4 bytes in the
/// host's byte order.
pub fn host_u32(value: u32) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

/// A port as headers hold it: 2 bytes, big-endian.
pub fn port(port: u16) -> Vec<u8> {
    port.to_be_bytes().to_vec()
}

/// An interface name as `iifname`/`oifname` load it: NUL-padded to
/// IFNAMSIZ, so a compare matches the whole name. A name the kernel could
/// not have (16 bytes or more) is `None`.
pub fn ifname(name: &str) -> Option<Vec<u8>> {
    const IFNAMSIZ: usize = 16;
    if name.len() >= IFNAMSIZ || name.as_bytes().contains(&0) {
        return None;
    }
    let mut data = name.as_bytes().to_vec();
    data.resize(IFNAMSIZ, 0);
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(e: &Expr) -> Vec<u8> {
        let mut a = Attrs::new();
        e.encode(&mut a);
        a.into_bytes()
    }

    // Each expected encoding below is what sagernet/nftables v0.3.0-beta.4
    // marshals for the same expression (a Go program calling
    // `expr.Marshal` and wrapping it in an NFTA_LIST_ELEM as rule.go:108-113
    // does), checked against the marshal code cited.

    /// Hex-decodes a golden string.
    pub(in super::super) fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn matches_go_library() {
        // What sagernet/nftables v0.3.0-beta.4 marshals for each expression:
        // the output of a Go program that builds it, calls `expr.Marshal`
        // and wraps the result in an NFTA_LIST_ELEM as rule.go:108-113
        // does, run on x86_64 Linux. An inverted lookup by name is left
        // out: Go adds a set id of 0 there (lookup.go:52-55), which this
        // encoder omits.
        let cases: Vec<(Expr, &str)> = vec![
            (
                meta(MetaKey::OifName),
                "24000180090001006d657461000000001400028008000200000000070800010000000001",
            ),
            (
                Expr::MetaSet { key: MetaKey::Mark, sreg: Reg::R1 },
                "24000180090001006d657461000000001400028008000200000000030800030000000001",
            ),
            (
                ct(CtKey::Mark),
                "2000018007000100637400001400028008000200000000030800010000000001",
            ),
            (
                Expr::CtSet { key: CtKey::Mark, sreg: Reg::R1 },
                "2000018007000100637400001400028008000200000000030800040000000001",
            ),
            (
                ct(CtKey::Direction),
                "2000018007000100637400001400028008000200000000010800010000000001",
            ),
            (
                cmp(CmpOp::Eq, ifname("uplink0").unwrap()),
                "3800018008000100636d70002c00028008000100000000010800020000000000180003801400010075706c696e6b30000000000000000000",
            ),
            (
                cmp(CmpOp::Neq, vec![6]),
                "2c00018008000100636d700020000280080001000000000108000200000000010c0003800500010006000000",
            ),
            (
                Expr::Payload { base: PayloadBase::Transport, offset: 2, len: 2, dreg: Reg::R1 },
                "340001800c0001007061796c6f616400240002800800010000000001080002000000000208000300000000020800040000000002",
            ),
            (
                Expr::Bitwise { sreg: Reg::R1, dreg: Reg::R1, len: 4, mask: vec![0xff, 0xff, 0xff, 0], xor: vec![0; 4] },
                "440001800c0001006269747769736500340002800800010000000001080002000000000108000300000000040c00048008000100ffffff000c0005800800010000000000",
            ),
            (
                Expr::Byteorder { sreg: Reg::R1, dreg: Reg::R1, op: ByteorderOp::Hton, len: 4, size: 4 },
                "400001800e000100627974656f726465720000002c00028008000100000000010800020000000001080003000000000108000400000000040800050000000004",
            ),
            (
                ct(CtKey::Status),
                "2000018007000100637400001400028008000200000000020800010000000001",
            ),
            (
                Expr::Immediate { dreg: Reg::R1, data: port(2222) },
                "2c0001800e000100696d6d6564696174650000001800028008000100000000010c0002800600010008ae0000",
            ),
            (
                verdict(Verdict::Return),
                "300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c00028008000100fffffffb",
            ),
            (
                verdict(Verdict::Jump("istio_redirect".into())),
                "440001800e000100696d6d656469617465000000300002800800010000000000240002802000028008000100fffffffd13000200697374696f5f72656469726563740000",
            ),
            (
                verdict(Verdict::Accept),
                "300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c0002800800010000000001",
            ),
            (
                verdict(Verdict::Drop),
                "300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c0002800800010000000000",
            ),
            (
                verdict(Verdict::Goto("x".into())),
                "380001800e000100696d6d656469617465000000240002800800010000000000180002801400028008000100fffffffc0600020078000000",
            ),
            (
                lookup(&SetRef { name: "__set%d".into(), id: Some(1) }, false),
                "300001800b0001006c6f6f6b757000002000028008000200000000010c0001005f5f7365742564000800040000000001",
            ),
            (
                Expr::Redir { proto_min: Some(Reg::R1), flags: 0 },
                "1c0001800a00010072656469720000000c0002800800010000000001",
            ),
            (
                Expr::Redir { proto_min: Some(Reg::R1), flags: NAT_RANGE_PROTO_SPECIFIED },
                "240001800a00010072656469720000001400028008000100000000010800030000000002",
            ),
            (
                Expr::Nat { kind: NatKind::Dnat, family: Family::Ipv4, addr_min: Some(Reg::R1), proto_min: Some(Reg::R2), flags: 0 },
                "30000180080001006e617400240002800800010000000001080002000000000208000300000000010800050000000002",
            ),
            (
                Expr::Nat { kind: NatKind::Dnat, family: Family::Ipv6, addr_min: Some(Reg::R1), proto_min: None, flags: 0 },
                "28000180080001006e6174001c0002800800010000000001080002000000000a0800030000000001",
            ),
            (
                Expr::Queue { num: 100, total: 0, flags: QUEUE_FLAG_BYPASS },
                "2c0001800a00010071756575650000001c000280060001000064000006000200000100000600030000010000",
            ),
            (
                Expr::Reject { kind: RejectKind::TcpRst, code: 1 },
                "240001800b00010072656a65637400001400028008000100000000010500020001000000",
            ),
            (
                Expr::Reject { kind: RejectKind::Icmpx, code: 3 },
                "240001800b00010072656a65637400001400028008000100000000020500020003000000",
            ),
            (
                Expr::Exthdr { op: ExthdrOp::TcpOpt, ty: 30, offset: 0, len: 1, flags: EXTHDR_F_PRESENT, dreg: Reg::R1 },
                "440001800b0001006578746864720000340002800800010000000001050002001e0000000800030000000000080004000000000108000600000000010800050000000001",
            ),
            (
                Expr::Counter,
                "2c0001800c000100636f756e746572001c0002800c00010000000000000000000c0002000000000000000000",
            ),
        ];
        for (e, want) in cases {
            assert_eq!(encoded(&e), hex(want), "{:?}", e);
        }
    }

    #[test]
    fn meta_load() {
        // expr/expr.go:218-248; nftables_test.go:240 ("meta load oifname").
        let e = meta(MetaKey::OifName);
        assert_eq!(
            encoded(&e),
            b"\x24\x00\x01\x80\
              \x09\x00\x01\x00meta\x00\x00\x00\x00\
              \x14\x00\x02\x80\
              \x08\x00\x02\x00\x00\x00\x00\x07\
              \x08\x00\x01\x00\x00\x00\x00\x01"
        );
    }

    #[test]
    fn meta_set() {
        // expr/expr.go:227-236: NFTA_META_SREG (3) in place of DREG.
        let e = Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Reg::R1,
        };
        assert_eq!(
            encoded(&e),
            b"\x24\x00\x01\x80\
              \x09\x00\x01\x00meta\x00\x00\x00\x00\
              \x14\x00\x02\x80\
              \x08\x00\x02\x00\x00\x00\x00\x03\
              \x08\x00\x03\x00\x00\x00\x00\x01"
        );
    }

    #[test]
    fn ct_load_and_set() {
        // expr/ct.go:75-107; nftables_test.go:1335 ("ct load mark => reg 1")
        // and :1390 ("ct set mark with reg 1").
        assert_eq!(
            encoded(&ct(CtKey::Mark)),
            b"\x20\x00\x01\x80\
              \x07\x00\x01\x00ct\x00\x00\
              \x14\x00\x02\x80\
              \x08\x00\x02\x00\x00\x00\x00\x03\
              \x08\x00\x01\x00\x00\x00\x00\x01"
        );
        let set = Expr::CtSet {
            key: CtKey::Mark,
            sreg: Reg::R1,
        };
        assert_eq!(
            encoded(&set),
            b"\x20\x00\x01\x80\
              \x07\x00\x01\x00ct\x00\x00\
              \x14\x00\x02\x80\
              \x08\x00\x02\x00\x00\x00\x00\x03\
              \x08\x00\x04\x00\x00\x00\x00\x01"
        );
        assert_eq!(
            encoded(&ct(CtKey::Direction))[20..24],
            [0, 0, 0, 1],
            "ct direction is key 1"
        );
    }

    #[test]
    fn cmp_with_nested_value() {
        // expr/expr.go:363-381; nftables_test.go:240 (oifname "uplink0",
        // the value padded to 16 bytes).
        let e = cmp(CmpOp::Eq, ifname("uplink0").unwrap());
        assert_eq!(
            encoded(&e),
            b"\x38\x00\x01\x80\
              \x08\x00\x01\x00cmp\x00\
              \x2c\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x08\x00\x02\x00\x00\x00\x00\x00\
              \x18\x00\x03\x80\
              \x14\x00\x01\x00uplink0\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        );
        // A one-byte value is padded after its length.
        let e = cmp(CmpOp::Neq, vec![6]);
        assert_eq!(
            encoded(&e),
            b"\x2c\x00\x01\x80\
              \x08\x00\x01\x00cmp\x00\
              \x20\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x08\x00\x02\x00\x00\x00\x00\x01\
              \x0c\x00\x03\x80\
              \x05\x00\x01\x00\x06\x00\x00\x00"
        );
    }

    #[test]
    fn payload_load() {
        // expr/payload.go:67-81; nftables_test.go:4292 ("payload load 2b @
        // transport header + 2 => reg 1").
        let e = Expr::Payload {
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
            dreg: Reg::R1,
        };
        assert_eq!(
            encoded(&e),
            b"\x34\x00\x01\x80\
              \x0c\x00\x01\x00payload\x00\
              \x24\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x08\x00\x02\x00\x00\x00\x00\x02\
              \x08\x00\x03\x00\x00\x00\x00\x02\
              \x08\x00\x04\x00\x00\x00\x00\x02"
        );
    }

    #[test]
    fn bitwise() {
        // expr/bitwise.go:36-60; nftables_test.go:240 (ip daddr 10.0.0.0/24:
        // mask ff.ff.ff.00, xor 0).
        let e = Expr::Bitwise {
            sreg: Reg::R1,
            dreg: Reg::R1,
            len: 4,
            mask: vec![0xff, 0xff, 0xff, 0],
            xor: vec![0; 4],
        };
        assert_eq!(
            encoded(&e),
            b"\x44\x00\x01\x80\
              \x0c\x00\x01\x00bitwise\x00\
              \x34\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x08\x00\x02\x00\x00\x00\x00\x01\
              \x08\x00\x03\x00\x00\x00\x00\x04\
              \x0c\x00\x04\x80\x08\x00\x01\x00\xff\xff\xff\x00\
              \x0c\x00\x05\x80\x08\x00\x01\x00\x00\x00\x00\x00"
        );
    }

    #[test]
    fn byteorder_hton() {
        // expr/byteorder.go:39-54, as nft(8) sends it before looking a uid
        // up in an interval set: "byteorder reg 1 = hton(reg 1, 4, 4)".
        let e = Expr::Byteorder {
            sreg: Reg::R1,
            dreg: Reg::R1,
            op: ByteorderOp::Hton,
            len: 4,
            size: 4,
        };
        assert_eq!(
            encoded(&e),
            b"\x40\x00\x01\x80\
              \x0e\x00\x01\x00byteorder\x00\x00\x00\
              \x2c\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x08\x00\x02\x00\x00\x00\x00\x01\
              \x08\x00\x03\x00\x00\x00\x00\x01\
              \x08\x00\x04\x00\x00\x00\x00\x04\
              \x08\x00\x05\x00\x00\x00\x00\x04"
        );
    }

    #[test]
    fn immediate_data() {
        // expr/immediate.go:31-50; nftables_test.go:4292 ("immediate reg 1
        // 0x0000ae08", port 2222).
        let e = Expr::Immediate {
            dreg: Reg::R1,
            data: port(2222),
        };
        assert_eq!(
            encoded(&e),
            b"\x2c\x00\x01\x80\
              \x0e\x00\x01\x00immediate\x00\x00\x00\
              \x18\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x0c\x00\x02\x80\x06\x00\x01\x00\x08\xae\x00\x00"
        );
    }

    #[test]
    fn verdicts() {
        // expr/verdict.go:66-99; nftables_test.go:4507 ("immediate reg 0
        // return") and :4399 (jump istio_redirect).
        assert_eq!(
            encoded(&verdict(Verdict::Return)),
            b"\x30\x00\x01\x80\
              \x0e\x00\x01\x00immediate\x00\x00\x00\
              \x1c\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x00\
              \x10\x00\x02\x80\x0c\x00\x02\x80\
              \x08\x00\x01\x00\xff\xff\xff\xfb"
        );
        assert_eq!(
            encoded(&verdict(Verdict::Jump("istio_redirect".into()))),
            b"\x44\x00\x01\x80\
              \x0e\x00\x01\x00immediate\x00\x00\x00\
              \x30\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x00\
              \x24\x00\x02\x80\x20\x00\x02\x80\
              \x08\x00\x01\x00\xff\xff\xff\xfd\
              \x13\x00\x02\x00istio_redirect\x00\x00"
        );
        // Accept is 1 and drop 0 (NF_ACCEPT, NF_DROP).
        assert_eq!(encoded(&verdict(Verdict::Accept))[44..48], [0, 0, 0, 1]);
        assert_eq!(encoded(&verdict(Verdict::Drop))[44..48], [0, 0, 0, 0]);
        assert_eq!(
            encoded(&verdict(Verdict::Goto("x".into())))[44..48],
            [0xff, 0xff, 0xff, 0xfc]
        );
    }

    #[test]
    fn lookup_by_id_and_inverted_by_name() {
        // expr/lookup.go:43-60; nftables_test.go:2663 ("lookup reg 1 set
        // __set%d" with set id 1).
        let set = SetRef {
            name: "__set%d".into(),
            id: Some(1),
        };
        assert_eq!(
            encoded(&lookup(&set, false)),
            b"\x30\x00\x01\x80\
              \x0b\x00\x01\x00lookup\x00\x00\
              \x20\x00\x02\x80\
              \x08\x00\x02\x00\x00\x00\x00\x01\
              \x0c\x00\x01\x00__set%d\x00\
              \x08\x00\x04\x00\x00\x00\x00\x01"
        );
        // Inverted, the flags come between the register and the name.
        assert_eq!(
            encoded(&lookup(&SetRef::named("s"), true)),
            b"\x2c\x00\x01\x80\
              \x0b\x00\x01\x00lookup\x00\x00\
              \x1c\x00\x02\x80\
              \x08\x00\x02\x00\x00\x00\x00\x01\
              \x08\x00\x05\x00\x00\x00\x00\x01\
              \x06\x00\x01\x00s\x00\x00\x00"
        );
    }

    #[test]
    fn redir() {
        // expr/redirect.go:34-51; nftables_test.go:4292 ("redir proto_min
        // reg 1").
        let e = Expr::Redir {
            proto_min: Some(Reg::R1),
            flags: 0,
        };
        assert_eq!(
            encoded(&e),
            b"\x1c\x00\x01\x80\
              \x0a\x00\x01\x00redir\x00\x00\x00\
              \x0c\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01"
        );
        let e = Expr::Redir {
            proto_min: Some(Reg::R1),
            flags: NAT_RANGE_PROTO_SPECIFIED,
        };
        assert_eq!(
            encoded(&e),
            b"\x24\x00\x01\x80\
              \x0a\x00\x01\x00redir\x00\x00\x00\
              \x14\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x08\x00\x03\x00\x00\x00\x00\x02"
        );
    }

    #[test]
    fn nat() {
        // expr/nat.go:61-101; nftables_test.go:240 ("dnat 192.168.23.2:4080":
        // type 1, family 2, addr reg 1, proto reg 2).
        let e = Expr::Nat {
            kind: NatKind::Dnat,
            family: Family::Ipv4,
            addr_min: Some(Reg::R1),
            proto_min: Some(Reg::R2),
            flags: 0,
        };
        assert_eq!(
            encoded(&e),
            b"\x30\x00\x01\x80\
              \x08\x00\x01\x00nat\x00\
              \x24\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x08\x00\x02\x00\x00\x00\x00\x02\
              \x08\x00\x03\x00\x00\x00\x00\x01\
              \x08\x00\x05\x00\x00\x00\x00\x02"
        );
        // An address alone, for IPv6: family 10.
        let e = Expr::Nat {
            kind: NatKind::Dnat,
            family: Family::Ipv6,
            addr_min: Some(Reg::R1),
            proto_min: None,
            flags: 0,
        };
        assert_eq!(
            encoded(&e),
            b"\x28\x00\x01\x80\
              \x08\x00\x01\x00nat\x00\
              \x1c\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x08\x00\x02\x00\x00\x00\x00\x0a\
              \x08\x00\x03\x00\x00\x00\x00\x01"
        );
    }

    #[test]
    fn queue() {
        // expr/queue.go:44-60: three big-endian u16s.
        let e = Expr::Queue {
            num: 100,
            total: 0,
            flags: QUEUE_FLAG_BYPASS,
        };
        assert_eq!(
            encoded(&e),
            b"\x2c\x00\x01\x80\
              \x0a\x00\x01\x00queue\x00\x00\x00\
              \x1c\x00\x02\x80\
              \x06\x00\x01\x00\x00\x64\x00\x00\
              \x06\x00\x02\x00\x00\x01\x00\x00\
              \x06\x00\x03\x00\x00\x01\x00\x00"
        );
    }

    #[test]
    fn reject() {
        // expr/reject.go:30-41; nftables_test.go:5166 ("reject with tcp
        // reset": type 1, code 1 -- the Go test passes the type as the code).
        let e = Expr::Reject {
            kind: RejectKind::TcpRst,
            code: 1,
        };
        assert_eq!(
            encoded(&e),
            b"\x24\x00\x01\x80\
              \x0b\x00\x01\x00reject\x00\x00\
              \x14\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x05\x00\x02\x00\x01\x00\x00\x00"
        );
        let e = Expr::Reject {
            kind: RejectKind::Icmpx,
            code: 3,
        };
        assert_eq!(encoded(&e)[24..32], *b"\x00\x00\x00\x02\x05\x00\x02\x00");
        assert_eq!(encoded(&e)[32], 3);
    }

    #[test]
    fn exthdr_tcp_option_present() {
        // expr/exthdr.go:43-67: tcp option mptcp (kind 30) exists.
        let e = Expr::Exthdr {
            op: ExthdrOp::TcpOpt,
            ty: 30,
            offset: 0,
            len: 1,
            flags: EXTHDR_F_PRESENT,
            dreg: Reg::R1,
        };
        assert_eq!(
            encoded(&e),
            b"\x44\x00\x01\x80\
              \x0b\x00\x01\x00exthdr\x00\x00\
              \x34\x00\x02\x80\
              \x08\x00\x01\x00\x00\x00\x00\x01\
              \x05\x00\x02\x00\x1e\x00\x00\x00\
              \x08\x00\x03\x00\x00\x00\x00\x00\
              \x08\x00\x04\x00\x00\x00\x00\x01\
              \x08\x00\x06\x00\x00\x00\x00\x01\
              \x08\x00\x05\x00\x00\x00\x00\x01"
        );
    }

    #[test]
    fn counter() {
        // expr/counter.go:30-42: bytes and packets, both zero.
        assert_eq!(
            encoded(&Expr::Counter),
            b"\x2c\x00\x01\x80\
              \x0c\x00\x01\x00counter\x00\
              \x1c\x00\x02\x80\
              \x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\
              \x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        );
    }

    #[test]
    fn data_helpers() {
        assert_eq!(ifname("tun0").unwrap(), b"tun0\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(ifname("fifteen-chars-x").unwrap().len(), 16);
        assert_eq!(ifname("sixteen-chars-xx"), None);
        assert_eq!(port(53), vec![0, 53]);
        assert_eq!(host_u32(0x2023), 0x2023u32.to_ne_bytes().to_vec());
        assert_eq!(
            meta_cmp(MetaKey::Mark, CmpOp::Eq, host_u32(1)),
            [meta(MetaKey::Mark), cmp(CmpOp::Eq, host_u32(1))]
        );
    }
}
