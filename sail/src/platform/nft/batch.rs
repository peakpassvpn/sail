//! The objects of a ruleset and the batch that carries them to the kernel:
//! each `Batch` call encodes one nf_tables message, and a commit sends them
//! all between `NFNL_MSG_BATCH_BEGIN` and `_END`, so they take effect
//! together or not at all.
//!
//! The encoding follows sagernet/nftables v0.3.0-beta.4 (table.go,
//! chain.go, rule.go, set.go, conn.go).

use std::net::IpAddr;

use super::expr::{Expr, SetRef};
#[cfg(test)]
use super::netlink::{align, messages};
use super::netlink::{nft_type, put_message, Attrs};
use super::sys::*;
use super::Family;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub family: Family,
    pub name: String,
}

impl Table {
    pub fn new(family: Family, name: impl Into<String>) -> Table {
        Table {
            family,
            name: name.into(),
        }
    }
}

impl std::fmt::Display for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.family, self.name)
    }
}

/// What a base chain is for (`nft_chain_type`s the kernel registers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainType {
    Filter,
    Nat,
    /// A filter that reroutes an output packet whose mark or addresses it
    /// changed.
    Route,
}

impl ChainType {
    fn name(self) -> &'static str {
        match self {
            ChainType::Filter => "filter",
            ChainType::Nat => "nat",
            ChainType::Route => "route",
        }
    }
}

/// The netfilter hooks of the ip, ip6 and inet families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    Prerouting = 0,
    Input = 1,
    Forward = 2,
    Output = 3,
    Postrouting = 4,
}

/// A base chain's default verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Drop = 0,
    Accept = 1,
}

/// Where a base chain hooks in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseChain {
    pub ty: ChainType,
    pub hook: Hook,
    /// Lower runs first: mangle is -150, dstnat -100, filter 0.
    pub priority: i32,
    /// Left out, the kernel takes accept.
    pub policy: Option<Policy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub name: String,
    /// `None` for a regular chain, reached by jump or goto.
    pub base: Option<BaseChain>,
}

impl Chain {
    /// A base chain with policy accept.
    pub fn base(name: impl Into<String>, ty: ChainType, hook: Hook, priority: i32) -> Chain {
        Chain {
            name: name.into(),
            base: Some(BaseChain {
                ty,
                hook,
                priority,
                policy: Some(Policy::Accept),
            }),
        }
    }

    pub fn regular(name: impl Into<String>) -> Chain {
        Chain {
            name: name.into(),
            base: None,
        }
    }
}

/// How nft(8) is to print a set's keys: the byte order the key is held in,
/// kept in the set's user data (`NFTNL_UDATA_SET_KEYBYTEORDER`). The kernel
/// does not look at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    Host = 1,
    Big = 2,
}

/// A set's key: nft's datatype number, its length, and its byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyType {
    pub datatype: u32,
    pub len: u32,
    pub byteorder: ByteOrder,
}

impl KeyType {
    // Datatype numbers are nft's (include/datatype.h), as set.go:67-114 has
    // them; byte orders are those of the expressions nft loads the keys
    // with (`ip daddr` big-endian, `meta mark` host).
    pub const IPV4_ADDR: KeyType = KeyType::new(7, 4, ByteOrder::Big);
    pub const IPV6_ADDR: KeyType = KeyType::new(8, 16, ByteOrder::Big);
    pub const INET_PROTO: KeyType = KeyType::new(12, 1, ByteOrder::Host);
    pub const INET_SERVICE: KeyType = KeyType::new(13, 2, ByteOrder::Big);
    pub const MARK: KeyType = KeyType::new(19, 4, ByteOrder::Host);
    /// A host-order key. The kernel orders an interval set's keys as
    /// bytes, so ranges of host-order numbers need them in big-endian
    /// order (nft adds a byteorder expression to the lookup); plain sets
    /// are fine.
    pub const UID: KeyType = KeyType::new(24, 4, ByteOrder::Host);
    pub const IFNAME: KeyType = KeyType::new(41, 16, ByteOrder::Host);

    pub const fn new(datatype: u32, len: u32, byteorder: ByteOrder) -> KeyType {
        KeyType {
            datatype,
            len,
            byteorder,
        }
    }
}

/// A set to create. An anonymous set is constant, lives as long as the
/// rule that uses it, and is reached by the id its batch gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Set {
    name: Option<String>,
    key: KeyType,
    constant: bool,
    interval: bool,
}

impl Set {
    pub fn named(name: impl Into<String>, key: KeyType) -> Set {
        Set {
            name: Some(name.into()),
            key,
            constant: false,
            interval: false,
        }
    }

    pub fn anonymous(key: KeyType) -> Set {
        Set {
            name: None,
            key,
            constant: true,
            interval: false,
        }
    }

    /// Elements are ranges: each a start, then an end flagged
    /// `interval_end` that is one past the last key in it.
    pub fn interval(mut self) -> Set {
        self.interval = true;
        self
    }

    /// Its elements cannot change once the batch is committed.
    pub fn constant(mut self) -> Set {
        self.constant = true;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetElem {
    pub key: Vec<u8>,
    /// Ends an interval (exclusively) rather than starting one.
    pub interval_end: bool,
}

impl SetElem {
    pub fn new(key: impl Into<Vec<u8>>) -> SetElem {
        SetElem {
            key: key.into(),
            interval_end: false,
        }
    }

    pub fn end(key: impl Into<Vec<u8>>) -> SetElem {
        SetElem {
            key: key.into(),
            interval_end: true,
        }
    }

    /// The interval of addresses `first..=last`, both of one family, for
    /// an interval set: the start, then the end one past `last` -- left
    /// out when `last` is the top of the address space, as nft(8) does,
    /// the interval then running to the end.
    pub fn ip_range(first: IpAddr, last: IpAddr) -> Vec<SetElem> {
        let (start, end) = match (first, last) {
            (IpAddr::V4(first), IpAddr::V4(last)) => (
                first.octets().to_vec(),
                u32::from(last)
                    .checked_add(1)
                    .map(|n| n.to_be_bytes().to_vec()),
            ),
            (IpAddr::V6(first), IpAddr::V6(last)) => (
                first.octets().to_vec(),
                u128::from(last)
                    .checked_add(1)
                    .map(|n| n.to_be_bytes().to_vec()),
            ),
            _ => panic!("ip_range: {} and {} are of different families", first, last),
        };
        let mut elems = vec![SetElem::new(start)];
        elems.extend(end.map(SetElem::end));
        elems
    }

    /// The addresses of the prefix `addr/len`, host bits ignored, as
    /// `ip_range` gives them.
    pub fn ip_prefix(addr: IpAddr, len: u8) -> Vec<SetElem> {
        match addr {
            IpAddr::V4(addr) => {
                let len = u32::from(len.min(32));
                let host = u32::MAX.checked_shr(len).unwrap_or(0);
                let first = u32::from(addr) & !host;
                SetElem::ip_range(
                    IpAddr::from(first.to_be_bytes()),
                    IpAddr::from((first | host).to_be_bytes()),
                )
            }
            IpAddr::V6(addr) => {
                let len = u32::from(len.min(128));
                let host = u128::MAX.checked_shr(len).unwrap_or(0);
                let first = u128::from(addr) & !host;
                SetElem::ip_range(
                    IpAddr::from(first.to_be_bytes()),
                    IpAddr::from((first | host).to_be_bytes()),
                )
            }
        }
    }
}

/// One encoded message of a batch, and what it does, for errors.
#[derive(Debug)]
pub(super) struct Pending {
    pub ty: u16,
    pub flags: u16,
    pub body: Vec<u8>,
    pub what: String,
}

/// Messages to commit as one transaction.
#[derive(Debug, Default)]
pub struct Batch {
    pub(super) messages: Vec<Pending>,
    next_set_id: u32,
    /// Rules added so far per chain, to name a failing one.
    rules: Vec<(String, String, usize)>,
}

impl Batch {
    pub fn new() -> Batch {
        Batch::default()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn push(&mut self, msg: u16, flags: u16, body: Attrs, what: String) {
        self.messages.push(Pending {
            ty: nft_type(msg),
            flags: NLM_F_REQUEST | NLM_F_ACK | flags,
            body: body.into_bytes(),
            what,
        });
    }

    /// table.go:65-80.
    pub fn add_table(&mut self, table: &Table) {
        let mut body = Attrs::nfgen(table.family as u8, 0);
        body.str(NFTA_TABLE_NAME, &table.name)
            .be32(NFTA_TABLE_FLAGS, 0);
        self.push(
            NFT_MSG_NEWTABLE,
            NLM_F_CREATE,
            body,
            format!("creating table {}", table),
        );
    }

    /// Deletes the table and all in it. It must exist, or the whole batch
    /// fails with ENOENT; see `del_table_if_exists`. table.go:48-62.
    pub fn del_table(&mut self, table: &Table) {
        let mut body = Attrs::nfgen(table.family as u8, 0);
        body.str(NFTA_TABLE_NAME, &table.name)
            .be32(NFTA_TABLE_FLAGS, 0);
        self.push(
            NFT_MSG_DELTABLE,
            0,
            body,
            format!("deleting table {}", table),
        );
    }

    /// Deletes the table if it is there. Any failed message aborts the
    /// whole transaction, so ENOENT cannot just be ignored; this adds the
    /// table first -- a no-op when it exists -- and then deletes it, as
    /// `table x; delete table x` does in an nft script.
    pub fn del_table_if_exists(&mut self, table: &Table) {
        self.add_table(table);
        self.messages.last_mut().unwrap().what = format!("deleting table {}", table);
        self.del_table(table);
    }

    /// chain.go:108-153.
    pub fn add_chain(&mut self, table: &Table, chain: &Chain) {
        let mut body = Attrs::nfgen(table.family as u8, 0);
        body.str(NFTA_CHAIN_TABLE, &table.name)
            .str(NFTA_CHAIN_NAME, &chain.name);
        if let Some(base) = &chain.base {
            body.nested(NFTA_CHAIN_HOOK, |a| {
                a.be32(NFTA_HOOK_HOOKNUM, base.hook as u32);
                a.be32(NFTA_HOOK_PRIORITY, base.priority as u32);
            });
            if let Some(policy) = base.policy {
                body.be32(NFTA_CHAIN_POLICY, policy as u32);
            }
            body.str(NFTA_CHAIN_TYPE, base.ty.name());
        }
        self.push(
            NFT_MSG_NEWCHAIN,
            NLM_F_CREATE,
            body,
            format!("creating chain {} in table {}", chain.name, table),
        );
    }

    /// Appends a rule to the chain. rule.go:101-168, without NLM_F_ECHO:
    /// the kernel would send each rule back, and the handles are not
    /// needed.
    pub fn add_rule(&mut self, table: &Table, chain: &str, exprs: &[Expr]) {
        let n = match self
            .rules
            .iter_mut()
            .find(|(t, c, _)| *t == table.name && c == chain)
        {
            Some((_, _, n)) => {
                *n += 1;
                *n
            }
            None => {
                self.rules.push((table.name.clone(), chain.to_string(), 1));
                1
            }
        };
        let mut body = Attrs::nfgen(table.family as u8, 0);
        body.str(NFTA_RULE_TABLE, &table.name)
            .str(NFTA_RULE_CHAIN, chain);
        body.nested(NFTA_RULE_EXPRESSIONS, |a| {
            for e in exprs {
                e.encode(a);
            }
        });
        self.push(
            NFT_MSG_NEWRULE,
            NLM_F_CREATE | NLM_F_APPEND,
            body,
            format!("creating rule {} in chain {}", n, chain),
        );
    }

    /// Creates a set, with `elems` in it, and returns what rules look it
    /// up by: its name and the id this batch gave it. set.go:505-647.
    pub fn add_set(&mut self, table: &Table, set: &Set, elems: &[SetElem]) -> SetRef {
        self.next_set_id += 1;
        let id = self.next_set_id;
        // The kernel names an anonymous set itself, filling in the %d.
        let name = set.name.clone().unwrap_or_else(|| "__set%d".to_string());
        let what = match &set.name {
            Some(name) => format!("set {}", name),
            None => format!("anonymous set {}", id),
        };
        let mut flags = 0;
        if set.name.is_none() {
            flags |= NFT_SET_ANONYMOUS;
        }
        if set.constant {
            flags |= NFT_SET_CONSTANT;
        }
        if set.interval {
            flags |= NFT_SET_INTERVAL;
        }
        let mut body = Attrs::nfgen(table.family as u8, 0);
        body.str(NFTA_SET_TABLE, &table.name)
            .str(NFTA_SET_NAME, &name)
            .be32(NFTA_SET_FLAGS, flags)
            .be32(NFTA_SET_KEY_TYPE, set.key.datatype)
            .be32(NFTA_SET_KEY_LEN, set.key.len)
            .be32(NFTA_SET_ID, id);
        if set.constant {
            // The number of elements, as nft(8) gives it for a constant
            // set, so the kernel can pick the backend and size it.
            body.nested(NFTA_SET_DESC, |a| {
                a.be32(NFTA_SET_DESC_SIZE, elems.len() as u32);
            });
        }
        // One nftnl_udata TLV: NFTNL_UDATA_SET_KEYBYTEORDER (0), 4 bytes,
        // a host-order u32.
        let mut udata = vec![0, 4];
        udata.extend_from_slice(&(set.key.byteorder as u32).to_ne_bytes());
        body.bytes(NFTA_SET_USERDATA, &udata);
        self.push(
            NFT_MSG_NEWSET,
            NLM_F_CREATE,
            body,
            format!("creating {}", what),
        );

        let set = SetRef { name, id: Some(id) };
        if !elems.is_empty() {
            self.push_elements(table, &set, elems, format!("adding elements to {}", what));
        }
        set
    }

    /// Adds elements to a set, one made in this batch or one that exists.
    pub fn add_elements(&mut self, table: &Table, set: &SetRef, elems: &[SetElem]) {
        let what = format!("adding elements to set {}", set.name);
        self.push_elements(table, set, elems, what);
    }

    /// set.go:399-503, for a set without data. The element list is one
    /// attribute, whose length is 16 bits, so a long list is split over
    /// as many messages as it takes -- as nft(8) and set.go's callers do --
    /// all in the same transaction.
    fn push_elements(&mut self, table: &Table, set: &SetRef, elems: &[SetElem], what: String) {
        // Room for the elements in one list attribute, with its header.
        const ROOM: usize = u16::MAX as usize - NLA_HDRLEN;
        let mut rest = elems;
        while !rest.is_empty() {
            let mut size = 0;
            let mut n = 0;
            for elem in rest {
                // The entry, its flags, the key nested twice.
                let len = NLA_HDRLEN
                    + if elem.interval_end { 8 } else { 0 }
                    + 2 * NLA_HDRLEN
                    + super::netlink::align(elem.key.len());
                if n > 0 && size + len > ROOM {
                    break;
                }
                size += len;
                n += 1;
            }
            let (chunk, tail) = rest.split_at(n);
            rest = tail;
            let mut body = Attrs::nfgen(table.family as u8, 0);
            body.str(NFTA_SET_ELEM_LIST_SET, &set.name);
            if let Some(id) = set.id {
                body.be32(NFTA_SET_ELEM_LIST_SET_ID, id);
            }
            body.str(NFTA_SET_ELEM_LIST_TABLE, &table.name);
            body.nested(NFTA_SET_ELEM_LIST_ELEMENTS, |a| {
                for (i, elem) in chunk.iter().enumerate() {
                    // Each element is a list entry numbered from 1; the
                    // kernel does not read the number.
                    a.nested((i as u16).wrapping_add(1), |a| {
                        if elem.interval_end {
                            a.be32(NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
                        }
                        a.nested(NFTA_SET_ELEM_KEY, |a| {
                            a.bytes(NFTA_DATA_VALUE, &elem.key);
                        });
                    });
                }
            });
            self.push(NFT_MSG_NEWSETELEM, NLM_F_CREATE, body, what.clone());
        }
    }

    /// Removes every element from a named set. set.go:689-703.
    pub fn flush_set(&mut self, table: &Table, set: &str) {
        let mut body = Attrs::nfgen(table.family as u8, 0);
        body.str(NFTA_SET_ELEM_LIST_TABLE, &table.name)
            .str(NFTA_SET_ELEM_LIST_SET, set);
        self.push(NFT_MSG_DELSETELEM, 0, body, format!("flushing set {}", set));
    }

    /// What each message does, in order: "creating rule 3 in chain
    /// output", say.
    pub fn descriptions(&self) -> impl Iterator<Item = &str> + '_ {
        self.messages.iter().map(|m| m.what.as_str())
    }

    /// Encodes the batch and reads it back: each message, and each
    /// attribute in it, nested ones too, must span its bytes exactly.
    /// Returns the number of messages, the framing included. For the tests
    /// of what builds batches.
    #[cfg(test)]
    pub(crate) fn check_wire(&self) -> usize {
        fn walk(mut buf: &[u8]) {
            while !buf.is_empty() {
                assert!(buf.len() >= NLA_HDRLEN, "truncated attribute header");
                let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
                let ty = u16::from_ne_bytes([buf[2], buf[3]]);
                assert!(
                    len >= NLA_HDRLEN && len <= buf.len(),
                    "bad attribute length"
                );
                if ty & NLA_F_NESTED != 0 {
                    walk(&buf[NLA_HDRLEN..len]);
                }
                buf = &buf[align(len).min(buf.len())..];
            }
        }
        let wire = self.encode(1);
        let mut n = 0;
        for msg in messages(&wire) {
            let msg = msg.expect("a well-formed message");
            // The nfgenmsg, then the attributes.
            assert!(msg.body.len() >= 4);
            walk(&msg.body[4..]);
            n += 1;
        }
        assert_eq!(n, self.messages.len() + 2);
        n
    }

    /// The batch as it is sent: BATCH_BEGIN, the messages numbered from
    /// `seq + 1`, BATCH_END. The begin and end markers carry the
    /// nf_tables subsystem as their resource id (conn.go:319-342).
    pub(super) fn encode(&self, seq: u32) -> Vec<u8> {
        let marker = Attrs::nfgen(0, NFNL_SUBSYS_NFTABLES).into_bytes();
        let mut out = Vec::new();
        put_message(&mut out, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, seq, &marker);
        for (i, msg) in self.messages.iter().enumerate() {
            put_message(
                &mut out,
                msg.ty,
                msg.flags,
                seq.wrapping_add(i as u32 + 1),
                &msg.body,
            );
        }
        let end = seq.wrapping_add(self.messages.len() as u32 + 1);
        put_message(&mut out, NFNL_MSG_BATCH_END, NLM_F_REQUEST, end, &marker);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::expr::*;
    use super::super::netlink::messages;
    use super::*;

    /// The bodies of the batch's messages, header and all, as the Go tests
    /// compare them (without the 16-byte nlmsghdr).
    fn bodies(batch: &Batch) -> Vec<Vec<u8>> {
        batch.messages.iter().map(|m| m.body.clone()).collect()
    }

    fn nat_table() -> Table {
        Table::new(Family::Ipv4, "nat")
    }

    fn nat_prerouting() -> Chain {
        Chain {
            name: "prerouting".into(),
            base: Some(BaseChain {
                ty: ChainType::Nat,
                hook: Hook::Prerouting,
                priority: 0,
                policy: None,
            }),
        }
    }

    #[test]
    fn table_and_chain() {
        // nftables_test.go:243-245, straced from nft(8): "add table ip nat",
        // "add chain nat prerouting { type nat hook prerouting priority 0 }".
        let mut b = Batch::new();
        b.add_table(&nat_table());
        b.add_chain(&nat_table(), &nat_prerouting());
        assert_eq!(
            bodies(&b),
            [
                b"\x02\x00\x00\x00\x08\x00\x01\x00nat\x00\x08\x00\x02\x00\x00\x00\x00\x00".to_vec(),
                b"\x02\x00\x00\x00\x08\x00\x01\x00nat\x00\
                  \x0f\x00\x03\x00prerouting\x00\x00\
                  \x14\x00\x04\x80\
                  \x08\x00\x01\x00\x00\x00\x00\x00\
                  \x08\x00\x02\x00\x00\x00\x00\x00\
                  \x08\x00\x07\x00nat\x00"
                    .to_vec(),
            ]
        );
        assert_eq!(
            b.messages[0].flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE
        );
        assert_eq!(b.messages[0].ty, 0x0a00);
        assert_eq!(b.messages[1].ty, 0x0a03);
    }

    #[test]
    fn chain_priority_is_signed_and_policy_follows_the_hook() {
        // chain.go:117-137: priority as a big-endian two's-complement u32,
        // then the policy, then the type.
        let mut b = Batch::new();
        let t = Table::new(Family::Inet, "t");
        b.add_chain(&t, &Chain::base("c", ChainType::Route, Hook::Output, -151));
        assert_eq!(
            bodies(&b)[0],
            b"\x01\x00\x00\x00\x06\x00\x01\x00t\x00\x00\x00\
              \x06\x00\x03\x00c\x00\x00\x00\
              \x14\x00\x04\x80\
              \x08\x00\x01\x00\x00\x00\x00\x03\
              \x08\x00\x02\x00\xff\xff\xff\x69\
              \x08\x00\x05\x00\x00\x00\x00\x01\
              \x0a\x00\x07\x00route\x00\x00\x00"
        );
        // A regular chain is just table and name (nftables_test.go:5176).
        let mut b = Batch::new();
        b.add_chain(
            &Table::new(Family::Ipv4, "filter"),
            &Chain::regular("base-chain"),
        );
        assert_eq!(
            bodies(&b)[0],
            b"\x02\x00\x00\x00\x0b\x00\x01\x00filter\x00\x00\
              \x0f\x00\x03\x00base-chain\x00\x00"
        );
    }

    #[test]
    fn redirect_rule() {
        // nftables_test.go:4299, straced from nft(8): "add rule nat
        // prerouting tcp dport 22 redirect to 2222".
        let mut b = Batch::new();
        let mut rule = meta_cmp(MetaKey::L4Proto, CmpOp::Eq, vec![6]).to_vec();
        rule.push(Expr::Payload {
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
            dreg: Reg::R1,
        });
        rule.push(cmp(CmpOp::Eq, port(22)));
        rule.push(Expr::Immediate {
            dreg: Reg::R1,
            data: port(2222),
        });
        rule.push(Expr::Redir {
            proto_min: Some(Reg::R1),
            flags: 0,
        });
        b.add_rule(&nat_table(), "prerouting", &rule);
        let want = b"\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\xfc\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x00\x16\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x06\x00\x01\x00\x08\xae\x00\x00\x1c\x00\x01\x80\x0a\x00\x01\x00\x72\x65\x64\x69\x72\x00\x00\x00\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01";
        assert_eq!(bodies(&b)[0], want.to_vec());
        assert_eq!(
            b.messages[0].flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND
        );
        assert_eq!(b.messages[0].what, "creating rule 1 in chain prerouting");
    }

    #[test]
    fn anonymous_set_and_its_lookup() {
        // nftables_test.go:2664-2672, straced from nft(8): "add rule filter
        // forward tcp dport {69, 1163} drop" -- the set, its elements, the
        // rule looking it up by id.
        let filter = Table::new(Family::Ipv4, "filter");
        let mut b = Batch::new();
        let set = b.add_set(
            &filter,
            &Set::anonymous(KeyType::INET_SERVICE),
            &[SetElem::new(port(69)), SetElem::new(port(1163))],
        );
        let mut rule = meta_cmp(MetaKey::L4Proto, CmpOp::Eq, vec![6]).to_vec();
        rule.push(Expr::Payload {
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
            dreg: Reg::R1,
        });
        rule.push(lookup(&set, false));
        rule.push(verdict(Verdict::Drop));
        b.add_rule(&filter, "forward", &rule);
        let want: [&[u8]; 3] = [
            b"\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x5f\x5f\x73\x65\x74\x25\x64\x00\x08\x00\x03\x00\x00\x00\x00\x03\x08\x00\x04\x00\x00\x00\x00\x0d\x08\x00\x05\x00\x00\x00\x00\x02\x08\x00\x0a\x00\x00\x00\x00\x01\x0c\x00\x09\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0a\x00\x0d\x00\x00\x04\x02\x00\x00\x00\x00\x00",
            b"\x02\x00\x00\x00\x0c\x00\x02\x00\x5f\x5f\x73\x65\x74\x25\x64\x00\x08\x00\x04\x00\x00\x00\x00\x01\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x24\x00\x03\x80\x10\x00\x01\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x00\x45\x00\x00\x10\x00\x02\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x04\x8b\x00\x00",
            b"\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xe8\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x30\x00\x01\x80\x0b\x00\x01\x00\x6c\x6f\x6f\x6b\x75\x70\x00\x00\x20\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x01\x00\x5f\x5f\x73\x65\x74\x25\x64\x00\x08\x00\x04\x00\x00\x00\x00\x01\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00",
        ];
        let got = bodies(&b);
        // The user data is the one byte-order-dependent part: a big-endian
        // key is 2 as a host u32, which the Go code hardcodes little-endian.
        if cfg!(target_endian = "little") {
            assert_eq!(got[0], want[0]);
        }
        assert_eq!(got[1], want[1]);
        assert_eq!(got[2], want[2]);
        assert_eq!(b.messages[0].what, "creating anonymous set 1");
        assert_eq!(b.messages[1].what, "adding elements to anonymous set 1");
    }

    #[test]
    fn named_interval_set() {
        // set.go:531-608 for a named, non-constant interval set: no
        // NFTA_SET_DESC; then set.go:420-503 for its elements, the end of
        // each interval flagged NFT_SET_ELEM_INTERVAL_END.
        let t = Table::new(Family::Inet, "t");
        let mut b = Batch::new();
        let elems = SetElem::ip_prefix("10.1.0.0".parse().unwrap(), 16);
        let set = b.add_set(&t, &Set::named("s4", KeyType::IPV4_ADDR).interval(), &elems);
        assert_eq!(
            set,
            SetRef {
                name: "s4".into(),
                id: Some(1)
            }
        );
        let mut want_set = b"\x01\x00\x00\x00\
            \x06\x00\x01\x00t\x00\x00\x00\
            \x07\x00\x02\x00s4\x00\x00\
            \x08\x00\x03\x00\x00\x00\x00\x04\
            \x08\x00\x04\x00\x00\x00\x00\x07\
            \x08\x00\x05\x00\x00\x00\x00\x04\
            \x08\x00\x0a\x00\x00\x00\x00\x01\
            \x0a\x00\x0d\x00\x00\x04"
            .to_vec();
        want_set.extend_from_slice(&2u32.to_ne_bytes());
        want_set.extend_from_slice(&[0, 0]);
        let want_elems = b"\x01\x00\x00\x00\
            \x07\x00\x02\x00s4\x00\x00\
            \x08\x00\x04\x00\x00\x00\x00\x01\
            \x06\x00\x01\x00t\x00\x00\x00\
            \x2c\x00\x03\x80\
            \x10\x00\x01\x80\x0c\x00\x01\x80\x08\x00\x01\x00\x0a\x01\x00\x00\
            \x18\x00\x02\x80\
            \x08\x00\x03\x00\x00\x00\x00\x01\
            \x0c\x00\x01\x80\x08\x00\x01\x00\x0a\x02\x00\x00";
        assert_eq!(bodies(&b), [want_set, want_elems.to_vec()]);
    }

    #[test]
    fn ip_ranges() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(
            SetElem::ip_prefix(ip("192.168.1.10"), 24),
            [
                SetElem::new([192, 168, 1, 0]),
                SetElem::end([192, 168, 2, 0])
            ]
        );
        // The top of the space has no end element.
        assert_eq!(SetElem::ip_prefix(ip("0.0.0.0"), 0), [SetElem::new([0; 4])]);
        assert_eq!(
            SetElem::ip_prefix(ip("255.255.255.255"), 32),
            [SetElem::new([255; 4])]
        );
        let mut end = [0u8; 16];
        end[0] = 0xfe;
        end[1] = 0xc0;
        assert_eq!(
            SetElem::ip_prefix(ip("fe80::1"), 10),
            [SetElem::new(v6_octets("fe80::")), SetElem::end(end)]
        );
        assert_eq!(
            SetElem::ip_prefix(ip("::1"), 128)[1],
            SetElem::end(v6_octets("::2"))
        );
    }

    fn v6_octets(s: &str) -> [u8; 16] {
        s.parse::<std::net::Ipv6Addr>().unwrap().octets()
    }

    #[test]
    fn delete_and_flush() {
        let t = Table::new(Family::Inet, "t");
        let mut b = Batch::new();
        b.del_table_if_exists(&t);
        b.flush_set(&t, "s");
        // table.go:48-62: name and zero flags, no NLM_F_CREATE.
        assert_eq!(b.messages[0].ty, 0x0a00);
        assert_eq!(b.messages[1].ty, 0x0a02);
        assert_eq!(b.messages[1].flags, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(
            b.messages[1].body,
            b"\x01\x00\x00\x00\x06\x00\x01\x00t\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"
        );
        assert_eq!(b.messages[0].what, "deleting table inet t");
        // set.go:689-703: DELSETELEM with only table and set.
        assert_eq!(b.messages[2].ty, 0x0a0e);
        assert_eq!(b.messages[2].flags, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(
            b.messages[2].body,
            b"\x01\x00\x00\x00\x06\x00\x01\x00t\x00\x00\x00\x06\x00\x02\x00s\x00\x00\x00"
        );
    }

    #[test]
    fn long_element_list_is_split() {
        // 3000 IPv6 intervals do not fit one 64 KiB attribute.
        let t = Table::new(Family::Inet, "t");
        let mut b = Batch::new();
        let elems: Vec<SetElem> = (0..3000u128)
            .flat_map(|i| SetElem::ip_prefix(IpAddr::from((i << 64).to_be_bytes()), 64))
            .collect();
        let set = b.add_set(&t, &Set::named("s6", KeyType::IPV6_ADDR).interval(), &elems);
        assert!(b.messages.len() > 2, "{} messages", b.messages.len());
        b.check_wire();
        // Every element went, once, in order.
        let mut keys = Vec::new();
        for m in &b.messages[1..] {
            assert_eq!(m.ty, 0x0a0c);
            assert_eq!(m.what, "adding elements to set s6");
            for (ty, list) in super::super::netlink::attrs(&m.body[4..]) {
                if ty == NFTA_SET_ELEM_LIST_ELEMENTS {
                    for (_, elem) in super::super::netlink::attrs(list) {
                        keys.push(elem.to_vec());
                    }
                }
            }
        }
        assert_eq!(keys.len(), elems.len());
        assert_eq!(set.id, Some(1));
        // Adding them later splits the same way.
        let mut b = Batch::new();
        b.add_elements(&t, &SetRef::named("s6"), &elems);
        assert_eq!(b.messages.len(), 3);
    }

    #[test]
    fn batch_framing() {
        // conn.go:319-342: begin and end are nfgenmsg-only messages with
        // res_id NFNL_SUBSYS_NFTABLES (big-endian 10) and no ack asked.
        let t = Table::new(Family::Inet, "t");
        let mut b = Batch::new();
        b.add_table(&t);
        b.add_rule(&t, "c", &[Expr::Counter]);
        b.add_rule(&t, "c", &[Expr::Counter]);
        b.add_rule(&t, "d", &[Expr::Counter]);
        let wire = b.encode(100);
        let msgs: Vec<_> = messages(&wire).collect::<Result<_, _>>().unwrap();
        assert_eq!(msgs.len(), 6);
        assert_eq!((msgs[0].ty, msgs[0].flags, msgs[0].seq), (0x10, 1, 100));
        assert_eq!(msgs[0].body, [0, 0, 0, 10]);
        assert_eq!((msgs[5].ty, msgs[5].flags, msgs[5].seq), (0x11, 1, 105));
        assert_eq!(msgs[5].body, [0, 0, 0, 10]);
        for (i, m) in msgs[1..5].iter().enumerate() {
            assert_eq!(m.seq, 101 + i as u32);
            assert_ne!(m.flags & NLM_F_ACK, 0);
            assert_eq!(m.body, b.messages[i].body);
        }
        assert_eq!(wire.len() % 4, 0);
        let whats: Vec<_> = b.messages.iter().map(|m| m.what.as_str()).collect();
        assert_eq!(
            whats,
            [
                "creating table inet t",
                "creating rule 1 in chain c",
                "creating rule 2 in chain c",
                "creating rule 1 in chain d"
            ]
        );
    }
}
