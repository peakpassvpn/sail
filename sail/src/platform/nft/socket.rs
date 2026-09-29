//! The `NETLINK_NETFILTER` socket: committing a batch and reading its
//! acknowledgements, and dumping the tables.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use super::netlink::{attr_be32, attr_str, attrs, messages, nft_type, put_message, Attrs};
use super::sys::*;
use super::{Batch, Error, Family};

/// How long to wait for the kernel's answer. It handles a batch within the
/// send, so the answer is there when the send returns; this is only so a
/// kernel that loses one cannot hang the caller.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// Room in the receive buffer per acknowledgement: each is its own small
/// skb, and all of a batch's are queued before the first is read.
const ACK_ROOM: usize = 1024;

pub(in crate::platform) struct Socket {
    fd: OwnedFd,
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

impl Socket {
    pub(in crate::platform) fn open() -> io::Result<Socket> {
        Socket::open_protocol(libc::NETLINK_NETFILTER)
    }

    /// A socket of another netlink family: `NETLINK_ROUTE` for rtnetlink.
    pub(in crate::platform) fn open_protocol(protocol: libc::c_int) -> io::Result<Socket> {
        // SAFETY: plain socket(2); the result is checked and owned.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh descriptor nothing else owns.
        let socket = Socket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        // Errors come back with the failed message's header only, and with
        // the kernel's own words where it has any. Older kernels lack
        // these; the answers are then just longer and plainer.
        let _ = socket.set_int(libc::SOL_NETLINK, libc::NETLINK_CAP_ACK, 1);
        let _ = socket.set_int(libc::SOL_NETLINK, libc::NETLINK_EXT_ACK, 1);
        let timeout = libc::timeval {
            tv_sec: ANSWER_TIMEOUT.as_secs() as libc::time_t,
            tv_usec: 0,
        };
        socket.set(libc::SOL_SOCKET, libc::SO_RCVTIMEO, &timeout)?;
        Ok(socket)
    }

    fn set<T>(&self, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
        // SAFETY: value points to a live T of the size passed.
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                level,
                name,
                value as *const T as *const libc::c_void,
                std::mem::size_of::<T>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(in crate::platform) fn set_int(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        self.set(level, name, &value)
    }

    /// Makes a socket buffer at least `size` bytes: past the system limit
    /// where we may (CAP_NET_ADMIN, which committing needs anyway), up to
    /// it otherwise.
    fn grow_buffer(&self, force: libc::c_int, plain: libc::c_int, size: usize) {
        let size = size.min(libc::c_int::MAX as usize) as libc::c_int;
        if self.set_int(libc::SOL_SOCKET, force, size).is_err() {
            let _ = self.set_int(libc::SOL_SOCKET, plain, size);
        }
    }

    pub(in crate::platform) fn send(&self, buf: &[u8]) -> io::Result<()> {
        loop {
            // SAFETY: buf is valid for its length. Unconnected, a netlink
            // socket sends to the kernel.
            let n = unsafe { libc::send(self.fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n as usize != buf.len() {
                return Err(io::Error::other(format!(
                    "sent {} of {} bytes",
                    n,
                    buf.len()
                )));
            }
            return Ok(());
        }
    }

    /// One datagram, whole: its size is peeked first.
    pub(in crate::platform) fn recv(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 0];
        let mut flags = libc::MSG_PEEK | libc::MSG_TRUNC;
        loop {
            // SAFETY: buf is valid for its length.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    flags,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let n = n as usize;
            if flags != 0 {
                buf.resize(n, 0);
                flags = 0;
                continue;
            }
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

/// Maps a failed receive to what it means for the caller.
fn recv_error(e: io::Error, doing: &str) -> Error {
    match e.raw_os_error() {
        Some(libc::EAGAIN) => Error::Protocol(format!(
            "{}: no answer from the kernel in {}s",
            doing,
            ANSWER_TIMEOUT.as_secs()
        )),
        Some(libc::ENOBUFS) => Error::Protocol(format!(
            "{}: the kernel dropped answers for want of buffer space",
            doing
        )),
        _ => Error::Io(e),
    }
}

/// An `NLMSG_ERROR`'s errno (positive, 0 for an acknowledgement), and the
/// kernel's message if it gave one.
pub(in crate::platform) fn parse_error(
    flags: u16,
    body: &[u8],
) -> Result<(i32, Option<String>), Error> {
    let short = || Error::Protocol("short NLMSG_ERROR".into());
    let errno = -i32::from_ne_bytes(body.get(..4).ok_or_else(short)?.try_into().unwrap());
    if flags & NLM_F_ACK_TLVS == 0 {
        return Ok((errno, None));
    }
    // After the errno, the original message: its header only when capped.
    let orig = body.get(4..).ok_or_else(short)?;
    let orig_len = if flags & NLM_F_CAPPED != 0 {
        NLMSG_HDRLEN
    } else {
        let len = orig.get(..4).ok_or_else(short)?;
        super::netlink::align(u32::from_ne_bytes(len.try_into().unwrap()) as usize)
    };
    let message = orig
        .get(orig_len..)
        .and_then(|tlvs| attrs(tlvs).find(|(ty, _)| *ty == NLMSGERR_ATTR_MSG))
        .map(|(_, msg)| attr_str(msg))
        .filter(|msg| !msg.is_empty());
    Ok((errno, message))
}

/// A sequence number to start from: a fresh socket sees only answers to
/// its own requests, so this needs only to be unlikely to repeat.
pub(in crate::platform) fn first_seq() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1)
}

impl Batch {
    /// Sends the batch as one transaction and waits for the kernel to
    /// acknowledge each message. On an error nothing of it was applied;
    /// the error names the first message that failed.
    pub fn commit(&self) -> Result<(), Error> {
        if self.messages.is_empty() {
            return Ok(());
        }
        let socket = Socket::open()?;
        let seq = first_seq();
        let wire = self.encode(seq);
        socket.grow_buffer(libc::SO_SNDBUFFORCE, libc::SO_SNDBUF, wire.len() + 4096);
        socket.grow_buffer(
            libc::SO_RCVBUFFORCE,
            libc::SO_RCVBUF,
            self.messages.len() * ACK_ROOM + 65536,
        );
        socket.send(&wire)?;

        let end = seq.wrapping_add(self.messages.len() as u32 + 1);
        let mut acked = vec![false; self.messages.len()];
        let mut left = self.messages.len();
        // (index of the message, errno, the kernel's words)
        let mut failed: Vec<(usize, i32, Option<String>)> = Vec::new();
        while left > 0 {
            let dgram = socket
                .recv()
                .map_err(|e| recv_error(e, "committing the nftables batch"))?;
            for msg in messages(&dgram) {
                let msg = msg.map_err(|e| Error::Protocol(e.into()))?;
                if msg.ty != NLMSG_ERROR {
                    continue;
                }
                let (errno, message) = parse_error(msg.flags, msg.body)?;
                if msg.seq == seq || msg.seq == end {
                    // Refused as a whole -- no permission, no nf_tables --
                    // or failed in the commit itself: the kernel answers
                    // for the batch at its first message.
                    return Err(Error::Kernel {
                        what: "committing the nftables batch".into(),
                        errno: if errno == 0 { libc::EPROTO } else { errno },
                        message,
                        others: 0,
                    });
                }
                let i = msg.seq.wrapping_sub(seq).wrapping_sub(1) as usize;
                if i >= acked.len() || acked[i] {
                    continue;
                }
                acked[i] = true;
                left -= 1;
                if errno != 0 {
                    failed.push((i, errno, message));
                }
            }
        }
        failed.sort_by_key(|(i, _, _)| *i);
        let others = failed.len().saturating_sub(1);
        match failed.into_iter().next() {
            None => Ok(()),
            Some((i, errno, message)) => Err(Error::Kernel {
                what: self.messages[i].what.clone(),
                errno,
                message,
                others,
            }),
        }
    }
}

/// A table the kernel has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableInfo {
    pub family: Family,
    pub name: String,
    pub flags: u32,
    /// How many objects -- chains, sets and the like -- it holds
    /// (`NFTA_TABLE_USE`).
    pub uses: u32,
}

/// The tables of `family`, or of every family. Failing to list them --
/// no nf_tables in the kernel, say -- is the sign nftables cannot be used.
pub fn list_tables(family: Option<Family>) -> Result<Vec<TableInfo>, Error> {
    let socket = Socket::open()?;
    let seq = first_seq();
    let mut wire = Vec::new();
    let body = Attrs::nfgen(family.map_or(0, |f| f as u8), 0).into_bytes();
    put_message(
        &mut wire,
        nft_type(NFT_MSG_GETTABLE),
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        &body,
    );
    socket.send(&wire)?;

    let mut tables = Vec::new();
    loop {
        let dgram = socket
            .recv()
            .map_err(|e| recv_error(e, "listing nftables tables"))?;
        for msg in messages(&dgram) {
            let msg = msg.map_err(|e| Error::Protocol(e.into()))?;
            if msg.seq != seq {
                continue;
            }
            match msg.ty {
                NLMSG_DONE => {
                    // A dump that failed part way says so here.
                    let status = msg
                        .body
                        .get(..4)
                        .map_or(0, |b| -i32::from_ne_bytes(b.try_into().unwrap()));
                    if status > 0 {
                        return Err(Error::Kernel {
                            what: "listing tables".into(),
                            errno: status,
                            message: None,
                            others: 0,
                        });
                    }
                    return Ok(tables);
                }
                NLMSG_ERROR => {
                    let (errno, message) = parse_error(msg.flags, msg.body)?;
                    if errno != 0 {
                        return Err(Error::Kernel {
                            what: "listing tables".into(),
                            errno,
                            message,
                            others: 0,
                        });
                    }
                }
                ty if ty == nft_type(NFT_MSG_NEWTABLE) => {
                    let Some(family) = msg.body.first().and_then(|&f| Family::from_u8(f)) else {
                        continue;
                    };
                    let mut table = TableInfo {
                        family,
                        name: String::new(),
                        flags: 0,
                        uses: 0,
                    };
                    for (ty, payload) in attrs(msg.body.get(4..).unwrap_or_default()) {
                        match ty {
                            NFTA_TABLE_NAME => table.name = attr_str(payload),
                            NFTA_TABLE_FLAGS => table.flags = attr_be32(payload).unwrap_or(0),
                            NFTA_TABLE_USE => table.uses = attr_be32(payload).unwrap_or(0),
                            _ => {}
                        }
                    }
                    tables.push(table);
                }
                _ => {}
            }
            // A dump's parts carry NLM_F_MULTI until the DONE; a lone
            // answer without it ends the dump.
            if msg.flags & NLM_F_MULTI == 0 && msg.ty != NLMSG_ERROR {
                return Ok(tables);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::process::Command;

    use super::super::*;

    const TABLE: &str = "sail-nft-test";

    /// nft(8), to read back what the kernel has: `$SAIL_NFT`, or `nft`.
    fn nft(args: &[&str]) -> String {
        let bin = std::env::var("SAIL_NFT").unwrap_or_else(|_| "nft".into());
        let out = Command::new(&bin)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("cannot run {}: {}", bin, e));
        assert!(
            out.status.success(),
            "nft {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn rule(parts: impl IntoIterator<Item = impl IntoIterator<Item = Expr>>) -> Vec<Expr> {
        parts.into_iter().flatten().collect()
    }

    fn l4proto(op: CmpOp, proto: u8) -> [Expr; 2] {
        meta_cmp(MetaKey::L4Proto, op, vec![proto])
    }

    fn nfproto(family: Family) -> [Expr; 2] {
        meta_cmp(MetaKey::NfProto, CmpOp::Eq, vec![family as u8])
    }

    fn mark(op: CmpOp, value: u32) -> [Expr; 2] {
        meta_cmp(MetaKey::Mark, op, host_u32(value))
    }

    fn payload(base: PayloadBase, offset: u32, len: u32) -> [Expr; 1] {
        [Expr::Payload {
            base,
            offset,
            len,
            dreg: Reg::R1,
        }]
    }

    fn immediate(dreg: Reg, data: impl Into<Vec<u8>>) -> [Expr; 1] {
        [Expr::Immediate {
            dreg,
            data: data.into(),
        }]
    }

    fn then(v: Verdict) -> [Expr; 2] {
        [Expr::Counter, verdict(v)]
    }

    /// Builds a table with every chain type, named and anonymous sets and
    /// every expression, commits it, and reads it back with nft(8). Run as
    /// root in a network namespace of its own, since nftables state is per
    /// namespace:
    ///
    /// ```text
    /// ip netns add sail-nft-test
    /// ip netns exec sail-nft-test <test binary> --ignored --exact \
    ///     platform::nft::socket::tests::commit_and_read_back
    /// ip netns del sail-nft-test
    /// ```
    #[test]
    #[ignore = "requires root and nf_tables"]
    fn commit_and_read_back() {
        let t = Table::new(Family::Inet, TABLE);
        const UDP: u8 = 17;
        const TCP: u8 = 6;
        const ICMP: u8 = 1;
        const ICMPV6: u8 = 58;

        let mut b = Batch::new();
        b.del_table_if_exists(&t);
        b.add_table(&t);
        let v4 = b.add_set(
            &t,
            &Set::named("v4", KeyType::IPV4_ADDR).interval(),
            &[
                SetElem::ip_prefix(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
                SetElem::ip_prefix(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)), 24),
                SetElem::ip_prefix(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 3),
            ]
            .concat(),
        );
        let v6 = b.add_set(
            &t,
            &Set::named("v6", KeyType::IPV6_ADDR).interval(),
            &[
                SetElem::ip_prefix(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
                SetElem::ip_prefix("fd00::".parse().unwrap(), 8),
            ]
            .concat(),
        );
        b.add_chain(
            &t,
            &Chain::base("prematch", ChainType::Filter, Hook::Prerouting, -101),
        );
        b.add_chain(
            &t,
            &Chain::base("output", ChainType::Nat, Hook::Output, -100),
        );
        b.add_chain(
            &t,
            &Chain::base("output_route", ChainType::Route, Hook::Output, -150),
        );
        b.add_chain(&t, &Chain::regular("bypass"));

        // prematch: filter, prerouting.
        let no_udp_icmp = b.add_set(
            &t,
            &Set::anonymous(KeyType::INET_PROTO),
            &[
                SetElem::new([UDP]),
                SetElem::new([ICMP]),
                SetElem::new([ICMPV6]),
            ],
        );
        let ifaces = b.add_set(
            &t,
            &Set::anonymous(KeyType::IFNAME),
            &[
                SetElem::new(ifname("eth1").unwrap()),
                SetElem::new(ifname("eth2").unwrap()),
            ],
        );
        let rules = vec![
            rule([
                meta_cmp(MetaKey::IifName, CmpOp::Eq, ifname("tun0").unwrap()).to_vec(),
                vec![verdict(Verdict::Return)],
            ]),
            rule([
                vec![meta(MetaKey::IifName), lookup(&ifaces, false)],
                then(Verdict::Return).to_vec(),
            ]),
            rule([
                vec![meta(MetaKey::L4Proto), lookup(&no_udp_icmp, true)],
                vec![verdict(Verdict::Return)],
            ]),
            rule([
                mark(CmpOp::Eq, 0x2024).to_vec(),
                then(Verdict::Return).to_vec(),
            ]),
            rule([
                ct_cmp(CtKey::Mark, CmpOp::Eq, host_u32(0x2024)).to_vec(),
                vec![verdict(Verdict::Return)],
            ]),
            rule([
                ct_cmp(CtKey::Direction, CmpOp::Eq, vec![1]).to_vec(),
                vec![verdict(Verdict::Return)],
            ]),
            // tcp flags & (syn | ack) == syn counter queue num 100 bypass
            rule([
                l4proto(CmpOp::Eq, TCP).to_vec(),
                payload(PayloadBase::Transport, 13, 1).to_vec(),
                vec![
                    Expr::Bitwise {
                        sreg: Reg::R1,
                        dreg: Reg::R1,
                        len: 1,
                        mask: vec![0x12],
                        xor: vec![0],
                    },
                    cmp(CmpOp::Eq, vec![0x02]),
                    Expr::Counter,
                    Expr::Queue {
                        num: 100,
                        total: 1,
                        flags: QUEUE_FLAG_BYPASS,
                    },
                ],
            ]),
            rule([
                l4proto(CmpOp::Eq, TCP).to_vec(),
                mark(CmpOp::Eq, 0x2025).to_vec(),
                vec![
                    Expr::Counter,
                    Expr::Reject {
                        kind: RejectKind::TcpRst,
                        code: 0,
                    },
                ],
            ]),
            rule([
                mark(CmpOp::Eq, 0x2026).to_vec(),
                vec![Expr::Reject {
                    kind: RejectKind::Icmpx,
                    code: 3,
                }],
            ]),
            rule([
                nfproto(Family::Ipv4).to_vec(),
                mark(CmpOp::Eq, 0x2027).to_vec(),
                vec![Expr::Reject {
                    kind: RejectKind::Icmp,
                    code: 0,
                }],
            ]),
            rule([
                mark(CmpOp::Eq, 0x2024).to_vec(),
                vec![
                    meta(MetaKey::Mark),
                    Expr::CtSet {
                        key: CtKey::Mark,
                        sreg: Reg::R1,
                    },
                    Expr::Counter,
                ],
            ]),
            rule([
                nfproto(Family::Ipv4).to_vec(),
                payload(PayloadBase::Network, 16, 4).to_vec(),
                vec![lookup(&v4, false)],
                then(Verdict::Return).to_vec(),
            ]),
            rule([
                nfproto(Family::Ipv6).to_vec(),
                payload(PayloadBase::Network, 24, 16).to_vec(),
                vec![lookup(&SetRef::named("v6"), true)],
                then(Verdict::Return).to_vec(),
            ]),
            rule([
                l4proto(CmpOp::Eq, TCP).to_vec(),
                vec![
                    Expr::Exthdr {
                        op: ExthdrOp::TcpOpt,
                        ty: 30,
                        offset: 0,
                        len: 1,
                        flags: EXTHDR_F_PRESENT,
                        dreg: Reg::R1,
                    },
                    cmp(CmpOp::Eq, vec![1]),
                ],
                then(Verdict::Drop).to_vec(),
            ]),
            rule([
                mark(CmpOp::Eq, 0x2028).to_vec(),
                vec![verdict(Verdict::Jump("bypass".into()))],
            ]),
        ];
        for r in &rules {
            b.add_rule(&t, "prematch", r);
        }
        b.add_rule(&t, "bypass", &then(Verdict::Accept));
        drop(v6);

        // output: nat, output. An anonymous set binds to one rule only, so
        // each rule gets its own.
        let mut dns = |family: Family, addr: Vec<u8>| {
            let tcp_udp = b.add_set(
                &t,
                &Set::anonymous(KeyType::INET_PROTO),
                &[SetElem::new([TCP]), SetElem::new([UDP])],
            );
            rule([
                nfproto(family).to_vec(),
                meta_cmp(MetaKey::OifName, CmpOp::Neq, ifname("lo").unwrap()).to_vec(),
                vec![meta(MetaKey::L4Proto), lookup(&tcp_udp, false)],
                payload(PayloadBase::Transport, 2, 2).to_vec(),
                vec![cmp(CmpOp::Eq, port(53)), Expr::Counter],
                immediate(Reg::R1, addr).to_vec(),
                vec![Expr::Nat {
                    kind: NatKind::Dnat,
                    family,
                    addr_min: Some(Reg::R1),
                    proto_min: None,
                    flags: 0,
                }],
            ])
        };
        let dns4 = dns(Family::Ipv4, vec![172, 18, 0, 2]);
        let dns6 = dns(
            Family::Ipv6,
            "fdfe:dcba:9876::2"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        );
        b.add_rule(&t, "output", &dns4);
        b.add_rule(&t, "output", &dns6);
        b.add_rule(
            &t,
            "output",
            &rule([
                nfproto(Family::Ipv4).to_vec(),
                mark(CmpOp::Eq, 0x2029).to_vec(),
                immediate(Reg::R1, vec![127, 0, 0, 1]).to_vec(),
                immediate(Reg::R2, port(5353)).to_vec(),
                vec![Expr::Nat {
                    kind: NatKind::Dnat,
                    family: Family::Ipv4,
                    addr_min: Some(Reg::R1),
                    proto_min: Some(Reg::R2),
                    flags: NAT_RANGE_PROTO_SPECIFIED,
                }],
            ]),
        );
        b.add_rule(
            &t,
            "output",
            &rule([
                l4proto(CmpOp::Eq, TCP).to_vec(),
                vec![Expr::Counter],
                immediate(Reg::R1, port(7890)).to_vec(),
                vec![Expr::Redir {
                    proto_min: Some(Reg::R1),
                    flags: NAT_RANGE_PROTO_SPECIFIED,
                }],
                vec![verdict(Verdict::Return)],
            ]),
        );

        // output_route: route, output.
        let uids = b.add_set(
            &t,
            &Set::anonymous(KeyType::UID),
            &[SetElem::new(host_u32(1000)), SetElem::new(host_u32(2000))],
        );
        let routed = b.add_set(
            &t,
            &Set::anonymous(KeyType::IPV4_ADDR).interval(),
            &[
                SetElem::ip_prefix(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
                SetElem::ip_prefix(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
            ]
            .concat(),
        );
        b.add_rule(
            &t,
            "output_route",
            &rule([
                meta_cmp(MetaKey::SkUid, CmpOp::Eq, host_u32(0)).to_vec(),
                vec![verdict(Verdict::Return)],
            ]),
        );
        b.add_rule(
            &t,
            "output_route",
            &rule([
                vec![meta(MetaKey::SkUid), lookup(&uids, true)],
                vec![verdict(Verdict::Return)],
            ]),
        );
        b.add_rule(
            &t,
            "output_route",
            &rule([
                nfproto(Family::Ipv4).to_vec(),
                payload(PayloadBase::Network, 16, 4).to_vec(),
                vec![lookup(&routed, true)],
                then(Verdict::Return).to_vec(),
            ]),
        );
        b.add_rule(
            &t,
            "output_route",
            &rule([
                meta_cmp(MetaKey::OifName, CmpOp::Neq, ifname("tun0").unwrap()).to_vec(),
                ct_cmp(CtKey::Mark, CmpOp::Eq, host_u32(0x2023)).to_vec(),
                vec![
                    ct(CtKey::Mark),
                    Expr::MetaSet {
                        key: MetaKey::Mark,
                        sreg: Reg::R1,
                    },
                    Expr::Counter,
                ],
            ]),
        );
        b.add_rule(
            &t,
            "output_route",
            &rule([
                immediate(Reg::R1, host_u32(0x2023)).to_vec(),
                vec![
                    Expr::MetaSet {
                        key: MetaKey::Mark,
                        sreg: Reg::R1,
                    },
                    meta(MetaKey::Mark),
                    Expr::CtSet {
                        key: CtKey::Mark,
                        sreg: Reg::R1,
                    },
                ],
                then(Verdict::Return).to_vec(),
            ]),
        );
        b.commit().unwrap_or_else(|e| panic!("commit: {}", e));

        // The probe sees it.
        let tables = list_tables(Some(Family::Inet)).expect("list tables");
        let ours = tables
            .iter()
            .find(|t| t.name == TABLE)
            .expect("the table is listed");
        assert_eq!(ours.family, Family::Inet);
        // Four chains and two named sets.
        assert_eq!(ours.uses, 6);
        assert!(list_tables(None).unwrap().iter().any(|t| t.name == TABLE));
        assert!(!list_tables(Some(Family::Ipv4))
            .unwrap()
            .iter()
            .any(|t| t.name == TABLE));

        let listing = nft(&["list", "table", "inet", TABLE]);
        println!("{}", listing);
        let got: Vec<&str> = listing
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let want: Vec<&str> = WANT
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(got, want);

        // The JSON view parses and holds every rule, none of them
        // something nft could not make out.
        let json: serde_json::Value =
            serde_json::from_str(&nft(&["-j", "list", "table", "inet", TABLE])).unwrap();
        let mut per_chain = std::collections::HashMap::<String, usize>::new();
        for item in json["nftables"].as_array().unwrap() {
            if let Some(rule) = item.get("rule") {
                *per_chain
                    .entry(rule["chain"].as_str().unwrap().to_string())
                    .or_default() += 1;
                let text = rule["expr"].to_string();
                assert!(!text.contains("unknown"), "{}", text);
            }
        }
        assert_eq!(per_chain["prematch"], rules.len());
        assert_eq!(per_chain["output"], 4);
        assert_eq!(per_chain["output_route"], 5);
        assert_eq!(per_chain["bypass"], 1);

        // Committing it again replaces it whole.
        b.commit()
            .unwrap_or_else(|e| panic!("second commit: {}", e));
        assert_eq!(nft(&["list", "table", "inet", TABLE]), listing);

        let mut del = Batch::new();
        del.del_table(&t);
        del.commit().expect("delete");
        assert!(!list_tables(None).unwrap().iter().any(|t| t.name == TABLE));
        // Gone, it is still fine to delete if it exists...
        let mut del = Batch::new();
        del.del_table_if_exists(&t);
        del.commit().expect("delete if exists");
        // ...but not to delete it outright.
        let mut del = Batch::new();
        del.del_table(&t);
        let err = del.commit().unwrap_err();
        assert_eq!(err.errno(), Some(libc::ENOENT));
        assert!(
            err.to_string()
                .starts_with("deleting table inet sail-nft-test: ENOENT"),
            "{}",
            err
        );
    }

    /// A failed message aborts the batch, and the error names it.
    #[test]
    #[ignore = "requires root and nf_tables"]
    fn failed_rule_is_named_and_aborts_the_batch() {
        let t = Table::new(Family::Inet, "sail-nft-test-fail");
        let mut b = Batch::new();
        b.del_table_if_exists(&t);
        b.add_table(&t);
        b.add_chain(
            &t,
            &Chain::base("c", ChainType::Filter, Hook::Prerouting, 0),
        );
        b.add_rule(&t, "c", &[Expr::Counter]);
        // redir only works in a nat chain.
        b.add_rule(
            &t,
            "c",
            &[Expr::Redir {
                proto_min: None,
                flags: 0,
            }],
        );
        b.add_rule(&t, "c", &[Expr::Counter]);
        let err = b.commit().unwrap_err();
        println!("{}", err);
        assert_eq!(err.errno(), Some(libc::EOPNOTSUPP));
        assert!(
            err.to_string()
                .starts_with("creating rule 2 in chain c: EOPNOTSUPP"),
            "{}",
            err
        );
        assert!(!list_tables(None).unwrap().iter().any(|x| x.name == t.name));
    }

    /// What nft(8) lists for the table `commit_and_read_back` builds, line
    /// by line with the indentation dropped (nft 1.1.3; another version may
    /// wrap set elements differently). nft leaves out what a rule needs only
    /// as a dependency: the `meta nfproto` before `ip daddr`, the `meta
    /// l4proto tcp` before `tcp flags`.
    const WANT: &str = r#"
table inet sail-nft-test {
    set v4 {
        type ipv4_addr
        flags interval
        elements = { 10.0.0.0/8, 192.168.1.0/24,
                     224.0.0.0/3 }
    }
    set v6 {
        type ipv6_addr
        flags interval
        elements = { ::1,
                     fd00::/8 }
    }
    chain prematch {
        type filter hook prerouting priority dstnat - 1; policy accept;
        iifname "tun0" return
        iifname { "eth1", "eth2" } counter packets 0 bytes 0 return
        meta l4proto != { icmp, udp, ipv6-icmp } return
        meta mark 0x00002024 counter packets 0 bytes 0 return
        ct mark 0x00002024 return
        ct direction reply return
        tcp flags & (syn | ack) == syn counter packets 0 bytes 0 queue flags bypass to 100
        meta l4proto tcp meta mark 0x00002025 counter packets 0 bytes 0 reject with tcp reset
        meta mark 0x00002026 reject with icmpx admin-prohibited
        meta mark 0x00002027 reject with icmp net-unreachable
        meta mark 0x00002024 ct mark set meta mark counter packets 0 bytes 0
        ip daddr @v4 counter packets 0 bytes 0 return
        ip6 daddr != @v6 counter packets 0 bytes 0 return
        tcp option mptcp exists counter packets 0 bytes 0 drop
        meta mark 0x00002028 jump bypass
    }
    chain output {
        type nat hook output priority dstnat; policy accept;
        meta nfproto ipv4 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter packets 0 bytes 0 dnat ip to 172.18.0.2
        meta nfproto ipv6 oifname != "lo" meta l4proto { tcp, udp } th dport 53 counter packets 0 bytes 0 dnat ip6 to fdfe:dcba:9876::2
        meta nfproto ipv4 meta mark 0x00002029 dnat ip to 127.0.0.1:5353
        meta l4proto tcp counter packets 0 bytes 0 redirect to :7890 return
    }
    chain output_route {
        type route hook output priority mangle; policy accept;
        meta skuid 0 return
        meta skuid != { 1000, 2000 } return
        ip daddr != { 10.0.0.0/8, 172.16.0.0/12 } counter packets 0 bytes 0 return
        oifname != "tun0" ct mark 0x00002023 meta mark set ct mark counter packets 0 bytes 0
        meta mark set 0x00002023 ct mark set meta mark counter packets 0 bytes 0 return
    }
    chain bypass {
        counter packets 0 bytes 0 accept
    }
}
"#;
}
