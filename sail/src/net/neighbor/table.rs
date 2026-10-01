//! The system's neighbor table (ARP and NDP): which MAC address each
//! address on the LAN has, read once and then followed as it changes, as
//! sing-box 1.14.1 has it (route/neighbor_table_{linux,darwin}.go and the
//! loading and subscribing halves of route/neighbor_resolver_*.go).
//!
//! Linux reads it over rtnetlink: an `RTM_GETNEIGH` dump, then the
//! `RTNLGRP_NEIGH` group. macOS reads it from the routing table: the
//! `NET_RT_FLAGS`/`RTF_LLINFO` sysctl, then the routing socket. The parsers
//! are plain bytes and build everywhere, so they are tested on any host;
//! only the system calls are per platform.
//!
//! Which entries count is sing-box's, rule for rule; each parser says what
//! its rules are. Where sail differs it is because a MAC here is six bytes:
//! sing-box keeps a link address of any length it accepts, sail drops one
//! that is not six bytes long.

use std::io;
use std::net::IpAddr;

/// A MAC address.
pub(crate) type Mac = [u8; 6];

/// A change to the neighbor table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NeighborEvent {
    /// The address has this MAC now.
    Add(IpAddr, Mac),
    /// The address has left the table.
    Delete(IpAddr),
}

/// How many events wait for the reader before the watching thread waits
/// too. A judgment call: a LAN's worth of changes at once.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const EVENT_QUEUE: usize = 256;

/// How long the watching thread waits for the kernel before it checks
/// whether anyone still reads: sing-box's read deadline (3 s).
#[cfg(any(target_os = "linux", target_os = "macos"))]
const WATCH_POLL: std::time::Duration = std::time::Duration::from_secs(3);

/// The neighbor table now: address and MAC of each entry sing-box keeps.
/// Ports `ReadNeighborEntries` (and `loadNeighborTable`, which on Linux is
/// the same loop and on macOS calls it).
pub(crate) fn read_neighbors() -> io::Result<Vec<(IpAddr, Mac)>> {
    #[cfg(target_os = "linux")]
    {
        linux::read_neighbors()
    }
    #[cfg(target_os = "macos")]
    {
        macos::read_neighbors()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(unsupported())
    }
}

/// Changes to the table as the system reports them, until the receiver is
/// dropped. Ports `subscribeNeighborUpdates`: a thread reads the kernel's
/// notices and stops within `WATCH_POLL` of the receiver going away.
pub(crate) fn watch_neighbors() -> io::Result<tokio::sync::mpsc::Receiver<NeighborEvent>> {
    #[cfg(target_os = "linux")]
    {
        linux::watch_neighbors()
    }
    #[cfg(target_os = "macos")]
    {
        macos::watch_neighbors()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(unsupported())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the neighbor table is read on Linux and macOS only",
    )
}

/// Runs `next` on a thread of its own, sending what it returns, until the
/// receiver is dropped. A read that timed out only lets it check for that;
/// any other error is logged and reading goes on, as sing-box does.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_watch<F>(mut next: F) -> io::Result<tokio::sync::mpsc::Receiver<NeighborEvent>>
where
    F: FnMut() -> io::Result<Vec<NeighborEvent>> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(EVENT_QUEUE);
    std::thread::Builder::new()
        .name("sail-neighbors".into())
        .spawn(move || loop {
            if tx.is_closed() {
                return;
            }
            match next() {
                Ok(events) => {
                    for event in events {
                        if tx.blocking_send(event).is_err() {
                            return;
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    if tx.is_closed() {
                        return;
                    }
                    tracing::warn!("receive neighbor update: {}", e);
                }
            }
        })?;
    Ok(rx)
}

/// Sets how long a receive on `fd` waits.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_receive_timeout(fd: &std::os::fd::OwnedFd, timeout: std::time::Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    // SAFETY: `tv` is a timeval, of the length given, set on a descriptor
    // this owns.
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

// ---------------------------------------------------------------------------
// Linux: rtnetlink neighbor messages.
// ---------------------------------------------------------------------------

// linux/rtnetlink.h and linux/neighbour.h. Linux's numbers, not the host's,
// so the parser builds and is tested anywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RTM_NEWNEIGH: u16 = 28;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RTM_DELNEIGH: u16 = 29;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RTM_GETNEIGH: u16 = 30;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NDA_DST: u16 = 1;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NDA_LLADDR: u16 = 2;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NDA_CACHEINFO: u16 = 3;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NDA_IFINDEX: u16 = 8;
// linux/netlink.h
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NLMSG_ERROR: u16 = 2;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NLMSG_DONE: u16 = 3;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NLMSG_HDRLEN: usize = 16;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NLA_HDRLEN: usize = 4;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NLA_TYPE_MASK: u16 = !(0x8000 | 0x4000);
/// `struct ndmsg`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NDMSG_LEN: usize = 12;

/// What sing-box's rtnetlink library (jsimonetti/rtnetlink,
/// `NeighMessage.UnmarshalBinary`) takes from a neighbor message.
#[derive(Default)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct DecodedNeighbor<'a> {
    address: Option<IpAddr>,
    ll_address: Option<&'a [u8]>,
}

/// Decodes a neighbor message's body (`struct ndmsg` and attributes) as
/// sing-box's library does; None where it fails. It fails on a body
/// shorter than `ndmsg`, a tail too short for an attribute header, an
/// `NDA_DST` not 4 or 16 bytes, an `NDA_LLADDR` not 0, 6, 8 or 20 bytes (0
/// is ignored), and an `NDA_CACHEINFO` not 16 bytes. An attribute that does
/// not fit, or an `NDA_IFINDEX` not 4 bytes, ends the attributes without
/// failing. The family, state and flags are not looked at.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn decode_neighbor(body: &[u8]) -> Option<DecodedNeighbor<'_>> {
    let attrs = body.get(NDMSG_LEN..)?;
    // The decoder counts the attributes first: a tail shorter than a
    // header is an error.
    let mut i = 0;
    while i < attrs.len() {
        if attrs.len() - i < NLA_HDRLEN {
            return None;
        }
        let len = usize::from(u16::from_ne_bytes([attrs[i], attrs[i + 1]]));
        i += align4(len.max(NLA_HDRLEN));
    }
    let mut decoded = DecodedNeighbor::default();
    let mut rest = attrs;
    while rest.len() >= NLA_HDRLEN {
        let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        let ty = u16::from_ne_bytes([rest[2], rest[3]]) & NLA_TYPE_MASK;
        if len > rest.len() || (len != 0 && len < NLA_HDRLEN) {
            break;
        }
        let data = rest.get(NLA_HDRLEN..len).unwrap_or_default();
        rest = rest.get(align4(len.max(NLA_HDRLEN))..).unwrap_or_default();
        match ty {
            NDA_DST => {
                decoded.address = Some(match data.len() {
                    4 => IpAddr::from(<[u8; 4]>::try_from(data).ok()?),
                    16 => IpAddr::from(<[u8; 16]>::try_from(data).ok()?),
                    _ => return None,
                });
            }
            NDA_LLADDR => match data.len() {
                0 => {}
                6 | 8 | 20 => decoded.ll_address = Some(data),
                _ => return None,
            },
            NDA_CACHEINFO if data.len() != 16 => return None,
            NDA_IFINDEX if data.len() != 4 => break,
            _ => {}
        }
    }
    Some(decoded)
}

/// A neighbor notice, from its netlink message type and body. Ports
/// `ParseNeighborMessage`: it needs an address (`NDA_DST`); `RTM_DELNEIGH`
/// is a delete; any other type is an add, and an add needs a link address
/// (`NDA_LLADDR`) -- which the kernel sends only for an entry in a valid
/// state, so incomplete and failed entries are no adds. Neither the family
/// nor the state is looked at otherwise, and a zero MAC is a MAC. Unlike
/// sing-box, an add whose link address is not six bytes (8 or 20) is
/// dropped.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_neighbor_message(ty: u16, body: &[u8]) -> Option<NeighborEvent> {
    let decoded = decode_neighbor(body)?;
    let address = decoded.address?;
    if ty == RTM_DELNEIGH {
        return Some(NeighborEvent::Delete(address));
    }
    let mac = Mac::try_from(decoded.ll_address?).ok()?;
    Some(NeighborEvent::Add(address, mac))
}

/// An entry of a neighbor dump, from one message: Err if the message is
/// malformed, which fails the whole dump as it does sing-box's
/// (`Neigh.List`). Ports `ReadNeighborEntries`' loop: only neighbor
/// messages count, and each needs an address and a link address; a link
/// address not six bytes long is dropped.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn dump_entry(ty: u16, body: &[u8]) -> Result<Option<(IpAddr, Mac)>, ()> {
    if !matches!(ty, RTM_NEWNEIGH | RTM_DELNEIGH | RTM_GETNEIGH) {
        return Ok(None);
    }
    let decoded = decode_neighbor(body).ok_or(())?;
    Ok(match (decoded.address, decoded.ll_address) {
        (Some(address), Some(ll)) => Mac::try_from(ll).ok().map(|mac| (address, mac)),
        _ => None,
    })
}

/// The netlink messages of a datagram, as (type, seq, body); None if it is
/// malformed, which drops the whole datagram as sing-box's `Receive` does.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn netlink_messages(mut dgram: &[u8]) -> Option<Vec<(u16, u32, &[u8])>> {
    let mut messages = Vec::new();
    while dgram.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes([dgram[0], dgram[1], dgram[2], dgram[3]]) as usize;
        if len < NLMSG_HDRLEN || len > dgram.len() {
            return None;
        }
        let ty = u16::from_ne_bytes([dgram[4], dgram[5]]);
        let seq = u32::from_ne_bytes([dgram[8], dgram[9], dgram[10], dgram[11]]);
        messages.push((ty, seq, &dgram[NLMSG_HDRLEN..len]));
        dgram = dgram.get(align4(len)..).unwrap_or_default();
    }
    Some(messages)
}

/// The changes a datagram of the `RTNLGRP_NEIGH` group tells of. A
/// malformed datagram, or one carrying a netlink error, tells of none.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_neighbor_datagram(dgram: &[u8]) -> Vec<NeighborEvent> {
    let Some(messages) = netlink_messages(dgram) else {
        return Vec::new();
    };
    let error = messages.iter().any(|&(ty, _, body)| {
        ty == NLMSG_ERROR && body.get(..4).is_none_or(|errno| errno != [0, 0, 0, 0])
    });
    if error {
        return Vec::new();
    }
    messages
        .into_iter()
        .filter_map(|(ty, _, body)| parse_neighbor_message(ty, body))
        .collect()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;

    use super::*;

    /// How long a dump waits for the kernel: `nft`'s answer timeout. The
    /// kernel answers within the call; this only keeps a dump from hanging.
    const DUMP_TIMEOUT: Duration = Duration::from_secs(5);

    // linux/rtnetlink.h: RTNLGRP_NEIGH (3), as a bind(2) group mask.
    const RTMGRP_NEIGH: u32 = 1 << (3 - 1);
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_DUMP: u16 = 0x100 | 0x200;

    /// A `NETLINK_ROUTE` socket in `groups`.
    fn open(groups: u32, timeout: Duration) -> io::Result<OwnedFd> {
        // SAFETY: plain socket(2); the descriptor is owned from here on.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a descriptor just opened, and owned by none else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zeroed sockaddr_nl is valid; the fields set are its own.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = groups;
        // SAFETY: `addr` is a sockaddr_nl of the length given.
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        set_receive_timeout(&fd, timeout)?;
        Ok(fd)
    }

    /// One datagram, whole: its size is peeked first.
    fn recv(fd: &OwnedFd) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut flags = libc::MSG_PEEK | libc::MSG_TRUNC;
        loop {
            // SAFETY: `buf` is writable for its length.
            let n = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
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

    /// Ports `ReadNeighborEntries`: a dump of every family's neighbors.
    pub(super) fn read_neighbors() -> io::Result<Vec<(IpAddr, Mac)>> {
        let fd = open(0, DUMP_TIMEOUT).map_err(|e| context("dial rtnetlink", e))?;
        let seq = 1u32;
        let mut request = Vec::with_capacity(NLMSG_HDRLEN + NDMSG_LEN);
        request.extend_from_slice(&((NLMSG_HDRLEN + NDMSG_LEN) as u32).to_ne_bytes());
        request.extend_from_slice(&RTM_GETNEIGH.to_ne_bytes());
        request.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request.extend_from_slice(&seq.to_ne_bytes());
        request.extend_from_slice(&0u32.to_ne_bytes());
        request.extend_from_slice(&[0; NDMSG_LEN]);
        // SAFETY: `request` is readable for its length.
        let sent = unsafe {
            libc::send(
                fd.as_raw_fd(),
                request.as_ptr() as *const libc::c_void,
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(context("list neighbors", io::Error::last_os_error()));
        }
        let mut entries = Vec::new();
        loop {
            let dgram = recv(&fd).map_err(|e| context("list neighbors", e))?;
            let messages = netlink_messages(&dgram)
                .ok_or_else(|| invalid("list neighbors: malformed netlink message"))?;
            for (ty, msg_seq, body) in messages {
                if msg_seq != seq {
                    continue;
                }
                match ty {
                    NLMSG_DONE | NLMSG_ERROR => {
                        let errno = body
                            .get(..4)
                            .map_or(0, |b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
                        if errno != 0 {
                            return Err(context(
                                "list neighbors",
                                io::Error::from_raw_os_error(errno.saturating_neg()),
                            ));
                        }
                        return Ok(entries);
                    }
                    _ => match dump_entry(ty, body) {
                        Ok(Some(entry)) => entries.push(entry),
                        Ok(None) => {}
                        Err(()) => {
                            return Err(invalid("list neighbors: malformed neighbor message"))
                        }
                    },
                }
            }
        }
    }

    /// Ports `subscribeNeighborUpdates`: the `RTNLGRP_NEIGH` group.
    pub(super) fn watch_neighbors() -> io::Result<tokio::sync::mpsc::Receiver<NeighborEvent>> {
        let fd =
            open(RTMGRP_NEIGH, WATCH_POLL).map_err(|e| context("subscribe neighbor updates", e))?;
        spawn_watch(move || Ok(parse_neighbor_datagram(&recv(&fd)?)))
    }

    fn context(what: &str, e: io::Error) -> io::Error {
        io::Error::new(e.kind(), format!("{}: {}", what, e))
    }

    fn invalid(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, what)
    }
}

// ---------------------------------------------------------------------------
// macOS: routing messages.
// ---------------------------------------------------------------------------

// net/route.h and sys/socket.h: Darwin's numbers, so the parser builds and
// is tested anywhere.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RTM_VERSION: u8 = 5;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RTM_DELETE: u8 = 0x2;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RTF_LLINFO: i32 = 0x400;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DARWIN_AF_INET: u8 = 2;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DARWIN_AF_INET6: u8 = 30;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DARWIN_AF_LINK: u8 = 18;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RTAX_DST: usize = 0;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RTAX_GATEWAY: usize = 1;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RTAX_NETMASK: usize = 2;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RTAX_GENMASK: usize = 3;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RTAX_MAX: usize = 8;
/// `sizeof(struct rt_msghdr)`, and of `rt_msghdr2`: where the addresses
/// start.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RT_MSGHDR_LEN: usize = 92;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SOCKADDR_IN_LEN: usize = 16;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SOCKADDR_IN6_LEN: usize = 28;

/// An address of a routing message, as golang.org/x/net/route reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum RouteAddr<'a> {
    #[default]
    None,
    /// A `sockaddr_dl`'s link address.
    Link(&'a [u8]),
    Inet(IpAddr),
}

/// A routing message: its type, flags and addresses by `RTAX_*`.
#[derive(Debug)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct RouteMessage<'a> {
    ty: u8,
    flags: i32,
    addrs: [RouteAddr<'a>; RTAX_MAX],
}

/// The route messages of a buffer of routing messages (a sysctl dump, or
/// what a routing socket read), as x/net/route's `ParseRIB` gives them;
/// None where it fails, which fails them all. It fails on a message of
/// length 0, one longer than the buffer, one of another version, and a
/// route message it cannot parse. Messages that are not route messages are
/// passed over, unparsed.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_rib(mut buf: &[u8]) -> Option<Vec<RouteMessage<'_>>> {
    let mut messages = Vec::new();
    while buf.len() > 4 {
        let len = usize::from(u16::from_ne_bytes([buf[0], buf[1]]));
        if len == 0 || buf.len() < len || buf[2] != RTM_VERSION {
            return None;
        }
        // RTM_ADD ... RTM_LOCK, RTM_RESOLVE, RTM_GET2.
        if matches!(buf[3], 0x1..=0x8 | 0xb | 0x14) {
            messages.push(parse_route_message(&buf[..len])?);
        }
        buf = &buf[len..];
    }
    Some(messages)
}

/// One route message, whole (x/net/route's `parseRouteMessage`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_route_message(message: &[u8]) -> Option<RouteMessage<'_>> {
    if message.len() < RT_MSGHDR_LEN {
        return None;
    }
    let flags = i32::from_ne_bytes([message[8], message[9], message[10], message[11]]);
    let attrs = u32::from_ne_bytes([message[12], message[13], message[14], message[15]]);
    Some(RouteMessage {
        ty: message[3],
        flags,
        addrs: parse_addrs(attrs, &message[RT_MSGHDR_LEN..])?,
    })
}

/// The addresses `attrs` names, in order, each padded to 4 bytes
/// (x/net/route's `parseAddrs`). A link address is a `sockaddr_dl`; an
/// internet one is a `sockaddr_in` or `sockaddr_in6`, or, for a netmask
/// after one, a sockaddr of any family cut short; anything else is read in
/// the kernel's short form. IPv6 link-local and interface- or link-local
/// multicast addresses lose the interface index the kernel embeds in their
/// third and fourth bytes.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_addrs(attrs: u32, mut b: &[u8]) -> Option<[RouteAddr<'_>; RTAX_MAX]> {
    let mut addrs = [RouteAddr::None; RTAX_MAX];
    let mut af = 0u8;
    let is_inet = |family: u8| family == DARWIN_AF_INET || family == DARWIN_AF_INET6;
    for (i, slot) in addrs.iter_mut().enumerate() {
        if b.len() < 4 {
            break;
        }
        if attrs & (1 << i) == 0 {
            continue;
        }
        let family = b[1];
        if family == DARWIN_AF_LINK {
            // sdl_len, sdl_family, sdl_index, sdl_type, sdl_nlen, sdl_alen,
            // sdl_slen, sdl_data; a length of 0xff is "don't care", 0.
            if b.len() < 8 {
                return None;
            }
            let field = |n: u8| usize::from(if n == 0xff { 0 } else { n });
            let (nlen, alen, slen) = (field(b[5]), field(b[6]), field(b[7]));
            if b.len() - 4 < 4 + nlen + alen + slen {
                return None;
            }
            *slot = RouteAddr::Link(&b[8 + nlen..8 + nlen + alen]);
            b = b.get(roundup(b[0])..)?;
        } else if is_inet(family) || ((i == RTAX_NETMASK || i == RTAX_GENMASK) && is_inet(af)) {
            if is_inet(family) {
                af = family;
            }
            *slot = RouteAddr::Inet(parse_inet_addr(af, b)?);
            b = b.get(roundup(b[0])..)?;
        } else {
            let (taken, address) = parse_kernel_inet_addr(af, b)?;
            *slot = RouteAddr::Inet(address);
            b = b.get(roundup(b[0])..).or_else(|| b.get(taken..))?;
        }
    }
    Some(addrs)
}

/// A sockaddr's length padded to 4 bytes; an empty one takes 4.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn roundup(len: u8) -> usize {
    if len == 0 {
        4
    } else {
        align4(usize::from(len))
    }
}

/// A `sockaddr_in` or `sockaddr_in6` of family `af`, perhaps cut short
/// (x/net/route's `parseInetAddr`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_inet_addr(af: u8, b: &[u8]) -> Option<IpAddr> {
    let len = usize::from(b[0]);
    if b.len() < len {
        return None;
    }
    if af == DARWIN_AF_INET {
        let mut ip = [0u8; 4];
        if len > 4 {
            let src = &b[4..len.min(8)];
            ip[..src.len()].copy_from_slice(src);
        }
        return Some(IpAddr::from(ip));
    }
    let mut ip = [0u8; 16];
    if len > 8 {
        let src = &b[8..len.min(24)];
        ip[..src.len()].copy_from_slice(src);
        let link_local = ip[0] == 0xfe && ip[1] & 0xc0 == 0x80;
        let local_multicast = ip[0] == 0xff && matches!(ip[1] & 0x0f, 0x01 | 0x02);
        if link_local || local_multicast {
            ip[2] = 0;
            ip[3] = 0;
        }
    }
    Some(IpAddr::from(ip))
}

/// An address in the kernel's short form, the length byte then the
/// address's last bytes (x/net/route's `parseKernelInetAddr`, on Darwin):
/// how many bytes it says it takes, and the address.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_kernel_inet_addr(af: u8, b: &[u8]) -> Option<(usize, IpAddr)> {
    let stated = usize::from(b[0]);
    let mut len = stated;
    if len == 0 || b.len() > roundup(b[0]) {
        len = roundup(b[0]);
    }
    if b.len() < len {
        return None;
    }
    let address = if stated == SOCKADDR_IN6_LEN {
        IpAddr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?)
    } else if af == DARWIN_AF_INET6 {
        let mut ip = [0u8; 16];
        let src = if len < 9 {
            &b[1..len]
        } else {
            &b[len - 8..len]
        };
        ip[..src.len()].copy_from_slice(src);
        IpAddr::from(ip)
    } else if stated == SOCKADDR_IN_LEN {
        IpAddr::from(<[u8; 4]>::try_from(&b[4..8]).ok()?)
    } else {
        let mut ip = [0u8; 4];
        let src = if len < 5 {
            &b[1..len]
        } else {
            &b[len - 4..len]
        };
        ip[..src.len()].copy_from_slice(src);
        IpAddr::from(ip)
    };
    Some((stated, address))
}

/// The destination of a route message, if it is an IP address.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn route_destination(message: &RouteMessage<'_>) -> Option<IpAddr> {
    match message.addrs[RTAX_DST] {
        RouteAddr::Inet(address) => Some(address),
        _ => None,
    }
}

/// The gateway's link address, if it is one of at least six bytes, as
/// sing-box asks; sing-box keeps a longer one whole, sail drops it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn route_mac(message: &RouteMessage<'_>) -> Option<Mac> {
    match message.addrs[RTAX_GATEWAY] {
        RouteAddr::Link(address) if address.len() >= 6 => Mac::try_from(address).ok(),
        _ => None,
    }
}

/// An entry of a `RTF_LLINFO` dump. Ports `parseRouteNeighborEntry`: the
/// gateway must be a link address of at least six bytes -- an unresolved
/// entry's is empty -- and the destination an IPv4 or IPv6 address. A zero,
/// broadcast or multicast MAC is a MAC.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_route_neighbor_entry(message: &RouteMessage<'_>) -> Option<(IpAddr, Mac)> {
    let mac = route_mac(message)?;
    Some((route_destination(message)?, mac))
}

/// A routing-socket notice. Ports `ParseRouteNeighborMessage`: the
/// destination must be an IPv4 or IPv6 address; `RTM_DELETE` is a delete,
/// whatever its gateway; any other type is an add, which needs a link
/// address of at least six bytes.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_route_neighbor_message(message: &RouteMessage<'_>) -> Option<NeighborEvent> {
    let address = route_destination(message)?;
    if message.ty == RTM_DELETE {
        return Some(NeighborEvent::Delete(address));
    }
    Some(NeighborEvent::Add(address, route_mac(message)?))
}

/// The changes a read of the routing socket tells of: those of its route
/// messages with `RTF_LLINFO`, as `subscribeNeighborUpdates` keeps. A
/// buffer `parse_rib` fails on tells of none.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_route_neighbor_messages(buf: &[u8]) -> Vec<NeighborEvent> {
    let Some(messages) = parse_rib(buf) else {
        return Vec::new();
    };
    messages
        .iter()
        .filter(|m| m.flags & RTF_LLINFO != 0)
        .filter_map(parse_route_neighbor_message)
        .collect()
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    // sys/socket.h
    const NET_RT_FLAGS: libc::c_int = 2;

    /// How many times the sysctl is asked, in all, when the table outgrew
    /// the buffer in between: x/net/route's `FetchRIB`.
    const FETCH_TRIES: usize = 3;

    /// The routing socket's reads: more than any one message, whose length
    /// is 16 bits.
    const READ_BUFFER: usize = 64 * 1024;

    /// Ports `ReadNeighborEntries`: IPv4's entries, then IPv6's.
    pub(super) fn read_neighbors() -> io::Result<Vec<(IpAddr, Mac)>> {
        let mut entries =
            read_family(libc::AF_INET).map_err(|e| context("read IPv4 neighbors", e))?;
        entries.extend(read_family(libc::AF_INET6).map_err(|e| context("read IPv6 neighbors", e))?);
        Ok(entries)
    }

    /// Ports `readNeighborEntriesAF`.
    fn read_family(af: libc::c_int) -> io::Result<Vec<(IpAddr, Mac)>> {
        let rib = fetch_rib(af)?;
        let messages = parse_rib(&rib).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed routing message")
        })?;
        Ok(messages
            .iter()
            .filter_map(parse_route_neighbor_entry)
            .collect())
    }

    /// The routes of `af` with `RTF_LLINFO`: x/net/route's `FetchRIB` with
    /// `NET_RT_FLAGS`.
    fn fetch_rib(af: libc::c_int) -> io::Result<Vec<u8>> {
        let mut mib = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            af,
            NET_RT_FLAGS,
            RTF_LLINFO,
        ];
        let mut tries = 0;
        loop {
            tries += 1;
            let mut size = 0usize;
            // SAFETY: asks for the size only.
            let ret = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as libc::c_uint,
                    std::ptr::null_mut(),
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            if size == 0 {
                return Ok(Vec::new());
            }
            let mut buffer = vec![0u8; size];
            let mut filled = buffer.len();
            // SAFETY: `buffer` is writable for `filled` bytes.
            let ret = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as libc::c_uint,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    &mut filled,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if ret == 0 {
                buffer.truncate(filled);
                return Ok(buffer);
            }
            let e = io::Error::last_os_error();
            // The table grew in between: ask again, a few times.
            if e.raw_os_error() != Some(libc::ENOMEM) || tries >= FETCH_TRIES {
                return Err(e);
            }
        }
    }

    /// Ports `subscribeNeighborUpdates`: a routing socket.
    pub(super) fn watch_neighbors() -> io::Result<tokio::sync::mpsc::Receiver<NeighborEvent>> {
        let fd = open().map_err(|e| context("subscribe neighbor updates", e))?;
        let mut buf = vec![0u8; READ_BUFFER];
        spawn_watch(move || {
            // SAFETY: `buf` is writable for its length.
            let n = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            Ok(parse_route_neighbor_messages(&buf[..n as usize]))
        })
    }

    fn open() -> io::Result<OwnedFd> {
        // SAFETY: plain socket(2); owned from here on.
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor just opened, owned by none else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: fcntl on a descriptor this owns.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        set_receive_timeout(&fd, WATCH_POLL)?;
        Ok(fd)
    }

    fn context(what: &str, e: io::Error) -> io::Error {
        io::Error::new(e.kind(), format!("{}: {}", what, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: Mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ip6(s: &str) -> [u8; 16] {
        s.parse::<std::net::Ipv6Addr>().unwrap().octets()
    }

    // ---- Linux ----

    const NUD_INCOMPLETE: u16 = 0x01;
    const NUD_REACHABLE: u16 = 0x02;
    const NUD_STALE: u16 = 0x04;
    const NUD_FAILED: u16 = 0x20;
    const NUD_NOARP: u16 = 0x40;
    const NUD_PERMANENT: u16 = 0x80;
    const LINUX_AF_INET: u8 = 2;
    const LINUX_AF_INET6: u8 = 10;
    const LINUX_AF_BRIDGE: u8 = 7;

    /// A netlink attribute, padded.
    fn attr(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut out = ((NLA_HDRLEN + data.len()) as u16).to_ne_bytes().to_vec();
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(data);
        out.resize(align4(out.len()), 0);
        out
    }

    /// A `struct ndmsg` of `family` in `state`, then `attrs`.
    fn ndmsg(family: u8, state: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![family, 0, 0, 0];
        out.extend_from_slice(&3u32.to_ne_bytes()); // ndm_ifindex
        out.extend_from_slice(&state.to_ne_bytes());
        out.extend_from_slice(&[0, 1]); // ndm_flags, ndm_type
        for a in attrs {
            out.extend_from_slice(a);
        }
        out
    }

    /// A netlink message around `body`.
    fn nlmsg(ty: u16, body: &[u8]) -> Vec<u8> {
        let mut out = ((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(&[0; 10]); // flags, seq, pid
        out.extend_from_slice(body);
        out.resize(align4(out.len()), 0);
        out
    }

    #[test]
    fn a_reachable_ipv4_neighbor_is_an_add() {
        let body = ndmsg(
            LINUX_AF_INET,
            NUD_REACHABLE,
            &[
                attr(NDA_DST, &[192, 168, 1, 20]),
                attr(NDA_LLADDR, &MAC),
                attr(NDA_CACHEINFO, &[0; 16]),
                attr(NDA_IFINDEX, &3u32.to_ne_bytes()),
            ],
        );
        assert_eq!(
            parse_neighbor_message(RTM_NEWNEIGH, &body),
            Some(NeighborEvent::Add(ip("192.168.1.20"), MAC))
        );
        assert_eq!(
            dump_entry(RTM_NEWNEIGH, &body),
            Ok(Some((ip("192.168.1.20"), MAC)))
        );
    }

    #[test]
    fn a_stale_ipv6_link_local_neighbor_is_an_add() {
        let body = ndmsg(
            LINUX_AF_INET6,
            NUD_STALE,
            &[attr(NDA_DST, &ip6("fe80::1c:2d")), attr(NDA_LLADDR, &MAC)],
        );
        assert_eq!(
            parse_neighbor_message(RTM_NEWNEIGH, &body),
            Some(NeighborEvent::Add(ip("fe80::1c:2d"), MAC))
        );
    }

    /// Incomplete and failed entries come without a link address: no add,
    /// and nothing in a dump. The state itself is not looked at.
    #[test]
    fn an_entry_without_a_link_address_is_no_add() {
        for state in [NUD_INCOMPLETE, NUD_FAILED] {
            let body = ndmsg(LINUX_AF_INET, state, &[attr(NDA_DST, &[10, 0, 0, 9])]);
            assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &body), None);
            assert_eq!(dump_entry(RTM_NEWNEIGH, &body), Ok(None));
        }
        // An empty link address is ignored, as if absent.
        let body = ndmsg(
            LINUX_AF_INET,
            NUD_REACHABLE,
            &[attr(NDA_DST, &[10, 0, 0, 9]), attr(NDA_LLADDR, &[])],
        );
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &body), None);
        // A failed entry that still carries one is kept, as sing-box does.
        let body = ndmsg(
            LINUX_AF_INET,
            NUD_FAILED,
            &[attr(NDA_DST, &[10, 0, 0, 9]), attr(NDA_LLADDR, &MAC)],
        );
        assert_eq!(
            parse_neighbor_message(RTM_NEWNEIGH, &body),
            Some(NeighborEvent::Add(ip("10.0.0.9"), MAC))
        );
    }

    #[test]
    fn a_zero_mac_is_a_mac() {
        for state in [NUD_NOARP, NUD_PERMANENT] {
            let body = ndmsg(
                LINUX_AF_INET,
                state,
                &[attr(NDA_DST, &[10, 0, 0, 1]), attr(NDA_LLADDR, &[0; 6])],
            );
            assert_eq!(
                parse_neighbor_message(RTM_NEWNEIGH, &body),
                Some(NeighborEvent::Add(ip("10.0.0.1"), [0; 6]))
            );
        }
    }

    #[test]
    fn a_delete_needs_only_the_address() {
        let bare = ndmsg(
            LINUX_AF_INET6,
            NUD_FAILED,
            &[attr(NDA_DST, &ip6("2001:db8::7"))],
        );
        assert_eq!(
            parse_neighbor_message(RTM_DELNEIGH, &bare),
            Some(NeighborEvent::Delete(ip("2001:db8::7")))
        );
        let with_mac = ndmsg(
            LINUX_AF_INET,
            NUD_STALE,
            &[attr(NDA_DST, &[10, 0, 0, 2]), attr(NDA_LLADDR, &MAC)],
        );
        assert_eq!(
            parse_neighbor_message(RTM_DELNEIGH, &with_mac),
            Some(NeighborEvent::Delete(ip("10.0.0.2")))
        );
        // No address: nothing, add or delete.
        let no_address = ndmsg(LINUX_AF_INET, 0, &[attr(NDA_LLADDR, &MAC)]);
        assert_eq!(parse_neighbor_message(RTM_DELNEIGH, &no_address), None);
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &no_address), None);
        assert_eq!(dump_entry(RTM_NEWNEIGH, &no_address), Ok(None));
    }

    /// A link address of 8 or 20 bytes is valid but no MAC here: no add
    /// (sing-box keeps it), still a delete. Other lengths make the message
    /// malformed.
    #[test]
    fn link_address_lengths() {
        let long = ndmsg(
            LINUX_AF_INET,
            NUD_REACHABLE,
            &[attr(NDA_DST, &[10, 0, 0, 3]), attr(NDA_LLADDR, &[1; 20])],
        );
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &long), None);
        assert_eq!(dump_entry(RTM_NEWNEIGH, &long), Ok(None));
        assert_eq!(
            parse_neighbor_message(RTM_DELNEIGH, &long),
            Some(NeighborEvent::Delete(ip("10.0.0.3")))
        );
        // An ipip neighbor's 4-byte link address.
        let odd = ndmsg(
            LINUX_AF_INET,
            NUD_REACHABLE,
            &[attr(NDA_DST, &[10, 0, 0, 3]), attr(NDA_LLADDR, &[1; 4])],
        );
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &odd), None);
        assert_eq!(parse_neighbor_message(RTM_DELNEIGH, &odd), None);
        assert_eq!(dump_entry(RTM_NEWNEIGH, &odd), Err(()));
    }

    #[test]
    fn malformed_messages_are_dropped() {
        let short = ndmsg(LINUX_AF_INET, NUD_REACHABLE, &[]);
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &short[..11]), None);
        assert_eq!(dump_entry(RTM_NEWNEIGH, &short[..11]), Err(()));
        // No attributes at all.
        assert_eq!(parse_neighbor_message(RTM_DELNEIGH, &short), None);
        assert_eq!(dump_entry(RTM_NEWNEIGH, &short), Ok(None));
        // An address of 5 bytes.
        let bad_dst = ndmsg(LINUX_AF_INET, NUD_REACHABLE, &[attr(NDA_DST, &[1; 5])]);
        assert_eq!(parse_neighbor_message(RTM_DELNEIGH, &bad_dst), None);
        assert_eq!(dump_entry(RTM_NEWNEIGH, &bad_dst), Err(()));
        // Cache info of the wrong size.
        let bad_cache = ndmsg(
            LINUX_AF_INET,
            NUD_REACHABLE,
            &[
                attr(NDA_DST, &[10, 0, 0, 4]),
                attr(NDA_LLADDR, &MAC),
                attr(NDA_CACHEINFO, &[0; 12]),
            ],
        );
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &bad_cache), None);
        // A tail shorter than an attribute header.
        let mut tail = ndmsg(
            LINUX_AF_INET,
            NUD_REACHABLE,
            &[attr(NDA_DST, &[10, 0, 0, 4]), attr(NDA_LLADDR, &MAC)],
        );
        tail.extend_from_slice(&[0, 0]);
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &tail), None);
    }

    /// An attribute that does not fit, or an interface index of the wrong
    /// size, ends the attributes without failing the message.
    #[test]
    fn attributes_end_quietly() {
        let body = ndmsg(
            LINUX_AF_INET,
            NUD_REACHABLE,
            &[
                attr(NDA_DST, &[10, 0, 0, 5]),
                attr(NDA_IFINDEX, &[1, 0]),
                attr(NDA_LLADDR, &MAC),
            ],
        );
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &body), None);
        assert_eq!(
            parse_neighbor_message(RTM_DELNEIGH, &body),
            Some(NeighborEvent::Delete(ip("10.0.0.5")))
        );
        let mut overlong = attr(NDA_LLADDR, &MAC);
        overlong[..2].copy_from_slice(&200u16.to_ne_bytes());
        let body = ndmsg(
            LINUX_AF_INET,
            NUD_REACHABLE,
            &[attr(NDA_DST, &[10, 0, 0, 5]), overlong],
        );
        assert_eq!(dump_entry(RTM_NEWNEIGH, &body), Ok(None));
    }

    /// A bridge FDB notice (also in RTNLGRP_NEIGH) has no address: nothing.
    #[test]
    fn a_bridge_fdb_notice_is_nothing() {
        let body = ndmsg(
            LINUX_AF_BRIDGE,
            NUD_PERMANENT,
            &[attr(NDA_LLADDR, &MAC), attr(5, &[1, 0])],
        );
        assert_eq!(parse_neighbor_message(RTM_NEWNEIGH, &body), None);
    }

    #[test]
    fn a_datagram_carries_several_notices() {
        let mut dgram = nlmsg(
            RTM_NEWNEIGH,
            &ndmsg(
                LINUX_AF_INET,
                NUD_REACHABLE,
                &[attr(NDA_DST, &[10, 0, 0, 6]), attr(NDA_LLADDR, &MAC)],
            ),
        );
        dgram.extend(nlmsg(
            RTM_NEWNEIGH,
            &ndmsg(
                LINUX_AF_INET,
                NUD_INCOMPLETE,
                &[attr(NDA_DST, &[10, 0, 0, 7])],
            ),
        ));
        dgram.extend(nlmsg(
            RTM_DELNEIGH,
            &ndmsg(
                LINUX_AF_INET6,
                NUD_FAILED,
                &[attr(NDA_DST, &ip6("fd00::8"))],
            ),
        ));
        assert_eq!(
            parse_neighbor_datagram(&dgram),
            [
                NeighborEvent::Add(ip("10.0.0.6"), MAC),
                NeighborEvent::Delete(ip("fd00::8")),
            ]
        );
        // A message longer than the datagram drops it all.
        assert_eq!(parse_neighbor_datagram(&dgram[..dgram.len() - 4]), []);
        // So does a netlink error.
        let mut error = dgram;
        error.extend(nlmsg(NLMSG_ERROR, &(-1i32).to_ne_bytes()));
        assert_eq!(parse_neighbor_datagram(&error), []);
    }

    // ---- macOS ----

    const RTM_ADD: u8 = 0x1;
    const RTM_GET: u8 = 0x4;
    const RTM_IFINFO: u8 = 0xe;
    const RTF_UP: i32 = 0x1;
    const RTF_HOST: i32 = 0x4;
    const DST_GATEWAY: u32 = 0x1 | 0x2;
    const NETMASK: u32 = 0x4;

    fn sockaddr_in(a: [u8; 4]) -> Vec<u8> {
        let mut out = vec![16, DARWIN_AF_INET, 0, 0];
        out.extend_from_slice(&a);
        out.extend_from_slice(&[0; 8]);
        out
    }

    fn sockaddr_in6(a: [u8; 16]) -> Vec<u8> {
        let mut out = vec![28, DARWIN_AF_INET6, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(&a);
        out.extend_from_slice(&[0; 4]);
        out
    }

    /// A `sockaddr_dl` of en0 with link address `mac`, at least 20 bytes as
    /// the kernel writes it.
    fn sockaddr_dl(mac: &[u8]) -> Vec<u8> {
        let name = b"en0";
        let len = (8 + name.len() + mac.len()).max(20);
        let mut out = vec![
            len as u8,
            DARWIN_AF_LINK,
            4,
            0,
            6,
            name.len() as u8,
            mac.len() as u8,
            0,
        ];
        out.extend_from_slice(name);
        out.extend_from_slice(mac);
        out.resize(align4(len), 0);
        out
    }

    /// An `rt_msghdr` of `ty` with `flags`, then `addrs` in RTAX order.
    fn rt_msg(ty: u8, flags: i32, attrs: u32, addrs: &[Vec<u8>]) -> Vec<u8> {
        let body = addrs.concat();
        let len = RT_MSGHDR_LEN + body.len();
        let mut out = vec![0u8; RT_MSGHDR_LEN];
        out[0..2].copy_from_slice(&(len as u16).to_ne_bytes());
        out[2] = RTM_VERSION;
        out[3] = ty;
        out[4..6].copy_from_slice(&4u16.to_ne_bytes());
        out[8..12].copy_from_slice(&flags.to_ne_bytes());
        out[12..16].copy_from_slice(&attrs.to_ne_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn only(buf: &[u8]) -> RouteMessage<'_> {
        let mut messages = parse_rib(buf).unwrap();
        assert_eq!(messages.len(), 1);
        messages.remove(0)
    }

    #[test]
    fn an_arp_entry_is_read() {
        let buf = rt_msg(
            RTM_GET,
            RTF_UP | RTF_HOST | RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_in([192, 168, 1, 1]), sockaddr_dl(&MAC)],
        );
        assert_eq!(
            parse_route_neighbor_entry(&only(&buf)),
            Some((ip("192.168.1.1"), MAC))
        );
    }

    /// The interface index the kernel embeds is taken out of a link-local
    /// address; a global one keeps its bytes.
    #[test]
    fn an_ndp_entry_loses_its_embedded_scope() {
        let mut address = ip6("fe80::aa:bb");
        address[3] = 4;
        let buf = rt_msg(
            RTM_ADD,
            RTF_UP | RTF_HOST | RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_in6(address), sockaddr_dl(&MAC)],
        );
        assert_eq!(
            parse_route_neighbor_messages(&buf),
            [NeighborEvent::Add(ip("fe80::aa:bb"), MAC)]
        );
        let buf = rt_msg(
            RTM_ADD,
            RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_in6(ip6("2001:db8:4::1")), sockaddr_dl(&MAC)],
        );
        assert_eq!(
            parse_route_neighbor_messages(&buf),
            [NeighborEvent::Add(ip("2001:db8:4::1"), MAC)]
        );
    }

    /// An unresolved entry has an empty link address: no entry and no add,
    /// but its delete is a delete.
    #[test]
    fn an_incomplete_entry_is_no_add() {
        let entry = |ty| {
            rt_msg(
                ty,
                RTF_UP | RTF_HOST | RTF_LLINFO,
                DST_GATEWAY,
                &[sockaddr_in([192, 168, 1, 30]), sockaddr_dl(&[])],
            )
        };
        assert_eq!(parse_route_neighbor_entry(&only(&entry(RTM_GET))), None);
        assert_eq!(parse_route_neighbor_messages(&entry(RTM_ADD)), []);
        assert_eq!(
            parse_route_neighbor_messages(&entry(RTM_DELETE)),
            [NeighborEvent::Delete(ip("192.168.1.30"))]
        );
    }

    #[test]
    fn a_delete_needs_only_the_destination() {
        let buf = rt_msg(
            RTM_DELETE,
            RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_in6(ip6("fd00::5")), sockaddr_in([0, 0, 0, 0])],
        );
        assert_eq!(
            parse_route_neighbor_messages(&buf),
            [NeighborEvent::Delete(ip("fd00::5"))]
        );
    }

    /// Routes without RTF_LLINFO, gateways that are IP addresses, and
    /// destinations that are not, are no neighbors.
    #[test]
    fn other_routes_are_passed_over() {
        let plain = rt_msg(
            RTM_ADD,
            RTF_UP,
            DST_GATEWAY,
            &[sockaddr_in([10, 0, 0, 0]), sockaddr_dl(&MAC)],
        );
        assert_eq!(parse_route_neighbor_messages(&plain), []);
        let via = rt_msg(
            RTM_GET,
            RTF_UP | RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_in([10, 0, 0, 1]), sockaddr_in([10, 0, 0, 254])],
        );
        assert_eq!(parse_route_neighbor_entry(&only(&via)), None);
        assert_eq!(parse_route_neighbor_messages(&via), []);
        let link = rt_msg(
            RTM_DELETE,
            RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_dl(&MAC), sockaddr_dl(&MAC)],
        );
        assert_eq!(parse_route_neighbor_messages(&link), []);
    }

    /// A dump holds several. A netmask of family 0 cut short after an
    /// internet destination is read as a netmask; a multicast entry's MAC
    /// is kept; a message that is not a route message is passed over.
    #[test]
    fn a_dump_is_read_whole() {
        let mut dump = rt_msg(
            RTM_GET,
            RTF_UP | RTF_HOST | RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_in([192, 168, 1, 1]), sockaddr_dl(&MAC)],
        );
        dump.extend(rt_msg(
            RTM_GET,
            RTF_UP | RTF_LLINFO,
            DST_GATEWAY | NETMASK,
            &[
                sockaddr_in([224, 0, 0, 251]),
                sockaddr_dl(&[1, 0, 0x5e, 0, 0, 0xfb]),
                vec![5, 0, 0, 0, 255, 0, 0, 0],
            ],
        ));
        dump.extend(rt_msg(RTM_IFINFO, 0, 0, &[]));
        let entries: Vec<_> = parse_rib(&dump)
            .unwrap()
            .iter()
            .filter_map(parse_route_neighbor_entry)
            .collect();
        assert_eq!(
            entries,
            [
                (ip("192.168.1.1"), MAC),
                (ip("224.0.0.251"), [1, 0, 0x5e, 0, 0, 0xfb]),
            ]
        );
    }

    #[test]
    fn malformed_ribs_fail() {
        let good = rt_msg(
            RTM_GET,
            RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_in([10, 0, 0, 1]), sockaddr_dl(&MAC)],
        );
        // Another version.
        let mut other = good.clone();
        other[2] = 4;
        assert!(parse_rib(&other).is_none());
        // A length of 0, or past the end.
        let mut zero = good.clone();
        zero[0..2].copy_from_slice(&0u16.to_ne_bytes());
        assert!(parse_rib(&zero).is_none());
        assert!(parse_rib(&good[..good.len() - 1]).is_none());
        // A route message shorter than its header.
        let mut short = good[..40].to_vec();
        short[0..2].copy_from_slice(&40u16.to_ne_bytes());
        assert!(parse_rib(&short).is_none());
        // A link address past its message.
        let mut cut = good.clone();
        cut[RT_MSGHDR_LEN + 16 + 6] = 40;
        assert!(parse_rib(&cut).is_none());
        assert_eq!(parse_route_neighbor_messages(&cut), []);
        // A link address longer than six bytes: sing-box keeps it, sail
        // cannot.
        let long = rt_msg(
            RTM_GET,
            RTF_LLINFO,
            DST_GATEWAY,
            &[sockaddr_in([10, 0, 0, 1]), sockaddr_dl(&[1; 8])],
        );
        assert_eq!(parse_route_neighbor_entry(&only(&long)), None);
    }

    /// A destination of no internet family is read in the kernel's short
    /// form, as IPv4.
    #[test]
    fn a_destination_in_the_short_form_is_ipv4() {
        let buf = rt_msg(
            RTM_ADD,
            RTF_LLINFO,
            DST_GATEWAY,
            &[vec![8, 0, 0, 0, 10, 1, 2, 3], sockaddr_dl(&MAC)],
        );
        assert_eq!(
            parse_route_neighbor_messages(&buf),
            [NeighborEvent::Add(ip("10.1.2.3"), MAC)]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_numbers_are_darwin_s() {
        assert_eq!(std::mem::size_of::<libc::rt_msghdr>(), RT_MSGHDR_LEN);
        assert_eq!(libc::AF_INET as u8, DARWIN_AF_INET);
        assert_eq!(libc::AF_INET6 as u8, DARWIN_AF_INET6);
        assert_eq!(libc::AF_LINK as u8, DARWIN_AF_LINK);
        assert_eq!(libc::RTM_VERSION as u8, RTM_VERSION);
        assert_eq!(libc::RTF_LLINFO, RTF_LLINFO);
    }

    // ---- this host ----

    /// Reading this host's table changes nothing: it reads, no address is
    /// unspecified, and no link-local one keeps an embedded scope.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn this_host_s_table_is_read() {
        let entries = read_neighbors().unwrap();
        println!("{} neighbors", entries.len());
        for (address, _) in &entries {
            assert!(!address.is_unspecified(), "{:?}", entries);
            if let IpAddr::V6(v6) = address {
                if v6.segments()[0] & 0xffc0 == 0xfe80 {
                    assert_eq!(v6.segments()[1], 0, "{}", v6);
                }
            }
        }
    }

    /// Watching opens; its thread ends once the receiver is dropped.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn watching_opens() {
        drop(watch_neighbors().unwrap());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn other_systems_are_unsupported() {
        assert_eq!(
            read_neighbors().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            watch_neighbors().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
