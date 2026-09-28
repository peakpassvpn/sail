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

struct Socket {
    fd: OwnedFd,
}

impl Socket {
    fn open() -> io::Result<Socket> {
        // SAFETY: plain socket(2); the result is checked and owned.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
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

    fn set_int(&self, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
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

    fn send(&self, buf: &[u8]) -> io::Result<()> {
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
    fn recv(&self) -> io::Result<Vec<u8>> {
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
fn parse_error(flags: u16, body: &[u8]) -> Result<(i32, Option<String>), Error> {
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
fn first_seq() -> u32 {
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
