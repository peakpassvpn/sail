//! Linux: who opened a socket of this network namespace, as sing-box's
//! searcher_linux finds it. netlink's sock_diag, asked for the one socket
//! of a 4-tuple, gives its uid and inode; the process holding the inode
//! is found among that uid's in /proc, and its path is /proc/<pid>/exe.
//! The walk of /proc is the costly part, and is skipped when only the uid
//! is wanted.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// netlink's sock_diag protocol, and its request (linux/sock_diag.h).
const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// No cookie: the socket is found by its addresses alone.
const NO_COOKIE: u32 = u32::MAX;

/// A socket's owner: its uid and inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Socket {
    pub uid: u32,
    pub inode: u32,
}

/// The sock_diag request for the socket of `protocol` (IPPROTO_TCP or
/// IPPROTO_UDP) from `local` to `remote`: a netlink header, then
/// inet_diag_req_v2, its inet_diag_sockid in network order.
pub(crate) fn request(protocol: u8, local: SocketAddr, remote: SocketAddr) -> Vec<u8> {
    let family = if local.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    } as u8;
    let mut msg = Vec::with_capacity(72);
    // nlmsghdr: length, type, flags (a request), sequence, port.
    msg.extend_from_slice(&72u32.to_ne_bytes());
    msg.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    msg.extend_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    // inet_diag_req_v2: family, protocol, extensions, pad, every state.
    msg.extend_from_slice(&[family, protocol, 0, 0]);
    msg.extend_from_slice(&u32::MAX.to_ne_bytes());
    // inet_diag_sockid: ports, addresses, interface, cookie.
    msg.extend_from_slice(&local.port().to_be_bytes());
    msg.extend_from_slice(&remote.port().to_be_bytes());
    for address in [local.ip(), remote.ip()] {
        let mut field = [0u8; 16];
        match address {
            IpAddr::V4(a) => field[..4].copy_from_slice(&a.octets()),
            IpAddr::V6(a) => field.copy_from_slice(&a.octets()),
        }
        msg.extend_from_slice(&field);
    }
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&NO_COOKIE.to_ne_bytes());
    msg.extend_from_slice(&NO_COOKIE.to_ne_bytes());
    msg
}

/// The socket an answer to `request` tells of: none for an error (no such
/// socket here) or an answer too short.
pub(crate) fn answer(reply: &[u8]) -> Option<Socket> {
    // nlmsghdr, then inet_diag_msg: family, state, timer, retrans (4),
    // inet_diag_sockid (48), expires, rqueue, wqueue, uid, inode.
    let kind = u16::from_ne_bytes(reply.get(4..6)?.try_into().ok()?);
    if kind != SOCK_DIAG_BY_FAMILY {
        return None;
    }
    let msg = reply.get(16..)?;
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_ne_bytes(msg.get(at..at + 4)?.try_into().ok()?))
    };
    Some(Socket {
        uid: word(64)?,
        inode: word(68)?,
    })
}

/// The owner of the socket of `protocol` from `local` to `remote`, in
/// this network namespace; none when there is none.
pub(crate) fn socket(
    protocol: u8,
    local: SocketAddr,
    remote: SocketAddr,
) -> io::Result<Option<Socket>> {
    // SAFETY: a netlink socket, owned below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor just opened, owned here alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: a timeval of the size given.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let msg = request(protocol, local, remote);
    // SAFETY: a buffer of the length given; to the kernel (address zero).
    let mut to: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    to.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &to as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut reply = [0u8; 512];
    // SAFETY: a buffer of the length given.
    let got = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            reply.as_mut_ptr() as *mut libc::c_void,
            reply.len(),
            0,
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(answer(&reply[..got as usize]))
}

/// The process holding the socket `inode`, among those of `uid`: its pid.
pub(crate) fn pid_of(inode: u32, uid: u32) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let wanted = format!("socket:[{}]", inode);
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if entry.metadata().map(|m| m.uid()).ok() != Some(uid) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path())
                .ok()
                .is_some_and(|target| target.as_os_str() == wanted.as_str())
            {
                return Some(pid);
            }
        }
    }
    None
}

/// The path of the program `pid` runs.
pub(crate) fn path_of(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_inet_diag_req_v2() {
        let msg = request(
            libc::IPPROTO_TCP as u8,
            "10.0.0.2:40000".parse().unwrap(),
            "1.2.3.4:443".parse().unwrap(),
        );
        assert_eq!(msg.len(), 72);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()), 72);
        assert_eq!(msg[16], libc::AF_INET as u8);
        assert_eq!(msg[17], libc::IPPROTO_TCP as u8);
        // Ports and addresses in network order.
        assert_eq!(&msg[24..26], &40000u16.to_be_bytes());
        assert_eq!(&msg[26..28], &443u16.to_be_bytes());
        assert_eq!(&msg[28..32], &[10, 0, 0, 2]);
        assert_eq!(&msg[44..48], &[1, 2, 3, 4]);
        assert_eq!(&msg[64..72], &[0xff; 8]);
    }

    #[test]
    fn an_answer_gives_the_uid_and_inode() {
        let mut reply = vec![0u8; 16 + 72];
        reply[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        reply[16 + 64..16 + 68].copy_from_slice(&1000u32.to_ne_bytes());
        reply[16 + 68..16 + 72].copy_from_slice(&4242u32.to_ne_bytes());
        assert_eq!(
            answer(&reply),
            Some(Socket {
                uid: 1000,
                inode: 4242
            })
        );
        // NLMSG_ERROR: no such socket.
        reply[4..6].copy_from_slice(&2u16.to_ne_bytes());
        assert_eq!(answer(&reply), None);
        assert_eq!(answer(&[0u8; 8]), None);
    }

    /// A connection of this process's own is found, by uid, inode, pid and
    /// path: the test's binary.
    #[test]
    fn a_socket_of_this_process_is_found() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (local, remote) = (client.local_addr().unwrap(), client.peer_addr().unwrap());
        let found = socket(libc::IPPROTO_TCP as u8, local, remote)
            .unwrap()
            .unwrap();
        // SAFETY: getuid cannot fail.
        assert_eq!(found.uid, unsafe { libc::getuid() });
        assert_eq!(pid_of(found.inode, found.uid), Some(std::process::id()));
        let path = path_of(std::process::id()).unwrap();
        assert_eq!(
            std::path::Path::new(&path),
            std::env::current_exe().unwrap()
        );
        // No such socket: none.
        let gone: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(socket(libc::IPPROTO_TCP as u8, gone, remote).unwrap(), None);
    }
}
