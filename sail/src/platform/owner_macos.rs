//! macOS: who opened a socket of this host, as sing-box's searcher_darwin
//! finds it. The kernel's list of TCP or UDP sockets
//! (`net.inet.{tcp,udp}.pcblist_n`) holds, for each socket, records each
//! with its length and kind (bsd/netinet/in_pcblist.c, get_pcblist_n):
//! the socket's addresses and ports (xinpcb_n) and the pid that last used
//! it (xsocket_n's so_last_pid). The pid's path and uid come from libproc.
//! The records are walked by their own lengths; the fields within them are
//! at sing-box's offsets.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The kinds of record (bsd/sys/socketvar.h).
const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;
/// The list's header, xinpgen, padded.
const HEADER: usize = 24;

/// The pid of the socket `local` is the address of, in `list`, a
/// pcblist_n as the kernel gives it.
pub(crate) fn pid_in(list: &[u8], local: SocketAddr) -> Option<u32> {
    let rup8 = |n: usize| (n + 7) & !7;
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_ne_bytes(list.get(at..at + 4)?.try_into().ok()?))
    };
    let mut at = HEADER;
    // Whether the last inpcb record read is the socket's.
    let mut ours = false;
    while at + 8 <= list.len() {
        let len = u32_at(at)? as usize;
        let kind = u32_at(at + 4)?;
        if len < 8 {
            break;
        }
        match kind {
            XSO_INPCB => {
                let port = u16::from_be_bytes(list.get(at + 18..at + 20)?.try_into().ok()?);
                let flag = *list.get(at + 44)?;
                let address = match local.ip() {
                    IpAddr::V4(_) if flag & 0x1 != 0 => {
                        let b: [u8; 4] = list.get(at + 76..at + 80)?.try_into().ok()?;
                        Some(IpAddr::V4(Ipv4Addr::from(b)))
                    }
                    IpAddr::V6(_) if flag & 0x2 != 0 => {
                        let b: [u8; 16] = list.get(at + 64..at + 80)?.try_into().ok()?;
                        Some(IpAddr::V6(Ipv6Addr::from(b)))
                    }
                    _ => None,
                };
                // A socket bound to any address takes what comes to its
                // port, as sing-box takes it.
                ours = port == local.port()
                    && address.is_some_and(|a| a == local.ip() || a.is_unspecified());
            }
            XSO_SOCKET if ours => return u32_at(at + 68),
            _ => {}
        }
        at += rup8(len);
    }
    None
}

/// The kernel's list of the sockets of `tcp` or UDP.
pub(crate) fn list(tcp: bool) -> io::Result<Vec<u8>> {
    let name = if tcp {
        c"net.inet.tcp.pcblist_n"
    } else {
        c"net.inet.udp.pcblist_n"
    };
    for _ in 0..3 {
        let mut size: libc::size_t = 0;
        // SAFETY: asks the size alone.
        if unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // Room for the sockets opened meanwhile.
        size += size / 8 + 4096;
        let mut buf = vec![0u8; size];
        // SAFETY: a buffer as long as `size` says.
        let ret = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret == 0 {
            buf.truncate(size);
            return Ok(buf);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOMEM) {
            return Err(e);
        }
    }
    Err(io::Error::other("the socket list kept growing"))
}

/// The path and uid of the process `pid`.
pub(crate) fn process(pid: u32) -> Option<(Option<String>, u32)> {
    let pid = pid as libc::c_int;
    // SAFETY: zeroed is a valid proc_bsdinfo, filled by the call.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: a buffer of the size given.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
            size,
        )
    };
    if got != size {
        return None;
    }
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: a buffer of the size given.
    let len = unsafe {
        libc::proc_pidpath(
            pid,
            path.as_mut_ptr() as *mut libc::c_void,
            path.len() as u32,
        )
    };
    let path = (len > 0).then(|| String::from_utf8_lossy(&path[..len as usize]).into_owned());
    Some((path, info.pbi_uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A list of one inpcb record and its socket record, as the kernel
    /// writes them: found by its local address and port.
    #[test]
    fn a_socket_is_found_by_its_local_address() {
        let mut list = vec![0u8; HEADER];
        let mut inp = vec![0u8; 104];
        inp[0..4].copy_from_slice(&104u32.to_ne_bytes());
        inp[4..8].copy_from_slice(&XSO_INPCB.to_ne_bytes());
        inp[18..20].copy_from_slice(&40000u16.to_be_bytes());
        inp[44] = 0x1;
        inp[76..80].copy_from_slice(&[10, 0, 0, 2]);
        let mut so = vec![0u8; 112];
        so[0..4].copy_from_slice(&112u32.to_ne_bytes());
        so[4..8].copy_from_slice(&XSO_SOCKET.to_ne_bytes());
        so[68..72].copy_from_slice(&4242u32.to_ne_bytes());
        list.extend_from_slice(&inp);
        list.extend_from_slice(&so);
        let local = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(pid_in(&list, local("10.0.0.2:40000")), Some(4242));
        assert_eq!(pid_in(&list, local("10.0.0.2:40001")), None);
        assert_eq!(pid_in(&list, local("10.0.0.3:40000")), None);
        assert_eq!(pid_in(&list, local("[::1]:40000")), None);
    }

    /// A connection of this process's own is found in the kernel's list,
    /// with this process's path and uid.
    #[test]
    fn a_socket_of_this_process_is_found() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let pid = pid_in(&list(true).unwrap(), client.local_addr().unwrap());
        assert_eq!(pid, Some(std::process::id()));
        let (path, uid) = process(std::process::id()).unwrap();
        assert_eq!(
            std::path::PathBuf::from(path.unwrap())
                .canonicalize()
                .unwrap(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
        // SAFETY: getuid cannot fail.
        assert_eq!(uid, unsafe { libc::getuid() });
    }
}
