//! macOS's routing socket (PF_ROUTE) and routing table (sysctl
//! NET_RT_DUMP), spoken without route(8): adding and deleting the routes of
//! a TUN, and finding the interface of the default route.
//!
//! A message is an `rt_msghdr` followed by the socket addresses its
//! `rtm_addrs` names, in the order of their bits (destination, gateway,
//! netmask, ...), each padded to 4 bytes, as route(8) writes them.

// Adding routes is the TUN's; reading the default route is everyone's.
#![cfg_attr(not(feature = "inbound-tun"), allow(dead_code))]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_STATIC: i32 = 0x800;
const RTF_IFSCOPE: i32 = 0x100_0000;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
/// The address kinds a message may carry, in the order they follow it.
const RTAX_MAX: u32 = 8;

const HEADER: usize = std::mem::size_of::<libc::rt_msghdr>();

/// What a route message asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Add,
    Delete,
}

/// The message that adds or deletes the route to `dst` through `gateway`
/// (an address of the TUN: the kernel finds the interface from it), as
/// `route add -net DST GATEWAY` sends it.
pub(crate) fn message(change: Change, seq: i32, dst: (IpAddr, u8), gateway: IpAddr) -> Vec<u8> {
    let (address, len) = dst;
    let mut addresses = Vec::new();
    push_sockaddr(&mut addresses, masked(address, len));
    push_sockaddr(&mut addresses, gateway);
    push_sockaddr(&mut addresses, mask(address.is_ipv6(), len));

    // SAFETY: a plain C struct, all zeros valid.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_msglen = (HEADER + addresses.len()) as u16;
    header.rtm_version = libc::RTM_VERSION as u8;
    header.rtm_type = match change {
        Change::Add => RTM_ADD,
        Change::Delete => RTM_DELETE,
    };
    header.rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
    header.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    header.rtm_seq = seq;
    let mut bytes = Vec::with_capacity(usize::from(header.rtm_msglen));
    // SAFETY: the header's bytes, for its size.
    bytes.extend_from_slice(unsafe {
        std::slice::from_raw_parts(&header as *const _ as *const u8, HEADER)
    });
    bytes.extend_from_slice(&addresses);
    bytes
}

fn masked(address: IpAddr, len: u8) -> IpAddr {
    match address {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            Ipv4Addr::from(u32::from(a) & mask).into()
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            Ipv6Addr::from(u128::from(a) & mask).into()
        }
    }
}

fn mask(v6: bool, len: u8) -> IpAddr {
    if v6 {
        Ipv6Addr::from(u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0)).into()
    } else {
        Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)).into()
    }
}

/// Appends a `sockaddr_in` or `sockaddr_in6` holding `address`.
fn push_sockaddr(out: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(a) => {
            // sin_len, sin_family, sin_port, sin_addr, sin_zero
            out.extend_from_slice(&[16, libc::AF_INET as u8, 0, 0]);
            out.extend_from_slice(&a.octets());
            out.extend_from_slice(&[0; 8]);
        }
        IpAddr::V6(a) => {
            // sin6_len, sin6_family, sin6_port, sin6_flowinfo, sin6_addr,
            // sin6_scope_id
            out.extend_from_slice(&[28, libc::AF_INET6 as u8, 0, 0]);
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&a.octets());
            out.extend_from_slice(&[0; 4]);
        }
    }
}

/// The addresses a message carries, by kind (RTAX_DST = 0, ...), from the
/// bytes after its header.
fn sockaddrs(addrs: i32, mut bytes: &[u8]) -> [Option<IpAddr>; RTAX_MAX as usize] {
    let mut found = [None; RTAX_MAX as usize];
    for (kind, slot) in found.iter_mut().enumerate() {
        if addrs & (1 << kind) == 0 {
            continue;
        }
        let Some(&len) = bytes.first() else {
            break;
        };
        // An empty sockaddr still takes 4 bytes; the rest are padded to 4.
        let taken = if len == 0 {
            4
        } else {
            (usize::from(len) + 3) & !3
        };
        if bytes.len() >= 2 {
            *slot = match i32::from(bytes[1]) {
                libc::AF_INET if len >= 8 => {
                    Some(IpAddr::from([bytes[4], bytes[5], bytes[6], bytes[7]]))
                }
                // A netmask may be cut short: the missing bytes are zeros.
                libc::AF_INET => {
                    let mut octets = [0u8; 4];
                    for (i, byte) in bytes.iter().take(usize::from(len)).skip(4).enumerate() {
                        octets[i] = *byte;
                    }
                    Some(IpAddr::from(octets))
                }
                libc::AF_INET6 if len >= 24 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&bytes[8..24]);
                    Some(IpAddr::from(octets))
                }
                _ => None,
            };
        }
        bytes = bytes.get(taken..).unwrap_or_default();
    }
    found
}

/// A default route of the table: the interface index, whether it is
/// scoped to its interface, and whether it has a gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DefaultRoute {
    index: u16,
    scoped: bool,
}

/// The IPv4 default routes, up and through a gateway, of a table dump, in
/// its order.
fn default_routes(mut dump: &[u8]) -> Vec<DefaultRoute> {
    let mut routes = Vec::new();
    while dump.len() >= HEADER {
        let len = usize::from(u16::from_ne_bytes([dump[0], dump[1]]));
        if len < HEADER || len > dump.len() {
            break;
        }
        // SAFETY: at least a header's bytes; read unaligned.
        let header: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(dump.as_ptr() as *const libc::rt_msghdr) };
        let flags = header.rtm_flags;
        if flags & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY {
            let found = sockaddrs(header.rtm_addrs, &dump[HEADER..len]);
            let destination = found[0];
            let netmask = found[2];
            let default = destination == Some(Ipv4Addr::UNSPECIFIED.into())
                && netmask.is_none_or(|m| m == IpAddr::from(Ipv4Addr::UNSPECIFIED));
            if default {
                routes.push(DefaultRoute {
                    index: header.rtm_index,
                    scoped: flags & RTF_IFSCOPE != 0,
                });
            }
        }
        dump = &dump[len..];
    }
    routes
}

/// The routing table of IPv4, as the kernel dumps it.
#[cfg(target_os = "macos")]
fn dump_ipv4() -> io::Result<Vec<u8>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_DUMP,
        0,
    ];
    loop {
        let mut size = 0usize;
        // SAFETY: asks for the size only.
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u8; size + size / 8 + 1024];
        let mut filled = buffer.len();
        // SAFETY: `buffer` is writable for `filled` bytes.
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
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
        // The table grew in between: ask again.
        if e.raw_os_error() != Some(libc::ENOMEM) {
            return Err(e);
        }
    }
}

/// The interface of the system's default route: the first unscoped IPv4
/// one, or else the first, as sing-tun reads it from the table. A TUN's
/// split routes are never a default route.
#[cfg(target_os = "macos")]
pub(crate) fn default_interface() -> io::Result<String> {
    let routes = default_routes(&dump_ipv4()?);
    let route = routes
        .iter()
        .find(|r| !r.scoped)
        .or_else(|| routes.first())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no default route"))?;
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `name` holds IF_NAMESIZE bytes, as if_indextoname needs.
    let found = unsafe { libc::if_indextoname(u32::from(route.index), name.as_mut_ptr()) };
    if found.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: if_indextoname wrote a C string into `name`.
    Ok(unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

/// A routing socket, writing one message at a time and reading its answer.
#[cfg(target_os = "macos")]
pub(crate) struct RouteSocket {
    fd: std::os::fd::OwnedFd,
    seq: std::sync::atomic::AtomicI32,
}

#[cfg(target_os = "macos")]
impl RouteSocket {
    pub(crate) fn open() -> io::Result<RouteSocket> {
        use std::os::fd::FromRawFd;
        // SAFETY: plain socket(2); owned from here on.
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor just opened, owned by none else.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        Ok(RouteSocket {
            fd,
            seq: std::sync::atomic::AtomicI32::new(1),
        })
    }

    /// Adds the route to `dst` through `gateway`. One already there -- left
    /// by a run that died, or another VPN's -- is replaced, as sing-tun does.
    pub(crate) fn add(&self, dst: (IpAddr, u8), gateway: IpAddr) -> io::Result<()> {
        match self.send(Change::Add, dst, gateway) {
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                let _ = self.send(Change::Delete, dst, gateway);
                self.send(Change::Add, dst, gateway)
            }
            other => other,
        }
    }

    pub(crate) fn delete(&self, dst: (IpAddr, u8), gateway: IpAddr) -> io::Result<()> {
        self.send(Change::Delete, dst, gateway)
    }

    fn send(&self, change: Change, dst: (IpAddr, u8), gateway: IpAddr) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let message = message(change, seq, dst, gateway);
        // A write fails with the kernel's error for the message.
        // SAFETY: `message` is readable for its length.
        let written = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                message.as_ptr() as *const libc::c_void,
                message.len(),
            )
        };
        if written < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                e.kind(),
                format!(
                    "{} route {}/{} via {}: {}",
                    match change {
                        Change::Add => "adding",
                        Change::Delete => "deleting",
                    },
                    dst.0,
                    dst.1,
                    gateway,
                    e
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `route add -net 1.0.0.0/8 172.19.0.1`: the header, then the
    /// destination, the gateway and the netmask.
    #[test]
    fn an_added_ipv4_route_is_what_route_8_sends() {
        let bytes = message(
            Change::Add,
            7,
            ("1.2.3.4".parse().unwrap(), 8),
            "172.19.0.1".parse().unwrap(),
        );
        assert_eq!(bytes.len(), HEADER + 48);
        assert_eq!(
            u16::from_ne_bytes([bytes[0], bytes[1]]) as usize,
            bytes.len()
        );
        assert_eq!(bytes[2], 5); // RTM_VERSION
        assert_eq!(bytes[3], RTM_ADD);
        // SAFETY: at least a header's bytes.
        let header: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const libc::rt_msghdr) };
        assert_eq!(header.rtm_flags, RTF_UP | RTF_STATIC | RTF_GATEWAY);
        assert_eq!(header.rtm_addrs, RTA_DST | RTA_GATEWAY | RTA_NETMASK);
        assert_eq!(header.rtm_seq, 7);
        assert_eq!(
            &bytes[HEADER..],
            [
                16, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1.0.0.0
                16, 2, 0, 0, 172, 19, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, // 172.19.0.1
                16, 2, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 255.0.0.0
            ]
        );
    }

    #[test]
    fn an_ipv6_route_carries_sockaddr_in6() {
        let bytes = message(
            Change::Delete,
            1,
            ("8000::".parse().unwrap(), 1),
            "fdfe:dcba:9876::1".parse().unwrap(),
        );
        assert_eq!(bytes[3], RTM_DELETE);
        let found = sockaddrs(RTA_DST | RTA_GATEWAY | RTA_NETMASK, &bytes[HEADER..]);
        assert_eq!(found[0], Some("8000::".parse().unwrap()));
        assert_eq!(found[1], Some("fdfe:dcba:9876::1".parse().unwrap()));
        assert_eq!(found[2], Some("8000::".parse().unwrap()));
        assert_eq!(bytes.len(), HEADER + 3 * 28);
    }

    /// A dump holds a scoped default route first, then the primary one; a
    /// cut-short netmask of zeros is a default route's.
    #[test]
    fn the_default_route_is_found_in_a_dump() {
        let entry = |index: u16, flags: i32, dst: &str, netmask: &[u8]| {
            let mut addresses = Vec::new();
            push_sockaddr(&mut addresses, dst.parse().unwrap());
            push_sockaddr(&mut addresses, "192.168.1.1".parse().unwrap());
            addresses.extend_from_slice(netmask);
            // SAFETY: a plain C struct, all zeros valid.
            let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
            header.rtm_msglen = (HEADER + addresses.len()) as u16;
            header.rtm_index = index;
            header.rtm_flags = flags;
            header.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
            let mut bytes =
                unsafe { std::slice::from_raw_parts(&header as *const _ as *const u8, HEADER) }
                    .to_vec();
            bytes.extend_from_slice(&addresses);
            bytes
        };
        let mut dump = entry(
            9,
            RTF_UP | RTF_GATEWAY | RTF_IFSCOPE,
            "0.0.0.0",
            &[0, 0, 0, 0],
        );
        dump.extend(entry(
            4,
            RTF_UP | RTF_GATEWAY,
            "1.0.0.0",
            &[5, 2, 0, 0, 255, 0, 0, 0],
        ));
        dump.extend(entry(
            6,
            RTF_UP | RTF_GATEWAY | RTF_STATIC,
            "0.0.0.0",
            &[0, 0, 0, 0],
        ));
        dump.extend(entry(7, RTF_UP, "0.0.0.0", &[0, 0, 0, 0]));
        assert_eq!(
            default_routes(&dump),
            [
                DefaultRoute {
                    index: 9,
                    scoped: true
                },
                DefaultRoute {
                    index: 6,
                    scoped: false
                },
            ]
        );
    }

    /// Reading this host's table changes nothing: whatever it holds, the
    /// dump parses, and a host with a network has a default interface.
    #[cfg(target_os = "macos")]
    #[test]
    fn this_host_s_table_is_read() {
        let dump = dump_ipv4().unwrap();
        assert!(!dump.is_empty());
        if let Ok(name) = default_interface() {
            assert!(!name.is_empty());
        }
    }
}
