//! Addresses of a macOS utun, set without ifconfig(8): the IPv6 one, as
//! sing-tun sets it (`SIOCAIFADDR_IN6`, no duplicate address detection,
//! lifetimes that do not end). The `tun` crate sets the IPv4 one.

use std::io;
use std::net::Ipv6Addr;

/// `struct in6_addrlifetime`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Lifetime {
    expire: libc::time_t,
    preferred: libc::time_t,
    valid_lifetime: u32,
    preferred_lifetime: u32,
}

/// `struct in6_aliasreq`.
#[repr(C)]
#[derive(Clone, Copy)]
struct AliasRequest {
    name: [libc::c_char; libc::IFNAMSIZ],
    address: libc::sockaddr_in6,
    destination: libc::sockaddr_in6,
    prefix_mask: libc::sockaddr_in6,
    flags: libc::c_int,
    lifetime: Lifetime,
}

/// `_IOW('i', 26, struct in6_aliasreq)`.
const SIOCAIFADDR_IN6: libc::c_ulong = 0x8000_0000
    | ((std::mem::size_of::<AliasRequest>() as libc::c_ulong & 0x1fff) << 16)
    | ((b'i' as libc::c_ulong) << 8)
    | 26;
const IN6_IFF_NODAD: libc::c_int = 0x0020;
const IN6_IFF_SECURED: libc::c_int = 0x0400;
const ND6_INFINITE_LIFETIME: u32 = 0xffff_ffff;

fn sockaddr(address: Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: a plain C struct, all zeros valid.
    let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sin6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sin6.sin6_addr.s6_addr = address.octets();
    sin6
}

fn request(name: &str, address: Ipv6Addr, prefix_len: u8) -> io::Result<AliasRequest> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    // SAFETY: a plain C struct, all zeros valid.
    let mut request: AliasRequest = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    request.address = sockaddr(address);
    let mask = u128::MAX
        .checked_shl(128 - u32::from(prefix_len))
        .unwrap_or(0);
    request.prefix_mask = sockaddr(Ipv6Addr::from(mask));
    // A point-to-point peer only for a single address, as sing-tun has it.
    if prefix_len == 128 {
        request.destination = sockaddr(Ipv6Addr::from(u128::from(address).wrapping_add(1)));
    }
    request.flags = IN6_IFF_NODAD | IN6_IFF_SECURED;
    request.lifetime.valid_lifetime = ND6_INFINITE_LIFETIME;
    request.lifetime.preferred_lifetime = ND6_INFINITE_LIFETIME;
    Ok(request)
}

/// Adds `address`/`prefix_len` to the interface `name`.
pub(crate) fn add_ipv6_address(name: &str, address: Ipv6Addr, prefix_len: u8) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let request = request(name, address, prefix_len)?;
    // SAFETY: plain socket(2); owned from here on.
    let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor just opened, owned by none else.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: `request` is the in6_aliasreq the ioctl reads.
    let ret = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCAIFADDR_IN6, &request) };
    if ret < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(
            e.kind(),
            format!("adding {}/{} to {}: {}", address, prefix_len, name, e),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout and request number of <netinet6/in6_var.h>.
    #[test]
    fn the_request_is_in6_aliasreq() {
        assert_eq!(std::mem::size_of::<AliasRequest>(), 128);
        assert_eq!(SIOCAIFADDR_IN6, 0x8080_691a);
        let aliased = request("utun9", "fdfe:dcba:9876::1".parse().unwrap(), 126).unwrap();
        assert_eq!(aliased.name[..5], b"utun9".map(|b| b as libc::c_char));
        assert_eq!(aliased.address.sin6_len, 28);
        assert_eq!(
            Ipv6Addr::from(aliased.prefix_mask.sin6_addr.s6_addr),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(aliased.destination.sin6_len, 0);
        assert_eq!(aliased.lifetime.valid_lifetime, u32::MAX);
        assert!(request("a-name-far-too-long", Ipv6Addr::LOCALHOST, 128).is_err());
    }
}
