//! macOS: the IPv4 default route from the routing table, as
//! `detect_default_interface` takes it; the interface's kind from its
//! functional type (`SIOCGIFFUNCTIONALTYPE`, what `ifconfig -v` prints as
//! `type:`), which tells Wi-Fi from Ethernet where the link type does not;
//! its MTU; every interface, typed the same way, but that a point-to-point
//! one (a VPN's utun, whatever type it claims) is other. No SSID: CoreWLAN gives it only to an app the user lets see
//! their location.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::net::network::{NetworkState, NetworkType};
use crate::platform::route_socket;

// sys/sockio.h: _IOWR('i', 51 and 173, struct ifreq), a 32-byte ifreq.
const SIOCGIFFLAGS: libc::c_ulong = 0xc020_6911;
const SIOCGIFMTU: libc::c_ulong = 0xc020_6933;
const SIOCGIFFUNCTIONALTYPE: libc::c_ulong = 0xc020_69ad;

// net/if.h
const IFRTYPE_FUNCTIONAL_WIRED: u32 = 2;
const IFRTYPE_FUNCTIONAL_WIFI_INFRA: u32 = 3;
const IFRTYPE_FUNCTIONAL_CELLULAR: u32 = 5;

pub(super) fn detect() -> NetworkState {
    let socket = socket().ok();
    let kind_of = |name: &str| {
        let ask = |request| socket.as_ref().and_then(|s| ask(s, request, name).ok());
        let point_to_point =
            ask(SIOCGIFFLAGS).is_some_and(|flags| flags & libc::IFF_POINTOPOINT as u32 != 0);
        if point_to_point {
            NetworkType::Other
        } else {
            kind(ask(SIOCGIFFUNCTIONALTYPE).unwrap_or(0))
        }
    };
    let mut state = NetworkState {
        interfaces: super::interfaces(kind_of),
        ..Default::default()
    };
    let route = match route_socket::default_route() {
        Ok(route) => route,
        Err(e) => {
            tracing::debug!("network: no default route: {}", e);
            return state;
        }
    };
    let Ok(name) = route_socket::interface_name(route.index) else {
        return state;
    };
    state.gateway = route.gateway;
    if let Some(socket) = &socket {
        state.kind = Some(kind_of(&name));
        state.mtu = ask(socket, SIOCGIFMTU, &name).ok();
    }
    state.index = Some(u32::from(route.index));
    state.addresses = super::addresses_of(&name);
    state.interface = Some(name);
    state
}

/// The kind of an interface of functional type `ty`. A VPN's, a bridge's
/// or one the system does not type is other.
fn kind(ty: u32) -> NetworkType {
    match ty {
        IFRTYPE_FUNCTIONAL_WIFI_INFRA => NetworkType::Wifi,
        IFRTYPE_FUNCTIONAL_CELLULAR => NetworkType::Cellular,
        IFRTYPE_FUNCTIONAL_WIRED => NetworkType::Ethernet,
        _ => NetworkType::Other,
    }
}

/// `ifreq`: the name, and the union whose first four bytes the answers
/// here are.
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    data: [u8; 16],
}

/// A socket to ask the interfaces' ioctls on.
fn socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); owned from here on.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor just opened, owned by none else.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The u32 ioctl `request` answers of interface `name`.
fn ask(socket: &OwnedFd, request: libc::c_ulong, name: &str) -> io::Result<u32> {
    let mut req = IfReq {
        name: [0; libc::IFNAMSIZ],
        data: [0; 16],
    };
    if name.len() >= req.name.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: `req` is an ifreq the ioctl reads the name of and writes the
    // answer into.
    if unsafe { libc::ioctl(socket.as_raw_fd(), request, &mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u32::from_ne_bytes(req.data[..4].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn functional_types_are_kinds() {
        assert_eq!(kind(IFRTYPE_FUNCTIONAL_WIFI_INFRA), NetworkType::Wifi);
        assert_eq!(kind(IFRTYPE_FUNCTIONAL_CELLULAR), NetworkType::Cellular);
        assert_eq!(kind(IFRTYPE_FUNCTIONAL_WIRED), NetworkType::Ethernet);
        // Unknown (a utun), AWDL.
        assert_eq!(kind(0), NetworkType::Other);
        assert_eq!(kind(4), NetworkType::Other);
    }

    /// The loopback answers as the system has it: its MTU, and the
    /// loopback's functional type.
    #[test]
    fn the_loopback_is_asked() {
        let socket = socket().unwrap();
        assert_eq!(ask(&socket, SIOCGIFFUNCTIONALTYPE, "lo0").unwrap(), 1);
        assert_eq!(ask(&socket, SIOCGIFMTU, "lo0").unwrap(), 16384);
        let flags = ask(&socket, SIOCGIFFLAGS, "lo0").unwrap();
        assert!(flags & libc::IFF_LOOPBACK as u32 != 0, "{:#x}", flags);
        assert!(flags & libc::IFF_POINTOPOINT as u32 == 0, "{:#x}", flags);
        assert!(ask(&socket, SIOCGIFMTU, "nonesuch0").is_err());
    }
}
