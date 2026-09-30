//! NAT64 on an IPv6-only network (a desktop's; phones translate IPv4
//! themselves, 464XLAT): IPv4 addresses sail sends to are written into
//! the network's NAT64 prefix (RFC 6052), found by asking for
//! `ipv4only.arpa`'s AAAA records (RFC 7050), and taken back out of what
//! comes back. That covers IPv4 literals, the A records the rules or the
//! DNS give, and what the TUN's applications send to IPv4 alike: nothing
//! is rewritten in DNS answers (no DNS64).
//!
//! The prefix is the host's network's, one per process.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwapOption;

/// A NAT64 prefix: its first `len` bits, `len` one of RFC 6052's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    bytes: [u8; 16],
    len: u8,
}

/// The lengths RFC 6052 allows, the most common first.
const LENGTHS: [u8; 6] = [96, 64, 56, 48, 40, 32];

/// The addresses `ipv4only.arpa` has, which a NAT64 prefix is found by
/// (RFC 7050 §2.2).
const WELL_KNOWN: [Ipv4Addr; 2] = [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

/// Where the IPv4 address's bytes go: after the prefix, skipping byte 8
/// (bits 64 to 71), which is zero (RFC 6052 §2.2).
fn positions(len: u8) -> impl Iterator<Item = usize> {
    (usize::from(len) / 8..16).filter(|&i| i != 8).take(4)
}

impl Prefix {
    pub fn new(address: Ipv6Addr, len: u8) -> Option<Prefix> {
        if !LENGTHS.contains(&len) {
            return None;
        }
        let mut bytes = [0u8; 16];
        let octets = address.octets();
        bytes[..usize::from(len) / 8].copy_from_slice(&octets[..usize::from(len) / 8]);
        Some(Prefix { bytes, len })
    }

    /// `v4` in this prefix.
    pub fn synthesize(&self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut bytes = self.bytes;
        for (at, byte) in positions(self.len).zip(v4.octets()) {
            bytes[at] = byte;
        }
        Ipv6Addr::from(bytes)
    }

    /// The IPv4 address `v6` carries, if it is in this prefix.
    pub fn extract(&self, v6: Ipv6Addr) -> Option<Ipv4Addr> {
        let octets = v6.octets();
        let n = usize::from(self.len) / 8;
        if octets[..n] != self.bytes[..n] || (n <= 8 && octets[8] != 0) {
            return None;
        }
        let mut v4 = [0u8; 4];
        for (byte, at) in v4.iter_mut().zip(positions(self.len)) {
            *byte = octets[at];
        }
        Some(Ipv4Addr::from(v4))
    }

    /// The prefix `v6`, an answer for `ipv4only.arpa`, is in: the first of
    /// RFC 6052's lengths at which it carries a well-known address.
    pub fn found_in(v6: Ipv6Addr) -> Option<Prefix> {
        LENGTHS.into_iter().find_map(|len| {
            let prefix = Prefix::new(v6, len)?;
            prefix
                .extract(v6)
                .filter(|v4| WELL_KNOWN.contains(v4))
                .map(|_| prefix)
        })
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.bytes), self.len)
    }
}

static PREFIX: ArcSwapOption<Prefix> = ArcSwapOption::const_empty();

/// The prefix in use; none but on an IPv6-only network with NAT64.
pub fn current() -> Option<Prefix> {
    PREFIX.load().as_deref().copied()
}

/// Uses `prefix`, or none, from now on; whether that changed anything.
pub fn set(prefix: Option<Prefix>) -> bool {
    if current() == prefix {
        return false;
    }
    PREFIX.store(prefix.map(Arc::new));
    true
}

/// Finds the NAT64 prefix of the network the system resolver is on, as
/// RFC 7050 has it; none where there is none. Blocks, on the resolver.
pub fn discover() -> Option<Prefix> {
    use std::net::ToSocketAddrs;
    ("ipv4only.arpa", 0)
        .to_socket_addrs()
        .ok()?
        .find_map(|a| match a.ip() {
            IpAddr::V6(v6) => Prefix::found_in(v6),
            IpAddr::V4(_) => None,
        })
}

/// Where to send to reach `addr`: an IPv4 address in the prefix in use.
pub fn map(addr: SocketAddr) -> SocketAddr {
    map_with(addr, current())
}

/// What an address that came back is: an IPv6 address in the prefix in use
/// is the IPv4 address it carries.
pub fn unmap(addr: SocketAddr) -> SocketAddr {
    unmap_with(addr, current())
}

/// `map`, with `prefix`. The host's own addresses, and those no NAT64
/// reaches (loopback, link-local, multicast, broadcast, unspecified), are
/// left as they are.
fn map_with(addr: SocketAddr, prefix: Option<Prefix>) -> SocketAddr {
    match (addr, prefix) {
        (SocketAddr::V4(v4), Some(prefix)) if translatable(*v4.ip()) => {
            SocketAddr::new(IpAddr::V6(prefix.synthesize(*v4.ip())), v4.port())
        }
        _ => addr,
    }
}

fn unmap_with(addr: SocketAddr, prefix: Option<Prefix>) -> SocketAddr {
    match (addr, prefix) {
        (SocketAddr::V6(v6), Some(prefix)) => match prefix.extract(*v6.ip()) {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        _ => addr,
    }
}

fn translatable(v4: Ipv4Addr) -> bool {
    !(v4.is_loopback()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6052_s_examples_are_written_and_read() {
        // RFC 6052 §2.4: 192.0.2.33 in each prefix length of 2001:db8::.
        let v4: Ipv4Addr = "192.0.2.33".parse().unwrap();
        for (len, prefix, want) in [
            (32, "2001:db8::", "2001:db8:c000:221::"),
            (40, "2001:db8:100::", "2001:db8:1c0:2:21::"),
            (48, "2001:db8:122::", "2001:db8:122:c000:2:2100::"),
            (56, "2001:db8:122:300::", "2001:db8:122:3c0:0:221::"),
            (64, "2001:db8:122:344::", "2001:db8:122:344:c0:2:2100:0"),
            (96, "2001:db8:122:344::", "2001:db8:122:344::192.0.2.33"),
        ] {
            let prefix = Prefix::new(prefix.parse().unwrap(), len).unwrap();
            let want: Ipv6Addr = want.parse().unwrap();
            assert_eq!(prefix.synthesize(v4), want, "/{}", len);
            assert_eq!(prefix.extract(want), Some(v4), "/{}", len);
        }
        assert!(Prefix::new(Ipv6Addr::UNSPECIFIED, 80).is_none());
    }

    #[test]
    fn the_prefix_is_found_in_ipv4only_arpa_s_answer() {
        let answer: Ipv6Addr = "64:ff9b::192.0.0.170".parse().unwrap();
        let prefix = Prefix::found_in(answer).unwrap();
        assert_eq!(prefix.to_string(), "64:ff9b::/96");
        let other: Ipv6Addr = "2001:db8:122:344:c0:0:aa00:0".parse().unwrap();
        assert_eq!(Prefix::found_in(other).unwrap().len, 64);
        // An ordinary address carries no well-known one.
        assert!(Prefix::found_in("2001:db8::1".parse().unwrap()).is_none());
    }

    /// With a prefix (the global one is left alone: other tests dial).
    #[test]
    fn addresses_go_through_the_prefix_and_back() {
        let prefix = Prefix::found_in("64:ff9b::192.0.0.170".parse().unwrap());
        let v4: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let v6 = map_with(v4, prefix);
        assert_eq!(v6, "[64:ff9b::5db8:d822]:443".parse().unwrap());
        assert_eq!(unmap_with(v6, prefix), v4);
        // Others pass as they are: IPv6, the host's own, and without one.
        for other in ["[2001:db8::1]:443", "127.0.0.1:80", "169.254.1.1:80"] {
            let other: SocketAddr = other.parse().unwrap();
            assert_eq!(map_with(other, prefix), other);
            assert_eq!(unmap_with(other, prefix), other);
        }
        assert_eq!(map_with(v4, None), v4);
    }
}
