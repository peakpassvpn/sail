//! What a `UDP ASSOCIATE` keeps: its place among the inbound's
//! associations, and which client its relay socket takes datagrams from.
//!
//! Each association has a UDP relay socket of its own (RFC 1928), bound when
//! the client asks and closed when its control connection closes, so a
//! datagram's association is the socket it arrived on: nothing is guessed.
//! What is left to check is that the datagram came from the client:
//!
//! - its IP must be the control connection's, and
//! - its address the one the client declared, when it declared one; else
//!   the address of its first datagram, which the association keeps.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::session::SocksAddr;

/// How many associations, and so relay sockets, an inbound keeps at once.
/// A client asking for one more is refused.
pub const MAX_ASSOCIATIONS: usize = 4096;

/// The live associations of an inbound, counted.
#[derive(Default)]
pub struct Associations {
    live: AtomicUsize,
}

/// An association's place; dropping it frees the place.
pub struct Slot(Arc<Associations>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Associations {
    /// A place for one more association, unless all are taken.
    pub fn acquire(self: &Arc<Self>) -> Option<Slot> {
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_ASSOCIATIONS).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(self.clone()))
    }

    /// How many associations are live.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }
}

/// `addr` with an IPv4-mapped IPv6 address as the IPv4 one, as a dual-stack
/// socket may report either.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Which source an association's relay socket takes datagrams from.
#[derive(Debug)]
pub struct ClientFilter {
    /// The control connection's IP.
    peer_ip: IpAddr,
    /// The client's address: declared, or learned from its first datagram.
    client: Option<SocketAddr>,
}

impl ClientFilter {
    /// The filter of an association asked for from `peer`, declaring
    /// `declared`.
    ///
    /// An unspecified IP with a port is the peer's IP with that port. A
    /// zero port, a domain, or an IP other than the peer's declares
    /// nothing: datagrams must come from the peer's IP in any case, and a
    /// client behind NAT declares the address it has behind it, which the
    /// server never sees.
    pub fn new(peer: SocketAddr, declared: &SocksAddr) -> Self {
        let peer_ip = peer.ip().to_canonical();
        let client = match declared {
            SocksAddr::Ip(addr) if addr.port() != 0 => {
                let ip = addr.ip().to_canonical();
                if ip.is_unspecified() {
                    Some(SocketAddr::new(peer_ip, addr.port()))
                } else if ip == peer_ip {
                    Some(SocketAddr::new(ip, addr.port()))
                } else {
                    None
                }
            }
            _ => None,
        };
        ClientFilter { peer_ip, client }
    }

    /// Whether a datagram from `src` is the client's. The first from the
    /// peer's IP pins the client's address when it declared none.
    pub fn accept(&mut self, src: SocketAddr) -> bool {
        let src = canonical(src);
        if src.ip() != self.peer_ip {
            return false;
        }
        match self.client {
            Some(client) => client == src,
            None => {
                self.client = Some(src);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_declared_address_is_matched_exactly() {
        let mut f = ClientFilter::new(
            addr("10.0.0.1:4000"),
            &SocksAddr::from(addr("10.0.0.1:5000")),
        );
        assert!(!f.accept(addr("10.0.0.1:5001")));
        assert!(!f.accept(addr("10.0.0.2:5000")));
        assert!(f.accept(addr("10.0.0.1:5000")));
        assert!(f.accept(addr("[::ffff:10.0.0.1]:5000")));
    }

    #[test]
    fn an_unspecified_ip_is_the_peers() {
        let mut f = ClientFilter::new(
            addr("10.0.0.1:4000"),
            &SocksAddr::from(addr("0.0.0.0:7000")),
        );
        assert!(!f.accept(addr("10.0.0.1:7001")));
        assert!(f.accept(addr("10.0.0.1:7000")));
    }

    #[test]
    fn without_a_declaration_the_first_datagram_pins_the_port() {
        let mut f = ClientFilter::new(addr("10.0.0.1:4000"), &SocksAddr::any());
        // Another host neither passes nor pins.
        assert!(!f.accept(addr("10.0.0.2:6000")));
        assert!(f.accept(addr("10.0.0.1:6000")));
        assert!(!f.accept(addr("10.0.0.1:6001")));
        assert!(f.accept(addr("10.0.0.1:6000")));
    }

    #[test]
    fn a_declaration_of_another_ip_is_no_declaration() {
        // A client behind NAT declares its private address.
        let mut f = ClientFilter::new(
            addr("203.0.113.1:4000"),
            &SocksAddr::from(addr("192.168.1.2:5000")),
        );
        assert!(!f.accept(addr("192.168.1.2:5000")));
        assert!(f.accept(addr("203.0.113.1:61000")));
        assert!(!f.accept(addr("203.0.113.1:61001")));
    }

    #[test]
    fn associations_are_bounded() {
        let a = Arc::new(Associations::default());
        let held: Vec<_> = (0..MAX_ASSOCIATIONS)
            .map(|_| a.acquire().unwrap())
            .collect();
        assert!(a.acquire().is_none());
        drop(held);
        assert_eq!(a.len(), 0);
        assert!(a.acquire().is_some());
    }
}
