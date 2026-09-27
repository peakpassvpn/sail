//! Which `UDP ASSOCIATE` a datagram belongs to.
//!
//! A SOCKS5 client authenticates on its TCP control connection, but its
//! datagrams arrive on the inbound's one UDP socket, where nothing says who
//! sent them. RFC 1928 has the client declare the address it will send
//! from, zeros when it does not know it; the server may take datagrams only
//! from there. So an association is known by:
//!
//! - the address the client declared, when it declared one: with the
//!   control connection's IP for an unspecified IP, and
//! - the control connection's IP, for datagrams from any port. When more
//!   than one association shares the IP, a datagram from an unknown port
//!   goes to the oldest one not yet sent from, preferring those that
//!   declared no port, as clients send in the order they associate; else
//!   to the newest. The port is then learned, so that later datagrams from
//!   it stay with that association. Which of two such clients sent a
//!   datagram cannot be known on one shared socket; clients that declare
//!   their address are never guessed at.
//!
//! An association is in the table while its control connection is open,
//! and the table holds at most [`MAX_ASSOCIATIONS`].

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::session::SocksAddr;

/// How many associations an inbound keeps at once. A client asking for
/// one more is refused.
pub const MAX_ASSOCIATIONS: usize = 4096;

/// How many source addresses an association is known by, declared and
/// learned. Datagrams from further ones are still matched by IP, just not
/// remembered.
const MAX_ADDRS: usize = 8;

/// What a datagram's association tells of it.
#[derive(Clone, Debug)]
pub struct Found {
    /// Who authenticated on the control connection.
    pub user: Option<Arc<str>>,
}

struct Entry {
    found: Found,
    peer_ip: IpAddr,
    /// Addresses in `by_addr` that are this entry's.
    addrs: Vec<SocketAddr>,
    /// Whether a datagram has come from an address learned for it.
    learned: bool,
    /// Whether the client declared the port it sends from.
    declared: bool,
}

#[derive(Default)]
struct Table {
    next_id: u64,
    entries: HashMap<u64, Entry>,
    by_addr: HashMap<SocketAddr, u64>,
    /// Ids by control connection IP, oldest first.
    by_ip: HashMap<IpAddr, Vec<u64>>,
}

/// The live associations of an inbound, shared by its TCP and UDP sides.
#[derive(Default)]
pub struct Associations {
    table: Mutex<Table>,
}

/// An association in the table; dropping it takes it out.
pub struct Registration {
    associations: Arc<Associations>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.associations.remove(self.id);
    }
}

/// `addr` with an IPv4-mapped IPv6 address as the IPv4 one, as a dual-stack
/// socket may report either.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

impl Associations {
    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Enters the association the control connection from `peer` asked for,
    /// declaring `declared`, as `found`. None when the table is full.
    pub fn register(
        self: &Arc<Self>,
        peer: SocketAddr,
        declared: &SocksAddr,
        found: Found,
    ) -> Option<Registration> {
        let peer_ip = peer.ip().to_canonical();
        // A domain says nothing of where datagrams come from; a zero port,
        // that any may.
        let declared = match declared {
            SocksAddr::Ip(addr) if addr.port() != 0 => {
                let ip = if addr.ip().is_unspecified() {
                    peer_ip
                } else {
                    addr.ip().to_canonical()
                };
                Some(SocketAddr::new(ip, addr.port()))
            }
            _ => None,
        };
        let mut table = self.lock();
        if table.entries.len() >= MAX_ASSOCIATIONS {
            return None;
        }
        table.next_id += 1;
        let id = table.next_id;
        let mut addrs = Vec::new();
        if let Some(addr) = declared {
            // A newer claim on an address wins over an older one.
            table.by_addr.insert(addr, id);
            addrs.push(addr);
        }
        table.by_ip.entry(peer_ip).or_default().push(id);
        table.entries.insert(
            id,
            Entry {
                found,
                peer_ip,
                declared: !addrs.is_empty(),
                addrs,
                learned: false,
            },
        );
        Some(Registration {
            associations: self.clone(),
            id,
        })
    }

    /// The association a datagram from `src` belongs to, if any.
    pub fn find(&self, src: SocketAddr) -> Option<Found> {
        let src = canonical(src);
        let mut guard = self.lock();
        let table = &mut *guard;
        if let Some(entry) = table.by_addr.get(&src).and_then(|id| table.entries.get(id)) {
            return Some(entry.found.clone());
        }
        let ids = table.by_ip.get(&src.ip())?;
        let unlearned = |declared: bool| {
            ids.iter().find(|id| {
                table
                    .entries
                    .get(id)
                    .is_some_and(|e| !e.learned && e.declared == declared)
            })
        };
        let id = unlearned(false)
            .or_else(|| unlearned(true))
            .or(ids.last())
            .copied()?;
        let entry = table.entries.get_mut(&id)?;
        entry.learned = true;
        let found = entry.found.clone();
        if entry.addrs.len() < MAX_ADDRS {
            entry.addrs.push(src);
            table.by_addr.insert(src, id);
        }
        Some(found)
    }

    fn remove(&self, id: u64) {
        let mut guard = self.lock();
        let table = &mut *guard;
        let Some(entry) = table.entries.remove(&id) else {
            return;
        };
        for addr in &entry.addrs {
            if table.by_addr.get(addr) == Some(&id) {
                table.by_addr.remove(addr);
            }
        }
        if let Some(ids) = table.by_ip.get_mut(&entry.peer_ip) {
            ids.retain(|i| *i != id);
            if ids.is_empty() {
                table.by_ip.remove(&entry.peer_ip);
            }
        }
    }

    /// How many associations are live.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn found(user: &str) -> Found {
        Found {
            user: Some(user.into()),
        }
    }

    fn user_of(a: &Associations, src: &str) -> Option<String> {
        a.find(addr(src))
            .and_then(|f| f.user.map(|u| u.to_string()))
    }

    #[test]
    fn declared_address_is_matched_exactly() {
        let a = Arc::new(Associations::default());
        let _x = a
            .register(
                addr("10.0.0.1:4000"),
                &SocksAddr::from(addr("10.0.0.1:5000")),
                found("x"),
            )
            .unwrap();
        let _y = a
            .register(
                addr("10.0.0.1:4001"),
                &SocksAddr::from(addr("10.0.0.1:5001")),
                found("y"),
            )
            .unwrap();
        assert_eq!(user_of(&a, "10.0.0.1:5000").as_deref(), Some("x"));
        assert_eq!(user_of(&a, "10.0.0.1:5001").as_deref(), Some("y"));
        // Another host is nobody's.
        assert_eq!(user_of(&a, "10.0.0.2:5000"), None);
    }

    #[test]
    fn unspecified_address_goes_by_the_peer_ip() {
        let a = Arc::new(Associations::default());
        let x = a
            .register(addr("10.0.0.1:4000"), &SocksAddr::any(), found("x"))
            .unwrap();
        assert_eq!(user_of(&a, "10.0.0.1:6000").as_deref(), Some("x"));
        // An unspecified IP with a port is the peer's IP with that port.
        let _y = a
            .register(
                addr("10.0.0.1:4001"),
                &SocksAddr::from(addr("0.0.0.0:7000")),
                found("y"),
            )
            .unwrap();
        assert_eq!(user_of(&a, "10.0.0.1:7000").as_deref(), Some("y"));
        // The learned port stays with x.
        assert_eq!(user_of(&a, "10.0.0.1:6000").as_deref(), Some("x"));
        drop(x);
        assert_eq!(user_of(&a, "10.0.0.1:6000").as_deref(), Some("y"));
    }

    #[test]
    fn a_new_port_goes_to_the_oldest_unused_association() {
        let a = Arc::new(Associations::default());
        // z declared a port it does not send from, as some clients do.
        let _z = a
            .register(
                addr("10.0.0.1:3999"),
                &SocksAddr::from(addr("10.0.0.1:1")),
                found("z"),
            )
            .unwrap();
        let _x = a
            .register(addr("10.0.0.1:4000"), &SocksAddr::any(), found("x"))
            .unwrap();
        let _y = a
            .register(addr("10.0.0.1:4001"), &SocksAddr::any(), found("y"))
            .unwrap();
        assert_eq!(user_of(&a, "10.0.0.1:6000").as_deref(), Some("x"));
        assert_eq!(user_of(&a, "10.0.0.1:6001").as_deref(), Some("y"));
        assert_eq!(user_of(&a, "10.0.0.1:6002").as_deref(), Some("z"));
        assert_eq!(user_of(&a, "10.0.0.1:6000").as_deref(), Some("x"));
        assert_eq!(user_of(&a, "10.0.0.1:6001").as_deref(), Some("y"));
        assert_eq!(user_of(&a, "[::ffff:10.0.0.1]:6000").as_deref(), Some("x"));
        // All sent from: the newest takes a new port.
        assert_eq!(user_of(&a, "10.0.0.1:6003").as_deref(), Some("y"));
    }

    #[test]
    fn closing_takes_the_association_out() {
        let a = Arc::new(Associations::default());
        let x = a
            .register(
                addr("10.0.0.1:4000"),
                &SocksAddr::from(addr("10.0.0.1:5000")),
                found("x"),
            )
            .unwrap();
        assert!(a.find(addr("10.0.0.1:5000")).is_some());
        drop(x);
        assert!(a.find(addr("10.0.0.1:5000")).is_none());
        assert!(a.find(addr("10.0.0.1:6000")).is_none());
        let table = a.lock();
        assert!(table.by_addr.is_empty() && table.by_ip.is_empty());
    }

    #[test]
    fn the_table_is_bounded() {
        let a = Arc::new(Associations::default());
        let held: Vec<_> = (0..MAX_ASSOCIATIONS)
            .map(|_| {
                a.register(addr("10.0.0.1:4000"), &SocksAddr::any(), found("x"))
                    .unwrap()
            })
            .collect();
        assert!(a
            .register(addr("10.0.0.1:4000"), &SocksAddr::any(), found("x"))
            .is_none());
        drop(held);
        assert_eq!(a.len(), 0);
        // Learned addresses per association are bounded too.
        let _x = a
            .register(addr("10.0.0.1:4000"), &SocksAddr::any(), found("x"))
            .unwrap();
        for port in 6000..6100 {
            assert!(a
                .find(SocketAddr::new([10, 0, 0, 1].into(), port))
                .is_some());
        }
        assert_eq!(a.lock().by_addr.len(), MAX_ADDRS);
    }
}
