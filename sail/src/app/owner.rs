//! Who opened a connection: the program and the user, or on Android the
//! package. Looked up only when something needs it (a rule's conditions
//! on it, or `route.find_process`), as sing-box's `needFindProcess`; once
//! a connection, and kept a few seconds by the client's socket, so that a
//! UDP flow's packets and a retried connection ask once. See
//! design-notes/connection-owner-lookup.md of the project.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::runtime::platform::ConnectionOwner;
use crate::session::Network;

/// How many sockets' owners are kept.
const CAPACITY: usize = 256;
/// How long an answer is taken, a miss too: a port another program takes
/// after it is looked up anew.
const KEPT: Duration = Duration::from_secs(5);

/// Who opened a connection, as far as it was found.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Found {
    /// The program's path.
    pub process: Option<String>,
    /// Its uid, user and packages.
    pub owner: Option<Arc<ConnectionOwner>>,
}

/// The client's socket a connection is looked up by: its network, its
/// own address, and the one it is connected to (a listener's, or through
/// a TUN its destination's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Socket {
    pub network: Network,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// The answers of the last few seconds.
pub(crate) struct Owners {
    kept: Mutex<lru::LruCache<Socket, (Instant, Found)>>,
}

impl Default for Owners {
    fn default() -> Self {
        Owners {
            kept: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(CAPACITY).expect("not zero"),
            )),
        }
    }
}

impl Owners {
    /// The answer kept for `socket`, if it is recent.
    pub(crate) fn get(&self, socket: &Socket) -> Option<Found> {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        match kept.get(socket) {
            Some((at, found)) if at.elapsed() < KEPT => Some(found.clone()),
            Some(_) => {
                kept.pop(socket);
                None
            }
            None => None,
        }
    }

    /// Keeps `found` for `socket`.
    pub(crate) fn put(&self, socket: Socket, found: Found) {
        self.kept
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(socket, (Instant::now(), found));
    }
}

/// Who opened the connection of `socket`, as this system tells sail
/// itself; none where it does not (another machine's socket, or a
/// system sail cannot ask).
pub(crate) fn find(socket: &Socket) -> Found {
    let _ = socket;
    Found::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(port: u16) -> Socket {
        Socket {
            network: Network::Tcp,
            local: SocketAddr::from(([127, 0, 0, 1], port)),
            remote: SocketAddr::from(([127, 0, 0, 1], 80)),
        }
    }

    #[test]
    fn an_answer_is_kept_by_its_socket() {
        let owners = Owners::default();
        let found = Found {
            process: Some("/usr/bin/curl".into()),
            owner: None,
        };
        assert_eq!(owners.get(&socket(1)), None);
        owners.put(socket(1), found.clone());
        assert_eq!(owners.get(&socket(1)), Some(found));
        assert_eq!(owners.get(&socket(2)), None);
        // A miss is kept too.
        owners.put(socket(2), Found::default());
        assert_eq!(owners.get(&socket(2)), Some(Found::default()));
    }

    #[test]
    fn only_the_last_ones_are_kept() {
        let owners = Owners::default();
        for port in 0..=CAPACITY as u16 {
            owners.put(socket(port), Found::default());
        }
        assert_eq!(owners.get(&socket(0)), None);
        assert!(owners.get(&socket(CAPACITY as u16)).is_some());
    }
}
