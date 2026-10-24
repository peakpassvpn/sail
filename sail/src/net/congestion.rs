//! The congestion control of sail's own TCP sockets, `relay.tcp_congestion`:
//! the connections outbounds dial and those inbounds accept, where the
//! kernel's TCP carries the proxied bytes. Linux and Android only, the
//! systems that choose it a socket (`TCP_CONGESTION`); elsewhere the system
//! chooses, and the option does nothing.
//!
//! A system may refuse one: one not built or loaded (ENOENT), or, for a
//! process without `CAP_NET_ADMIN` such as an Android app, one not in
//! `net.ipv4.tcp_allowed_congestion_control` (EPERM). The socket then keeps
//! the system's, and the connection goes ahead; the first outcome is kept
//! for the process, so a refused one is not asked for again, and said once
//! with what the sockets use instead. TCP Brutal, which a multiplexed
//! connection may negotiate later (`transport::mux::brutal`), replaces it
//! on that connection's socket.

// What only Linux and Android set.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(dead_code, unused_imports)
)]

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use socket2::SockRef;
use tracing::{debug, info};

const UNKNOWN: u8 = 0;
const APPLIED: u8 = 1;
const REFUSED: u8 = 2;

/// A congestion control to set on sockets, or none: the system's.
#[derive(Debug, Clone, Default)]
pub struct Congestion(Option<Arc<Choice>>);

#[derive(Debug)]
struct Choice {
    name: Box<str>,
    /// What setting it has done so far, `UNKNOWN`, `APPLIED` or `REFUSED`:
    /// the process's, one to each name.
    outcome: AtomicU8,
}

/// The choices made so far, by name: few, as each instance makes one.
static CHOICES: Mutex<Vec<Arc<Choice>>> = Mutex::new(Vec::new());

impl Congestion {
    /// `name`, as the kernel names it (`bbr`, `cubic`); none if empty.
    pub fn new(name: &str) -> Congestion {
        if name.is_empty() {
            return Congestion(None);
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        debug!(
            "relay.tcp_congestion {}: this system chooses a socket's congestion control itself",
            name
        );
        let mut choices = CHOICES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(choice) = choices.iter().find(|c| *c.name == *name) {
            return Congestion(Some(choice.clone()));
        }
        let choice = Arc::new(Choice {
            name: name.into(),
            outcome: AtomicU8::new(UNKNOWN),
        });
        choices.push(choice.clone());
        Congestion(Some(choice))
    }

    /// Sets it on `socket`, a TCP socket not yet connected or listening,
    /// unless the system has refused it before. Never fails: a refused one
    /// leaves the socket with the system's.
    pub fn apply(&self, socket: SockRef<'_>) {
        let Some(choice) = &self.0 else {
            return;
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let outcome = choice.outcome.load(Ordering::Relaxed);
            if outcome == REFUSED {
                return;
            }
            let set = socket.set_tcp_congestion(choice.name.as_bytes());
            if outcome == APPLIED {
                if let Err(e) = set {
                    debug!("relay.tcp_congestion {}: {}", choice.name, e);
                }
                return;
            }
            let now = match set {
                Ok(()) => APPLIED,
                Err(_) => REFUSED,
            };
            if choice
                .outcome
                .compare_exchange(UNKNOWN, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let used = in_use(&socket);
                match set {
                    Ok(()) => info!("TCP congestion control: {}", used),
                    Err(e) => info!(
                        "TCP congestion control: relay.tcp_congestion {} refused ({}), using {}",
                        choice.name, e, used
                    ),
                }
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = (choice, socket);
    }
}

/// The congestion control `socket` has, as the kernel names it.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn in_use(socket: &SockRef<'_>) -> String {
    match socket.tcp_congestion() {
        Ok(name) => {
            let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
            String::from_utf8_lossy(&name[..end]).into_owned()
        }
        Err(e) => format!("the system's ({})", e),
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;

    fn tcp() -> socket2::Socket {
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap()
    }

    fn named(socket: &socket2::Socket) -> String {
        in_use(&SockRef::from(socket))
    }

    /// reno is always built in and always allowed.
    #[test]
    fn it_is_set_on_a_socket() {
        let congestion = Congestion::new("reno");
        let socket = tcp();
        congestion.apply(SockRef::from(&socket));
        assert_eq!(named(&socket), "reno");
        assert_eq!(
            congestion.0.unwrap().outcome.load(Ordering::Relaxed),
            APPLIED
        );
    }

    #[test]
    fn a_refused_one_leaves_the_systems_and_is_not_asked_again() {
        let system = named(&tcp());
        let congestion = Congestion::new("no-such-cc");
        for _ in 0..2 {
            let socket = tcp();
            congestion.apply(SockRef::from(&socket));
            assert_eq!(named(&socket), system);
        }
        assert_eq!(
            congestion
                .0
                .as_ref()
                .unwrap()
                .outcome
                .load(Ordering::Relaxed),
            REFUSED
        );
        assert!(Arc::ptr_eq(
            congestion.0.as_ref().unwrap(),
            Congestion::new("no-such-cc").0.as_ref().unwrap()
        ));
    }

    #[test]
    fn none_leaves_the_systems() {
        let system = named(&tcp());
        let socket = tcp();
        Congestion::new("").apply(SockRef::from(&socket));
        assert_eq!(named(&socket), system);
    }
}
