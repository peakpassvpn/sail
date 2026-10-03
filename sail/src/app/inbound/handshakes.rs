//! How many connections an inbound has in their handshake at once:
//! `inbound.max_handshakes`, and, when set, `inbound.max_handshakes_per_source`
//! for one address. A connection holds a place from its accept until it
//! is a session, with a place of `inbound.max_connections`, or is closed;
//! one more than the limit is closed at once, not kept waiting, so that
//! those in their handshake are not slowed by a flood of others.
//!
//! What never authenticates takes memory and a descriptor until the
//! handshake deadline, 25 to 37 KiB each in a musl build, which allocates
//! with mimalloc, and 9 to 20 with glibc's (measured): the limit keeps a flood
//! of them within a budget. sing-box has none; a sail extension.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

/// The refusals are logged at most this often, with their count since.
const WARN_EVERY: Duration = Duration::from_secs(10);

/// The handshakes of each address, when they are limited.
type Sources = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// The places of one inbound.
pub(crate) struct Handshakes {
    tag: String,
    /// None when there is no limit.
    places: Option<Arc<Semaphore>>,
    /// The most one address holds; 0, no limit.
    per_source: usize,
    sources: Sources,
    refused: AtomicUsize,
    warned: Mutex<Option<Instant>>,
}

/// A connection's place while it is in its handshake, given back when it
/// is dropped.
pub struct HandshakePlace {
    _place: Option<OwnedSemaphorePermit>,
    source: Option<(Sources, IpAddr)>,
}

impl std::fmt::Debug for HandshakePlace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HandshakePlace")
    }
}

impl Drop for HandshakePlace {
    fn drop(&mut self) {
        if let Some((sources, source)) = self.source.take() {
            let mut sources = sources.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(held) = sources.get_mut(&source) {
                *held -= 1;
                if *held == 0 {
                    sources.remove(&source);
                }
            }
        }
    }
}

impl Handshakes {
    pub(crate) fn new(tag: &str, options: &crate::runtime::options::Inbound) -> Self {
        Handshakes {
            tag: tag.to_owned(),
            places: (options.max_handshakes > 0)
                .then(|| Arc::new(Semaphore::new(options.max_handshakes))),
            per_source: options.max_handshakes_per_source,
            sources: Sources::default(),
            refused: AtomicUsize::new(0),
            warned: Mutex::new(None),
        }
    }

    /// A place for a connection from `source`, or none: it is to be closed.
    pub(crate) fn enter(&self, source: IpAddr) -> Option<HandshakePlace> {
        let place = match &self.places {
            Some(places) => match places.clone().try_acquire_owned() {
                Ok(place) => Some(place),
                Err(_) => return self.refuse("inbound.max_handshakes"),
            },
            None => None,
        };
        let source = if self.per_source > 0 {
            let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
            let held = sources.entry(source).or_insert(0);
            if *held >= self.per_source {
                drop(sources);
                return self.refuse("inbound.max_handshakes_per_source");
            }
            *held += 1;
            Some((self.sources.clone(), source))
        } else {
            None
        };
        Some(HandshakePlace {
            _place: place,
            source,
        })
    }

    fn refuse(&self, limit: &str) -> Option<HandshakePlace> {
        let refused = self.refused.fetch_add(1, Ordering::Relaxed) + 1;
        let mut warned = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        if warned.is_none_or(|at| at.elapsed() >= WARN_EVERY) {
            *warned = Some(Instant::now());
            self.refused.store(0, Ordering::Relaxed);
            warn!(
                "[{}] inbound: {} connections closed at accept: {} in their handshake already",
                self.tag, refused, limit
            );
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshakes(max: usize, per_source: usize) -> Handshakes {
        let mut options = crate::runtime::RuntimeOptions::default().inbound;
        options.max_handshakes = max;
        options.max_handshakes_per_source = per_source;
        Handshakes::new("in", &options)
    }

    #[test]
    fn one_more_than_the_limit_is_refused_until_a_place_is_given_back() {
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let limited = handshakes(2, 0);
        let first = limited.enter(a).unwrap();
        let _second = limited.enter(a).unwrap();
        assert!(limited.enter(a).is_none());
        drop(first);
        assert!(limited.enter(a).is_some());
        // No limit: every one has a place.
        let unlimited = handshakes(0, 0);
        let held: Vec<_> = (0..10_000).map(|_| unlimited.enter(a).unwrap()).collect();
        assert_eq!(held.len(), 10_000);
    }

    #[test]
    fn an_address_holds_no_more_than_its_share() {
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        let limited = handshakes(10, 2);
        let first = limited.enter(a).unwrap();
        let _second = limited.enter(a).unwrap();
        assert!(limited.enter(a).is_none(), "a third from one address");
        // Another address is not held back by it, and the place the
        // refused one took of the inbound's was given back.
        let others: Vec<_> = (0..8).map(|_| limited.enter(b)).collect();
        assert_eq!(others.iter().filter(|p| p.is_some()).count(), 2);
        drop(first);
        assert!(limited.enter(a).is_some());
        assert!(limited.sources.lock().unwrap().contains_key(&a));
        drop(others);
        assert!(!limited.sources.lock().unwrap().contains_key(&b));
    }
}
