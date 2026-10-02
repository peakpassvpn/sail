//! Counters of the sessions of every protocol on the core, for all
//! instances of the process: how many are open, their streams, and the
//! streams reset for stalling.

use portable_atomic::AtomicU64;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde_derive::Serialize;

/// One protocol's counters.
#[derive(Default)]
pub struct Counters {
    sessions: AtomicU64,
    streams: AtomicU64,
    stalls: AtomicU64,
    refused: AtomicU64,
}

impl Counters {
    pub(super) fn session_opened(&self) {
        self.sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn session_closed(&self) {
        self.sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn stream_opened(&self) {
        self.streams.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn stream_closed(&self) {
        self.streams.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn stalled(&self) {
        self.stalls.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            sessions: self.sessions.load(Ordering::Relaxed),
            streams: self.streams.load(Ordering::Relaxed),
            stalls: self.stalls.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
        }
    }
}

/// One protocol's counters as they stand.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// Sessions open.
    pub sessions: u64,
    /// Streams open, across those sessions.
    pub streams: u64,
    /// Streams reset since start because nothing read their data.
    pub stalls: u64,
    /// Streams the peer opened and this end turned away, since start.
    pub refused: u64,
}

static COUNTERS: Mutex<BTreeMap<&'static str, Arc<Counters>>> = Mutex::new(BTreeMap::new());

/// The counters of `protocol`.
pub(super) fn counters(protocol: &'static str) -> Arc<Counters> {
    let mut all = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    all.entry(protocol).or_default().clone()
}

/// Every protocol's counters, by name, for those that have had a session.
pub fn snapshot() -> BTreeMap<&'static str, Snapshot> {
    let all = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    all.iter().map(|(name, c)| (*name, c.snapshot())).collect()
}
