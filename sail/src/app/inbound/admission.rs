//! Admission under memory pressure: what an instance does with connections
//! that have not authenticated yet when memory, or descriptors, run short
//! (`inbound.memory_reserve`, sail#15). The fixed counts
//! (`inbound.max_handshakes`) bound a flood by number; a small host can run
//! out of memory before them, under a burst of handshakes or many slow
//! ones.
//!
//! A connection is unauthenticated while it holds a handshake place, from
//! its accept until it is a session (handshakes.rs). Under pressure, as a
//! connection is accepted:
//! - the handshakes in flight longer than `inbound.handshake_stall` are
//!   closed, oldest first: what a slow client holds goes to those that
//!   handshake promptly, where refusing new ones alone would leave the
//!   flood holding everything;
//! - with `inbound.score_sources`, a source whose recent handshakes mostly
//!   failed is refused;
//! - under hard pressure, less than half the reserve free, every new one
//!   is refused.
//!
//! Sessions, the connections that authenticated, are never touched.
//!
//! Pressure is read when a connection is accepted, at most every
//! `READ_EVERY`, as the QUIC window budget reads it: an idle instance never
//! wakes for it. A sing-box based server in production, whose admission this follows, holds
//! a 20% reserve, evicts handshakes stalled 3 s and refuses sources with
//! more failures than successes; sing-box itself has none of this.

use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::control::events::{AdmissionChange, AdmissionLevel, EventHub};

/// How often the memory is read, at most (a judgment: a flood fills memory
/// over seconds; a read is one small file, two with a cgroup).
const READ_EVERY: Duration = Duration::from_millis(250);

/// Pressure ends once this much more than the reserve is free, in
/// hundredths of the reserve, so that it does not flap on its edge (a
/// judgment).
const HYSTERESIS: u64 = 5;

/// A source is judged on its handshakes of this long (a judgment).
const SCORE_WINDOW: Duration = Duration::from_secs(60);

/// A source is judged once it made this many handshakes in the window
/// (a judgment: a client that mistyped its password a few times is not
/// refused for it).
const SCORE_MIN: u32 = 4;

/// The sources judged at once, at most (a judgment): a flood from spread
/// addresses costs no more than this.
const SCORE_SOURCES: usize = 4096;

/// The refusals are logged at most this often, with their count since.
const WARN_EVERY: Duration = Duration::from_secs(10);

/// Why a connection was refused at accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Hard pressure: every new one is.
    Hard,
    /// Its source's handshakes mostly failed.
    Source,
}

/// What the instance's admission did, since it started.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmissionInfo {
    pub level: AdmissionLevel,
    /// The memory free as last read, and the reserve, in bytes.
    pub free: Option<u64>,
    pub reserve: u64,
    /// Connections in their handshake now.
    pub handshakes: usize,
    /// Refused at accept under hard pressure.
    pub refused: u64,
    /// Refused at accept for their source's failures.
    pub refused_sources: u64,
    /// Closed in their handshake, stalled under pressure.
    pub evicted: u64,
    /// How long the instance was under pressure, hard pressure included.
    pub pressure: Duration,
}

/// The handshakes of an instance, and how hard it holds back new ones.
pub(crate) struct Admission {
    /// Bytes kept free; 0, memory is not looked at.
    reserve: u64,
    /// More handshakes than this are pressure; 0, no such bound.
    descriptors: usize,
    stall: Duration,
    score: bool,
    free: Box<dyn Fn() -> Option<u64> + Send + Sync>,
    /// How often the memory is read, at most: `READ_EVERY`.
    read_every: Duration,
    start: Instant,
    /// When to read the memory again, and to look for stalled handshakes,
    /// in milliseconds from `start`.
    next: AtomicU64,
    level: AtomicU8,
    free_read: AtomicU64,
    handshakes: Mutex<InFlight>,
    in_flight: AtomicUsize,
    sources: Mutex<HashMap<IpAddr, Score>>,
    refused: AtomicU64,
    refused_sources: AtomicU64,
    evicted: AtomicU64,
    /// When pressure began, and what earlier pressure lasted.
    pressure: Mutex<(Option<Instant>, Duration)>,
    unwarned: AtomicU64,
    warned: Mutex<Option<Instant>>,
    events: EventHub,
}

#[derive(Default)]
struct InFlight {
    next_id: u64,
    entries: HashMap<u64, Arc<Entry>>,
}

/// One handshake in flight.
struct Entry {
    started: Instant,
    /// It authenticated: it is no longer evicted.
    done: AtomicBool,
    evicted: AtomicBool,
    notify: tokio::sync::Notify,
}

/// A source's handshakes in the window.
struct Score {
    since: Instant,
    ok: u32,
    failed: u32,
}

impl Score {
    fn failing(&self) -> bool {
        self.ok + self.failed >= SCORE_MIN && self.failed > self.ok
    }
}

const NORMAL: u8 = 0;
const PRESSURE: u8 = 1;
const HARD: u8 = 2;

fn level_of(code: u8) -> AdmissionLevel {
    match code {
        NORMAL => AdmissionLevel::Normal,
        PRESSURE => AdmissionLevel::Pressure,
        _ => AdmissionLevel::Hard,
    }
}

impl Admission {
    /// The admission `options` set, telling its changes to `events`; none
    /// when neither memory nor descriptors are looked at.
    pub(crate) fn new(
        options: &crate::runtime::options::Inbound,
        events: EventHub,
    ) -> Option<Arc<Self>> {
        let total = crate::runtime::system_memory::total();
        let reserve = total.map_or(0, |total| total / 100 * u64::from(options.memory_reserve));
        let descriptors = match options.handshake_descriptor_share {
            0 => 0,
            share => file_limit() / share as usize,
        };
        if reserve == 0 && descriptors == 0 {
            return None;
        }
        let free = crate::runtime::system_memory::Free::new();
        Some(Arc::new(Self::with(
            reserve,
            descriptors,
            options.handshake_stall,
            options.score_sources,
            Box::new(move || free.bytes()),
            READ_EVERY,
            events,
        )))
    }

    fn with(
        reserve: u64,
        descriptors: usize,
        stall: Duration,
        score: bool,
        free: Box<dyn Fn() -> Option<u64> + Send + Sync>,
        read_every: Duration,
        events: EventHub,
    ) -> Self {
        Admission {
            reserve,
            descriptors,
            stall,
            score,
            free,
            read_every,
            start: Instant::now(),
            next: AtomicU64::new(0),
            level: AtomicU8::new(NORMAL),
            free_read: AtomicU64::new(u64::MAX),
            handshakes: Mutex::default(),
            in_flight: AtomicUsize::new(0),
            sources: Mutex::default(),
            refused: AtomicU64::new(0),
            refused_sources: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            pressure: Mutex::default(),
            unwarned: AtomicU64::new(0),
            warned: Mutex::default(),
            events,
        }
    }

    /// Whether a connection from `source` is taken in, as it is accepted:
    /// under pressure, the stalled handshakes are closed first.
    pub(crate) fn check(&self, source: IpAddr) -> Result<(), Refusal> {
        let level = self.update();
        if level == NORMAL {
            return Ok(());
        }
        if level == HARD {
            self.refused.fetch_add(1, Ordering::Relaxed);
            self.warn("hard memory pressure");
            return Err(Refusal::Hard);
        }
        if self.score && self.failing(source) {
            self.refused_sources.fetch_add(1, Ordering::Relaxed);
            self.warn("its source's handshakes mostly failed, under memory pressure");
            return Err(Refusal::Source);
        }
        Ok(())
    }

    /// A handshake of a connection from `source` that was taken in, in
    /// flight until the ticket is told it authenticated or is dropped.
    pub(crate) fn enter(self: &Arc<Self>, source: IpAddr) -> Ticket {
        let entry = Arc::new(Entry {
            started: Instant::now(),
            done: AtomicBool::new(false),
            evicted: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        let id = {
            let mut handshakes = self.handshakes.lock().unwrap_or_else(|e| e.into_inner());
            let id = handshakes.next_id;
            handshakes.next_id += 1;
            handshakes.entries.insert(id, entry.clone());
            id
        };
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        Ticket {
            admission: self.clone(),
            entry,
            id,
            source,
            ended: false,
        }
    }

    /// The level now, read again if it was read more than `READ_EVERY`
    /// ago; then, under pressure, the stalled handshakes closed.
    fn update(&self) -> u8 {
        let now = self.start.elapsed().as_millis() as u64;
        let next = self.next.load(Ordering::Relaxed);
        if now < next
            || self
                .next
                .compare_exchange(
                    next,
                    now + self.read_every.as_millis() as u64,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return self.level.load(Ordering::Relaxed);
        }
        let free = (self.reserve > 0).then(|| (self.free)()).flatten();
        self.free_read
            .store(free.unwrap_or(u64::MAX), Ordering::Relaxed);
        let was = self.level.load(Ordering::Relaxed);
        let mut level = match free {
            Some(free) if free < self.reserve / 2 => HARD,
            Some(free) if free < self.reserve => PRESSURE,
            // Still short of the reserve and its margin: pressure goes on.
            Some(free) if was != NORMAL && free < self.reserve / 100 * (100 + HYSTERESIS) => {
                PRESSURE
            }
            _ => NORMAL,
        };
        if self.descriptors > 0 && self.in_flight.load(Ordering::Relaxed) > self.descriptors {
            level = level.max(PRESSURE);
        }
        if level != was {
            self.level.store(level, Ordering::Relaxed);
            self.changed(was, level, free);
        }
        if level != NORMAL {
            self.evict();
        }
        level
    }

    /// Tells and logs a change of level, and keeps how long pressure
    /// lasted.
    fn changed(&self, was: u8, level: u8, free: Option<u64>) {
        let handshakes = self.in_flight.load(Ordering::Relaxed);
        {
            let mut pressure = self.pressure.lock().unwrap_or_else(|e| e.into_inner());
            match (was == NORMAL, level == NORMAL) {
                (true, false) => pressure.0 = Some(Instant::now()),
                (false, true) => {
                    if let Some(since) = pressure.0.take() {
                        pressure.1 += since.elapsed();
                    }
                }
                _ => {}
            }
        }
        let mib = |bytes: u64| bytes >> 20;
        let free_text = free.map_or("unknown".to_string(), |free| format!("{} MiB", mib(free)));
        match level {
            NORMAL => info!(
                "admission: memory pressure over: {} free (reserve {} MiB), {} handshakes",
                free_text,
                mib(self.reserve),
                handshakes
            ),
            _ => warn!(
                "admission: {}: {} free (reserve {} MiB), {} handshakes: stalled ones are \
                 closed{}",
                match level {
                    PRESSURE => "memory pressure",
                    _ => "hard memory pressure",
                },
                free_text,
                mib(self.reserve),
                handshakes,
                match level {
                    PRESSURE if self.score => ", failing sources refused",
                    PRESSURE => "",
                    _ => ", new connections refused",
                }
            ),
        }
        self.events.admission_changed(AdmissionChange {
            level: level_of(level),
            free,
            reserve: self.reserve,
            handshakes,
        });
    }

    /// Closes the handshakes in flight longer than the stall, oldest first.
    fn evict(&self) {
        let mut stalled: Vec<Arc<Entry>> = self
            .handshakes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .values()
            .filter(|e| e.started.elapsed() >= self.stall && !e.done.load(Ordering::Relaxed))
            .cloned()
            .collect();
        stalled.sort_by_key(|e| e.started);
        for entry in stalled {
            if !entry.evicted.swap(true, Ordering::Relaxed) {
                self.evicted.fetch_add(1, Ordering::Relaxed);
                entry.notify.notify_waiters();
            }
        }
    }

    /// Whether `source`'s handshakes in the window mostly failed.
    fn failing(&self, source: IpAddr) -> bool {
        let sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        sources
            .get(&source)
            .is_some_and(|s| s.since.elapsed() < SCORE_WINDOW && s.failing())
    }

    /// Counts a handshake of `source` that authenticated, or failed.
    fn scored(&self, source: IpAddr, ok: bool) {
        if !self.score {
            return;
        }
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        if sources.len() >= SCORE_SOURCES && !sources.contains_key(&source) {
            sources.retain(|_, s| s.since.elapsed() < SCORE_WINDOW);
            if sources.len() >= SCORE_SOURCES {
                return;
            }
        }
        let score = sources.entry(source).or_insert_with(|| Score {
            since: Instant::now(),
            ok: 0,
            failed: 0,
        });
        if score.since.elapsed() >= SCORE_WINDOW {
            *score = Score {
                since: Instant::now(),
                ok: 0,
                failed: 0,
            };
        }
        match ok {
            true => score.ok += 1,
            false => score.failed += 1,
        }
    }

    fn warn(&self, why: &str) {
        let refused = self.unwarned.fetch_add(1, Ordering::Relaxed) + 1;
        let mut warned = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        if warned.is_none_or(|at| at.elapsed() >= WARN_EVERY) {
            *warned = Some(Instant::now());
            self.unwarned.store(0, Ordering::Relaxed);
            warn!(
                "admission: {} connections closed at accept: {}",
                refused, why
            );
        }
    }

    /// What it did, since it started.
    pub(crate) fn info(&self) -> AdmissionInfo {
        let free = self.free_read.load(Ordering::Relaxed);
        let pressure = {
            let pressure = self.pressure.lock().unwrap_or_else(|e| e.into_inner());
            pressure.1 + pressure.0.map_or(Duration::ZERO, |since| since.elapsed())
        };
        AdmissionInfo {
            level: level_of(self.level.load(Ordering::Relaxed)),
            free: (free != u64::MAX).then_some(free),
            reserve: self.reserve,
            handshakes: self.in_flight.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            refused_sources: self.refused_sources.load(Ordering::Relaxed),
            evicted: self.evicted.load(Ordering::Relaxed),
            pressure,
        }
    }
}

/// A handshake in flight: it fails unless told it authenticated before
/// it is dropped.
pub(crate) struct Ticket {
    admission: Arc<Admission>,
    entry: Arc<Entry>,
    id: u64,
    source: IpAddr,
    ended: bool,
}

impl Ticket {
    /// It authenticated: it is a session from now on, never evicted, and
    /// its source is counted as one that succeeded.
    pub(crate) fn succeeded(&mut self) {
        if !self.ended {
            self.ended = true;
            self.entry.done.store(true, Ordering::Relaxed);
            self.end();
            self.admission.scored(self.source, true);
        }
    }

    /// Ready once it is evicted, before it authenticated; never otherwise.
    pub(crate) fn eviction(&self) -> Eviction {
        Eviction(self.entry.clone())
    }

    fn end(&self) {
        self.admission
            .handshakes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .remove(&self.id);
        self.admission.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.ended {
            self.end();
            self.admission.scored(self.source, false);
        }
    }
}

/// A handshake's eviction, waited for beside its connection.
pub(crate) struct Eviction(Arc<Entry>);

impl Eviction {
    pub(crate) async fn evicted(self) {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0.evicted.load(Ordering::Relaxed) && !self.0.done.load(Ordering::Relaxed) {
                return;
            }
            notified.await;
        }
    }
}

/// The open-file limit the process runs with; none known, as if unlimited.
fn file_limit() -> usize {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes the struct it is given, nothing else.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            return usize::try_from(limit.rlim_cur).unwrap_or(usize::MAX);
        }
    }
    usize::MAX
}

#[cfg(test)]
mod tests;
