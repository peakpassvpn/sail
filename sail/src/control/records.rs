//! Connection records that are never lost, for a host that bills by them
//! (`embed::Options::connection_records_lossless`, sail#14 and sail#24).
//!
//! `Kinds::CONNECTION` is a broadcast: a subscriber that falls behind is
//! told `lagged`, and the records it missed are gone, so that no connection
//! waits for it. This sink loses no connection's end instead: its records
//! queue for one reader, and every closed record is kept, however far
//! behind the reader is. What bounds them is admission: while `cap`
//! closed records wait for the reader, a new connection is refused, and
//! counted so, until it catches up. Interim records carry a connection's
//! bytes since it started, so the next holds all one held: those of a
//! timed pass are dropped, and counted, while `cap` records wait; those of
//! a pass the host asks for are kept, as a barrier it asked for.
//!
//! Adding a record is a push under a short lock, made where records are
//! made, as a connection closes and in interim passes: the data path never
//! waits for the reader. The queue belongs to the instance, not a run: the
//! records of the connections a stop cut wait for the reader. What is not
//! read when the process ends, a crash, is lost with it.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::events::{ConnectionRecord, RecordKind};

/// Refusals while `cap` closed records wait are logged at most this often,
/// with their count since the previous warning.
pub(crate) const WARN_EVERY: Duration = Duration::from_secs(10);

/// Closed-record count at or below which an active refusal stall clears.
/// Keeping 5% headroom (at least two slots when `cap > 2`, or empty when
/// `cap <= 2`) prevents a slow reader trickling around `cap - 1 <-> cap`
/// from resetting the stall timer or logging false recoveries while the
/// queue remains saturated.
const fn recover_closed(cap: usize) -> usize {
    if cap <= 2 {
        0
    } else {
        let fifth_percent = cap / 20;
        let margin = if fifth_percent > 2 { fifth_percent } else { 2 };
        cap.saturating_sub(margin)
    }
}

/// Snapshot of an instance's lossless connection-record queue
/// (`embed::Options::connection_records_lossless`), readable without
/// holding [`RecordStream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "internal-diagnostics", derive(serde_derive::Serialize))]
#[non_exhaustive]
pub struct ConnectionRecordsInfo {
    /// Closed records kept before new connections and uncached UDP targets
    /// are refused (`1` at least).
    pub capacity: usize,
    /// Records queued now, closed and interim together.
    pub queued: usize,
    /// Closed records queued now.
    pub closed: usize,
    /// Timed interim records dropped since the sink was made while the
    /// queue held `capacity` records.
    pub dropped: u64,
    /// Admission attempts refused since the sink was made while `capacity`
    /// closed records waited.
    pub refused: u64,
    /// Whether a [`RecordStream`] currently holds the sink.
    pub has_reader: bool,
}

/// One record and the host-private binding captured for it. Keep the whole
/// envelope until durable spool handoff succeeds. Neither JSON nor the C ABI
/// serializes `context`; the record's target and outcome remain independent.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RecordEnvelope {
    pub record: Arc<ConnectionRecord>,
    pub context: Option<super::context::RecordContext>,
}

/// A lossless sink of connection records, the instance's.
pub struct LosslessRecords {
    cap: usize,
    recover_closed: usize,
    queue: Mutex<Queue>,
    /// Closed records queued: read without the lock, as each new
    /// connection asks whether it is refused, and updated under `queue`.
    closed: AtomicUsize,
    notify: tokio::sync::Notify,
    /// A reader holds it.
    taken: AtomicBool,
    log: std::sync::OnceLock<Arc<crate::app::logger::InstanceLog>>,
    #[cfg(test)]
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    #[cfg(test)]
    after_closed_enqueue: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

#[derive(Default)]
struct Queue {
    records: VecDeque<RecordEnvelope>,
    /// Interim records dropped since the sink was made.
    dropped: u64,
    /// Connections refused since the sink was made.
    refused: u64,
    /// Active saturation episode, set on the first refusal at `cap` and
    /// cleared once `take` drains `closed` to `recover_closed` or below.
    stall: Option<Stall>,
}

struct Stall {
    since: Instant,
    last_warned: Instant,
    /// Refusals in this saturation episode.
    episode_refused: u64,
    /// Refusals since `last_warned`.
    window_refused: u64,
}

struct WarnLog {
    window_refused: u64,
    total_refused: u64,
    closed: usize,
    queued: usize,
    cap: usize,
    blocked_for: Duration,
}

struct RecoverLog {
    blocked_for: Duration,
    episode_refused: u64,
    total_refused: u64,
    closed: usize,
    queued: usize,
    cap: usize,
}

impl LosslessRecords {
    /// A sink that keeps `cap` closed records (one at least) before it
    /// refuses new connections.
    pub fn new(cap: usize) -> Arc<Self> {
        let cap = cap.max(1);
        Arc::new(LosslessRecords {
            cap,
            recover_closed: recover_closed(cap),
            queue: Mutex::default(),
            closed: AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
            taken: AtomicBool::new(false),
            log: std::sync::OnceLock::new(),
            #[cfg(test)]
            clock: Box::new(Instant::now),
            #[cfg(test)]
            after_closed_enqueue: Mutex::default(),
        })
    }

    pub(crate) fn set_log(&self, log: Arc<crate::app::logger::InstanceLog>) {
        let _ = self.log.set(log);
    }

    #[cfg(test)]
    pub(crate) fn with_clock(
        cap: usize,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Arc<Self> {
        let cap = cap.max(1);
        Arc::new(LosslessRecords {
            cap,
            recover_closed: recover_closed(cap),
            queue: Mutex::default(),
            closed: AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
            taken: AtomicBool::new(false),
            log: std::sync::OnceLock::new(),
            clock: Box::new(clock),
            after_closed_enqueue: Mutex::default(),
        })
    }

    #[inline]
    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            (self.clock)()
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    #[cfg(test)]
    pub(crate) fn set_after_closed_enqueue(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self
            .after_closed_enqueue
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = hook;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes `record`: queued, unless it is `droppable` and `cap` records
    /// wait; a closed record always is. Never waits for the reader.
    #[cfg(test)]
    pub(crate) fn push(&self, record: Arc<ConnectionRecord>, droppable: bool) {
        self.push_envelope(
            RecordEnvelope {
                record,
                context: None,
            },
            droppable,
        );
    }

    pub(crate) fn push_envelope(&self, envelope: RecordEnvelope, droppable: bool) {
        let closed = matches!(envelope.record.kind, RecordKind::Closed(_));
        {
            let mut queue = self.lock();
            if !closed && droppable && queue.records.len() >= self.cap {
                queue.dropped += 1;
                return;
            }
            queue.records.push_back(envelope);
            if closed {
                self.closed.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.notify.notify_one();
        #[cfg(test)]
        if closed {
            let hook = self
                .after_closed_enqueue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(hook) = hook {
                hook();
            }
        }
    }

    /// Whether a new connection is refused: `cap` closed records wait for
    /// the reader. Counted when it is.
    pub(crate) fn refuse(&self) -> bool {
        if self.closed.load(Ordering::Relaxed) < self.cap {
            return false;
        }
        let warn = {
            let mut queue = self.lock();
            let closed = self.closed.load(Ordering::Relaxed);
            if closed < self.cap {
                return false;
            }
            queue.refused += 1;
            let total_refused = queue.refused;
            let queued = queue.records.len();
            let now = self.now();
            match &mut queue.stall {
                None => {
                    queue.stall = Some(Stall {
                        since: now,
                        last_warned: now,
                        episode_refused: 1,
                        window_refused: 0,
                    });
                    Some(WarnLog {
                        window_refused: 1,
                        total_refused,
                        closed,
                        queued,
                        cap: self.cap,
                        blocked_for: Duration::ZERO,
                    })
                }
                Some(stall) => {
                    stall.episode_refused += 1;
                    stall.window_refused += 1;
                    if now.saturating_duration_since(stall.last_warned) >= WARN_EVERY {
                        let window_refused = std::mem::take(&mut stall.window_refused);
                        stall.last_warned = now;
                        Some(WarnLog {
                            window_refused,
                            total_refused,
                            closed,
                            queued,
                            cap: self.cap,
                            blocked_for: now.saturating_duration_since(stall.since),
                        })
                    } else {
                        None
                    }
                }
            }
        };
        if let Some(warn) = warn {
            tracing::warn!(
                "connection records: {} connection(s) refused ({} total): {} closed records wait ({} queued, cap {}), stalled {:.1}s",
                warn.window_refused,
                warn.total_refused,
                warn.closed,
                warn.queued,
                warn.cap,
                warn.blocked_for.as_secs_f64(),
            );
        }
        true
    }

    /// The next record; none now.
    fn take(&self) -> Option<RecordEnvelope> {
        let (record, recovered) = {
            let mut queue = self.lock();
            let record = queue.records.pop_front()?;
            let recovered = if matches!(record.record.kind, RecordKind::Closed(_)) {
                let closed = self.closed.fetch_sub(1, Ordering::Relaxed) - 1;
                if closed <= self.recover_closed {
                    queue.stall.take().map(|stall| RecoverLog {
                        blocked_for: self.now().saturating_duration_since(stall.since),
                        episode_refused: stall.episode_refused,
                        total_refused: queue.refused,
                        closed,
                        queued: queue.records.len(),
                        cap: self.cap,
                    })
                } else {
                    None
                }
            } else {
                None
            };
            (record, recovered)
        };
        if let Some(recovered) = recovered {
            let _scope = self
                .log
                .get()
                .map(|log| crate::app::logger::enter(Some(log.clone())));
            tracing::info!(
                "connection records: backlog cleared after {:.1}s: {} refused in stall ({} total), {} queued ({} closed, cap {})",
                recovered.blocked_for.as_secs_f64(),
                recovered.episode_refused,
                recovered.total_refused,
                recovered.queued,
                recovered.closed,
                recovered.cap,
            );
        }
        Some(record)
    }

    /// Read-only snapshot of the queue and its counters, without taking
    /// [`RecordStream`].
    pub fn info(&self) -> ConnectionRecordsInfo {
        let has_reader = self.taken.load(Ordering::Acquire);
        let queue = self.lock();
        ConnectionRecordsInfo {
            capacity: self.cap,
            queued: queue.records.len(),
            closed: self.closed.load(Ordering::Relaxed),
            dropped: queue.dropped,
            refused: queue.refused,
            has_reader,
        }
    }

    /// The reader, unless one holds it already.
    pub fn reader(self: &Arc<Self>) -> Option<RecordStream> {
        (!self.taken.swap(true, Ordering::AcqRel)).then(|| RecordStream(self.clone()))
    }
}

/// The reader of a lossless sink: one at a time; dropped, another may be
/// taken, and nothing is lost in between.
pub struct RecordStream(Arc<LosslessRecords>);

impl RecordStream {
    /// The next record, waiting for one.
    pub async fn next(&mut self) -> Arc<ConnectionRecord> {
        self.next_envelope().await.record
    }

    /// The next record with its owned, frozen host context. Retain it on
    /// persistence failure; dropping it releases this reader's reference.
    pub async fn next_envelope(&mut self) -> RecordEnvelope {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(record) = self.0.take() {
                return record;
            }
            notified.await;
        }
    }

    /// The next record if there is one now: to drain what is left, as
    /// after a stop.
    pub fn try_next(&mut self) -> Option<Arc<ConnectionRecord>> {
        self.0.take().map(|envelope| envelope.record)
    }

    /// The next envelope, without waiting. Empty is not a family drain.
    pub fn try_next_envelope(&mut self) -> Option<RecordEnvelope> {
        self.0.take()
    }

    /// Closed records kept before new connections and uncached UDP targets
    /// are refused (`1` at least).
    pub fn capacity(&self) -> usize {
        self.0.cap
    }

    /// Records queued now.
    pub fn queued(&self) -> usize {
        self.0.lock().records.len()
    }

    /// Closed records queued now.
    pub fn closed(&self) -> usize {
        self.0.closed.load(Ordering::Relaxed)
    }

    /// Interim records dropped since the sink was made, the queue full:
    /// each connection's next record holds what they did.
    pub fn dropped(&self) -> u64 {
        self.0.lock().dropped
    }

    /// Admission attempts refused since the sink was made, its closed
    /// records at the cap: new connections and uncached UDP targets.
    /// The host's admission hook has not run for these attempts.
    pub fn refused(&self) -> u64 {
        self.0.lock().refused
    }
}

impl Drop for RecordStream {
    fn drop(&mut self) {
        self.0.taken.store(false, Ordering::Release);
    }
}

impl std::fmt::Debug for RecordStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordStream")
    }
}

#[cfg(test)]
mod tests;
