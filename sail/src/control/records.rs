//! Connection records that are never lost, for a host that bills by them
//! (`embed::Options::connection_records_lossless`, sail#14's R1-e).
//!
//! `Kinds::CONNECTION` is a broadcast: a subscriber that falls behind is
//! told `lagged`, and the records it missed are gone, so that no connection
//! waits for it. This sink keeps that rule and loses no byte instead: the
//! records queue for one reader, up to a cap the host sets; past it, a
//! record is not queued but folded into a summary of its user, inbound and
//! outbound, which counts its bytes and that it was folded. Once the reader
//! has taken every record queued, it is given the summaries. The records
//! and the summaries it reads add up to every byte the connections were
//! counted; only the detail of the folded records is lost.
//!
//! Adding a record is a push under a short lock, made where records are
//! made, as a connection closes and in interim passes: the data path never
//! waits for the reader. The queue belongs to the instance, not a run: the
//! records of the connections a stop cut wait for the reader. What is not
//! read when the process ends, a crash, is lost with it.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use super::events::ConnectionRecord;

/// What the reader of a lossless sink is given.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Record {
    /// A connection's record, as `Kinds::CONNECTION` tells it.
    Connection(Arc<ConnectionRecord>),
    /// The records folded while the queue was full, of one user, inbound
    /// and outbound together.
    Folded(RecordSummary),
}

/// What records folded together counted: their bytes, and how many they
/// were, of one user, inbound and outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordSummary {
    pub user: Option<String>,
    pub inbound: String,
    /// The outbound that carried them, the last of their chain; empty for
    /// none.
    pub outbound: String,
    /// The `up` and `down` of the records folded, added up.
    pub up: u64,
    pub down: u64,
    /// How many records were folded, and how many of them were closed
    /// records: the connections that ended.
    pub records: u64,
    pub closed: u64,
    /// The earliest `since` and the latest `at` of the records folded.
    pub since: SystemTime,
    pub at: SystemTime,
}

type Key = (Option<String>, String, String);

/// A lossless sink of connection records, the instance's.
pub struct LosslessRecords {
    cap: usize,
    queue: Mutex<Queue>,
    notify: tokio::sync::Notify,
    /// A reader holds it.
    taken: AtomicBool,
}

#[derive(Default)]
struct Queue {
    records: VecDeque<Arc<ConnectionRecord>>,
    folded: HashMap<Key, RecordSummary>,
    /// Records folded since the sink was made.
    folded_total: u64,
}

impl LosslessRecords {
    /// A sink that queues `cap` records at most (one at least) before it
    /// folds them.
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(LosslessRecords {
            cap: cap.max(1),
            queue: Mutex::default(),
            notify: tokio::sync::Notify::new(),
            taken: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes `record`: queued, or folded when the queue is full. Never
    /// waits for the reader.
    pub(crate) fn push(&self, record: Arc<ConnectionRecord>) {
        {
            let mut queue = self.lock();
            if queue.records.len() < self.cap {
                queue.records.push_back(record);
            } else {
                queue.folded_total += 1;
                let key = (
                    record.user.clone(),
                    record.inbound.clone(),
                    record.chain.last().cloned().unwrap_or_default(),
                );
                let closed = matches!(record.kind, super::events::RecordKind::Closed(_));
                let summary = queue
                    .folded
                    .entry(key)
                    .or_insert_with_key(|key| RecordSummary {
                        user: key.0.clone(),
                        inbound: key.1.clone(),
                        outbound: key.2.clone(),
                        up: 0,
                        down: 0,
                        records: 0,
                        closed: 0,
                        since: record.since,
                        at: record.at,
                    });
                summary.up += record.up;
                summary.down += record.down;
                summary.records += 1;
                summary.closed += u64::from(closed);
                summary.since = summary.since.min(record.since);
                summary.at = summary.at.max(record.at);
            }
        }
        self.notify.notify_one();
    }

    /// The next record, or summary once the queue is empty; none now.
    fn take(&self) -> Option<Record> {
        let mut queue = self.lock();
        if let Some(record) = queue.records.pop_front() {
            return Some(Record::Connection(record));
        }
        let key = queue.folded.keys().next().cloned()?;
        queue.folded.remove(&key).map(Record::Folded)
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
    pub async fn next(&mut self) -> Record {
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
    pub fn try_next(&mut self) -> Option<Record> {
        self.0.take()
    }

    /// Records queued now.
    pub fn queued(&self) -> usize {
        self.0.lock().records.len()
    }

    /// Records folded since the sink was made.
    pub fn folded_total(&self) -> u64 {
        self.0.lock().folded_total
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
