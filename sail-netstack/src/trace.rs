use std::collections::VecDeque;

use crate::buffer::PressureLevel;

/// Hard ceiling for opt-in diagnostic events retained by one runner.
pub const MAX_DEBUG_TRACE_EVENTS: usize = 4_096;

/// A compact diagnostic event emitted by a shard runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceKind {
    RunnerStarted,
    RxBatch {
        packets: usize,
    },
    TxBatch {
        packets: usize,
    },
    PartialSend {
        sent: usize,
        pending: usize,
    },
    SchedulerRound {
        packets: usize,
        bytes: usize,
    },
    PacketsDropped {
        count: usize,
    },
    PressureChanged {
        from: PressureLevel,
        to: PressureLevel,
    },
    ShutdownRequested {
        deadline_ms: u64,
    },
    Aborted,
    NetworkReset {
        generation: u64,
    },
    MtuChanged {
        mtu: usize,
    },
    RunnerClosed,
    RunnerFailed,
}

/// One ordered entry from the runner's bounded diagnostic ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceEvent {
    pub sequence: u64,
    pub now_ms: u64,
    pub kind: TraceKind,
}

/// Copy-out view of the diagnostic ring.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TraceSnapshot {
    pub events: Vec<TraceEvent>,
    pub overwritten_events: u64,
}

/// Opt-in, allocation-bounded diagnostic history. Capacity zero disables it.
#[derive(Debug)]
pub(crate) struct DebugTrace {
    capacity: usize,
    events: VecDeque<TraceEvent>,
    next_sequence: u64,
    overwritten_events: u64,
}

impl DebugTrace {
    pub(crate) fn new(capacity: usize) -> Self {
        debug_assert!(capacity <= MAX_DEBUG_TRACE_EVENTS);
        Self {
            capacity,
            events: VecDeque::new(),
            next_sequence: 0,
            overwritten_events: 0,
        }
    }

    pub(crate) fn record(&mut self, now_ms: u64, kind: TraceKind) {
        if self.capacity == 0 {
            return;
        }
        if self.events.len() == self.capacity {
            self.events.pop_front();
            self.overwritten_events = self.overwritten_events.saturating_add(1);
        }
        self.events.push_back(TraceEvent {
            sequence: self.next_sequence,
            now_ms,
            kind,
        });
        self.next_sequence = self.next_sequence.wrapping_add(1);
    }

    pub(crate) fn snapshot(&self) -> TraceSnapshot {
        TraceSnapshot {
            events: self.events.iter().copied().collect(),
            overwritten_events: self.overwritten_events,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.events.clear();
        self.overwritten_events = 0;
    }
}
