//! Observation-only counters for an explicitly enabled diagnostic build.

use portable_atomic::{AtomicU64, Ordering};
use serde_derive::Serialize;
use std::sync::Arc;

/// Independent atomic reads, not a transactional accounting identity.
/// None means the existing pool is absent or the metric is not observed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AdmissionDiagnostics {
    pub limit: usize,
    pub live: Option<usize>,
    /// The core's waiting-budget counter, including its baseline's bugs.
    pub waiting: Option<usize>,
    pub waiting_limit: Option<usize>,
    /// Permit grants, not completed connections or datagrams.
    pub admitted_total: Option<u64>,
    /// Refusal decisions, independent of the resettable warning window.
    pub refused_total: Option<u64>,
    /// Only the admission wait's own Tokio timeout; a subset of refusals.
    pub wait_timeout_total: Option<u64>,
    /// A polled queued future dropped before a terminal outcome. This
    /// includes outer timeout/shutdown/select cancellation, not user intent.
    pub wait_cancelled_total: Option<u64>,
    /// Caller intent is not observable at this layer.
    pub active_cancel_total: Option<u64>,
    /// Returned Places only, classified by their dispatcher caller. None
    /// without a limited pool; Unknown is a real unclassified grant.
    pub permit_classes: Option<PermitClasses>,
}

/// The currently running instance's dispatcher incarnation only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct InternalDiagnostics {
    #[cfg(feature = "internal-udp-target-diagnostics")]
    pub udp_target: crate::app::udp_target_diagnostics::Snapshot,
    pub schema_version: u32,
    pub instance_id: crate::RuntimeId,
    pub epoch: u64,
    pub sessions: AdmissionDiagnostics,
    /// Only terminal NAT uplink send errors and their current-entry cleanup.
    /// Not all UDP errors/cleanup, wire loss, or confirmation of permit drop.
    pub udp_send_terminal: UdpSendTerminalDiagnostics,
    /// Not inferred from application connections or accepted totals.
    pub dot_live_carriers: Option<usize>,
    pub dot_active_queries: Option<usize>,
}

pub(crate) fn next_epoch() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[derive(Default)]
pub(super) struct Counters {
    admitted: AtomicU64,
    refused: AtomicU64,
    timeout: AtomicU64,
    cancelled: AtomicU64,
    permit_classes: [PermitCounters; 3],
}

impl Counters {
    pub(super) fn admitted(&self) {
        self.admitted.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn timed_out(&self) {
        self.timeout.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(
        &self,
        limit: usize,
        live: usize,
        waiting: usize,
        waiting_limit: usize,
    ) -> AdmissionDiagnostics {
        AdmissionDiagnostics {
            limit,
            live: Some(live),
            waiting: Some(waiting),
            waiting_limit: Some(waiting_limit),
            admitted_total: Some(self.admitted.load(Ordering::Relaxed)),
            refused_total: Some(self.refused.load(Ordering::Relaxed)),
            wait_timeout_total: Some(self.timeout.load(Ordering::Relaxed)),
            wait_cancelled_total: Some(self.cancelled.load(Ordering::Relaxed)),
            active_cancel_total: None,
            permit_classes: Some(PermitClasses {
                tcp: self.permit_classes[PermitKind::Tcp as usize].snapshot(),
                udp: self.permit_classes[PermitKind::Udp as usize].snapshot(),
                unknown: self.permit_classes[PermitKind::Unknown as usize].snapshot(),
            }),
        }
    }
}

/// Records abandonment only. In particular this does not repair or
/// decrement the core waiting counter on baselines where it leaks.
pub(super) struct WaitObservation<'a> {
    counters: &'a Counters,
    terminal: bool,
}

impl<'a> WaitObservation<'a> {
    pub(super) fn new(counters: &'a Counters) -> Self {
        Self {
            counters,
            terminal: false,
        }
    }

    pub(super) fn finish(&mut self) {
        self.terminal = true;
    }
}

impl Drop for WaitObservation<'_> {
    fn drop(&mut self) {
        if !self.terminal {
            self.counters.cancelled.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Finite categories, not protocol inference from packet counts or addresses.
#[derive(Clone, Copy)]
pub(super) enum PermitKind {
    Tcp = 0,
    Udp = 1,
    Unknown = 2,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PermitCounts {
    pub granted_total: u64,
    pub dropped_total: u64,
    /// Observed Places still alive, not transient semaphore reservations.
    pub live: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PermitClasses {
    pub tcp: PermitCounts,
    pub udp: PermitCounts,
    pub unknown: PermitCounts,
}

#[derive(Default)]
struct PermitCounters {
    granted: AtomicU64,
    dropped: AtomicU64,
    live: AtomicU64,
}

impl PermitCounters {
    fn snapshot(&self) -> PermitCounts {
        PermitCounts {
            granted_total: self.granted.load(Ordering::Relaxed),
            dropped_total: self.dropped.load(Ordering::Relaxed),
            live: self.live.load(Ordering::Relaxed),
        }
    }
}

/// Keeps observation storage alive, never a permit or a dispatcher. An old
/// epoch's last drop cannot mutate a new dispatcher's counters.
pub(super) struct PermitObservation {
    counters: Arc<Counters>,
    kind: PermitKind,
}

impl Counters {
    pub(super) fn observe_permit(self: &Arc<Self>, kind: PermitKind) -> PermitObservation {
        let counts = &self.permit_classes[kind as usize];
        counts.granted.fetch_add(1, Ordering::Relaxed);
        counts.live.fetch_add(1, Ordering::Relaxed);
        PermitObservation {
            counters: self.clone(),
            kind,
        }
    }
}

impl Drop for PermitObservation {
    fn drop(&mut self) {
        let counts = &self.counters.permit_classes[self.kind as usize];
        counts.live.fetch_sub(1, Ordering::Relaxed);
        counts.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UdpSendTerminalDiagnostics {
    pub send_error_total: u64,
    pub current_entry_removed_total: u64,
    /// The failing generation had already ended or was replaced.
    pub entry_not_current_total: u64,
}

#[derive(Default)]
pub(crate) struct UdpSendTerminalCounters {
    errors: AtomicU64,
    removed: AtomicU64,
    not_current: AtomicU64,
}

impl UdpSendTerminalCounters {
    pub(crate) fn observe(&self, current_removed: bool) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        if current_removed {
            self.removed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.not_current.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot(&self) -> UdpSendTerminalDiagnostics {
        UdpSendTerminalDiagnostics {
            send_error_total: self.errors.load(Ordering::Relaxed),
            current_entry_removed_total: self.removed.load(Ordering::Relaxed),
            entry_not_current_total: self.not_current.load(Ordering::Relaxed),
        }
    }
}
