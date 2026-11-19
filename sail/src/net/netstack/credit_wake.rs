//! Executor side of the credit handshake. No flow/payload/task strong ownership.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use sail_netstack::{CreditReturnObserver, ResourceLedger};
use tokio::sync::Notify;

#[derive(Debug, Default)]
pub(super) struct CreditSlot {
    interested: AtomicBool,
    queued: AtomicBool,
    notify: Notify,
    #[cfg(test)]
    pub hints: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    pub notifications: std::sync::atomic::AtomicUsize,
}

impl CreditSlot {
    pub fn hint(&self) {
        #[cfg(test)]
        self.hints.fetch_add(1, Ordering::Relaxed);
        if !self.queued.swap(true, Ordering::AcqRel) {
            #[cfg(test)]
            self.notifications.fetch_add(1, Ordering::Relaxed);
            self.notify.notify_one();
        }
    }

    pub async fn ready(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            // Consumption occurs at processing start, never at its end.
            if self.queued.swap(false, Ordering::AcqRel) {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Debug)]
struct CreditGroup {
    slots: Box<[Weak<CreditSlot>]>,
}
impl CreditReturnObserver for CreditGroup {
    fn hint_interested(&self) {
        for slot in &self.slots {
            if let Some(slot) = slot.upgrade() {
                if slot.interested.load(Ordering::SeqCst) {
                    slot.hint();
                }
            }
        }
    }
}

/// Returns false on any duplicate installation; no replacement or registry.
pub(super) fn bind(ledger: &ResourceLedger, slots: &[Arc<CreditSlot>]) -> bool {
    let observer = Arc::new(CreditGroup {
        slots: slots.iter().map(Arc::downgrade).collect(),
    });
    ledger.install_credit_observer(observer).is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Availability {
    Available,
    Unbound,
    AlreadyBound,
    EpochExhausted,
    Stopped,
}

pub(super) struct CreditInterest {
    pub slot: Arc<CreditSlot>,
    ledger: Arc<ResourceLedger>,
    bound: bool,
    armed: bool,
    stopped: bool,
}
impl CreditInterest {
    pub fn new(ledger: Arc<ResourceLedger>) -> Self {
        Self {
            slot: Arc::default(),
            ledger,
            bound: false,
            armed: false,
            stopped: false,
        }
    }
    pub fn set_bound(&mut self, bound: bool) {
        self.bound = bound;
    }
    pub fn availability(&self) -> Availability {
        if self.stopped {
            return Availability::Stopped;
        }
        if !self.bound {
            return if self.ledger.credit_return_state().is_some() {
                Availability::AlreadyBound
            } else {
                Availability::Unbound
            };
        }
        if self
            .ledger
            .credit_return_state()
            .and_then(|state| state.epoch())
            .is_none()
        {
            Availability::EpochExhausted
        } else {
            Availability::Available
        }
    }
    /// W0 before the only resource-event attempt (or initial registration retry).
    pub fn epoch(&self) -> Option<u64> {
        if !self.bound || self.stopped {
            return None;
        }
        self.ledger.credit_return_state()?.epoch()
    }
    pub fn arm(&mut self) -> bool {
        if self.armed {
            // Mode may have changed since W0. No stale available claim.
            if self.epoch().is_none() {
                self.disarm();
                return false;
            }
            return true;
        }
        if self.availability() != Availability::Available {
            return false;
        }
        self.slot.interested.store(true, Ordering::SeqCst);
        let state = self.ledger.credit_return_state().expect("bound ledger");
        if !state.enter() {
            self.slot.interested.store(false, Ordering::SeqCst);
            return false;
        }
        self.armed = true;
        true
    }
    /// W4/W5 after the attempt; no stale-epoch selfhint in subsequent rounds.
    pub fn finish(&mut self, before: Option<u64>, waiting: bool) {
        if !waiting {
            self.disarm();
            return;
        }
        match (before, self.epoch()) {
            (_, None) => self.disarm(),
            (Some(before), Some(after)) if before != after => self.slot.hint(),
            _ => {}
        }
    }
    pub fn disarm(&mut self) {
        if std::mem::take(&mut self.armed) {
            self.slot.interested.store(false, Ordering::SeqCst);
            self.ledger
                .credit_return_state()
                .expect("armed ledger")
                .leave();
        }
    }
    pub fn stop(&mut self) {
        self.disarm();
        self.stopped = true;
    }
    pub fn reset(&mut self) {
        self.disarm();
        // This is a context transition, not an event-end clear. New enrollment
        // uses a fresh epoch handshake even if a stale publisher hints later.
        self.slot.queued.swap(false, Ordering::AcqRel);
    }
}
impl Drop for CreditInterest {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Feature-only owner-local values. No C/Swift snapshot or locks added.
#[cfg(feature = "internal-diagnostics")]
#[derive(Default)]
pub(super) struct CreditDiagnostics {
    pub resource_pending_writes: usize,
    pub resource_pending_bytes: usize,
    pub credit_event_written_bytes: u64,
    pub timer_retry_written_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sail_netstack::{BudgetProfile, ResourceKind};

    #[tokio::test(start_paused = true)]
    async fn hints_coalesce_and_processing_does_not_clear_a_later_hint() {
        let slot = CreditSlot::default();
        slot.hint();
        slot.hint();
        slot.hint();
        assert_eq!(slot.notifications.load(Ordering::Relaxed), 1);
        slot.ready().await;
        slot.hint(); // arrives during handling, after the start-time clear.
        slot.ready().await;
        assert_eq!(slot.notifications.load(Ordering::Relaxed), 2);
        // Earlier notify permits may be stale; an empty flag must not be ready.
        let next = slot.ready();
        tokio::pin!(next);
        assert!(futures::poll!(next.as_mut()).is_pending());
    }
    #[tokio::test(start_paused = true)]
    async fn hint_between_enable_and_flag_check_is_not_lost() {
        let slot = CreditSlot::default();
        let waiting = slot.ready();
        tokio::pin!(waiting);
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        slot.hint();
        waiting.await;
        assert!(!slot.queued.load(Ordering::Acquire));
    }
    #[test]
    fn weak_group_does_not_retain_runtime_and_duplicate_binding_is_unavailable() {
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let mut first = CreditInterest::new(ledger.clone());
        first.set_bound(bind(&ledger, &[first.slot.clone()]));
        assert!(first.arm());
        let weak = Arc::downgrade(&first.slot);
        let mut second = CreditInterest::new(ledger.clone());
        second.set_bound(bind(&ledger, &[second.slot.clone()]));
        assert_eq!(second.availability(), Availability::AlreadyBound);
        assert!(!second.arm());
        drop(first);
        assert!(weak.upgrade().is_none());
        // Last Weak upgrade after Drop is harmless; the ledger owns no slot.
        drop(ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap());
    }
    #[test]
    fn last_interest_survives_retry_and_reset_reenrollment_uses_new_epoch() {
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let mut interest = CreditInterest::new(ledger.clone());
        interest.set_bound(bind(&ledger, &[interest.slot.clone()]));
        let before = interest.epoch();
        assert!(interest.arm());
        // This stands for the synchronous interval while the FIFO node is off
        // the chain. No disarm is allowed until outcome classification.
        drop(ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap());
        interest.finish(before, true);
        assert!(interest.slot.queued.load(Ordering::Acquire));
        interest.reset();
        assert!(!interest.armed);
        let next = interest.epoch();
        assert!(interest.arm());
        interest.finish(next, true);
        assert!(!interest.slot.queued.load(Ordering::Acquire));
        interest.stop();
        assert_eq!(interest.availability(), Availability::Stopped);
        assert!(!interest.arm());
    }
    #[test]
    fn typed_wake_storage_and_feature_delta_are_reported() {
        eprintln!(
            "CreditSlot size={} align={} CreditInterest size={} align={} Weak={} Arc={}",
            std::mem::size_of::<CreditSlot>(),
            std::mem::align_of::<CreditSlot>(),
            std::mem::size_of::<CreditInterest>(),
            std::mem::align_of::<CreditInterest>(),
            std::mem::size_of::<Weak<CreditSlot>>(),
            std::mem::size_of::<Arc<CreditSlot>>()
        );
        #[cfg(feature = "internal-diagnostics")]
        eprintln!(
            "CreditDiagnostics size={} align={}",
            std::mem::size_of::<CreditDiagnostics>(),
            std::mem::align_of::<CreditDiagnostics>()
        );
        // Test-only probe atomics are reported separately from production.
    }
}
