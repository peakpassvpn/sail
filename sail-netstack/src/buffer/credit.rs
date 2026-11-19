//! A single immutable subscriber group. No executor dependency or flow ownership.
use portable_atomic::AtomicU64;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// An observer must only coalesce hints for its fixed, weakly held runtime slots.
/// Called after accounting updates; never called for failed-reserve rollback.
pub trait CreditReturnObserver: Debug + Send + Sync {
    fn hint_interested(&self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditObserverAlreadyBound;

/// All epoch, active and unavailable operations participate in the SC protocol.
/// Slot interest publication must precede `enter()`, and remain armed across retry.
#[derive(Debug)]
pub struct CreditReturnState {
    observer: Arc<dyn CreditReturnObserver>,
    epoch: AtomicU64,
    active: AtomicUsize,
    exhausted: AtomicBool,
    #[cfg(test)]
    cas_attempts: AtomicUsize,
}

impl CreditReturnState {
    pub(super) fn new(observer: Arc<dyn CreditReturnObserver>) -> Self {
        Self {
            observer,
            epoch: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
            #[cfg(test)]
            cas_attempts: AtomicUsize::new(0),
        }
    }

    /// W0/W4. None is monotonic unavailability; the original timer remains valid.
    #[must_use]
    pub fn epoch(&self) -> Option<u64> {
        if self.exhausted.load(Ordering::SeqCst) {
            None
        } else {
            Some(self.epoch.load(Ordering::SeqCst))
        }
    }

    /// W2, after the slot's SC interested=true. Recheck mode after increment:
    /// exhaustion between W0 and W1 cannot leave an unobserved registration.
    #[must_use]
    pub fn enter(&self) -> bool {
        self.active.fetch_add(1, Ordering::SeqCst);
        if self.exhausted.load(Ordering::SeqCst) {
            self.leave();
            false
        } else {
            true
        }
    }

    /// Exactly once per successful `enter()`, after SC `interested=false`.
    pub fn leave(&self) {
        let previous = self.active.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "credit interest underflow");
    }

    pub(super) fn returned(&self) {
        // P0 is complete before entry. Publish even when active==0.
        let mut epoch = self.epoch.load(Ordering::SeqCst);
        loop {
            let Some(next) = epoch.checked_add(1) else {
                // No wrap/ABA. Force a hint regardless of active count to cover
                // interest publication racing the transition; enter rechecks.
                if !self.exhausted.swap(true, Ordering::SeqCst) {
                    self.observer.hint_interested();
                }
                return;
            };
            #[cfg(test)]
            self.cas_attempts.fetch_add(1, Ordering::Relaxed);
            match self
                .epoch
                .compare_exchange_weak(epoch, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(observed) => epoch = observed,
            }
        }
        if self.active.load(Ordering::SeqCst) != 0 {
            self.observer.hint_interested();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BudgetProfile, ResourceKind, ResourceLedger};

    #[derive(Debug, Default)]
    struct Observer {
        interested: AtomicBool,
        hints: AtomicUsize,
    }
    impl CreditReturnObserver for Observer {
        fn hint_interested(&self) {
            if self.interested.load(Ordering::SeqCst) {
                self.hints.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn fixture() -> (Arc<ResourceLedger>, Arc<Observer>) {
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let observer = Arc::new(Observer::default());
        ledger.install_credit_observer(observer.clone()).unwrap();
        (ledger, observer)
    }
    fn arm(ledger: &ResourceLedger, observer: &Observer) {
        observer.interested.store(true, Ordering::SeqCst);
        assert!(ledger.credit_return_state().unwrap().enter());
    }
    fn leave(ledger: &ResourceLedger, observer: &Observer) {
        observer.interested.store(false, Ordering::SeqCst);
        ledger.credit_return_state().unwrap().leave();
    }
    #[test]
    fn release_before_w0_is_published_even_without_waiters() {
        let (ledger, observer) = fixture();
        let lease = ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap();
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert_eq!(ledger.credit_return_state().unwrap().epoch(), Some(1));
        arm(&ledger, &observer);
        let recheck = ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap();
        assert_eq!(observer.hints.load(Ordering::Relaxed), 0);
        leave(&ledger, &observer);
        drop(recheck);
    }
    #[test]
    fn release_between_w0_and_arm_is_detected_by_w4() {
        let (ledger, observer) = fixture();
        let state = ledger.credit_return_state().unwrap();
        let before = state.epoch().unwrap();
        let lease = ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap();
        std::thread::spawn(move || drop(lease)).join().unwrap();
        arm(&ledger, &observer);
        assert_ne!(before, state.epoch().unwrap(), "waiter must selfhint");
        assert_eq!(observer.hints.load(Ordering::Relaxed), 0);
        leave(&ledger, &observer);
    }
    #[test]
    fn release_after_w4_hints_published_interest() {
        let (ledger, observer) = fixture();
        arm(&ledger, &observer);
        let state = ledger.credit_return_state().unwrap();
        let before = state.epoch();
        let lease = ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap();
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert_ne!(before, state.epoch());
        assert_eq!(observer.hints.load(Ordering::Relaxed), 1);
        leave(&ledger, &observer);
        assert_eq!(state.active.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn epoch_exhausted_between_w0_and_w1_cannot_leak_active() {
        let (ledger, observer) = fixture();
        let state = ledger.credit_return_state().unwrap();
        state.epoch.store(u64::MAX, Ordering::SeqCst);
        assert_eq!(state.epoch(), Some(u64::MAX)); // W0 saw available.
        let lease = ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap();
        std::thread::spawn(move || drop(lease)).join().unwrap();
        observer.interested.store(true, Ordering::SeqCst); // W1 after exhaustion.
        assert!(!state.enter()); // W2 post-increment mode recheck rolls back.
        observer.interested.store(false, Ordering::SeqCst);
        assert_eq!(state.epoch(), None);
        assert_eq!(state.active.load(Ordering::SeqCst), 0);
        assert_eq!(state.epoch.load(Ordering::SeqCst), u64::MAX);
    }
    #[test]
    fn epoch_exhausted_between_w1_and_w2_hints_and_undoes_enter() {
        let (ledger, observer) = fixture();
        let state = ledger.credit_return_state().unwrap();
        state.epoch.store(u64::MAX, Ordering::SeqCst);
        assert!(state.epoch().is_some());
        observer.interested.store(true, Ordering::SeqCst);
        let lease = ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap();
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert!(!state.enter());
        observer.interested.store(false, Ordering::SeqCst);
        assert_eq!(state.active.load(Ordering::SeqCst), 0);
        assert_eq!(state.epoch(), None);
        assert_eq!(observer.hints.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn exhaustion_after_enter_hints_once_then_stays_unavailable() {
        let (ledger, observer) = fixture();
        let state = ledger.credit_return_state().unwrap();
        state.epoch.store(u64::MAX, Ordering::SeqCst);
        arm(&ledger, &observer);
        for _ in 0..2 {
            drop(ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap());
        }
        assert_eq!(state.epoch(), None);
        assert_eq!(observer.hints.load(Ordering::Relaxed), 1);
        leave(&ledger, &observer);
        assert_eq!(state.active.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn duplicate_binding_does_not_replace_observer() {
        let (ledger, observer) = fixture();
        let rejected = Arc::new(Observer::default());
        assert!(ledger.install_credit_observer(rejected.clone()).is_err());
        arm(&ledger, &observer);
        drop(ledger.try_acquire(ResourceKind::PacketBytes, 1).unwrap());
        assert_eq!(observer.hints.load(Ordering::Relaxed), 1);
        assert_eq!(rejected.hints.load(Ordering::Relaxed), 0);
        leave(&ledger, &observer);
    }
    #[test]
    fn split_zero_units_and_failed_pool_reserve_do_not_publish() {
        let (ledger, _) = fixture();
        let state = ledger.credit_return_state().unwrap();
        drop(ledger.try_acquire(ResourceKind::PacketBytes, 0).unwrap());
        drop(ledger.try_acquire(ResourceKind::TcpFlows, 1).unwrap());
        assert!(ledger
            .try_acquire_within(ResourceKind::PacketBytes, 1, 0)
            .is_err());
        let mut lease = ledger.try_acquire(ResourceKind::PacketBytes, 10).unwrap();
        let remainder = lease.split_off(5);
        assert_eq!(state.epoch(), Some(0));
        lease.shrink_to(3);
        assert_eq!(state.epoch(), Some(1));
        drop(lease);
        drop(remainder);
        assert_eq!(state.epoch(), Some(3));
        assert_eq!(ledger.snapshot().total_bytes, 0);
    }
    #[test]
    fn installed_idle_and_active_return_cost_probe() {
        // A bounded counter probe, not a throughput benchmark or acceptance.
        let (ledger, observer) = fixture();
        let state = ledger.credit_return_state().unwrap();
        for _ in 0..64 {
            drop(ledger.try_acquire(ResourceKind::PacketBytes, 1460).unwrap());
        }
        assert_eq!(state.cas_attempts.load(Ordering::Relaxed), 64);
        assert_eq!(observer.hints.load(Ordering::Relaxed), 0);
        arm(&ledger, &observer);
        for _ in 0..64 {
            drop(ledger.try_acquire(ResourceKind::PacketBytes, 1460).unwrap());
        }
        assert_eq!(state.cas_attempts.load(Ordering::Relaxed), 128);
        assert_eq!(observer.hints.load(Ordering::Relaxed), 64);
        leave(&ledger, &observer);
    }
    #[test]
    fn typed_ledger_state_size_is_reported() {
        eprintln!(
            "CreditReturnState size={} align={}",
            std::mem::size_of::<CreditReturnState>(),
            std::mem::align_of::<CreditReturnState>()
        );
        // test-only CAS probe is not production typed storage.
        assert!(std::mem::size_of::<CreditReturnState>() <= 64);
    }
}
