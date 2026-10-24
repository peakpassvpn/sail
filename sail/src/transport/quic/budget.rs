//! What all of a process's Hysteria2 and TUIC windows may grow by, together.
//!
//! quinn (sail's fork) grows a stream's receive window while it is read
//! about as fast as data arrives, the connection's with it, and the send
//! window with the congestion window; every growth past the starting sizes
//! is asked of a [`quinn::WindowBudget`] first. One budget for the process
//! lets one transfer take a large window while many connections share it,
//! and bounds what windows can hold at once, which is what QUIC's memory
//! goes to (sail#9).

use std::sync::{Arc, OnceLock};

use portable_atomic::{AtomicU64, Ordering};

/// The process's window budget.
#[derive(Debug, Default)]
pub struct WindowBudget {
    limit: AtomicU64,
    held: AtomicU64,
    peak: AtomicU64,
    refused: AtomicU64,
}

impl WindowBudget {
    /// What windows hold past their starting sizes now, in bytes.
    pub fn held(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }

    /// The most they have held.
    pub fn peak(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }

    /// Growths refused for want of budget.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
}

impl quinn::WindowBudget for WindowBudget {
    fn try_grow(&self, bytes: u64) -> bool {
        let limit = self.limit.load(Ordering::Relaxed);
        let grown = self
            .held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                held.checked_add(bytes).filter(|&held| held <= limit)
            });
        match grown {
            Ok(held) => {
                self.peak.fetch_max(held + bytes, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.refused.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn release(&self, bytes: u64) {
        let _ = self
            .held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                Some(held.saturating_sub(bytes))
            });
    }
}

/// The process's budget, at `limit` bytes from now on: what connections
/// already hold stays theirs, and new growth is judged against it.
pub fn window_budget(limit: u64) -> Arc<WindowBudget> {
    static BUDGET: OnceLock<Arc<WindowBudget>> = OnceLock::new();
    let budget = BUDGET.get_or_init(Default::default);
    budget.limit.store(limit, Ordering::Relaxed);
    budget.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::WindowBudget as _;

    #[test]
    fn growth_is_refused_past_the_limit_and_released() {
        let budget = WindowBudget::default();
        budget.limit.store(100, Ordering::Relaxed);
        assert!(budget.try_grow(60));
        assert!(!budget.try_grow(41));
        assert!(budget.try_grow(40));
        assert_eq!(
            (budget.held(), budget.peak(), budget.refused()),
            (100, 100, 1)
        );
        budget.release(70);
        assert!(budget.try_grow(41));
        assert_eq!((budget.held(), budget.peak()), (71, 100));
    }
}
