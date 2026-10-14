//! Closing what an outbound keeps connected for nothing: a carrier, the
//! connection its streams and UDP sessions go over, that has had none open
//! for the idle timeout (`Profile::carrier_idle_timeout`) is closed, and
//! the next stream dials anew. Without it a carrier the keep-alive holds
//! up stays for good, pinging its server, once anything has used it: a
//! group's probe, one request through a member not selected since.
//!
//! A pool counts what is open on each carrier, and a check of its own
//! (`spawn_check`) looks at them every half of the timeout: a carrier is
//! closed between one and one and a half timeouts after its last stream
//! ended.

use std::sync::Weak;
use std::time::Duration;

use tokio::time::Instant;

/// What is open on a carrier, as its `Open` guards count it.
#[cfg(any(feature = "outbound-hysteria2", feature = "outbound-quic"))]
#[derive(Debug, Default, Clone)]
pub struct Count(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(any(feature = "outbound-hysteria2", feature = "outbound-quic"))]
impl Count {
    /// One more open, until the guard is dropped. Taken where the pool
    /// hands out the carrier, under the lock its check takes, the carrier
    /// is never closed between being handed out and being used.
    pub fn open(&self) -> Open {
        self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Open(self.0.clone())
    }

    pub fn get(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// A stream or UDP session counted on its carrier while it lives.
#[cfg(any(feature = "outbound-hysteria2", feature = "outbound-quic"))]
#[derive(Debug)]
pub struct Open(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(any(feature = "outbound-hysteria2", feature = "outbound-quic"))]
impl Drop for Open {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Since when a carrier has had nothing open, as its pool's check last
/// saw it.
#[derive(Debug, Default)]
pub struct Idle(Option<Instant>);

impl Idle {
    /// Whether a carrier with `open` streams and sessions has had none
    /// for `timeout` at `now`: the first check to see it with none starts
    /// the time, and any that sees one open resets it. With no timeout,
    /// whether it has none open now (`close_idle`).
    pub fn expired(&mut self, open: usize, now: Instant, timeout: Duration) -> bool {
        if open > 0 {
            self.0 = None;
            return false;
        }
        let since = *self.0.get_or_insert(now);
        now.saturating_duration_since(since) >= timeout
    }
}

/// Runs `check` on the pool every half of `timeout`, until the pool is
/// gone, as a reload or a provider's refresh removing its outbound drops
/// it: the pool keeps the `Check`, which stops the task as it goes, so
/// that nothing of the outbound is left running. Started by the pool's
/// first dial: outbounds are built outside a runtime. Essential, as mux's:
/// a check that died would leave carriers open without a sign.
pub fn spawn_check<T: Send + Sync + 'static>(
    name: &'static str,
    pool: Weak<T>,
    timeout: Duration,
    check: impl Fn(&T, Instant) + Send + 'static,
) -> Check {
    let every = (timeout / 2).max(Duration::from_millis(1));
    let (task, handle) = futures::future::abortable(async move {
        loop {
            tokio::time::sleep(every).await;
            let Some(pool) = pool.upgrade() else {
                return;
            };
            check(&pool, Instant::now());
        }
    });
    crate::runtime::scope::spawn_essential(name, async move {
        let _ = task.await;
    });
    Check(handle)
}

/// A pool's idle check, stopped when dropped.
#[derive(Debug)]
pub struct Check(futures::future::AbortHandle);

impl Drop for Check {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_carrier_expires_a_timeout_after_a_check_first_saw_it_idle() {
        let timeout = Duration::from_secs(60);
        let start = Instant::now();
        let mut idle = Idle::default();
        assert!(!idle.expired(0, start, timeout));
        assert!(!idle.expired(0, start + timeout / 2, timeout));
        // One open resets the time.
        assert!(!idle.expired(1, start + timeout, timeout));
        assert!(!idle.expired(0, start + timeout, timeout));
        assert!(!idle.expired(0, start + timeout * 3 / 2, timeout));
        assert!(idle.expired(0, start + timeout * 2, timeout));
        // With no timeout, at once, but not with one open.
        assert!(Idle::default().expired(0, start, Duration::ZERO));
        assert!(!Idle::default().expired(1, start, Duration::ZERO));
    }
}
