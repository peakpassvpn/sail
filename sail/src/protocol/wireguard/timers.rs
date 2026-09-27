//! Protocol constants (whitepaper section 6.1) and the per-peer timers of
//! Linux's drivers/net/wireguard/timers.c, as deadlines a sans-IO core
//! checks in `tick`.

use std::time::{Duration, Instant};

pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Initiations sent before giving up: REKEY_ATTEMPT_TIME / REKEY_TIMEOUT.
pub const MAX_TIMER_HANDSHAKES: u32 =
    (REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs()) as u32;
/// The retransmission jitter is uniform in [0, this), Linux's HZ / 3.
pub const REKEY_TIMEOUT_JITTER_MAX: Duration = Duration::from_millis(333);
/// A responder takes at most this many initiations a second from a peer.
pub const INITIATIONS_PER_SECOND: u32 = 50;
/// Packets held per peer while a handshake is under way.
pub const MAX_STAGED_PACKETS: usize = 128;

/// Uniform jitter for the retransmission and new-handshake timers.
pub fn jitter() -> Duration {
    let r = super::crypto::random_u32() as u64;
    Duration::from_nanos(r % REKEY_TIMEOUT_JITTER_MAX.as_nanos() as u64)
}

/// A timer: armed with a deadline, or idle.
#[derive(Clone, Copy, Debug, Default)]
pub struct Timer(Option<Instant>);

impl Timer {
    pub fn is_pending(&self) -> bool {
        self.0.is_some()
    }

    /// `mod_timer`: (re)arms at `at`.
    pub fn set(&mut self, at: Instant) {
        self.0 = Some(at);
    }

    /// `del_timer`.
    pub fn clear(&mut self) {
        self.0 = None;
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.0
    }

    /// Disarms and reports whether the deadline had passed.
    pub fn fire(&mut self, now: Instant) -> bool {
        match self.0 {
            Some(at) if at <= now => {
                self.0 = None;
                true
            }
            _ => false,
        }
    }
}

/// The five timers of a peer, and their bookkeeping.
#[derive(Debug, Default)]
pub struct PeerTimers {
    /// Resend the initiation: REKEY_TIMEOUT + jitter after sending one.
    pub retransmit_handshake: Timer,
    /// Passive keepalive: KEEPALIVE_TIMEOUT after data arrived with nothing
    /// sent back.
    pub send_keepalive: Timer,
    /// Data went out but nothing came back for KEEPALIVE_TIMEOUT +
    /// REKEY_TIMEOUT: start a new handshake.
    pub new_handshake: Timer,
    /// REJECT_AFTER_TIME * 3 after the last session: forget all keys.
    pub zero_key_material: Timer,
    /// The configured persistent keepalive.
    pub persistent_keepalive: Timer,
    pub handshake_attempts: u32,
    pub need_another_keepalive: bool,
    pub sent_lastminute_handshake: bool,
}

impl PeerTimers {
    pub fn earliest(&self) -> Option<Instant> {
        [
            self.retransmit_handshake,
            self.send_keepalive,
            self.new_handshake,
            self.zero_key_material,
            self.persistent_keepalive,
        ]
        .iter()
        .filter_map(Timer::deadline)
        .min()
    }

    pub fn clear_all(&mut self) {
        self.retransmit_handshake.clear();
        self.send_keepalive.clear();
        self.new_handshake.clear();
        self.zero_key_material.clear();
        self.persistent_keepalive.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(MAX_TIMER_HANDSHAKES, 18);
        assert_eq!(REJECT_AFTER_MESSAGES, 0xffff_ffff_ffff_dfff);
        for _ in 0..100 {
            assert!(jitter() < REKEY_TIMEOUT_JITTER_MAX);
        }
    }

    #[test]
    fn timer_fires_once() {
        let t0 = Instant::now();
        let mut t = Timer::default();
        t.set(t0 + Duration::from_secs(1));
        assert!(!t.fire(t0));
        assert!(t.fire(t0 + Duration::from_secs(1)));
        assert!(!t.fire(t0 + Duration::from_secs(2)));
        assert!(!t.is_pending());
    }
}
