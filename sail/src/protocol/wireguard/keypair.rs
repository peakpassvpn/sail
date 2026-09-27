//! Transport sessions and a peer's three slots for them.
//!
//! As in Linux and wireguard-go, a peer holds up to three keypairs: the
//! current one, which sends; the previous one, still accepted on receive
//! so packets in flight across a rekey are not lost; and, on the responder,
//! the next one, which waits for the initiator's first transport packet
//! before it may send.

use std::time::Instant;

use super::crypto::AeadKey;
use super::noise::SessionKeys;
use super::replay::ReplayWindow;
use super::timers::{REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME};

pub struct Keypair {
    send: AeadKey,
    recv: AeadKey,
    /// The next counter to send.
    send_counter: u64,
    send_valid: bool,
    recv_valid: bool,
    pub replay: ReplayWindow,
    pub local_index: u32,
    pub remote_index: u32,
    pub birth: Instant,
    pub initiator: bool,
}

impl Keypair {
    pub fn new(keys: &SessionKeys, now: Instant) -> Self {
        Keypair {
            send: AeadKey::new(&keys.send),
            recv: AeadKey::new(&keys.recv),
            send_counter: 0,
            send_valid: true,
            recv_valid: true,
            replay: ReplayWindow::default(),
            local_index: keys.local_index,
            remote_index: keys.remote_index,
            birth: now,
            initiator: keys.initiator,
        }
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Whether this keypair may still send at `now`. Invalidates it once
    /// it is too old.
    pub fn can_send(&mut self, now: Instant) -> bool {
        if self.send_valid && now.saturating_duration_since(self.birth) >= REJECT_AFTER_TIME {
            self.send_valid = false;
        }
        self.send_valid
    }

    /// Whether the sending half is still marked valid, not checking age.
    pub fn send_marked_valid(&self) -> bool {
        self.send_valid
    }

    /// Whether this keypair may still receive at `now`.
    pub fn can_receive(&mut self, now: Instant) -> bool {
        if self.recv_valid
            && (now.saturating_duration_since(self.birth) >= REJECT_AFTER_TIME
                || self.replay.next() >= REJECT_AFTER_MESSAGES)
        {
            self.recv_valid = false;
        }
        self.recv_valid
    }

    /// Takes the next send counter; `None` once REJECT_AFTER_MESSAGES is
    /// reached, after which the keypair is invalid.
    pub fn next_counter(&mut self) -> Option<u64> {
        let n = self.send_counter;
        if n >= REJECT_AFTER_MESSAGES {
            self.send_valid = false;
            return None;
        }
        self.send_counter += 1;
        Some(n)
    }

    pub fn seal(&mut self, counter: u64, buf: &mut [u8]) {
        self.send.seal_in_place(counter, buf, &[]);
    }

    pub fn open(&mut self, counter: u64, buf: &mut [u8]) -> bool {
        self.recv.open_in_place(counter, buf, &[])
    }

    #[cfg(test)]
    pub fn set_send_counter(&mut self, n: u64) {
        self.send_counter = n;
    }
}

/// Which of a peer's slots a keypair sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Previous,
    Current,
    Next,
}

#[derive(Default)]
pub struct Keypairs {
    pub previous: Option<Keypair>,
    pub current: Option<Keypair>,
    pub next: Option<Keypair>,
}

impl Keypairs {
    /// Installs a fresh keypair as noise.c's add_new_keypair does, and
    /// returns the indices of keypairs it dropped.
    pub fn add(&mut self, new: Keypair) -> Vec<u32> {
        let mut dropped = Vec::new();
        let mut drop_kp = |kp: Option<Keypair>| {
            if let Some(kp) = kp {
                dropped.push(kp.local_index);
            }
        };
        if new.initiator {
            if let Some(next) = self.next.take() {
                // A pending next keypair becomes the previous one, and the
                // current one goes.
                drop_kp(self.previous.replace(next));
                drop_kp(self.current.take());
            } else {
                let current = self.current.take();
                drop_kp(std::mem::replace(&mut self.previous, current));
            }
            self.current = Some(new);
        } else {
            drop_kp(self.next.replace(new));
            drop_kp(self.previous.take());
        }
        dropped
    }

    /// Notes that a packet authenticated under the keypair in `slot`. If it
    /// was the next keypair, the initiator has confirmed it: it becomes
    /// current. Returns true then, and the index of the dropped previous.
    pub fn received_with(&mut self, slot: Slot) -> (bool, Option<u32>) {
        if slot != Slot::Next {
            return (false, None);
        }
        let next = self.next.take();
        let old = std::mem::replace(&mut self.previous, self.current.take());
        self.current = next;
        (true, old.map(|k| k.local_index))
    }

    pub fn find(&mut self, index: u32) -> Option<(Slot, &mut Keypair)> {
        if let Some(k) = self.current.as_mut().filter(|k| k.local_index == index) {
            return Some((Slot::Current, k));
        }
        if let Some(k) = self.previous.as_mut().filter(|k| k.local_index == index) {
            return Some((Slot::Previous, k));
        }
        if let Some(k) = self.next.as_mut().filter(|k| k.local_index == index) {
            return Some((Slot::Next, k));
        }
        None
    }

    /// Drops all keypairs, returning their indices.
    pub fn clear(&mut self) -> Vec<u32> {
        [self.previous.take(), self.current.take(), self.next.take()]
            .into_iter()
            .flatten()
            .map(|k| k.local_index)
            .collect()
    }

    pub fn indices(&self) -> Vec<u32> {
        [&self.previous, &self.current, &self.next]
            .into_iter()
            .flatten()
            .map(|k| k.local_index)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(index: u32, initiator: bool) -> Keypair {
        let keys = SessionKeys {
            send: [index as u8; 32],
            recv: [index as u8 ^ 0xff; 32],
            initiator,
            local_index: index,
            remote_index: 0,
        };
        Keypair::new(&keys, Instant::now())
    }

    fn slots(k: &Keypairs) -> [Option<u32>; 3] {
        [
            k.previous.as_ref().map(|k| k.local_index),
            k.current.as_ref().map(|k| k.local_index),
            k.next.as_ref().map(|k| k.local_index),
        ]
    }

    /// The rotations of Linux's add_new_keypair and received_with_keypair.
    #[test]
    fn rotation() {
        let mut k = Keypairs::default();
        // Initiator sessions slide current into previous.
        assert!(k.add(kp(1, true)).is_empty());
        assert_eq!(slots(&k), [None, Some(1), None]);
        assert!(k.add(kp(2, true)).is_empty());
        assert_eq!(slots(&k), [Some(1), Some(2), None]);
        assert_eq!(k.add(kp(3, true)), vec![1]);
        assert_eq!(slots(&k), [Some(2), Some(3), None]);

        // A responder session waits in next, and drops previous.
        assert_eq!(k.add(kp(4, false)), vec![2]);
        assert_eq!(slots(&k), [None, Some(3), Some(4)]);
        // Receiving on current changes nothing.
        assert_eq!(k.received_with(Slot::Current), (false, None));
        // Receiving on next confirms it.
        assert_eq!(k.received_with(Slot::Next), (true, None));
        assert_eq!(slots(&k), [Some(3), Some(4), None]);

        // A second responder session replaces an unconfirmed next.
        k.add(kp(5, false));
        assert_eq!(k.add(kp(6, false)), vec![5]);
        assert_eq!(slots(&k), [None, Some(4), Some(6)]);
        // An initiator session while next is pending: next becomes
        // previous, current goes.
        assert_eq!(k.add(kp(7, true)), vec![4]);
        assert_eq!(slots(&k), [Some(6), Some(7), None]);

        let mut all = k.clear();
        all.sort();
        assert_eq!(all, vec![6, 7]);
    }

    #[test]
    fn counters_and_expiry() {
        let mut k = kp(1, true);
        let t0 = k.birth;
        assert_eq!(k.next_counter(), Some(0));
        assert_eq!(k.next_counter(), Some(1));
        k.set_send_counter(REJECT_AFTER_MESSAGES);
        assert_eq!(k.next_counter(), None);
        assert!(!k.can_send(t0));

        let mut k = kp(2, true);
        let t0 = k.birth;
        assert!(k.can_send(t0 + REJECT_AFTER_TIME - std::time::Duration::from_millis(1)));
        assert!(!k.can_send(t0 + REJECT_AFTER_TIME));
        assert!(!k.can_receive(t0 + REJECT_AFTER_TIME));
    }
}
