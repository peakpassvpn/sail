//! The receive-side replay window: RFC 6479's bitmap ring, 8192 bits of
//! which 64 are redundant, so a window of 8128 counters, as Linux has it
//! (`counter_validate` in drivers/net/wireguard/receive.c).

use super::timers::REJECT_AFTER_MESSAGES;

const BITS_PER_WORD: u64 = 64;
const BITS_TOTAL: u64 = 8192;
const WORDS: usize = (BITS_TOTAL / BITS_PER_WORD) as usize;
/// How far below the highest counter seen a counter is still accepted.
pub const WINDOW_SIZE: u64 = BITS_TOTAL - BITS_PER_WORD;

#[derive(Clone)]
pub struct ReplayWindow {
    /// One more than the highest counter accepted; zero before any.
    next: u64,
    bitmap: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow {
            next: 0,
            bitmap: [0; WORDS],
        }
    }
}

impl ReplayWindow {
    /// One more than the highest counter accepted.
    pub fn next(&self) -> u64 {
        self.next
    }

    /// Whether `counter` is fresh; if so, records it. Call only after the
    /// packet authenticated, or a forger could move the window.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if self.next > REJECT_AFTER_MESSAGES || counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let counter = counter + 1;
        if WINDOW_SIZE + counter < self.next {
            return false;
        }
        let index = counter / BITS_PER_WORD;
        if counter > self.next {
            let current = self.next / BITS_PER_WORD;
            let top = (index - current).min(WORDS as u64);
            for i in 1..=top {
                self.bitmap[((i + current) % WORDS as u64) as usize] = 0;
            }
            self.next = counter;
        }
        let word = &mut self.bitmap[(index % WORDS as u64) as usize];
        let bit = 1u64 << (counter % BITS_PER_WORD);
        let fresh = *word & bit == 0;
        *word |= bit;
        fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux's selftest, drivers/net/wireguard/selftest/counter.c.
    #[test]
    fn linux_selftest() {
        const LIM: u64 = WINDOW_SIZE + 1;
        const R: u64 = REJECT_AFTER_MESSAGES;
        let mut w = ReplayWindow::default();
        let cases: &[(u64, bool)] = &[
            (0, true),
            (1, true),
            (1, false),
            (9, true),
            (8, true),
            (7, true),
            (7, false),
            (LIM, true),
            (LIM - 1, true),
            (LIM - 1, false),
            (LIM - 2, true),
            (2, true),
            (2, false),
            (LIM + 16, true),
            (3, false),
            (LIM + 16, false),
            (LIM * 4, true),
            (LIM * 4 - (LIM - 1), true),
            (10, false),
            (LIM * 4 - LIM, false),
            (LIM * 4 - (LIM + 1), false),
            (LIM * 4 - (LIM - 2), true),
            (LIM * 4 + 1 - LIM, false),
            (0, false),
            (R, false),
            (R - 1, true),
            (R, false),
            (R - 1, false),
            (R - 2, true),
            (R + 1, false),
            (R + 2, false),
            (R - 2, false),
            (R - 3, true),
            (0, false),
        ];
        for (i, &(n, want)) in cases.iter().enumerate() {
            assert_eq!(w.check_and_update(n), want, "case {} ({})", i + 1, n);
        }

        let mut w = ReplayWindow::default();
        for i in 1..=WINDOW_SIZE {
            assert!(w.check_and_update(i));
        }
        assert!(w.check_and_update(0));
        assert!(!w.check_and_update(0));

        let mut w = ReplayWindow::default();
        for i in 2..=WINDOW_SIZE + 1 {
            assert!(w.check_and_update(i));
        }
        assert!(w.check_and_update(1));
        assert!(!w.check_and_update(0));

        let mut w = ReplayWindow::default();
        for i in (0..=WINDOW_SIZE).rev() {
            assert!(w.check_and_update(i));
        }

        let mut w = ReplayWindow::default();
        for i in (1..=WINDOW_SIZE + 1).rev() {
            assert!(w.check_and_update(i));
        }
        assert!(!w.check_and_update(0));

        let mut w = ReplayWindow::default();
        for i in (1..=WINDOW_SIZE).rev() {
            assert!(w.check_and_update(i));
        }
        assert!(w.check_and_update(WINDOW_SIZE + 1));
        assert!(!w.check_and_update(0));

        let mut w = ReplayWindow::default();
        for i in (1..=WINDOW_SIZE).rev() {
            assert!(w.check_and_update(i));
        }
        assert!(w.check_and_update(0));
        assert!(w.check_and_update(WINDOW_SIZE + 1));
    }

    /// Out of order within the window is fine, each counter once; far
    /// behind the window is not.
    #[test]
    fn reorder_within_window() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_update(5000));
        for n in (0..5000).rev().step_by(7) {
            assert!(w.check_and_update(n), "{}", n);
            assert!(!w.check_and_update(n), "{}", n);
        }
        assert!(w.check_and_update(20_000));
        assert!(!w.check_and_update(20_000 - WINDOW_SIZE - 1));
        assert!(w.check_and_update(20_000 - WINDOW_SIZE + 1));
    }
}
