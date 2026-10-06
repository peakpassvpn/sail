//! Shard-local hierarchical timer wheel with a virtual-time API.

use std::collections::BTreeSet;
use std::fmt;

const LEVELS: usize = 4;
const SLOTS: usize = 256;
const LARGE_ADVANCE_TICKS: u64 = 65_536;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimerId(u64);

impl TimerId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerError {
    ClockWentBackwards { current_ms: u64, requested_ms: u64 },
    DeadlineOutOfRange,
}

impl fmt::Display for TimerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockWentBackwards {
                current_ms,
                requested_ms,
            } => write!(
                formatter,
                "timer clock moved backwards from {current_ms}ms to {requested_ms}ms"
            ),
            Self::DeadlineOutOfRange => formatter.write_str("timer deadline exceeds wheel range"),
        }
    }
}

impl std::error::Error for TimerError {}

#[derive(Debug)]
struct Entry<T> {
    deadline_tick: u64,
    level: usize,
    slot: usize,
    value: T,
}

/// A four-level, 256-slot timer wheel owned by one shard.
///
/// Deadlines are rounded up to `tick_ms` and therefore never fire early. The
/// wheel spans roughly `tick_ms * 2^32`. Very large virtual-clock jumps use a
/// bounded rebuild path instead of iterating every skipped tick.
#[derive(Debug)]
pub struct TimerWheel<T> {
    tick_ms: u64,
    current_tick: u64,
    next_id: u64,
    buckets: Vec<Vec<BTreeSet<TimerId>>>,
    entries: crate::FlowMap<TimerId, Entry<T>>,
}

impl<T> TimerWheel<T> {
    /// # Panics
    ///
    /// Panics when `tick_ms` is zero.
    #[must_use]
    pub fn new(tick_ms: u64, now_ms: u64) -> Self {
        assert!(tick_ms > 0, "timer tick must be non-zero");
        let buckets = (0..LEVELS)
            .map(|_| (0..SLOTS).map(|_| BTreeSet::new()).collect())
            .collect();
        Self {
            tick_ms,
            current_tick: now_ms / tick_ms,
            next_id: 0,
            buckets,
            entries: crate::FlowMap::default(),
        }
    }

    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.current_tick.saturating_mul(self.tick_ms)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// # Errors
    ///
    /// Returns [`TimerError::DeadlineOutOfRange`] if the deadline lies beyond
    /// the four-level wheel horizon.
    ///
    /// # Panics
    ///
    /// Panics only if the wheel's non-zero tick invariant is internally
    /// violated; [`TimerWheel::new`] prevents this through its public API.
    pub fn schedule(&mut self, deadline_ms: u64, value: T) -> Result<TimerId, TimerError> {
        let deadline_tick = deadline_ms
            .div_ceil(self.tick_ms)
            .max(self.current_tick.saturating_add(1));
        if deadline_tick.saturating_sub(self.current_tick) >= (1_u64 << 32) {
            return Err(TimerError::DeadlineOutOfRange);
        }
        let id = TimerId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        let (level, slot) = bucket_for(self.current_tick, deadline_tick);
        self.entries.insert(
            id,
            Entry {
                deadline_tick,
                level,
                slot,
                value,
            },
        );
        self.buckets[level][slot].insert(id);
        Ok(id)
    }

    pub fn cancel(&mut self, id: TimerId) -> Option<T> {
        self.entries.remove(&id).map(|entry| {
            self.buckets[entry.level][entry.slot].remove(&id);
            entry.value
        })
    }

    /// Advances virtual time and returns expired values in deadline order.
    ///
    /// # Errors
    ///
    /// Returns [`TimerError::ClockWentBackwards`] without changing state if
    /// `now_ms` precedes the current wheel time.
    pub fn advance_to(&mut self, now_ms: u64) -> Result<Vec<T>, TimerError> {
        if now_ms < self.now_ms() {
            return Err(TimerError::ClockWentBackwards {
                current_ms: self.now_ms(),
                requested_ms: now_ms,
            });
        }
        let target_tick = if now_ms == u64::MAX {
            now_ms.div_ceil(self.tick_ms)
        } else {
            now_ms / self.tick_ms
        };
        if target_tick.saturating_sub(self.current_tick) > LARGE_ADVANCE_TICKS {
            return Ok(self.large_advance(target_tick));
        }

        let mut expired = Vec::new();
        while self.current_tick < target_tick {
            self.current_tick += 1;
            self.cascade_boundaries();
            let slot = slot_for(self.current_tick, 0);
            let due = std::mem::take(&mut self.buckets[0][slot]);
            for id in due {
                let Some(entry) = self.entries.remove(&id) else {
                    continue;
                };
                if entry.deadline_tick <= self.current_tick {
                    expired.push(entry.value);
                } else {
                    let deadline_tick = entry.deadline_tick;
                    self.entries.insert(id, entry);
                    self.place(id, deadline_tick);
                }
            }
        }
        Ok(expired)
    }

    fn cascade_boundaries(&mut self) {
        for level in (1..LEVELS).rev() {
            let lower_bits = 8 * level;
            let mask = (1_u64 << lower_bits) - 1;
            if self.current_tick & mask != 0 {
                continue;
            }
            let slot = slot_for(self.current_tick, level);
            let ids = std::mem::take(&mut self.buckets[level][slot]);
            for id in ids {
                if let Some(entry) = self.entries.get(&id) {
                    self.place(id, entry.deadline_tick);
                }
            }
        }
    }

    fn large_advance(&mut self, target_tick: u64) -> Vec<T> {
        self.current_tick = target_tick;
        let mut due: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                (entry.deadline_tick <= target_tick).then_some((entry.deadline_tick, *id))
            })
            .collect();
        due.sort_unstable_by_key(|(deadline, id)| (*deadline, id.0));
        let expired = due
            .into_iter()
            .filter_map(|(_, id)| self.entries.remove(&id).map(|entry| entry.value))
            .collect();
        for level in &mut self.buckets {
            for slot in level {
                slot.clear();
            }
        }
        let future: Vec<_> = self
            .entries
            .iter()
            .map(|(id, entry)| (*id, entry.deadline_tick))
            .collect();
        for (id, deadline_tick) in future {
            self.place(id, deadline_tick);
        }
        expired
    }

    fn place(&mut self, id: TimerId, deadline_tick: u64) {
        let (level, slot) = bucket_for(self.current_tick, deadline_tick);
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.level = level;
            entry.slot = slot;
        }
        self.buckets[level][slot].insert(id);
    }
}

fn bucket_for(current_tick: u64, deadline_tick: u64) -> (usize, usize) {
    let delta = deadline_tick.saturating_sub(current_tick);
    let level = match delta {
        0..=255 => 0,
        256..=65_535 => 1,
        65_536..=16_777_215 => 2,
        _ => 3,
    };
    (level, slot_for(deadline_tick, level))
}

fn slot_for(tick: u64, level: usize) -> usize {
    usize::try_from((tick >> (8 * level)) & 0xff).expect("slot is one byte")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_cancel_and_reschedule_retains_only_live_bucket_ids() {
        let mut wheel = TimerWheel::new(10, 0);
        let mut timer = wheel.schedule(60_000, 0_u64).unwrap();
        for value in 1..10_000 {
            assert_eq!(wheel.cancel(timer), Some(value - 1));
            timer = wheel.schedule(60_000 + value, value).unwrap();
        }

        let bucket_ids = wheel
            .buckets
            .iter()
            .flat_map(|level| level.iter())
            .map(BTreeSet::len)
            .sum::<usize>();
        assert_eq!(wheel.len(), 1);
        assert_eq!(bucket_ids, wheel.len());
        assert_eq!(wheel.cancel(timer), Some(9_999));
        assert!(wheel.buckets.iter().flatten().all(BTreeSet::is_empty));
    }
}
