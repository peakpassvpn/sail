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
    /// One bit per bucket that holds a timer, for finding the next deadline
    /// without walking the buckets.
    occupied: [[u64; SLOTS / 64]; LEVELS],
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
            occupied: [[0; SLOTS / 64]; LEVELS],
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
        self.insert_into(level, slot, id);
        Ok(id)
    }

    pub fn cancel(&mut self, id: TimerId) -> Option<T> {
        let entry = self.entries.remove(&id)?;
        self.remove_from(entry.level, entry.slot, id);
        Some(entry.value)
    }

    /// The earliest time a timer may expire, or `None` with none scheduled.
    ///
    /// Within the first level's 256 ticks it is the deadline itself; past
    /// them it is the start of the bucket the soonest waits in, when its
    /// timers move a level down. It is never late: a caller that sleeps
    /// until it and then advances fires each timer on time, waking early at
    /// most once for each level a timer passes through.
    #[must_use]
    pub fn next_deadline_ms(&self) -> Option<u64> {
        if self.entries.is_empty() {
            return None;
        }
        let mut soonest: Option<u64> = None;
        for level in 0..LEVELS {
            let shift = 8 * level;
            let window = self.current_tick >> shift;
            // A higher level's buckets all start after this one's next.
            if soonest.is_some_and(|tick| tick <= window.saturating_add(1) << shift) {
                break;
            }
            let Some(ahead) =
                first_occupied(&self.occupied[level], slot_for(self.current_tick, level))
            else {
                continue;
            };
            let tick = (window.saturating_add(ahead) << shift).max(self.current_tick + 1);
            soonest = Some(soonest.map_or(tick, |soonest| soonest.min(tick)));
        }
        soonest.map(|tick| tick.saturating_mul(self.tick_ms))
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
            let due = self.take_slot(0, slot);
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
            let ids = self.take_slot(level, slot);
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
        self.occupied = [[0; SLOTS / 64]; LEVELS];
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
        self.insert_into(level, slot, id);
    }

    fn insert_into(&mut self, level: usize, slot: usize, id: TimerId) {
        self.buckets[level][slot].insert(id);
        self.occupied[level][slot / 64] |= 1 << (slot % 64);
    }

    fn remove_from(&mut self, level: usize, slot: usize, id: TimerId) {
        let bucket = &mut self.buckets[level][slot];
        bucket.remove(&id);
        if bucket.is_empty() {
            self.occupied[level][slot / 64] &= !(1 << (slot % 64));
        }
    }

    fn take_slot(&mut self, level: usize, slot: usize) -> BTreeSet<TimerId> {
        self.occupied[level][slot / 64] &= !(1 << (slot % 64));
        std::mem::take(&mut self.buckets[level][slot])
    }
}

/// How many buckets past `start` the first occupied one is, wrapping
/// around: `start` itself is 0.
fn first_occupied(occupied: &[u64; SLOTS / 64], start: usize) -> Option<u64> {
    let words = occupied.len();
    let mut mask = u64::MAX << (start % 64);
    // The start word twice: from `start` up first, all of it last.
    for word in (start / 64..).take(words + 1) {
        let hits = occupied[word % words] & mask;
        if hits != 0 {
            let bit = usize::try_from(hits.trailing_zeros()).expect("a bit index is below 64");
            let slot = (word % words) * 64 + bit;
            return Some(u64::try_from((slot + SLOTS - start) % SLOTS).expect("below 256"));
        }
        mask = u64::MAX;
    }
    None
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

    #[test]
    fn next_deadline_is_none_when_empty_and_exact_within_the_first_level() {
        let mut wheel = TimerWheel::new(10, 1_000);
        assert_eq!(wheel.next_deadline_ms(), None);
        let late = wheel.schedule(3_000, 1_u32).unwrap();
        let soon = wheel.schedule(1_041, 2_u32).unwrap();
        // Rounded up to the tick, as it fires.
        assert_eq!(wheel.next_deadline_ms(), Some(1_050));
        wheel.cancel(soon);
        assert_eq!(wheel.next_deadline_ms(), Some(3_000));
        wheel.cancel(late);
        assert_eq!(wheel.next_deadline_ms(), None);
        assert!(wheel.occupied.iter().flatten().all(|word| *word == 0));
    }

    /// Sleeping until each next deadline and advancing there fires every
    /// timer at its deadline, never later, with few early wakes.
    #[test]
    fn sleeping_until_the_next_deadline_fires_every_timer_on_time() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        let mut wheel = TimerWheel::new(1, 0);
        let mut live = std::collections::HashMap::new();
        for value in 0..2_000_u64 {
            // Spread over all four levels' ranges.
            let deadline = 1 + next(10_u64.pow(1 + u32::try_from(value % 8).unwrap()));
            let id = wheel.schedule(deadline, value).unwrap();
            live.insert(value, (id, deadline));
        }
        for value in (0..2_000_u64).step_by(3) {
            let (id, _) = live.remove(&value).unwrap();
            assert_eq!(wheel.cancel(id), Some(value));
        }
        let mut now = 0;
        let mut wakes = 0;
        while let Some(deadline) = wheel.next_deadline_ms() {
            let soonest = live.values().map(|(_, deadline)| *deadline).min().unwrap();
            assert!(
                deadline > now && deadline <= soonest,
                "{deadline} {soonest}"
            );
            now = deadline;
            wakes += 1;
            for value in wheel.advance_to(now).unwrap() {
                let (_, deadline) = live.remove(&value).unwrap();
                assert_eq!(deadline, now, "timer {value}");
            }
        }
        assert!(live.is_empty());
        // One wake per distinct deadline, plus at most one per level passed.
        assert!(wakes <= 2_000 * 4, "{wakes}");
    }
}
