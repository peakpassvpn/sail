use std::collections::HashMap;

use sail_netstack::{TimerError, TimerId, TimerWheel};

#[test]
fn deadlines_never_fire_early_and_are_ordered() {
    let mut wheel = TimerWheel::new(10, 0);
    wheel.schedule(11, "second").unwrap();
    wheel.schedule(10, "first").unwrap();
    wheel.schedule(2_560, "cascade").unwrap();
    assert!(wheel.advance_to(9).unwrap().is_empty());
    assert_eq!(wheel.advance_to(10).unwrap(), ["first"]);
    assert!(wheel.advance_to(19).unwrap().is_empty());
    assert_eq!(wheel.advance_to(20).unwrap(), ["second"]);
    assert_eq!(wheel.advance_to(2_560).unwrap(), ["cascade"]);
}

#[test]
fn cancellation_removes_the_deadline_without_firing_it() {
    let mut wheel = TimerWheel::new(1, 0);
    let cancelled = wheel.schedule(300, 7).unwrap();
    wheel.schedule(301, 8).unwrap();
    assert_eq!(wheel.cancel(cancelled), Some(7));
    assert_eq!(wheel.advance_to(400).unwrap(), [8]);
    assert!(wheel.is_empty());
}

#[test]
fn rollback_is_rejected_without_mutating_time_or_timers() {
    let mut wheel = TimerWheel::new(5, 100);
    wheel.schedule(150, "kept").unwrap();
    assert!(matches!(
        wheel.advance_to(95),
        Err(TimerError::ClockWentBackwards { .. })
    ));
    assert_eq!(wheel.now_ms(), 100);
    assert_eq!(wheel.len(), 1);
    assert_eq!(wheel.advance_to(150).unwrap(), ["kept"]);
}

#[test]
fn large_jump_expires_due_entries_and_rebuilds_future_buckets() {
    let mut wheel = TimerWheel::new(1, 0);
    wheel.schedule(10, "early").unwrap();
    wheel.schedule(70_000, "middle").unwrap();
    wheel.schedule(200_000, "future").unwrap();
    assert_eq!(wheel.advance_to(100_000).unwrap(), ["early", "middle"]);
    assert_eq!(wheel.len(), 1);
    assert_eq!(wheel.advance_to(200_000).unwrap(), ["future"]);
}

#[test]
fn all_hierarchy_boundaries_cascade() {
    let mut wheel = TimerWheel::new(1, 0);
    for deadline in [255, 256, 257, 65_535, 65_536, 65_537] {
        wheel.schedule(deadline, deadline).unwrap();
    }
    let mut observed = Vec::new();
    for target in [255, 256, 257, 65_535, 65_536, 65_537] {
        observed.extend(wheel.advance_to(target).unwrap());
    }
    assert_eq!(observed, [255, 256, 257, 65_535, 65_536, 65_537]);
}

#[test]
fn maximum_timestamp_deadline_does_not_round_early_or_become_unreachable() {
    let tick_ms = u64::MAX.div_ceil((1_u64 << 32) - 1);
    let mut wheel = TimerWheel::new(tick_ms, 0);
    wheel.schedule(u64::MAX, "last").unwrap();
    assert!(wheel.advance_to(u64::MAX - 1).unwrap().is_empty());
    assert_eq!(wheel.advance_to(u64::MAX).unwrap(), ["last"]);
}

#[test]
fn randomized_schedule_cancel_and_advance_matches_reference_model() {
    const TICK_MS: u64 = 7;
    const STEPS: usize = 10_000;

    let mut wheel = TimerWheel::new(TICK_MS, 0);
    let mut model = HashMap::<u64, (u64, u64)>::new();
    let mut live = Vec::<TimerId>::new();
    let mut current_tick = 0_u64;
    let mut random = 0x6a09_e667_f3bc_c909_u64;

    for step in 0..STEPS {
        random = xorshift64(random);
        match random % 10 {
            0..=5 => {
                let delta_ms = match (random >> 8) % 8 {
                    0 => 0,
                    1 => 1,
                    2 => TICK_MS - 1,
                    3 => TICK_MS,
                    4 => 255 * TICK_MS,
                    5 => 256 * TICK_MS,
                    6 => 65_536 * TICK_MS,
                    _ => (random >> 16) % (200_000 * TICK_MS),
                };
                let deadline_ms = current_tick
                    .saturating_mul(TICK_MS)
                    .saturating_add(delta_ms);
                let value = u64::try_from(step).unwrap();
                let id = wheel.schedule(deadline_ms, value).unwrap();
                let deadline_tick = deadline_ms.div_ceil(TICK_MS).max(current_tick + 1);
                assert!(model.insert(id.get(), (deadline_tick, value)).is_none());
                live.push(id);
            }
            6..=7 if !live.is_empty() => {
                let live_len = u64::try_from(live.len()).unwrap();
                let index = usize::try_from((random >> 16) % live_len).unwrap();
                let id = live.swap_remove(index);
                let (_, expected) = model.remove(&id.get()).unwrap();
                assert_eq!(wheel.cancel(id), Some(expected));
                assert_eq!(wheel.cancel(id), None);
            }
            _ => {
                let advance = match (random >> 8) % 8 {
                    0 => 0,
                    1 => 1,
                    2 => 255,
                    3 => 256,
                    4 => 65_535,
                    5 => 65_536,
                    6 => 70_000,
                    _ => (random >> 16) % 100_000,
                };
                let target_tick = current_tick.saturating_add(advance);
                let target_ms = target_tick.saturating_mul(TICK_MS);
                let mut expected = model
                    .iter()
                    .filter_map(|(&id, &(deadline, value))| {
                        (deadline <= target_tick).then_some((deadline, id, value))
                    })
                    .collect::<Vec<_>>();
                expected.sort_unstable();
                let expected_values = expected
                    .iter()
                    .map(|(_, _, value)| *value)
                    .collect::<Vec<_>>();
                assert_eq!(wheel.advance_to(target_ms).unwrap(), expected_values);
                for (_, id, _) in expected {
                    model.remove(&id);
                }
                live.retain(|id| model.contains_key(&id.get()));
                current_tick = target_tick;

                if current_tick > 0 && random & 0x40 != 0 {
                    let len = wheel.len();
                    assert!(matches!(
                        wheel.advance_to(target_ms - 1),
                        Err(TimerError::ClockWentBackwards { .. })
                    ));
                    assert_eq!(wheel.len(), len);
                }
            }
        }
        assert_eq!(wheel.len(), model.len());
    }

    let mut expected = model
        .into_iter()
        .map(|(id, (deadline, value))| (deadline, id, value))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    let final_tick = expected
        .last()
        .map_or(current_tick, |(deadline, _, _)| *deadline);
    assert_eq!(
        wheel
            .advance_to(final_tick.saturating_mul(TICK_MS))
            .unwrap(),
        expected
            .into_iter()
            .map(|(_, _, value)| value)
            .collect::<Vec<_>>()
    );
    assert!(wheel.is_empty());
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^ (value << 17)
}
