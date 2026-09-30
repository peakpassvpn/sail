//! Waking from sleep, seen without the system telling: a clock that counts
//! the time asleep drifts from one that does not, by the time asleep. The
//! same on every system, with no power-management notices to subscribe to:
//!
//! - Linux, Android: `CLOCK_BOOTTIME` against `CLOCK_MONOTONIC`.
//! - macOS, iOS: `CLOCK_MONOTONIC` (which counts sleep there) against
//!   `CLOCK_UPTIME_RAW`.
//! - Windows: `QueryInterruptTime` against `QueryUnbiasedInterruptTime`.

use std::time::Duration;

/// How often the clocks are compared, and how much more sleep than that
/// is a wake: a judgment call, not measured yet. A shorter poll finds a
/// wake sooner but wakes the process more; the connections a sleep this
/// long breaks are checked in the weak-network tests (5.5).
pub const POLL: Duration = Duration::from_secs(5);
pub const WOKE: Duration = Duration::from_secs(5);

/// The time the system has spent asleep since it started; none where it
/// cannot be told.
pub fn slept() -> Option<Duration> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Some(clock(libc::CLOCK_BOOTTIME)?.saturating_sub(clock(libc::CLOCK_MONOTONIC)?))
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        Some(clock(libc::CLOCK_MONOTONIC)?.saturating_sub(clock(libc::CLOCK_UPTIME_RAW)?))
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::WindowsProgramming::{
            QueryInterruptTime, QueryUnbiasedInterruptTime,
        };
        let (mut with, mut without) = (0u64, 0u64);
        // SAFETY: both write one u64, in units of 100 ns.
        let read = unsafe {
            QueryInterruptTime(&mut with);
            QueryUnbiasedInterruptTime(&mut without)
        };
        (read != 0).then(|| Duration::from_nanos(with.saturating_sub(without).saturating_mul(100)))
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )))]
    {
        None
    }
}

#[cfg(unix)]
#[cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )),
    allow(dead_code)
)]
fn clock(id: libc::clockid_t) -> Option<Duration> {
    // SAFETY: zeroed timespec is valid, and clock_gettime fills it.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
        return None;
    }
    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

/// Calls `woke` each time the system wakes from a sleep longer than
/// `WOKE`, looking every `POLL`; returns only where sleep cannot be told.
pub async fn follow(mut woke: impl FnMut(Duration)) {
    let Some(mut before) = slept() else {
        return;
    };
    let mut ticks = tokio::time::interval(POLL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let Some(now) = slept() else {
            return;
        };
        let asleep = now.saturating_sub(before);
        before = now;
        if asleep > WOKE {
            woke(asleep);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clocks are read, and the sleep they tell only grows.
    #[test]
    fn the_time_asleep_is_read_and_grows() {
        let Some(first) = slept() else {
            return;
        };
        std::thread::sleep(Duration::from_millis(20));
        let then = slept().unwrap();
        assert!(then >= first, "{:?} then {:?}", first, then);
        // Awake, it barely moves.
        assert!(then - first < Duration::from_secs(1));
    }
}
