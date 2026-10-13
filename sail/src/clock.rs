//! The time the protocols that check it go by: the system's, corrected by
//! the offset the instance's NTP server was measured at (`ntp`), none
//! without one. The system's clock is never set: only what sail reads of
//! it is corrected, as sing-box's `ntp` without `write_to_system`.
//!
//! The offset is the instance's, kept with its tasks' scope: the time read
//! on a task of no instance is the system's.

use std::time::{Duration, SystemTime};

use crate::runtime::scope::TaskScope;

/// The time now, for the instance of the task reading it.
pub fn now() -> SystemTime {
    corrected(SystemTime::now(), TaskScope::current_clock_offset())
}

/// `time`, `nanos` later; earlier when negative.
fn corrected(time: SystemTime, nanos: i64) -> SystemTime {
    let by = Duration::from_nanos(nanos.unsigned_abs());
    if nanos >= 0 {
        time.checked_add(by).unwrap_or(time)
    } else {
        time.checked_sub(by).unwrap_or(time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_offset_moves_the_time_either_way() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(corrected(t, 0), t);
        assert_eq!(corrected(t, 2_000_000_000), t + Duration::from_secs(2));
        assert_eq!(corrected(t, -2_000_000_000), t - Duration::from_secs(2));
    }

    #[tokio::test]
    async fn the_time_is_the_instance_s() {
        let scope = TaskScope::default();
        scope.set_clock_offset(3_600_000_000_000);
        let within = scope.enter(async { now() }).await;
        let outside = now();
        let ahead = within.duration_since(outside).unwrap();
        assert!(ahead > Duration::from_secs(3_599), "{:?}", ahead);
    }
}
