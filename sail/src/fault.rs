//! Faults a test arms, to see what a failure leaves in the system (feature
//! `fault-injection`). The feature is in no default, dist or release set,
//! nor in sail-cli's or sail-ffi's; CI fails a release that names it.
//! Without it `fault_point!` expands to nothing and this module is empty.

/// Panics here when a test armed a matching fault point: a pattern of
/// `fault::Point`, an optional guard, and what panicked, for its message.
#[cfg(feature = "fault-injection")]
macro_rules! fault_point {
    ($point:pat $(if $guard:expr)?, $what:expr) => {
        if $crate::fault::take(|point| matches!(point, $point $(if $guard)?)) {
            panic!("fault injected: {}", $what)
        }
    };
}

/// Nothing: the feature is off. (Unused while every call site is itself
/// under the feature.)
#[cfg(not(feature = "fault-injection"))]
#[allow(unused_macros)]
macro_rules! fault_point {
    ($($any:tt)*) => {};
}

#[cfg(feature = "fault-injection")]
pub use armed::*;

#[cfg(feature = "fault-injection")]
mod armed {
    use std::sync::{Mutex, MutexGuard};

    /// Where a fault can be armed.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Point {
        /// A contained task: the task of a TCP connection an inbound accepted.
        ContainedTask,
        /// An essential task of an instance with a TUN.
        EssentialTask,
        /// The TUN's runner, on the instance's own thread.
        TunRunner,
        /// The TUN's netstack: it ends with an error.
        NetstackFails,
        /// The start, once the TUN is routed: it fails with an error.
        StartFails,
        /// The teardown step of the resource whose name starts so.
        TeardownStep(String),
    }

    /// The points armed, each for one hit, in the whole process.
    static ARMED: Mutex<Vec<Point>> = Mutex::new(Vec::new());

    fn armed() -> MutexGuard<'static, Vec<Point>> {
        ARMED.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Arms `point` for its next hit.
    pub fn arm(point: Point) {
        armed().push(point);
    }

    /// Disarms every point not hit yet.
    pub fn disarm() {
        armed().clear();
    }

    /// Whether a point `matches` was armed; disarms it if so.
    pub(crate) fn take(matches: impl Fn(&Point) -> bool) -> bool {
        let mut armed = armed();
        match armed.iter().position(matches) {
            Some(at) => {
                armed.remove(at);
                true
            }
            None => false,
        }
    }
}
