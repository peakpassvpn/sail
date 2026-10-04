//! What an instance changed in the system, undone however the instance
//! ends: a stop, a failure, a start that fails partway, or a panic
//! unwinding its thread, while the process that hosts it lives on.
//!
//! Each resource registers a step to undo it as soon as it exists. Steps
//! run newest first, so a device's routes go before the device. Each step
//! runs at most once: either its owner runs it (a Drop, a reload replacing
//! it), or `run_all` does at the end. Each step runs on a thread of its
//! own, waited for up to its bound. A step that fails, panics or outlasts
//! its bound is reported as `Left`, for a person to clear by hand, and the
//! others still run.
//!
//! Nothing here panics, as it also runs while a panic unwinds, where a
//! second one would abort the host: no `unwrap`, no indexing, and a
//! poisoned lock is taken as it is.

use std::io;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// How long a step may take, unless it says otherwise: the calls behind
/// them (netlink, the routing socket, resolvectl) answer in milliseconds;
/// 5 s is room for a loaded system (judgment, not measured).
pub const WITHIN: Duration = Duration::from_secs(5);

/// What kind of resource is left, for a program to act on.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeftKind {
    /// A TUN device.
    Tun,
    /// A route.
    Route,
    /// A policy routing rule (Linux ip rule).
    Rule,
    /// DNS settings of the system or of an interface.
    Dns,
    /// An nftables table.
    Nft,
    /// Windows Filtering Platform filters.
    Wfp,
    /// A file written outside sail's own directory.
    File,
    /// A task of the instance still running.
    Task,
}

/// What could not be undone, for a person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Left {
    pub kind: LeftKind,
    /// The resource, e.g. "nft table inet sail_tun0".
    pub resource: String,
    /// Why: the error, "timed out after 5s", or "panicked: ...".
    pub why: String,
    /// The one command that clears it by hand, where there is one.
    pub clear: Option<String>,
}

impl std::fmt::Display for Left {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.resource, self.why)?;
        if let Some(clear) = &self.clear {
            write!(f, "; clear it with `{}`", clear)?;
        }
        Ok(())
    }
}

type Undo = Box<dyn FnOnce() -> io::Result<()> + Send>;

/// The undoing of one resource.
pub struct Step {
    kind: LeftKind,
    resource: String,
    clear: Option<String>,
    within: Duration,
    undo: Undo,
}

impl Step {
    /// Undoes `resource` with `undo`, within `WITHIN`.
    pub fn new(
        kind: LeftKind,
        resource: impl Into<String>,
        undo: impl FnOnce() -> io::Result<()> + Send + 'static,
    ) -> Step {
        Step {
            kind,
            resource: resource.into(),
            clear: None,
            within: WITHIN,
            undo: Box::new(undo),
        }
    }

    /// The command a person runs to clear the resource, should the step
    /// fail.
    pub fn clear(mut self, command: impl Into<String>) -> Step {
        self.clear = Some(command.into());
        self
    }

    /// How long the step may take.
    pub fn within(mut self, within: Duration) -> Step {
        self.within = within;
        self
    }
}

/// A step registered, for its owner to run it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepId(u64);

/// An instance's undo steps; clones share them.
#[derive(Clone, Default)]
pub struct Teardown(Arc<Inner>);

#[derive(Default)]
struct Inner {
    /// The last id given, and the steps not run yet, oldest first.
    steps: Mutex<(u64, Vec<(StepId, Step)>)>,
    left: Mutex<Vec<Left>>,
}

impl std::fmt::Debug for Teardown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Teardown")
            .field("pending", &lock(&self.0.steps).1.len())
            .field("left", &lock(&self.0.left).len())
            .finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Teardown {
    /// Registers `step`, to run once.
    pub fn push(&self, step: Step) -> StepId {
        let mut steps = lock(&self.0.steps);
        steps.0 = steps.0.wrapping_add(1);
        let id = StepId(steps.0);
        steps.1.push((id, step));
        id
    }

    /// Runs the step `id` now, unless it has run.
    pub fn run(&self, id: StepId) {
        let step = {
            let mut steps = lock(&self.0.steps);
            let at = steps.1.iter().position(|(each, _)| *each == id);
            at.map(|at| steps.1.remove(at).1)
        };
        if let Some(step) = step {
            self.execute(step);
        }
    }

    /// Runs `ids` now, the last first, each unless it has run.
    pub fn run_each(&self, ids: &[StepId]) {
        for &id in ids.iter().rev() {
            self.run(id);
        }
    }

    /// Runs every step not run yet, newest first.
    pub fn run_all(&self) {
        loop {
            let step = lock(&self.0.steps).1.pop();
            match step {
                Some((_, step)) => self.execute(step),
                None => return,
            }
        }
    }

    /// What could not be undone, of every step run so far.
    pub fn left(&self) -> Vec<Left> {
        lock(&self.0.left).clone()
    }

    fn execute(&self, step: Step) {
        let Step {
            kind,
            resource,
            clear,
            within,
            undo,
        } = step;
        #[cfg(feature = "fault-injection")]
        let undo: Undo = {
            let name = resource.clone();
            Box::new(move || {
                fault_point!(crate::fault::Point::TeardownStep(prefix) if name.starts_with(prefix.as_str()), name);
                undo()
            })
        };
        if let Err(why) = undo_within(undo, within) {
            tracing::warn!("teardown: {} is left: {}", resource, why);
            lock(&self.0.left).push(Left {
                kind,
                resource,
                why,
                clear,
            });
        } else {
            tracing::debug!("teardown: {} undone", resource);
        }
    }
}

/// Runs `undo` on a thread of its own, waiting `within` for it; inline,
/// where no thread can be had.
fn undo_within(undo: Undo, within: Duration) -> Result<(), String> {
    // The step, where the thread fails to start, comes back for inline.
    let slot = Arc::new(Mutex::new(Some(undo)));
    let (tx, rx) = mpsc::sync_channel(1);
    let theirs = slot.clone();
    let spawned = std::thread::Builder::new()
        .name("sail-teardown".into())
        .spawn(move || {
            let undo = lock(&theirs).take();
            if let Some(undo) = undo {
                let _ = tx.send(caught(undo));
            }
        });
    match spawned {
        Ok(_) => match rx.recv_timeout(within) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(format!("timed out after {:?}", within)),
            Err(RecvTimeoutError::Disconnected) => Err("its thread ended with no answer".into()),
        },
        Err(e) => {
            tracing::debug!("teardown: no thread ({}), the step runs here", e);
            let undo = lock(&slot).take();
            match undo {
                Some(undo) => caught(undo),
                None => Err("lost with its thread".into()),
            }
        }
    }
}

/// `undo`'s result, a panic as an error.
fn caught(undo: Undo) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(undo)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(panic) => Err(format!("panicked: {}", message(&*panic))),
    }
}

fn message(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic".to_string())
}

/// Runs `program` with `args`, killed when it outlasts `within`: a step's
/// command never holds its thread past the step's bound. Linux's steps
/// run commands (resolvectl, fw4).
#[cfg(all(target_os = "linux", feature = "inbound-tun"))]
pub(crate) fn command_within(program: &str, args: &[&str], within: Duration) -> io::Result<()> {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "{} {}: {}",
                    program,
                    args.join(" "),
                    status
                )))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{} {}: timed out after {:?}",
                    program,
                    args.join(" "),
                    within
                ),
            ));
        }
        // A command of these takes milliseconds; 10 ms adds little.
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting(order: &Arc<Mutex<Vec<&'static str>>>, name: &'static str) -> Step {
        let order = order.clone();
        Step::new(LeftKind::Route, name, move || {
            lock(&order).push(name);
            Ok(())
        })
    }

    #[test]
    fn steps_run_newest_first_and_once() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let teardown = Teardown::default();
        teardown.push(counting(&order, "device"));
        let routes = teardown.push(counting(&order, "routes"));
        teardown.push(counting(&order, "rules"));
        teardown.run(routes);
        teardown.run(routes);
        teardown.run_all();
        teardown.run_all();
        assert_eq!(*lock(&order), ["routes", "rules", "device"]);
        assert!(teardown.left().is_empty());
    }

    #[test]
    fn a_failing_or_panicking_step_is_left_and_the_rest_run() {
        let ran = Arc::new(AtomicUsize::new(0));
        let teardown = Teardown::default();
        let counted = |ran: &Arc<AtomicUsize>| {
            let ran = ran.clone();
            move || {
                ran.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        };
        teardown.push(Step::new(LeftKind::Tun, "first", counted(&ran)));
        teardown.push(
            Step::new(LeftKind::Nft, "nft table inet sail_t", || {
                Err(io::Error::other("EPERM"))
            })
            .clear("nft delete table inet sail_t"),
        );
        teardown.push(Step::new(LeftKind::Rule, "ip rule 9000", || {
            panic!("no rule")
        }));
        teardown.push(Step::new(LeftKind::Dns, "last", counted(&ran)));
        teardown.run_all();
        assert_eq!(ran.load(Ordering::SeqCst), 2);
        let left = teardown.left();
        assert_eq!(left.len(), 2);
        assert_eq!(left[0].kind, LeftKind::Rule);
        assert_eq!(left[0].why, "panicked: no rule");
        assert_eq!(left[1].kind, LeftKind::Nft);
        assert_eq!(
            left[1].to_string(),
            "nft table inet sail_t: EPERM; clear it with `nft delete table inet sail_t`"
        );
    }

    #[test]
    fn a_step_past_its_bound_is_left_and_the_rest_do_not_wait() {
        let teardown = Teardown::default();
        let ran = Arc::new(AtomicUsize::new(0));
        let after = ran.clone();
        teardown.push(Step::new(LeftKind::Tun, "after", move || {
            after.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        teardown.push(
            Step::new(LeftKind::Route, "stuck", || {
                std::thread::sleep(Duration::from_secs(3));
                Ok(())
            })
            .within(Duration::from_millis(50)),
        );
        let start = std::time::Instant::now();
        teardown.run_all();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(teardown.left()[0].why, "timed out after 50ms");
    }

    #[test]
    fn a_poisoned_teardown_still_runs() {
        let teardown = Teardown::default();
        let poisoner = teardown.clone();
        let _ = std::thread::spawn(move || {
            let _guard = lock(&poisoner.0.steps);
            panic!("poison");
        })
        .join();
        let ran = Arc::new(AtomicUsize::new(0));
        let counted = ran.clone();
        teardown.push(Step::new(LeftKind::Route, "routes", move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        teardown.run_all();
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }

    #[cfg(all(target_os = "linux", feature = "inbound-tun"))]
    #[test]
    fn a_command_past_its_bound_is_killed() {
        let start = std::time::Instant::now();
        let e = command_within("sleep", &["5"], Duration::from_millis(100)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(command_within("true", &[], WITHIN).is_ok());
        assert!(command_within("false", &[], WITHIN).is_err());
    }
}
