//! The URL tests `urltest` and `load-balance` check their members with:
//! every member at once, through it, every `interval`, while the group is
//! in use.

use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use futures::future::{abortable, AbortHandle, BoxFuture};
use futures::FutureExt;
use tokio::sync::Notify;
use tokio::time::Instant;
use tracing::debug;

use crate::adapter::AnyOutboundHandler;
use crate::app::healthcheck::HttpProbe;
use crate::app::outbound::selector::MemberLatencies;
use crate::app::SyncDnsClient;

/// How long one test may take before its member counts as failed.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A failed connection asks for the members to be tested again, but not
/// more often than this.
const MIN_RETEST: Duration = Duration::from_secs(2);

pub const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(3 * 60);

/// Called with the latencies after every round of tests.
pub type OnTested = Box<dyn Fn(&[Option<Duration>]) + Send + Sync>;

pub struct Checker {
    tag: String,
    members: Vec<AnyOutboundHandler>,
    probe: HttpProbe,
    dns_client: SyncDnsClient,
    interval: Duration,
    /// Tests pause once the group has not been used for this long, and
    /// resume, at once, when it is used again.
    idle: Option<Duration>,
    latencies: MemberLatencies,
    /// Whether a round of tests has been done: before, every member is
    /// taken to be up.
    tested: std::sync::atomic::AtomicBool,
    last_used: Mutex<Instant>,
    wake: Notify,
    on_tested: OnTested,
    /// The test loop, until there is a runtime to spawn it on.
    task: Mutex<Option<BoxFuture<'static, ()>>>,
}

impl Checker {
    /// A checker of `members`, and the handle that stops its tests.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: &str,
        members: Vec<AnyOutboundHandler>,
        probe: HttpProbe,
        dns_client: SyncDnsClient,
        interval: Duration,
        idle: Option<Duration>,
        on_tested: OnTested,
    ) -> (Arc<Self>, AbortHandle) {
        let n = members.len();
        let checker = Arc::new(Self {
            tag: tag.to_string(),
            members,
            probe,
            dns_client,
            interval,
            idle,
            latencies: Arc::new(RwLock::new(vec![None; n])),
            tested: Default::default(),
            last_used: Mutex::new(Instant::now()),
            wake: Notify::new(),
            on_tested,
            task: Mutex::new(None),
        });
        // The loop holds the checker weakly: a checker that is dropped
        // before its loop was ever spawned is not kept alive by it.
        let (task, abort_handle) = abortable(test_loop(Arc::downgrade(&checker)));
        if let Ok(mut slot) = checker.task.lock() {
            *slot = Some(task.map(|_| ()).boxed());
        }
        checker.start();
        (checker, abort_handle)
    }

    /// Spawns the test loop, once there is a runtime: a configuration can
    /// be built without one, to be checked.
    fn start(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let task = self.task.lock().ok().and_then(|mut slot| slot.take());
        if let Some(task) = task {
            runtime.spawn(task);
        }
    }

    pub fn latencies(&self) -> MemberLatencies {
        self.latencies.clone()
    }

    /// Whether member `i` passed its last test, or none was done yet.
    pub fn is_up(&self, i: usize) -> bool {
        if !self.tested.load(std::sync::atomic::Ordering::Relaxed) {
            return true;
        }
        self.latencies
            .read()
            .map(|l| l.get(i).is_some_and(Option::is_some))
            .unwrap_or(true)
    }

    /// Notes that the group is being used, which resumes paused tests.
    pub fn used(&self) {
        self.start();
        let now = Instant::now();
        let was_idle = match self.last_used.lock() {
            Ok(mut last) => {
                let idle = self
                    .idle
                    .is_some_and(|idle| now.duration_since(*last) > idle);
                *last = now;
                idle
            }
            Err(_) => false,
        };
        if was_idle {
            self.wake.notify_one();
        }
    }

    /// Asks for the members to be tested again soon, after a connection
    /// through one failed.
    pub fn retest(&self) {
        self.wake.notify_one();
    }

    fn is_idle(&self) -> bool {
        let Some(idle) = self.idle else {
            return false;
        };
        self.last_used
            .lock()
            .map(|last| last.elapsed() > idle)
            .unwrap_or(false)
    }

    async fn test_all(&self) {
        let tests = self.members.iter().map(|member| async move {
            match tokio::time::timeout(
                TEST_TIMEOUT,
                self.probe.run(self.dns_client.clone(), member),
            )
            .await
            {
                Ok(Ok(latency)) => Some(latency),
                Ok(Err(e)) => {
                    debug!("[{}] test of [{}] failed: {}", self.tag, member.tag(), e);
                    None
                }
                Err(_) => {
                    debug!("[{}] test of [{}] timed out", self.tag, member.tag());
                    None
                }
            }
        });
        let latencies = futures::future::join_all(tests).await;
        debug!(
            "[{}] tested: {}",
            self.tag,
            self.members
                .iter()
                .zip(&latencies)
                .map(|(m, l)| match l {
                    Some(l) => format!("{}({}ms)", m.tag(), l.as_millis()),
                    None => format!("{}(failed)", m.tag()),
                })
                .collect::<Vec<_>>()
                .join(" ")
        );
        if let Ok(mut current) = self.latencies.write() {
            current.clone_from(&latencies);
        }
        self.tested
            .store(true, std::sync::atomic::Ordering::Relaxed);
        (self.on_tested)(&latencies);
    }
}

async fn test_loop(checker: Weak<Checker>) {
    loop {
        let Some(c) = checker.upgrade() else {
            return;
        };
        if !c.is_idle() {
            c.test_all().await;
        } else {
            debug!("[{}] not used lately, tests paused", c.tag);
        }
        let tested = Instant::now();
        let interval = c.interval;
        // Woken early by a failure, or by use after a pause.
        let woken = tokio::time::timeout(interval, c.wake.notified())
            .await
            .is_ok();
        drop(c);
        if woken {
            tokio::time::sleep_until(tested + MIN_RETEST.min(interval)).await;
        }
    }
}
