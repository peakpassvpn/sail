//! An instance's life: made once, started from a configuration, reloaded,
//! stopped, any number of times; any number of instances at once.

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::{JoinHandle, ThreadId};
use std::time::{Duration, SystemTime};

use futures::future::BoxFuture;

use super::{Config, Error, ErrorKind, Options, State, Threads};
use crate::app::logger::{InstanceLog, InstanceLogRef};
use crate::runtime::{Host, Platform, PlatformRef, RuntimeOptions};
use crate::{RuntimeId, RuntimeManager};

/// The runtime ids the instances hold, from their making until they are
/// gone: two never share one.
static IDS: Mutex<BTreeSet<RuntimeId>> = Mutex::new(BTreeSet::new());

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn take_id() -> Result<RuntimeId, Error> {
    let mut ids = lock(&IDS);
    // Not 0: a host of its own may start an instance 0, as sail-cli does.
    (1..=RuntimeId::MAX)
        .find(|id| !ids.contains(id) && !crate::is_running(*id))
        .inspect(|id| {
            ids.insert(*id);
        })
        .ok_or_else(|| Error::state("too many instances"))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Idle,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Starting => "starting",
            Phase::Running => "running",
            Phase::Stopping => "stopping",
            Phase::Stopped => "stopped",
            Phase::Failed => "failed",
        }
    }

    /// Whether the instance's thread may still run.
    fn live(self) -> bool {
        matches!(self, Phase::Starting | Phase::Running | Phase::Stopping)
    }
}

struct Life {
    phase: Phase,
    failure: Option<Error>,
    manager: Option<Arc<RuntimeManager>>,
    thread: Option<JoinHandle<()>>,
    thread_id: Option<ThreadId>,
    /// A stop was asked for this run.
    stop: bool,
    started_at: Option<SystemTime>,
}

pub(super) struct Inner {
    id: RuntimeId,
    options: RuntimeOptions,
    host: Host,
    threads: Threads,
    log: Arc<InstanceLog>,
    platform: Option<Arc<dyn Platform>>,
    clash_modes: bool,
    life: Mutex<Life>,
    /// Told of each change of `life`, for those who wait blocking.
    changed: Condvar,
    /// The state, for those who wait or follow.
    state: tokio::sync::watch::Sender<State>,
    me: Weak<Inner>,
}

/// What a host holds of an instance; the instance's thread holds `Inner`
/// alone, so that the host's last one going asks it to stop.
struct Handle(Arc<Inner>);

impl Drop for Handle {
    fn drop(&mut self) {
        self.0.ask_stop();
    }
}

/// An instance: made once, started and stopped any number of times; its
/// log outlives its runs. Cheap to clone. When the last clone goes, a
/// running instance is asked to stop, without waiting: `stop().await`
/// first is the clean way.
#[derive(Clone)]
pub struct Instance(Arc<Handle>);

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Instance({}, {})", self.inner().id, self.state())
    }
}

impl Instance {
    /// Makes an instance, idle until started.
    pub fn new(options: Options) -> Result<Instance, Error> {
        let Options {
            settings,
            platform,
            log_lines,
            threads,
            clash_modes,
            log,
        } = options;
        let profile: crate::runtime::Profile = match &settings.profile {
            Some(p) => p
                .parse()
                .map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?,
            None => Default::default(),
        };
        let (options, host) = settings
            .resolve()
            .map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?;
        let threads = threads.unwrap_or(match profile {
            // A phone's budget: one thread, as libbox's.
            crate::runtime::Profile::Mobile => Threads::One,
            // As sail-cli runs: a worker a core.
            _ => Threads::Auto,
        });
        let id = take_id()?;
        let log = log.unwrap_or_else(|| InstanceLog::new(log_lines));
        let (state, _) = tokio::sync::watch::channel(State::Idle);
        let inner = Arc::new_cyclic(|me| Inner {
            id,
            options,
            host,
            threads,
            log,
            platform,
            clash_modes,
            life: Mutex::new(Life {
                phase: Phase::Idle,
                failure: None,
                manager: None,
                thread: None,
                thread_id: None,
                stop: false,
                started_at: None,
            }),
            changed: Condvar::new(),
            state,
            me: me.clone(),
        });
        Ok(Instance(Arc::new(Handle(inner))))
    }

    pub(super) fn inner(&self) -> &Arc<Inner> {
        &self.0 .0
    }

    /// Starts it with `config`; returns once it runs, or with why it did
    /// not start. It runs on threads of its own until stopped.
    pub async fn start(&self, config: Config) -> Result<(), Error> {
        let mut states = self.inner().start(config)?;
        let _ = states.wait_for(|s| !matches!(s, State::Starting)).await;
        self.inner().started()
    }

    /// Starts it as `start` does, blocking this thread.
    #[doc(hidden)]
    pub fn blocking_start(&self, config: Config) -> Result<(), Error> {
        self.inner().start(config)?;
        let life = self
            .inner()
            .changed
            .wait_while(lock(&self.inner().life), |l| l.phase == Phase::Starting)
            .unwrap_or_else(|e| e.into_inner());
        drop(life);
        self.inner().started()
    }

    /// Reloads it in place with `config`, or, with none, from the file it
    /// was started from. What did not change goes on; a reload that fails
    /// leaves it as it was. See docs/embed.md for what a reload keeps.
    pub async fn reload(&self, config: Option<Config>) -> Result<(), Error> {
        let host = self.inner().host.clone();
        self.with_manager(move |manager| {
            Box::pin(async move {
                match config {
                    None => manager.reload().await,
                    Some(config) => {
                        let config = match config {
                            Config::Json(text) => crate::config::from_string_for(&text, &host),
                            Config::File(path) => {
                                crate::config::from_file_for(&path.to_string_lossy(), &host)
                            }
                        }
                        .map_err(crate::Error::Config)?;
                        manager.reload_with(config).await
                    }
                }
            })
        })
        .await?
        .map_err(Error::from)
    }

    /// Asks it to stop, then waits until it has: its thread ended, its
    /// runtime gone, its listeners closed. A stop while it starts ends the
    /// start; one not running does nothing.
    pub async fn stop(&self) -> Result<(), Error> {
        let Some(mut states) = self.inner().ask_stop() else {
            return Ok(());
        };
        let _ = states
            .wait_for(|s| !matches!(s, State::Starting | State::Running { .. } | State::Stopping))
            .await;
        self.inner().join();
        Ok(())
    }

    /// Asks it to stop, and waits up to `wait` blocking this thread; zero
    /// does not wait.
    #[doc(hidden)]
    pub fn blocking_stop(&self, wait: Duration) -> Result<(), Error> {
        let own = self.on_own_thread();
        if self.inner().ask_stop().is_none() || own || wait.is_zero() {
            return Ok(());
        }
        let (life, timeout) = self
            .inner()
            .changed
            .wait_timeout_while(lock(&self.inner().life), wait, |l| l.phase.live())
            .unwrap_or_else(|e| e.into_inner());
        drop(life);
        if timeout.timed_out() {
            return Err(Error::new(
                ErrorKind::Timeout,
                "the instance is still stopping",
            ));
        }
        self.inner().join();
        Ok(())
    }

    /// The state now.
    pub fn state(&self) -> State {
        self.inner().state.borrow().clone()
    }

    /// The state, as each change is followed: `changed().await`, then
    /// `borrow()`.
    pub fn states(&self) -> tokio::sync::watch::Receiver<State> {
        self.inner().state.subscribe()
    }

    /// The instance's log: what it keeps, and what comes after.
    pub(super) fn log(&self) -> &Arc<InstanceLog> {
        &self.inner().log
    }

    /// Forgets the lines of the log kept; those following are told.
    pub fn clear_logs(&self) {
        self.inner().log.clear();
    }

    /// Whether this thread is one of the instance's own: the one starting
    /// it, or its runtime's, as a `Platform` callback runs on. A blocking
    /// call there would wait on itself.
    pub fn on_own_thread(&self) -> bool {
        let current = std::thread::current().id();
        lock(&self.inner().life).thread_id == Some(current)
            || crate::app::logger::current().is_some_and(|log| Arc::ptr_eq(&log, &self.inner().log))
    }

    /// What controls the running instance: sail's own, unstable.
    #[doc(hidden)]
    pub fn manager(&self) -> Result<Arc<RuntimeManager>, Error> {
        lock(&self.inner().life)
            .manager
            .clone()
            .ok_or_else(Error::not_running)
    }

    /// The runtime id, unique among the instances alive.
    #[doc(hidden)]
    pub fn id(&self) -> RuntimeId {
        self.inner().id
    }

    /// Runs `task` on the instance's runtime with what controls it, and
    /// waits for it, from any executor.
    #[doc(hidden)]
    pub async fn with_manager<T: Send + 'static>(
        &self,
        task: impl FnOnce(Arc<RuntimeManager>) -> BoxFuture<'static, T>,
    ) -> Result<T, Error> {
        let manager = self.manager()?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = task(manager.clone());
        manager.handle().spawn(async move {
            let _ = tx.send(task.await);
        });
        rx.await.map_err(|_| Error::state("the instance stopped"))
    }

    /// `with_manager`, blocking this thread; on one of the instance's own,
    /// a WrongThread error.
    #[doc(hidden)]
    pub fn blocking_with_manager<T: Send + 'static>(
        &self,
        task: impl FnOnce(Arc<RuntimeManager>) -> BoxFuture<'static, T>,
    ) -> Result<T, Error> {
        if self.on_own_thread() {
            return Err(Error::new(
                ErrorKind::WrongThread,
                "called on a thread of the instance's own, where it would wait on itself",
            ));
        }
        futures::executor::block_on(self.with_manager(task))
    }
}

impl Inner {
    /// What controls the instance, while it runs.
    pub(super) fn manager(&self) -> Result<Arc<RuntimeManager>, Error> {
        lock(&self.life)
            .manager
            .clone()
            .ok_or_else(Error::not_running)
    }

    /// The state, as each change is followed.
    pub(super) fn states(&self) -> tokio::sync::watch::Receiver<State> {
        self.state.subscribe()
    }

    fn publish(&self, life: &Life) {
        let state = match life.phase {
            Phase::Idle => State::Idle,
            Phase::Starting => State::Starting,
            Phase::Running => State::Running {
                since: life.started_at.unwrap_or_else(SystemTime::now),
            },
            Phase::Stopping => State::Stopping,
            Phase::Stopped => State::Stopped,
            Phase::Failed => State::Failed(
                life.failure
                    .clone()
                    .unwrap_or_else(|| Error::new(ErrorKind::Internal, "the instance failed")),
            ),
        };
        self.state.send_replace(state);
        self.changed.notify_all();
    }

    /// Spawns the run; the instance is starting when it returns.
    fn start(&self, config: Config) -> Result<tokio::sync::watch::Receiver<State>, Error> {
        let mut life = lock(&self.life);
        if life.phase.live() {
            return Err(Error::state(format!(
                "the instance is {} already",
                life.phase.name()
            )));
        }
        // The last run's thread has ended, or is ending.
        if let Some(thread) = life.thread.take() {
            let _ = thread.join();
        }
        let this = self
            .me
            .upgrade()
            .ok_or_else(|| Error::state("the instance is being freed"))?;
        let mut host = self.host.clone();
        host.platform = Some(PlatformRef(Arc::new(Running {
            host: self.platform.clone(),
            instance: self.me.clone(),
        })));
        host.log = Some(InstanceLogRef(self.log.clone()));
        host.clash_modes = self.clash_modes;
        let options = crate::StartOptions {
            config: match config {
                Config::Json(text) => crate::Config::Str(text),
                Config::File(path) => crate::Config::File(path.to_string_lossy().into_owned()),
            },
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: match self.threads {
                Threads::One => crate::RuntimeOption::SingleThread,
                Threads::Auto => crate::RuntimeOption::MultiThreadAuto(super::STACK_SIZE),
                Threads::Workers(n, stack) => crate::RuntimeOption::MultiThread(n, stack),
            },
            runtime: self.options.clone(),
            host,
        };
        let id = self.id;
        let states = self.state.subscribe();
        let thread = std::thread::Builder::new()
            .name(format!("sail-{}", id))
            .spawn(move || {
                let stopped = lock(&this.life).stop;
                let result = if stopped {
                    Ok(Ok(()))
                } else {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        crate::start(id, options)
                    }))
                };
                if result.is_err() {
                    // What a run that unwound left registered.
                    crate::forget(id);
                }
                this.finished(result);
            })
            .map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
        life.phase = Phase::Starting;
        life.failure = None;
        life.stop = false;
        life.started_at = None;
        life.thread_id = Some(thread.thread().id());
        life.thread = Some(thread);
        self.publish(&life);
        Ok(states)
    }

    /// How a start ended, once it has.
    fn started(&self) -> Result<(), Error> {
        let life = lock(&self.life);
        match life.phase {
            Phase::Running => Ok(()),
            Phase::Failed => Err(life
                .failure
                .clone()
                .unwrap_or_else(|| Error::state("the instance failed"))),
            _ => Err(Error::new(
                ErrorKind::Cancelled,
                "the instance was stopped while it started",
            )),
        }
    }

    /// Told by the core, on the thread starting it, that it runs.
    fn running(&self, manager: Arc<RuntimeManager>) {
        let mut life = lock(&self.life);
        if life.stop {
            // Asked to stop before the core had it to stop.
            manager.blocking_shutdown();
            life.phase = Phase::Stopping;
        } else {
            life.phase = Phase::Running;
            life.started_at = Some(SystemTime::now());
        }
        life.manager = Some(manager);
        self.publish(&life);
    }

    fn finished(&self, result: std::thread::Result<Result<(), crate::Error>>) {
        let mut life = lock(&self.life);
        life.manager = None;
        life.thread_id = None;
        match result {
            Ok(Ok(())) => life.phase = Phase::Stopped,
            Ok(Err(e)) => {
                life.phase = Phase::Failed;
                life.failure = Some(Error::from(e));
            }
            Err(panic) => {
                let what = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "a panic".to_string());
                life.phase = Phase::Failed;
                life.failure = Some(Error::new(
                    ErrorKind::Panicked,
                    format!("sail panicked: {}", what),
                ));
            }
        }
        self.publish(&life);
    }

    /// Asks it to stop, without waiting; none when it does not run.
    fn ask_stop(&self) -> Option<tokio::sync::watch::Receiver<State>> {
        let mut life = lock(&self.life);
        if !life.phase.live() {
            return None;
        }
        life.stop = true;
        if life.phase != Phase::Stopping {
            life.phase = Phase::Stopping;
            self.publish(&life);
        }
        let manager = life.manager.clone();
        let states = self.state.subscribe();
        drop(life);
        // Either the running instance, or its start, takes it; one not in
        // the core yet sees `stop` when it gets there.
        match manager {
            Some(manager) => {
                manager.blocking_shutdown();
            }
            None => {
                crate::shutdown(self.id);
            }
        }
        Some(states)
    }

    /// Joins the thread of a run that has ended; it ends right after it
    /// says so.
    fn join(&self) {
        let mut life = lock(&self.life);
        if life.phase.live() {
            return;
        }
        if let Some(thread) = life.thread.take() {
            drop(life);
            if thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        lock(&IDS).remove(&self.id);
    }
}

/// The platform an instance runs with: the host's, and the instance to
/// tell once it runs.
struct Running {
    host: Option<Arc<dyn Platform>>,
    instance: Weak<Inner>,
}

impl Platform for Running {
    fn log(&self, line: &str) {
        if let Some(host) = &self.host {
            host.log(line);
        }
    }

    fn protects_sockets(&self) -> bool {
        self.host.as_ref().is_some_and(|h| h.protects_sockets())
    }

    fn protect_socket(&self, fd: i32) -> std::io::Result<()> {
        match &self.host {
            Some(host) => host.protect_socket(fd),
            None => Ok(()),
        }
    }

    fn opens_tun(&self) -> bool {
        self.host.as_ref().is_some_and(|h| h.opens_tun())
    }

    fn open_tun(&self, request: &crate::runtime::TunRequest) -> std::io::Result<i32> {
        match &self.host {
            Some(host) => host.open_tun(request),
            None => Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
        }
    }

    fn finds_connection_owner(&self) -> bool {
        self.host
            .as_ref()
            .is_some_and(|h| h.finds_connection_owner())
    }

    fn find_connection_owner(
        &self,
        query: &crate::runtime::platform::ConnectionQuery,
    ) -> std::io::Result<Option<crate::runtime::platform::ConnectionOwner>> {
        match &self.host {
            Some(host) => host.find_connection_owner(query),
            None => Ok(None),
        }
    }

    fn running(&self, manager: &Arc<RuntimeManager>) {
        if let Some(host) = &self.host {
            host.running(manager);
        }
        if let Some(instance) = self.instance.upgrade() {
            instance.running(manager.clone());
        }
    }
}

/// The runtime ids the instances alive hold: for tests that none leak.
#[doc(hidden)]
pub fn ids_held() -> usize {
    lock(&IDS).len()
}
