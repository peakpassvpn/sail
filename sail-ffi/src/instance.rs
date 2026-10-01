//! Instances by handle: made with their settings and the host's callbacks,
//! started from a configuration, reloaded, stopped and freed, any number
//! at once, any number of times.

use std::collections::BTreeSet;
use std::ffi::c_char;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::{JoinHandle, ThreadId};
use std::time::{Duration, SystemTime};

use crate::events::Events;
use crate::handles::Table;
use crate::platform::{Callbacks, FfiPlatform, SailPlatform};
use crate::{call, json, opt_str_arg, out_json, out_value, str_arg, Failure};
use crate::{SAIL_ERR_CANCELLED, SAIL_ERR_TIMEOUT, SAIL_ERR_WRONG_THREAD};

/// An instance, as the host holds it; 0 is none.
pub type SailInstance = u64;

static INSTANCES: Mutex<Table<Instance>> = Mutex::new(Table::new());

/// The runtime ids the instances made here hold, from their making until
/// they have stopped: two never share one.
static IDS: Mutex<BTreeSet<sail::RuntimeId>> = Mutex::new(BTreeSet::new());

/// The lines an instance keeps of its log, unless the settings say: what
/// both sing-box apps keep (their `LogMaxLines`).
const LOG_LINES: usize = 3000;

/// The stack of each worker thread, unless the settings say: tokio's.
const STACK_SIZE: usize = 2 * 1024 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn instance(handle: SailInstance) -> Result<Arc<Instance>, Failure> {
    lock(&INSTANCES)
        .get(handle)
        .ok_or_else(Failure::no_instance)
}

fn take_id() -> Result<sail::RuntimeId, Failure> {
    let mut ids = lock(&IDS);
    // Not 0: a host of its own may start an instance 0, as sail-cli does.
    (1..=sail::RuntimeId::MAX)
        .find(|id| !ids.contains(id) && !sail::is_running(*id))
        .inspect(|id| {
            ids.insert(*id);
        })
        .ok_or_else(|| Failure::state("too many instances"))
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

/// What an instance is started from.
enum Source {
    Text(String),
    File(String),
}

struct Life {
    phase: Phase,
    failure: Option<Failure>,
    manager: Option<Arc<sail::RuntimeManager>>,
    thread: Option<JoinHandle<()>>,
    thread_id: Option<ThreadId>,
    /// A stop was asked for this run.
    stop: bool,
    started_at: Option<SystemTime>,
}

pub(crate) struct Instance {
    pub id: sail::RuntimeId,
    options: sail::runtime::RuntimeOptions,
    host: sail::runtime::Host,
    runtime: RuntimeShape,
    pub log: Arc<sail::app::logger::InstanceLog>,
    callbacks: Arc<Callbacks>,
    life: Mutex<Life>,
    changed: Condvar,
    /// The state, as the `state` subscription follows it.
    pub state: tokio::sync::watch::Sender<json::State>,
    pub events: Events,
    me: Weak<Instance>,
}

#[derive(Clone, Copy)]
enum RuntimeShape {
    SingleThread,
    MultiThread(usize, usize),
}

/// The settings the FFI reads before the core's.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct FfiSettings {
    log_lines: Option<usize>,
    worker_threads: Option<usize>,
    stack_size: Option<usize>,
}

impl Instance {
    fn new(settings: Option<&str>, platform: SailPlatform) -> Result<Arc<Self>, Failure> {
        let (ffi, core) = split_settings(settings)?;
        let (options, host) = crate::tools::start_settings(core.as_deref())?;
        let runtime = match ffi.worker_threads {
            None | Some(0) => RuntimeShape::SingleThread,
            Some(n) => RuntimeShape::MultiThread(n, ffi.stack_size.unwrap_or(STACK_SIZE)),
        };
        let callbacks = Callbacks::new(platform);
        let id = take_id()?;
        let events = match Events::new(id) {
            Ok(events) => events,
            Err(e) => {
                lock(&IDS).remove(&id);
                return Err(e);
            }
        };
        let log = sail::app::logger::InstanceLog::new(ffi.log_lines.unwrap_or(LOG_LINES));
        let (state, _) = tokio::sync::watch::channel(json::State {
            state: Phase::Idle.name(),
            error: None,
            started_at_ms: None,
        });
        Ok(Arc::new_cyclic(|me| Instance {
            id,
            options,
            host,
            runtime,
            log,
            callbacks,
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
            events,
            me: me.clone(),
        }))
    }

    fn publish(&self, life: &Life) {
        self.state.send_replace(json::State {
            state: life.phase.name(),
            error: life.failure.as_ref().map(|f| f.message.clone()),
            started_at_ms: life.started_at.map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as u64)
            }),
        });
        self.changed.notify_all();
    }

    /// Whether this thread is one of the instance's own: the one starting
    /// it, or its runtime's. Waiting on the instance there would wait on
    /// itself.
    pub fn on_own_thread(&self) -> bool {
        let current = std::thread::current().id();
        lock(&self.life).thread_id == Some(current)
            || sail::app::logger::current().is_some_and(|log| Arc::ptr_eq(&log, &self.log))
    }

    /// Whether the host opens the TUN device, and protects sockets.
    pub fn host_callbacks(&self) -> (bool, bool) {
        self.callbacks.given()
    }

    /// What controls the instance, while it runs.
    pub fn manager(&self) -> Result<Arc<sail::RuntimeManager>, Failure> {
        lock(&self.life)
            .manager
            .clone()
            .ok_or_else(|| Failure::state("the instance is not running"))
    }

    /// Runs `task` on the instance's runtime, and waits for it.
    pub fn run<T: Send + 'static>(
        &self,
        task: impl FnOnce(Arc<sail::RuntimeManager>) -> futures::future::BoxFuture<'static, T>,
    ) -> Result<T, Failure> {
        if self.on_own_thread() {
            return Err(Failure::new(
                SAIL_ERR_WRONG_THREAD,
                "called on a thread of the instance's own, where it would wait on itself",
            ));
        }
        let manager = self.manager()?;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let task = task(manager.clone());
        manager.handle().spawn(async move {
            let _ = tx.send(task.await);
        });
        rx.recv()
            .map_err(|_| Failure::state("the instance stopped"))
    }

    /// Told by the core, on the thread starting it, that it runs.
    pub fn running(&self, manager: Arc<sail::RuntimeManager>) {
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

    fn finished(&self, result: Result<(), sail::Error>) {
        let mut life = lock(&self.life);
        life.manager = None;
        life.thread_id = None;
        match result {
            Ok(()) => life.phase = Phase::Stopped,
            Err(e) => {
                life.phase = Phase::Failed;
                life.failure = Some(Failure::from(e));
            }
        }
        self.publish(&life);
    }

    fn start(&self, source: Source) -> Result<(), Failure> {
        let mut life = lock(&self.life);
        if life.phase.live() {
            return Err(Failure::state(format!(
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
            .ok_or_else(|| Failure::state("the instance is being freed"))?;
        let mut host = self.host.clone();
        host.platform = Some(sail::runtime::PlatformRef(Arc::new(FfiPlatform {
            callbacks: self.callbacks.clone(),
            instance: self.me.clone(),
        })));
        host.log = Some(sail::app::logger::InstanceLogRef(self.log.clone()));
        let options = sail::StartOptions {
            config: match source {
                Source::Text(text) => sail::Config::Str(text),
                Source::File(path) => sail::Config::File(path),
            },
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: match self.runtime {
                RuntimeShape::SingleThread => sail::RuntimeOption::SingleThread,
                RuntimeShape::MultiThread(n, stack) => sail::RuntimeOption::MultiThread(n, stack),
            },
            runtime: self.options.clone(),
            host,
        };
        let id = self.id;
        let thread = std::thread::Builder::new()
            .name(format!("sail-{}", id))
            .spawn(move || {
                let stopped = lock(&this.life).stop;
                let result = if stopped {
                    Ok(())
                } else {
                    sail::start(id, options)
                };
                this.finished(result);
            })
            .map_err(|e| Failure::new(crate::SAIL_ERR_IO, e.to_string()))?;
        life.phase = Phase::Starting;
        life.failure = None;
        life.stop = false;
        life.started_at = None;
        life.thread_id = Some(thread.thread().id());
        life.thread = Some(thread);
        self.publish(&life);
        let life = self
            .changed
            .wait_while(life, |l| l.phase == Phase::Starting)
            .unwrap_or_else(|e| e.into_inner());
        match life.phase {
            Phase::Running => Ok(()),
            Phase::Failed => Err(life
                .failure
                .clone()
                .unwrap_or_else(|| Failure::state("the instance failed"))),
            _ => Err(Failure::new(
                SAIL_ERR_CANCELLED,
                "the instance was stopped while it started",
            )),
        }
    }

    /// Asks the instance to stop, then waits up to `wait` for it to have
    /// stopped; on a thread of its own, it does not wait.
    pub fn stop(&self, wait: Duration) -> Result<(), Failure> {
        let own = self.on_own_thread();
        let mut life = lock(&self.life);
        if !life.phase.live() {
            return Ok(());
        }
        life.stop = true;
        if life.phase != Phase::Stopping {
            life.phase = Phase::Stopping;
            self.publish(&life);
        }
        let manager = life.manager.clone();
        drop(life);
        // Either the running instance, or its start, takes it; one not in
        // the core yet sees `stop` when it gets there.
        match manager {
            Some(manager) => {
                manager.blocking_shutdown();
            }
            None => {
                sail::shutdown(self.id);
            }
        }
        if own || wait.is_zero() {
            return Ok(());
        }
        let (mut life, timeout) = self
            .changed
            .wait_timeout_while(lock(&self.life), wait, |l| l.phase.live())
            .unwrap_or_else(|e| e.into_inner());
        if timeout.timed_out() {
            return Err(Failure::new(
                SAIL_ERR_TIMEOUT,
                "the instance is still stopping",
            ));
        }
        if let Some(thread) = life.thread.take() {
            drop(life);
            let _ = thread.join();
        }
        Ok(())
    }

    fn reload(&self, config: Option<String>) -> Result<(), Failure> {
        self.run(move |manager| {
            Box::pin(async move {
                match config {
                    Some(text) => {
                        let config =
                            sail::config::from_string(&text).map_err(sail::Error::Config)?;
                        manager.reload_with(config).await
                    }
                    None => manager.reload().await,
                }
            })
        })?
        .map_err(Failure::from)
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        lock(&IDS).remove(&self.id);
    }
}

/// The FFI's own settings, and the rest, the core's, as JSON.
fn split_settings(settings: Option<&str>) -> Result<(FfiSettings, Option<String>), Failure> {
    let Some(settings) = settings else {
        return Ok((FfiSettings::default(), None));
    };
    let mut all: serde_json::Map<String, serde_json::Value> = serde_json::from_str(settings)
        .map_err(|e| Failure::new(crate::SAIL_ERR_CONFIG, format!("settings: {}", e)))?;
    let mut ffi = serde_json::Map::new();
    for key in ["log_lines", "worker_threads", "stack_size"] {
        if let Some(value) = all.remove(key) {
            ffi.insert(key.into(), value);
        }
    }
    let ffi: FfiSettings = serde_json::from_value(serde_json::Value::Object(ffi))
        .map_err(|e| Failure::new(crate::SAIL_ERR_CONFIG, format!("settings: {}", e)))?;
    Ok((ffi, Some(serde_json::Value::Object(all).to_string())))
}

/// Makes an instance, idle until started.
///
/// @param settings JSON, or null for the defaults: the core's
///     (`{"profile": "mobile", "set": ["relay.buffer_size=32"], "data_dir",
///     "cache_dir", "log_to_system", "socket_protect", "sub_store"}`; on
///     iOS and Android the "mobile" profile and the system log unless
///     said), and the FFI's: `log_lines`, the lines of its log kept
///     (3000), `worker_threads`, 0 or unset for one thread, and
///     `stack_size` of each worker, in bytes.
/// @param platform What the host does for it, or null for nothing; read
///     during the call, its callbacks kept until `release`.
/// @param out Takes the instance's handle.
/// @param err Takes the message of a failure, or null.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_new(
    settings: *const c_char,
    platform: *const SailPlatform,
    out: *mut SailInstance,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        if out.is_null() {
            return Err(Failure::invalid("the out pointer is null"));
        }
        let settings = unsafe { opt_str_arg(settings, "settings") }?;
        let platform = unsafe { SailPlatform::read(platform) }?;
        let instance = Instance::new(settings, platform)?;
        out_value(out, lock(&INSTANCES).insert(instance))
    })
}

/// Starts the instance with the configuration `config`, in any format sail
/// reads (sing-box's JSON, Clash's YAML, a Surge profile). Returns once it
/// runs, or failed; it runs on a thread of its own until stopped.
///
/// @param err Takes why it did not start, or null.
/// @return SAIL_ERR_STATE when it is starting or running already;
///     SAIL_ERR_CANCELLED when stopped while it started.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_start(
    instance: SailInstance,
    config: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let config = unsafe { str_arg(config, "config") }?.to_string();
        self::instance(instance)?.start(Source::Text(config))
    })
}

/// Starts the instance as `sail_instance_start` does, from the file at
/// `path`, in the format its extension names; a reload without a
/// configuration reads it again.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_start_file(
    instance: SailInstance,
    path: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let path = unsafe { str_arg(path, "path") }?.to_string();
        self::instance(instance)?.start(Source::File(path))
    })
}

/// Reloads the running instance with `config`, or, when null, from the
/// file it was started from. What did not change goes on: connections,
/// selections, the delays measured. A reload that fails leaves the
/// instance as it was.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_reload(
    instance: SailInstance,
    config: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let config = unsafe { opt_str_arg(config, "config") }?.map(str::to_owned);
        self::instance(instance)?.reload(config)
    })
}

/// Stops the instance, and waits up to `timeout_ms` for it to have
/// stopped; 0 asks without waiting. A stop while it starts ends the
/// start. Stopping one not running does nothing. Called on a thread of
/// the instance's own (in `protect_socket` or `open_tun`), it asks
/// without waiting.
///
/// @return SAIL_OK once stopped, or asked; SAIL_ERR_TIMEOUT if it is still
///     stopping.
#[no_mangle]
pub extern "C" fn sail_instance_stop(
    instance: SailInstance,
    timeout_ms: u32,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        self::instance(instance)?.stop(Duration::from_millis(u64::from(timeout_ms)))
    })
}

/// Frees the instance: the handle names nothing from now on. It is asked
/// to stop, without waiting, and its subscriptions end, each context
/// released. The platform's `release` is called once it has stopped and
/// sail calls none of its callbacks any more. Freeing a handle freed, or
/// 0, does nothing.
#[no_mangle]
pub extern "C" fn sail_instance_free(instance: SailInstance) {
    call(std::ptr::null_mut(), || {
        let Some(instance) = lock(&INSTANCES).remove(instance) else {
            return Ok(());
        };
        let _ = instance.stop(Duration::ZERO);
        instance.events.close();
        Ok(())
    });
}

/// The instance's state, as JSON: `{"state": "idle" | "starting" |
/// "running" | "stopping" | "stopped" | "failed", "error": why it failed,
/// or null, "started_at_ms": when it last started running, or null}`.
#[no_mangle]
pub unsafe extern "C" fn sail_instance_state(
    instance: SailInstance,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        let state = self::instance(instance)?.state.borrow().clone();
        out_json(out, &state)
    })
}

#[cfg(test)]
pub(crate) fn live_instances() -> usize {
    lock(&INSTANCES).values().count()
}

#[cfg(test)]
pub(crate) fn ids_held() -> usize {
    lock(&IDS).len()
}
