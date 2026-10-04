//! sail embedded in a host's process: the one stable part of the crate.
//!
//! An [`Instance`] is made with [`Options`], started from a configuration
//! (sing-box's JSON is the contract; a file may be any format sail reads),
//! reloaded in place, queried, dialled through, followed, and stopped.
//! Every call is async and runtime-agnostic: the host awaits it on its
//! own runtime (or any executor), and the work runs on the instance's.
//! The C ABI (sail-ffi) is built on this module, so the two do the same.
//!
//! What only grows here: the types (fields and variants are
//! `non_exhaustive`), the functions, [`ErrorKind`] and its codes. A break
//! raises the version's minor number before 1.0, and is in the release
//! notes. Everything else in the crate is public for sail's own crates
//! only, and changes without notice. docs/embed.md is the contract: what a
//! reload keeps, the threads, the order of a snapshot and what follows.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

mod dial;
mod error;
mod instance;
mod logs;
mod network;
mod streams;

pub use crate::control::{
    ConnectionInfo, Delay, Failure, GroupInfo, InboundInfo, Mode, OutboundInfo, ProviderInfo,
    RuleSetInfo, SourceKind, SubscriptionInfo, Traffic,
};
pub use crate::control::{InboundChange, ReloadNote, ReloadPath, ReloadReport};
pub use crate::platform::sweep::RunDir;
pub use crate::runtime::platform::{ConnectionOwner, ConnectionQuery};
pub use crate::runtime::{Platform, TunRequest};
pub use crate::session::{Network, SocksAddr as Address};
pub use dial::{DialDatagram, DialStream};
pub use error::{Error, ErrorKind};
pub use instance::{ids_held, Instance};
pub use logs::{LogBatch, LogFilter, LogLine};
pub use network::{
    DialFailure, DialStage, DnsExchange, DnsOutcome, DnsSource, DomainSource, Event, GroupSwitch,
    Interface, Kinds, NetworkChangeKind, NetworkChangeReason, NetworkEvent, NetworkKind,
    NetworkState, RouteAction, RoutedConnection, SwitchReason, TunName, UserEvent,
};
pub use streams::Status;

/// Undoes what an instance killed with its process left in the system
/// (rules, routes, a TUN), as the ledgers under `run_dir` list them, with
/// no instance: a desktop service does it at its start. Every start does
/// it too. One line per thing undone; failures are logged, not returned.
/// An entry of a TUN still up in this network namespace is left, as a live
/// instance's.
pub fn sweep(run_dir: &RunDir) -> Vec<String> {
    crate::platform::sweep::sweep(run_dir)
}

/// The stack of each worker thread, unless the options say: tokio's.
const STACK_SIZE: usize = 2 * 1024 * 1024;

/// The lines an instance keeps of its log, unless the options say: what
/// both sing-box apps keep (their `LogMaxLines`).
const LOG_LINES: usize = 3000;

/// What an instance runs.
#[derive(Debug, Clone)]
pub enum Config {
    /// sing-box's JSON, sail's own, as text: the contract. (Clash's YAML
    /// and Surge profiles read too, as the CLI reads them.)
    Json(String),
    /// A file, in the format its extension or content says; a reload
    /// without a configuration reads it again.
    File(PathBuf),
}

/// The threads an instance's runtime runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Threads {
    /// One thread: the mobile profile's default.
    One,
    /// A worker a core, as sail-cli runs: every other profile's default.
    Auto,
    /// `n` workers of `stack` bytes each.
    Workers(usize, usize),
}

/// How an instance is made: `Options::new()`, then its setters.
#[derive(Default)]
pub struct Options {
    settings: crate::runtime::StartSettings,
    platform: Option<Arc<dyn Platform>>,
    log_lines: usize,
    threads: Option<Threads>,
    clash_modes: bool,
    log: Option<Arc<crate::app::logger::InstanceLog>>,
    stop_within: Option<Duration>,
}

impl Options {
    /// The desktop profile, its threads as sail-cli's, no platform, 3000
    /// lines of log kept.
    pub fn new() -> Self {
        Self {
            log_lines: LOG_LINES,
            ..Default::default()
        }
    }

    /// sail's start settings as JSON: `{"profile", "set": ["relay.buffer_size=32"],
    /// "data_dir", "cache_dir", "log_to_system", "socket_protect",
    /// "sub_store", "ui_download_url", "asset_sources"}`, as `sail -s`
    /// and the C ABI take them.
    pub fn settings_json(mut self, json: &str) -> Result<Self, Error> {
        self.settings = crate::runtime::StartSettings::from_json(json)
            .map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?;
        Ok(self)
    }

    /// The settings, as a host that has them parsed gives them.
    #[doc(hidden)]
    pub fn settings(mut self, settings: crate::runtime::StartSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Where the ledgers of what an instance changes in the system are
    /// kept, for the sweep after a kill: the system's by default (Linux's
    /// `/run/sail`; none elsewhere yet), a directory, or none. An instance
    /// that changes nothing (no TUN, no routes) creates nothing there.
    pub fn run_dir(mut self, run_dir: RunDir) -> Self {
        self.settings.run_dir = match run_dir {
            RunDir::Dir(dir) => Some(crate::runtime::RunDirSetting::Dir(dir)),
            RunDir::Off => Some(crate::runtime::RunDirSetting::Off),
            _ => None,
        };
        self
    }

    /// The tuning profile: `mobile`, `desktop`, `server` or `router`.
    pub fn profile(mut self, profile: &str) -> Self {
        self.settings.profile = Some(profile.to_string());
        self
    }

    /// Where it keeps its state: the cache of rule-sets and providers
    /// downloaded, relative paths in the configuration.
    pub fn data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.settings.data_dir = Some(dir.into());
        self
    }

    pub fn cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.settings.cache_dir = Some(dir.into());
        self
    }

    /// What only the host can do: open the TUN, protect sockets, tell who
    /// owns a connection, take the system log. Every method is optional.
    pub fn platform(mut self, platform: Arc<dyn Platform>) -> Self {
        self.platform = Some(platform);
        self
    }

    /// The lines of its log it keeps, for a follower's backlog; 0 keeps
    /// none.
    pub fn log_lines(mut self, lines: usize) -> Self {
        self.log_lines = lines;
        self
    }

    /// How long a stop waits for the instance's tasks to end before it
    /// says what is left (`stop()`'s Timeout, `stop_report()`): 2 s unless
    /// set.
    pub fn stop_within(mut self, within: Duration) -> Self {
        self.stop_within = Some(within);
        self
    }

    /// The threads its runtime runs on; the profile's when unset.
    pub fn threads(mut self, threads: Threads) -> Self {
        self.threads = Some(threads);
        self
    }

    /// Whether the modes the rules name are there without a Clash API, as
    /// libbox's apps have them.
    pub fn clash_modes(mut self, on: bool) -> Self {
        self.clash_modes = on;
        self
    }

    /// The log it keeps, the host's own, to read what a start that failed
    /// logged.
    #[doc(hidden)]
    pub fn log(mut self, log: Arc<crate::app::logger::InstanceLog>) -> Self {
        self.log = Some(log);
        self
    }
}

/// Where an instance is in its life.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Made, never started.
    Idle,
    Starting,
    Running {
        since: SystemTime,
    },
    Stopping,
    Stopped,
    /// It did not start, or it ended on its own: why.
    Failed(Error),
}

impl State {
    /// The state's name: `idle`, `starting`, `running`, `stopping`,
    /// `stopped` or `failed`.
    pub fn name(&self) -> &'static str {
        match self {
            State::Idle => "idle",
            State::Starting => "starting",
            State::Running { .. } => "running",
            State::Stopping => "stopping",
            State::Stopped => "stopped",
            State::Failed(_) => "failed",
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What sends sail's log lines to the instances they belong to, for a
/// host that installs its own `tracing` subscriber: add it to that
/// subscriber, and `Instance::logs` gets them. Sail then installs none of
/// its own, and a configuration's `log.output` is the host's business.
/// The host's global filters apply first: let sail's targets through at
/// the levels its instances log at.
pub fn tracing_layer<S>() -> impl tracing_subscriber::Layer<S> + Send + Sync + 'static
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    crate::app::logger::instance_layer()
}

/// Checks `config` as a start with `options` would: it reads and builds,
/// and nothing starts. No listener is bound, nothing is dialled, nothing
/// is downloaded. The warnings are what a start would log of it (fields
/// sail ignores, deprecated ones, what building it warned of), as
/// `sail -T` prints them. It blocks while it builds, on a thread of its
/// own, so any thread may call it, a runtime's too.
pub fn check(config: &Config, options: &Options) -> Result<Vec<String>, Error> {
    let config = config.clone();
    let settings = options.settings.clone();
    let platform = options.platform.clone();
    std::thread::Builder::new()
        .name("sail-check".into())
        .spawn(move || {
            let (runtime, mut host) = settings
                .resolve()
                .map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?;
            host.platform = platform.map(crate::runtime::PlatformRef);
            let env = crate::runtime::RuntimeEnv {
                options: runtime,
                host,
                ..Default::default()
            };
            let (read, mut warnings) = crate::app::logger::collect_warnings(|| match &config {
                Config::Json(text) => crate::config::from_string_for(text, &env.host),
                Config::File(path) => {
                    crate::config::from_file_for(&path.to_string_lossy(), &env.host)
                }
            });
            let read = read.map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?;
            warnings.extend(read.warnings.iter().cloned());
            warnings.extend(
                crate::check_config_with_warnings(&read, &env)
                    .map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?,
            );
            Ok(warnings)
        })
        .map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?
        .join()
        .unwrap_or_else(|_| Err(Error::new(ErrorKind::Panicked, "sail panicked checking")))
}

/// The compiled-in features, as the management API lists them.
pub fn features() -> Vec<&'static str> {
    crate::control::features()
}

/// Whether a panic inside sail is caught, as docs/embed.md says (the
/// instance fails, or the task alone ends; the host goes on): true when
/// built with `panic = "unwind"`. With `panic = "abort"` any panic ends
/// the process. A host asserts it at start.
pub const PANICS_ARE_CAUGHT: bool = cfg!(panic = "unwind");

pub use crate::control::events::Fault;
pub use crate::runtime::scope::{StopReport, TaskClass};

/// What this sail is: its release.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What this sail was built from, for a host's diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BuildInfo {
    /// The release: `VERSION`.
    pub version: &'static str,
    /// The commit's short hash: the release build's, else git's when built
    /// in a checkout of sail, else the revision Cargo checked it out at as
    /// a git dependency; `unknown` when none tells, never empty.
    pub commit: &'static str,
}

/// This build of sail. The CLI's `--version` and the C ABI's capabilities
/// tell the same.
pub const BUILD: BuildInfo = BuildInfo {
    version: VERSION,
    commit: env!("SAIL_BUILD_COMMIT"),
};

impl Instance {
    /// What it sent and received since it started.
    pub async fn traffic(&self) -> Result<Traffic, Error> {
        self.with_manager(|m| Box::pin(async move { m.traffic().await }))
            .await
    }

    /// The connections open, by id.
    pub async fn connections(&self) -> Result<Vec<ConnectionInfo>, Error> {
        self.with_manager(|m| Box::pin(async move { m.connections().await }))
            .await
    }

    /// Closes the connection `id`: whether there was one.
    pub async fn close_connection(&self, id: u64) -> Result<bool, Error> {
        self.with_manager(move |m| Box::pin(async move { m.close_connection(id).await }))
            .await
    }

    /// Closes every connection: how many.
    pub async fn close_all_connections(&self) -> Result<usize, Error> {
        self.with_manager(|m| Box::pin(async move { m.close_all_connections().await }))
            .await
    }

    /// The outbounds and groups, in the configuration's order.
    pub async fn outbounds(&self) -> Result<Vec<OutboundInfo>, Error> {
        self.with_manager(|m| Box::pin(async move { m.outbounds().await }))
            .await
    }

    /// The groups alone.
    pub async fn groups(&self) -> Result<Vec<OutboundInfo>, Error> {
        self.with_manager(|m| Box::pin(async move { m.groups().await }))
            .await
    }

    /// The outbound or group `tag`.
    pub async fn outbound(&self, tag: &str) -> Result<Option<OutboundInfo>, Error> {
        let tag = tag.to_string();
        self.with_manager(move |m| Box::pin(async move { m.outbound(&tag).await }))
            .await
    }

    /// Selects `member` in the group `group`; in a fallback or url-test,
    /// pins it until `unfix`.
    pub async fn select(&self, group: &str, member: &str) -> Result<(), Error> {
        let (group, member) = (group.to_string(), member.to_string());
        Ok(self
            .with_manager(move |m| Box::pin(async move { m.select(&group, &member).await }))
            .await??)
    }

    /// Lets the group `group` pick again, as Mihomo's DELETE does.
    pub async fn unfix(&self, group: &str) -> Result<(), Error> {
        let group = group.to_string();
        Ok(self
            .with_manager(move |m| Box::pin(async move { m.unfix(&group).await }))
            .await??)
    }

    /// Measures the delay of the outbound `tag` to `url` (the default
    /// test URL when none), within `timeout`.
    pub async fn url_test(
        &self,
        tag: &str,
        url: Option<&str>,
        timeout: Duration,
    ) -> Result<Duration, Error> {
        let (tag, url) = (tag.to_string(), url.map(str::to_owned));
        Ok(self
            .with_manager(move |m| {
                Box::pin(async move { m.url_test(&tag, url.as_deref(), timeout).await })
            })
            .await??)
    }

    /// Measures every member of the group `group`, at once: each member's
    /// delay, or why it has none.
    pub async fn url_test_members(
        &self,
        group: &str,
        url: Option<&str>,
        timeout: Duration,
    ) -> Result<Vec<(String, Result<Duration, Error>)>, Error> {
        let (group, url) = (group.to_string(), url.map(str::to_owned));
        let members = self
            .with_manager(move |m| {
                Box::pin(async move { m.url_test_members(&group, url.as_deref(), timeout).await })
            })
            .await??;
        Ok(members
            .into_iter()
            .map(|(tag, delay)| (tag, delay.map_err(Error::from)))
            .collect())
    }

    /// The outbound providers.
    pub async fn providers(&self) -> Result<Vec<ProviderInfo>, Error> {
        self.with_manager(|m| Box::pin(async move { m.providers().await }))
            .await
    }

    /// Updates the provider `tag` now.
    pub async fn update_provider(&self, tag: &str) -> Result<(), Error> {
        let tag = tag.to_string();
        Ok(self
            .with_manager(move |m| Box::pin(async move { m.update_provider(&tag).await }))
            .await??)
    }

    /// The rule-sets.
    pub async fn rule_sets(&self) -> Result<Vec<RuleSetInfo>, Error> {
        self.with_manager(|m| Box::pin(async move { m.rule_sets().await }))
            .await
    }

    /// Updates the rule-set `tag` now.
    pub async fn update_rule_set(&self, tag: &str) -> Result<(), Error> {
        let tag = tag.to_string();
        Ok(self
            .with_manager(move |m| Box::pin(async move { m.update_rule_set(&tag).await }))
            .await??)
    }

    /// The mode the rules match and the modes there are; none without
    /// modes (no Clash API, and no `clash_modes`).
    pub fn mode(&self) -> Result<Option<Mode>, Error> {
        Ok(self.manager()?.mode())
    }

    /// Switches the mode, as the Clash API does.
    pub fn set_mode(&self, mode: &str) -> Result<(), Error> {
        Ok(self.manager()?.set_mode(mode)?)
    }

    /// The inbounds.
    pub fn inbounds(&self) -> Result<Vec<InboundInfo>, Error> {
        Ok(self.manager()?.inbounds()?)
    }

    /// The names of the users of the inbound `tag`; none for no inbound so
    /// tagged.
    pub fn inbound_users(&self, tag: &str) -> Result<Option<Vec<String>>, Error> {
        Ok(self.manager()?.inbound_users(tag)?)
    }

    /// Adds a user, as the inbound's `users` entries are, to the inbound
    /// `tag`, without a reload.
    pub async fn add_inbound_user(&self, tag: &str, user: serde_json::Value) -> Result<(), Error> {
        let tag = tag.to_string();
        Ok(self
            .with_manager(move |m| Box::pin(async move { m.add_inbound_user(&tag, user).await }))
            .await??)
    }

    /// Replaces the user `name` of the inbound `tag`.
    pub async fn replace_inbound_user(
        &self,
        tag: &str,
        name: &str,
        user: serde_json::Value,
    ) -> Result<(), Error> {
        let (tag, name) = (tag.to_string(), name.to_string());
        Ok(self
            .with_manager(move |m| {
                Box::pin(async move { m.replace_inbound_user(&tag, &name, user).await })
            })
            .await??)
    }

    /// Removes the user `name` of the inbound `tag`; its connections close.
    pub async fn remove_inbound_user(&self, tag: &str, name: &str) -> Result<(), Error> {
        let (tag, name) = (tag.to_string(), name.to_string());
        Ok(self
            .with_manager(move |m| {
                Box::pin(async move { m.remove_inbound_user(&tag, &name).await })
            })
            .await??)
    }

    /// Adds an inbound, one entry of sing-box's `inbounds` as JSON, and
    /// starts listening on it, without a reload. Its tag must be new.
    pub async fn add_inbound(&self, inbound: serde_json::Value) -> Result<(), Error> {
        let host = self.inner().host().clone();
        let config = serde_json::json!({ "inbounds": [inbound] }).to_string();
        let mut config = crate::config::from_string_for(&config, &host)
            .map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?;
        let inbound = config
            .inbounds
            .pop()
            .ok_or_else(|| Error::new(ErrorKind::Config, "no inbound given"))?;
        Ok(self
            .with_manager(move |m| Box::pin(async move { m.add_inbound(inbound).await }))
            .await??)
    }

    /// Removes the inbound `tag`: it stops listening, and the connections
    /// it accepted are disconnected at once, its UDP sessions and the
    /// streams of its multiplexed connections among them. Connections of
    /// other inbounds are not touched. How many were disconnected.
    pub async fn remove_inbound(&self, tag: &str) -> Result<usize, Error> {
        let tag = tag.to_string();
        Ok(self
            .with_manager(move |m| Box::pin(async move { m.remove_inbound_closing(&tag).await }))
            .await??)
    }

    /// Tells it the host's network, as JSON (sail's network state), which
    /// it then goes by instead of its own detection.
    pub fn set_network_state(&self, json: &str) -> Result<(), Error> {
        self.manager()?;
        Ok(crate::set_network_state(self.id(), json)?)
    }

    /// Tells its TUN inbound that the host's network changed, with the new
    /// MTU when that changed too.
    pub async fn network_changed(&self, mtu: Option<usize>) -> Result<(), Error> {
        #[cfg(feature = "inbound-tun")]
        return Ok(self
            .with_manager(move |m| Box::pin(async move { m.network_changed(mtu).await }))
            .await??);
        #[cfg(not(feature = "inbound-tun"))]
        {
            let _ = mtu;
            self.manager()?;
            Err(Error::new(
                ErrorKind::Unsupported,
                "this build has no tun inbound",
            ))
        }
    }

    /// The panics of tasks the instance went on after, in this run.
    pub fn faults(&self) -> Result<u64, Error> {
        Ok(self.manager()?.env.scope.faults())
    }

    /// The tasks of the instance's scope now, by name, with how many of
    /// each.
    #[doc(hidden)]
    pub fn tasks(&self) -> Result<Vec<(&'static str, usize)>, Error> {
        Ok(self.manager()?.env.scope.tasks())
    }

    /// What the configurations it ran set that sail ignores, since last
    /// asked.
    pub fn take_warnings(&self) -> Result<Vec<String>, Error> {
        Ok(self.manager()?.take_warnings())
    }
}
