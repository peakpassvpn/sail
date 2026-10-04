// Unit tests drive tasks of their own; sail's tasks go through the scope.
#![cfg_attr(test, allow(clippy::disallowed_methods))]

use std::collections::HashMap;
use std::io;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::anyhow;
use lazy_static::lazy_static;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{info, trace, warn};

#[cfg(feature = "auto-reload")]
use notify::Error as NotifyError;

use app::{outbound::manager::OutboundManager, router::Router};

use crate::app::{SyncDnsClient, SyncOutboundManager, SyncRouter, SyncStatManager};

#[cfg(feature = "api")]
use crate::app::api::api_server::ApiServer;

// First: its macro is used by the modules below.
#[macro_use]
pub mod fault;

pub mod adapter;
#[cfg(feature = "alloc-stats")]
pub mod alloc_stats;
pub mod app;
pub mod assets;
pub mod common;
pub mod config;
pub mod control;
pub mod embed;
#[cfg(feature = "http-client")]
pub mod fetch;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
pub mod generate;
mod include;
pub mod net;
pub mod platform;
pub mod protocol;
pub mod runtime;
pub mod session;
pub mod sniff;
pub mod transport;
pub mod user;
pub mod util;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] anyhow::Error),
    #[error("no associated config file")]
    NoConfigFile,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[cfg(feature = "auto-reload")]
    #[error(transparent)]
    Watcher(#[from] NotifyError),
    #[error(transparent)]
    AsyncChannelSend(
        #[from] tokio::sync::mpsc::error::SendError<std::sync::mpsc::SyncSender<Result<(), Error>>>,
    ),
    #[error(transparent)]
    SyncChannelRecv(#[from] std::sync::mpsc::RecvError),
    #[error("runtime manager error")]
    RuntimeManager,
    #[error("runtime {0} is in use: it is starting or running")]
    InUse(RuntimeId),
    /// An essential task panicked, or a lock a panic poisoned was met.
    #[error("stopped after a panic: {0}")]
    Panicked(String),
    /// A reload that adds, removes or changes an inbound served by a
    /// listener of its own (a TUN): only a start does that. Nothing
    /// changed.
    #[error("{0}")]
    NeedsRestart(String),
    /// A reload that was to replace the inbound `tag` on the address it
    /// had: the new one did not bind, and the one before could not listen
    /// again. The reload failed, and `tag` listens no more; all else is as
    /// it was.
    #[error("[{tag}] inbound: lost: {reason}")]
    InboundLost { tag: String, reason: String },
    /// The inbound named, to remove, is not there.
    #[error("[{0}] inbound: does not exist")]
    NoInbound(String),
}

impl From<app::inbound::manager::Refused> for Error {
    fn from(refused: app::inbound::manager::Refused) -> Self {
        use app::inbound::manager::Refused;
        match refused {
            Refused::Config(e) => Error::Config(e),
            Refused::NeedsRestart(why) => Error::NeedsRestart(why),
            Refused::Lost { tag, reason } => Error::InboundLost { tag, reason },
        }
    }
}

pub type Runner = futures::future::BoxFuture<'static, ()>;

/// How long a reload goes on trying to bind an inbound to the address of
/// the one it replaces, once that one's listener has ended. A judgment
/// value: a TCP or UDP listener's socket is closed by then, and a QUIC
/// endpoint's within milliseconds of it, its connections being closed
/// with it; a second is far more, and bounds what an address that will
/// never bind costs a reload before it is refused.
const LATE_BIND_WITHIN: std::time::Duration = std::time::Duration::from_secs(1);

/// What the log says when a SIGHUP's reload took, and when it did not,
/// before the reason; and how a refusal that only a restart gets past
/// ends. A service manager's scripts read these (OpenWrt's init script
/// decides by them whether to restart): they are not reworded.
pub const SIGHUP_RELOADED: &str = "SIGHUP: reloaded";
pub const SIGHUP_NOT_LOADED: &str =
    "SIGHUP: the configuration is not loaded, the one before runs on";
pub const RESTART_TO_APPLY: &str = "restart to apply";

pub struct RuntimeManager {
    /// The runtime the instance runs on.
    handle: tokio::runtime::Handle,
    config_path: Option<String>,
    #[cfg(feature = "auto-reload")]
    auto_reload: bool,
    reload_tx: mpsc::Sender<std::sync::mpsc::SyncSender<Result<(), Error>>>,
    shutdown_tx: mpsc::Sender<()>,
    #[cfg(feature = "inbound-tun")]
    network_change_tx: mpsc::Sender<NetworkChange>,
    /// The TUN inbound's stack, when there is one.
    #[cfg(feature = "inbound-tun")]
    tun_control: Option<net::netstack::NativeRuntimeControl>,
    /// The generation of the network the TUN flows belong to.
    #[cfg(feature = "inbound-tun")]
    network_generation: Mutex<u64>,
    router: SyncRouter,
    dns_client: SyncDnsClient,
    outbound_manager: SyncOutboundManager,
    inbound_manager: Arc<Mutex<app::inbound::manager::InboundManager>>,
    stat_manager: SyncStatManager,
    env: runtime::SyncRuntimeEnv,
    /// What rule-sets are downloaded through; the same across reloads.
    dispatcher: std::sync::Weak<app::dispatcher::Dispatcher>,
    /// Downloads the remote rule-sets again as they fall due.
    rule_set_updater: Mutex<Option<tokio::task::AbortHandle>>,
    /// Updates the outbound providers as they fall due.
    #[cfg(feature = "outbound-provider")]
    provider_updater: Mutex<Option<tokio::task::AbortHandle>>,
    /// What outbounds dial with where theirs leave off, as the current
    /// configuration has it.
    dial_defaults: net::SharedDialDefaults,
    /// Serializes the changes: reloads, and outbounds and inbounds added
    /// or removed.
    update: tokio::sync::Mutex<()>,
    #[cfg(feature = "auto-reload")]
    watcher: Mutex<Option<runtime::watch::FileWatcher>>,
    #[cfg(feature = "auto-reload")]
    watch_events: Mutex<Option<runtime::watch::ReloadEvents>>,
    /// The certificate files of the inbounds, followed; the instance's,
    /// gone when it stops.
    #[cfg(feature = "auto-reload")]
    cert_follow: Mutex<Option<app::inbound::follow::CertFollow>>,
    /// How many reloads took, for tests: what follows a file must not
    /// reload the whole instance.
    reloads: portable_atomic::AtomicU64,
    /// What it runs, without its inbounds: what tells a reload that
    /// changes the inbounds alone. None once something else was changed
    /// while it ran (an outbound added or removed), until the next reload.
    running: Mutex<Option<runtime::running::Running>>,
    /// The instance itself, for what it starts to call back into.
    #[cfg_attr(not(feature = "auto-reload"), allow(dead_code))]
    this: std::sync::Weak<Self>,
    /// Where a reload's rule-sets go for the TUN's routing.
    #[cfg(all(
        feature = "inbound-tun",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    tun_rule_sets: Option<app::instance::TunRuleSets>,
    /// What the Clash API tells of the configuration.
    #[cfg(feature = "clash-api")]
    clash_view: arc_swap::ArcSwap<app::clash_api::ConfigView>,
    /// The modes the rules name, as sing-box lists them.
    modes: arc_swap::ArcSwap<Vec<String>>,
    /// The tags of the outbounds and endpoints, in the configuration's
    /// order, those added after it last: the outbounds there are, as
    /// identical outbounds share one handler, which goes by one of their
    /// tags.
    order: arc_swap::ArcSwap<Vec<String>>,
    /// The delays measured of each outbound.
    delays: control::Delays,
    /// What the configuration sets that sail ignores, until read.
    warnings: Mutex<Vec<String>>,
    /// The assets the configuration reads.
    assets: Mutex<Vec<assets::Asset>>,
}

impl RuntimeManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        #[cfg(feature = "auto-reload")] _rt_id: RuntimeId,
        config_path: Option<String>,
        #[cfg(feature = "auto-reload")] auto_reload: bool,
        reload_tx: mpsc::Sender<std::sync::mpsc::SyncSender<Result<(), Error>>>,
        shutdown_tx: mpsc::Sender<()>,
        #[cfg(feature = "inbound-tun")] network_change_tx: mpsc::Sender<NetworkChange>,
        instance: &app::instance::Instance,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            reloads: portable_atomic::AtomicU64::new(0),
            running: Mutex::new(None),
            handle: tokio::runtime::Handle::current(),
            config_path,
            #[cfg(feature = "auto-reload")]
            auto_reload,
            reload_tx,
            shutdown_tx,
            #[cfg(feature = "inbound-tun")]
            network_change_tx,
            #[cfg(feature = "inbound-tun")]
            tun_control: instance.tun_control.clone(),
            #[cfg(feature = "inbound-tun")]
            network_generation: Mutex::new(0),
            router: instance.router.clone(),
            dns_client: instance.dns_client.clone(),
            outbound_manager: instance.outbound_manager.clone(),
            inbound_manager: instance.inbound_manager.clone(),
            stat_manager: instance.stat_manager.clone(),
            env: instance.env.clone(),
            dispatcher: Arc::downgrade(&instance.dispatcher),
            #[cfg(all(
                feature = "inbound-tun",
                any(target_os = "linux", target_os = "macos", target_os = "windows")
            ))]
            tun_rule_sets: instance.tun_rule_sets(),
            rule_set_updater: Mutex::new(
                instance
                    .rule_sets
                    .spawn_updater(Arc::downgrade(&instance.dispatcher)),
            ),
            #[cfg(feature = "outbound-provider")]
            provider_updater: Mutex::new(
                instance
                    .outbound_manager
                    .load()
                    .providers()
                    .spawn_updater(Arc::downgrade(&instance.dispatcher)),
            ),
            dial_defaults: instance.dial_defaults.clone(),
            update: tokio::sync::Mutex::new(()),
            #[cfg(feature = "auto-reload")]
            watcher: Mutex::new(None),
            #[cfg(feature = "auto-reload")]
            watch_events: Mutex::new(None),
            #[cfg(feature = "auto-reload")]
            cert_follow: Mutex::new(None),
            #[cfg(feature = "clash-api")]
            clash_view: Default::default(),
            modes: Default::default(),
            order: Default::default(),
            delays: Default::default(),
            warnings: Default::default(),
            assets: Default::default(),
        })
    }

    /// The instance's log: the lines logged on its threads.
    pub fn logs(&self) -> Option<&Arc<app::logger::InstanceLog>> {
        self.env.host.log.as_ref().map(|log| &log.0)
    }

    /// The runtime the instance runs on, for the host to run calls into
    /// it on rather than a runtime of its own.
    pub fn handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    /// The assets the configuration reads, as they are now.
    pub fn assets(&self) -> Vec<assets::Asset> {
        let mut assets = self
            .assets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for asset in &mut assets {
            asset.present = std::path::Path::new(&asset.path).is_file();
        }
        assets
    }

    fn set_assets(&self, config: &config::Config) {
        *self.assets.lock().unwrap_or_else(|e| e.into_inner()) =
            assets::required(config, &self.env);
    }

    /// The outbounds, as they are now.
    #[cfg(all(feature = "clash-api", feature = "outbound-provider"))]
    pub(crate) fn outbound_manager(&self) -> Arc<app::outbound::manager::OutboundManager> {
        self.outbound_manager.load_full()
    }

    #[cfg(feature = "clash-api")]
    pub(crate) fn dns_client(&self) -> SyncDnsClient {
        self.dns_client.clone()
    }

    /// The dispatcher, while the instance runs.
    #[cfg(any(
        all(
            feature = "clash-api",
            any(feature = "outbound-provider", feature = "http-client")
        ),
        feature = "outbound-provider",
        feature = "rule-set"
    ))]
    pub(crate) fn dispatcher(&self) -> Option<Arc<app::dispatcher::Dispatcher>> {
        self.dispatcher.upgrade()
    }

    #[cfg(any(feature = "clash-api", feature = "rule-set"))]
    pub(crate) fn router(&self) -> Arc<app::router::Router> {
        self.router.load_full()
    }

    #[cfg(feature = "clash-api")]
    pub(crate) fn env(&self) -> runtime::SyncRuntimeEnv {
        self.env.clone()
    }

    /// The network the host is on, as it tells or sail detects it.
    pub fn network(&self) -> &net::network::Network {
        &self.env.network
    }

    /// Whether the configuration, as it is now, picks anything by the
    /// network the host is on: a routing rule, or a rule of a rule-set one
    /// names, with conditions on it (`wifi_ssid`, `network_type`, …), or a
    /// `network` group. Where none does, nothing needs the network found
    /// out. It changes only with a reload, or with a rule-set that a
    /// download replaces, so it is asked once before the instance starts
    /// and again after each reload.
    pub fn needs_network(&self) -> bool {
        self.router.load().needs_network()
            || self.outbound_manager.load().needs_network()
            || self.dns_client.load().needs_network()
    }

    /// Detects the network the host is on again, on a blocking thread,
    /// unless the host pushes it, for `reason`. Awaiting the handle waits
    /// for it, and says whether a change connections do not survive was
    /// told.
    fn detect_network(&self, reason: net::network::ChangeReason) -> tokio::task::JoinHandle<bool> {
        let network = self.network().clone();
        self.env.scope.spawn_blocking("network detection", move || {
            !network.pushed() && network.detected(platform::network::detect(), reason)
        })
    }

    /// What the instance does when the network changes so that connections
    /// made on the one before do not survive, as sing-box resets its
    /// network (route/network.go:493-520): the DNS answers kept and the
    /// connections the DNS servers keep go, the connections go, and the
    /// TUN's flows; then a line in the log, which tests measure by.
    async fn network_moved(&self, change: &net::network::NetworkChange) {
        let started = std::time::Instant::now();
        let _update = self.update.lock().await;
        self.dns_client.load().network_changed().await;
        // Every connection, until each tells the interface it is bound to.
        let closed = self.stat_manager.close_all();
        // What the outbounds keep of the network before: every outbound,
        // endpoint and provider member hears of it once.
        let outbounds = self.outbound_manager.load_full();
        for handler in outbounds.handlers() {
            handler.network_changed(change);
        }
        #[cfg(feature = "outbound-provider")]
        for members in outbounds.providers().members().values() {
            for member in members.load().members.iter() {
                member.handler.network_changed(change);
            }
        }
        #[cfg(feature = "inbound-tun")]
        if self.tun_control.is_some() {
            if let Err(e) = self.reset_tun_flows().await {
                warn!("network changed: resetting the tun's flows: {}", e);
            }
        }
        let name = |state: &net::network::NetworkState| {
            state.interface.clone().unwrap_or_else(|| "none".into())
        };
        if self.network().is_down() {
            info!("network: none; timed checks and updates wait for one");
        }
        info!(
            "network changed: generation {}, reason={}, interface={}→{}, closed={}, dns_flushed=true, took={}ms",
            change.generation,
            change.reason,
            name(&change.old),
            name(&change.new),
            closed,
            started.elapsed().as_millis()
        );
    }

    /// What the Clash API tells of the configuration.
    #[cfg(feature = "clash-api")]
    pub(crate) fn clash_view(&self) -> app::clash_api::ConfigView {
        (**self.clash_view.load()).clone()
    }

    /// What the Clash API and the modes tell of `config`, as it is now.
    fn set_views(&self, config: &config::Config) {
        self.modes.store(Arc::new(control::modes(config)));
        *self.warnings.lock().unwrap_or_else(|e| e.into_inner()) = config.warnings.clone();
        self.order.store(Arc::new(
            config
                .outbounds
                .iter()
                .map(|o| o.tag.clone())
                .chain(config.endpoints.iter().map(|e| e.tag.clone()))
                .collect(),
        ));
        #[cfg(feature = "clash-api")]
        self.clash_view
            .store(Arc::new(app::clash_api::ConfigView::of(config)));
    }

    /// Switches the mode rules match, as the Clash API does, keeping it in
    /// the cache file; the DNS answers kept go, as the rules that picked
    /// their servers may pick others now (sing-box's).
    pub fn switch_clash_mode(&self, mode: &str) {
        if self.env.clash_mode.get().as_deref() == Some(mode) {
            return;
        }
        self.env
            .clash_mode
            .switch(mode, self.env.cache_file.get().as_deref());
        self.dns_client.load().clear_cache();
        info!("clash mode: {}", mode);
    }

    /// What the DNS cache holds and how it served.
    pub fn dns_cache_stats(&self) -> app::dns::CacheStats {
        self.dns_client.load().cache_stats()
    }

    /// Forgets the DNS answers kept.
    pub fn clear_dns_cache(&self) {
        self.dns_client.load().clear_cache();
    }

    pub fn stat_manager(&self) -> SyncStatManager {
        self.stat_manager.clone()
    }

    pub async fn health_check_outbound(
        &self,
        tag: &str,
        to: Option<Duration>,
    ) -> Result<
        (
            Result<Duration, anyhow::Error>,
            Result<Duration, anyhow::Error>,
        ),
        Error,
    > {
        let to = to.unwrap_or(Duration::from_secs(4));
        let dns_client = self.dns_client.clone();
        let handler = self
            .outbound_manager
            .load()
            .get(tag)
            .ok_or_else(|| Error::Config(anyhow!("outbound {} not found", tag)))?;

        async fn test_tcp(
            dns_client: SyncDnsClient,
            handler: crate::adapter::AnyOutboundHandler,
        ) -> anyhow::Result<Duration> {
            crate::app::healthcheck::tcp(dns_client, handler).await
        }

        async fn test_udp(
            dns_client: SyncDnsClient,
            handler: crate::adapter::AnyOutboundHandler,
        ) -> anyhow::Result<Duration> {
            crate::app::healthcheck::udp(dns_client, handler).await
        }

        let (tcp_res, udp_res) = futures::future::join(
            timeout(to, test_tcp(dns_client.clone(), handler.clone())),
            timeout(to, test_udp(dns_client, handler)),
        )
        .await;

        let tcp_res = match tcp_res.map_err(|e| e.into()) {
            Err(e) => Err(e),
            Ok(res) => match res {
                Err(e) => Err(e),
                Ok(duration) => Ok(duration),
            },
        };
        let udp_res = match udp_res.map_err(|e| e.into()) {
            Err(e) => Err(e),
            Ok(res) => match res {
                Err(e) => Err(e),
                Ok(duration) => Ok(duration),
            },
        };
        Ok((tcp_res, udp_res))
    }

    #[cfg(feature = "outbound-select")]
    pub async fn set_outbound_selected(&self, outbound: &str, select: &str) -> Result<(), Error> {
        if let Some(selector) = self.outbound_manager.load().get_selector(outbound) {
            selector
                .write()
                .await
                .set_selected(select)
                .map_err(Error::Config)
        } else {
            Err(Error::Config(anyhow!("selector {} not found", outbound)))
        }
    }

    #[cfg(feature = "outbound-select")]
    pub async fn get_outbound_selected(&self, outbound: &str) -> Result<String, Error> {
        if let Some(selector) = self.outbound_manager.load().get_selector(outbound) {
            return Ok(selector.read().await.get_selected_tag());
        }
        Err(Error::Config(anyhow!("selector {} not found", outbound)))
    }

    #[cfg(feature = "outbound-select")]
    pub async fn get_outbound_selects(&self, outbound: &str) -> Result<Vec<String>, Error> {
        if let Some(selector) = self.outbound_manager.load().get_selector(outbound) {
            return Ok(selector.read().await.get_available_tags());
        }
        Err(Error::Config(anyhow!("selector {} not found", outbound)))
    }

    /// Get the last peer active time (in seconds) for an outbound
    pub async fn get_outbound_last_peer_active(
        &self,
        outbound: &str,
    ) -> Result<Option<u32>, Error> {
        Ok(self.stat_manager.get_last_peer_active(outbound))
    }

    /// Stops taking connections, and waits for the TCP connections open to
    /// finish, for `lifecycle.drain_timeout` at most, or until
    /// `interrupted`.
    #[cfg_attr(not(feature = "ctrlc"), allow(dead_code))]
    async fn drain<S: std::fmt::Display>(&self, interrupted: impl std::future::Future<Output = S>) {
        let timeout = self.env.options.lifecycle.drain_timeout;
        if timeout.is_zero() {
            return;
        }
        let listeners = self
            .inbound_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop_listening();
        let open = self.stat_manager.open_streams();
        if open == 0 {
            return;
        }
        info!(
            "stopping: {} listeners closed; waiting up to {:?} for {} connections",
            listeners, timeout, open
        );
        let finished = async {
            // How soon the stop follows the last connection; judgment, as
            // it costs one count a tick.
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
            while self.stat_manager.open_streams() > 0 {
                tick.tick().await;
            }
        };
        tokio::select! {
            _ = finished => info!("stopping: every connection finished"),
            _ = tokio::time::sleep(timeout) => info!(
                "stopping: {} connections still open after {:?} are closed",
                self.stat_manager.open_streams(),
                timeout
            ),
            signal = interrupted => info!("{} again: stopping now", signal),
        }
    }

    /// The TUNs' names by inbound tag, as the start settled them: the one
    /// configured, or, with none, the one chosen at start (macOS) or the
    /// default. A host reads the name a TUN got here.
    pub fn tun_names(&self) -> std::collections::BTreeMap<String, runtime::TunName> {
        self.env
            .tun_names
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Reloads DNS, outbounds and routing from the configuration file. They
    /// are all built before any is replaced: a configuration that fails to
    /// build changes nothing. Connections already routed keep what they
    /// were routed with.
    pub async fn reload(&self) -> Result<(), Error> {
        self.reload_reporting().await.map(|_| ())
    }

    /// `reload`, and what it did to each inbound.
    pub async fn reload_reporting(&self) -> Result<control::ReloadReport, Error> {
        let config_path = if let Some(p) = self.config_path.as_ref() {
            p
        } else {
            return Err(Error::NoConfigFile);
        };
        let _update = self.update.lock().await;
        info!("reloading from config file: {}", config_path);
        let config = config::from_file_for(config_path, &self.env.host).map_err(Error::Config)?;
        let report = self.apply(config).await?;
        info!("reloaded from config file: {}", config_path);
        Ok(report)
    }

    /// Reloads with `config`, as a reload from the file does: the host's,
    /// for an instance started from a string.
    pub async fn reload_with(&self, config: config::Config) -> Result<(), Error> {
        self.reload_with_reporting(config).await.map(|_| ())
    }

    /// `reload_with`, and what it did to each inbound.
    pub async fn reload_with_reporting(
        &self,
        config: config::Config,
    ) -> Result<control::ReloadReport, Error> {
        let _update = self.update.lock().await;
        info!("reloading with the configuration given");
        let report = self.apply(config).await?;
        info!("reloaded with the configuration given");
        Ok(report)
    }

    /// Replaces what the instance runs with what `config` makes, keeping
    /// all that did not change; the changes lock is held. The inbounds it
    /// has are those that run after it: see app/inbound/manager/reload.rs.
    async fn apply(&self, config: config::Config) -> Result<control::ReloadReport, Error> {
        #[cfg(feature = "inbound-tun")]
        let config = {
            let mut config = config;
            // A TUN whose name the start chose keeps it.
            let mut names = self.env.tun_names.lock().unwrap_or_else(|e| e.into_inner());
            *names =
                protocol::tun::inbound::resolve_names(&mut config.inbounds, &names, &self.env.host);
            config
        };
        // What did not change is left alone: a configuration that differs
        // from what runs in its inbounds alone changes the inbounds, and
        // nothing else is built again.
        let inbounds_alone = self
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|running| running.differs_in_inbounds_alone(&config));
        if inbounds_alone {
            return self.apply_inbounds(&config).await;
        }
        // The files it names, before any is read: the next reload tells by
        // them whether one was written since.
        let running = runtime::running::Running::of(&config, &self.env);
        self.env.neighbors.start_if_needed(&config);
        self.env
            .network
            .set_own_interfaces(own_interfaces(&config, &self.env.host));
        // Before their files are read again: those written until they are
        // watched show against this.
        #[cfg(feature = "auto-reload")]
        let inbound_files = app::inbound::follow::about_to_read(&config.inbounds, &self.env);
        // Built, and bound where no inbound that goes holds the address:
        // nothing running is touched, and what fails from here on drops
        // these with their sockets.
        let mut inbound_reload = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .prepare_reload(&config.inbounds)?;
        let dial_defaults = dial_defaults(&config, &self.env).map_err(Error::Config)?;
        // An endpoint is only set up at a start: one that runs, and what
        // it is built on, go on with the defaults they were built with.
        // The reload is taken all the same, and tells so.
        let notes: Vec<control::ReloadNote> = {
            let options = self
                .dial_defaults
                .load()
                .route
                .differs_in(&dial_defaults.route);
            let mut endpoints: Vec<String> = match options.is_empty() {
                true => Vec::new(),
                false => self
                    .outbound_manager
                    .load()
                    .endpoint_servers()
                    .into_iter()
                    .map(|(tag, _)| tag)
                    .collect(),
            };
            endpoints.sort();
            endpoints
                .into_iter()
                .map(|endpoint| control::ReloadNote::EndpointKeepsDefaults {
                    endpoint,
                    options: options.clone(),
                })
                .collect()
        };
        // The detours of DNS servers and HTTP clients find the outbounds
        // that replace these.
        dial_defaults.env.outbounds.set(&self.outbound_manager);
        // What is built from here on keeps its state in the new cache file;
        // a reload that fails puts the old one back.
        let cache_file = self
            .env
            .cache_file
            .replace(config.experimental.cache_file.as_ref(), &self.env)
            .map_err(Error::Config)?;
        // What is built from here on trusts the new roots; a reload that
        // fails puts the old ones back.
        #[cfg(feature = "tls")]
        let roots = self.env.tls_roots.replace(
            transport::tls::roots::configured(config.certificate.as_ref(), &self.env)
                .map_err(Error::Config)?,
        );
        let http_clients = app::http::HttpClients::new(&config, dial_defaults.clone());
        let rule_sets =
            app::router::rule_set::RuleSets::load(&config.route.rule_set, &http_clients, &self.env)
                .map_err(Error::Config)?;
        // Those configured as they were go on as they are.
        #[cfg(feature = "outbound-provider")]
        let providers = app::provider::Providers::load(
            &config.outbound_providers,
            &http_clients,
            dial_defaults.clone(),
            &self.env,
            Some(&self.outbound_manager.load().providers()),
        )
        .map_err(Error::Config)?;
        if let Some(dispatcher) = self.dispatcher.upgrade() {
            rule_sets
                .fetch_missing(&dispatcher)
                .await
                .map_err(Error::Config)?;
        }
        let dns_client = self
            .dns_client
            .load()
            .reloaded(&config.dns, dial_defaults.clone(), &self.env, &rule_sets)
            .map_err(Error::Config)?;
        dns_client.check_loops(&config).map_err(Error::Config)?;
        // Outbounds and routing reach the DNS client through the shared
        // cell, and so find the new one once it is stored.
        let outbound_manager = OutboundManager::reloaded(
            &self.outbound_manager.load(),
            &config.outbounds,
            &config.endpoints,
            #[cfg(feature = "outbound-provider")]
            providers,
            &dial_defaults,
            &self.env,
            self.dns_client.clone(),
        )
        .map_err(Error::Config)?;
        let router = Router::with_rule_sets(
            &config.route,
            self.dns_client.clone(),
            &self.env,
            &rule_sets,
            &dial_defaults,
        )
        .map_err(Error::Config)?;
        app::logger::setup_logger(&config.log, &self.env.host)?;
        if let Some(log) = &self.env.host.log {
            log.0.configure(&config.log);
        }
        log_warnings(&config);

        #[cfg(feature = "outbound-select")]
        outbound_manager
            .restore_selected(&self.outbound_manager.load())
            .await;
        #[cfg(all(
            feature = "inbound-tun",
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        ))]
        if let Some(feed) = &self.tun_rule_sets {
            feed.check(&rule_sets).map_err(Error::Config)?;
        }
        // The last step that can fail.
        self.rebind_for(&mut inbound_reload).await?;
        // Acquire the last fallible lock before publishing anything. Held
        // in a block of its own: nothing is awaited with it.
        let mut reloaded = {
            let mut inbounds = self
                .inbound_manager
                .lock()
                .map_err(|_| Error::RuntimeManager)?;
            self.env.clash_mode.configure(
                config.clash_api.as_ref(),
                self.env.host.clash_modes,
                self.env.cache_file.get().as_deref(),
            );
            self.set_views(&config);
            self.set_assets(&config);
            // The inbounds that go are stopped; the new ones are bound,
            // and accept once the routing they go by is in place.
            inbounds.commit_reload(inbound_reload)
        };
        // The users the new inbounds bound are limited as configured now.
        self.env
            .users
            .set_limits(user::UserRegistry::configured(&config));
        self.dns_client.store(dns_client.into_arc());
        let replaced = self.outbound_manager.swap(Arc::new(outbound_manager));
        self.router.store(Arc::new(router));
        #[cfg(all(
            feature = "inbound-tun",
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        ))]
        if let Some(feed) = &self.tun_rule_sets {
            feed.publish(rule_sets.clone());
        }
        self.finish_inbounds(&mut reloaded).await;
        {
            let mut updater = self
                .rule_set_updater
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(old) = updater.take() {
                old.abort();
            }
            *updater = rule_sets.spawn_updater(self.dispatcher.clone());
        }
        // It downloads the remote providers new to this configuration
        // first, now that their members are built onto the outbounds in
        // use.
        #[cfg(feature = "outbound-provider")]
        {
            let providers = self.outbound_manager.load().providers();
            let mut updater = self
                .provider_updater
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(old) = updater.take() {
                old.abort();
            }
            *updater = providers.spawn_updater(self.dispatcher.clone());
        }
        self.dial_defaults.store(dial_defaults);
        replaced.abort_tasks_replaced_by(&self.outbound_manager.load());
        #[cfg(feature = "tls")]
        roots.keep();
        cache_file.keep();
        self.prune_stats(&config);
        // What it matches on may be new to this configuration.
        self.detect_network(net::network::ChangeReason::State);
        #[cfg(feature = "auto-reload")]
        self.follow_certificates_read(&inbound_files);
        *self.running.lock().unwrap_or_else(|e| e.into_inner()) = Some(running);
        self.reloads
            .fetch_add(1, portable_atomic::Ordering::Relaxed);
        for note in &notes {
            warn!("{}", note);
        }
        Ok(control::ReloadReport {
            path: control::ReloadPath::Full,
            inbounds: reloaded.changes,
            notes,
        })
    }

    /// A reload of the inbounds alone: `config` is what runs but for its
    /// inbounds and its users' limits. The outbounds, their sessions, the
    /// groups, the DNS client and its cache, the routing and the rule-sets
    /// are not built again: they are those that ran before.
    async fn apply_inbounds(
        &self,
        config: &config::Config,
    ) -> Result<control::ReloadReport, Error> {
        #[cfg(feature = "auto-reload")]
        let inbound_files = app::inbound::follow::about_to_read(&config.inbounds, &self.env);
        let mut inbound_reload = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .prepare_reload(&config.inbounds)?;
        self.rebind_for(&mut inbound_reload).await?;
        let mut reloaded = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .commit_reload(inbound_reload);
        self.env
            .users
            .set_limits(user::UserRegistry::configured(config));
        self.finish_inbounds(&mut reloaded).await;
        self.prune_stats(config);
        #[cfg(feature = "auto-reload")]
        self.follow_certificates_read(&inbound_files);
        self.reloads
            .fetch_add(1, portable_atomic::Ordering::Relaxed);
        info!("only the inbounds differ: nothing else is built again");
        Ok(control::ReloadReport {
            path: control::ReloadPath::InboundsOnly,
            inbounds: reloaded.changes,
            notes: Vec::new(),
        })
    }

    /// Frees the addresses the new inbounds of `reload` wait for, and
    /// binds them: an inbound that goes and holds an address a new one
    /// takes stops first, and the new one binds once its socket is
    /// closed; one that does not bind puts those stopped back, listening
    /// as they were, and the reload fails with all else untouched.
    async fn rebind_for(
        &self,
        inbound_reload: &mut app::inbound::manager::PreparedReload,
    ) -> Result<(), Error> {
        let stopping = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .stop_for(inbound_reload);
        for stopped in stopping {
            // Aborted, it ends at its next poll: 2 s is far more.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), stopped).await;
        }
        // An address is free a moment after its listener's task has ended:
        // a QUIC endpoint closes its socket once its connections are gone.
        // The bind is tried again for that long before the reload gives up
        // and puts back what it stopped.
        let giving_up = tokio::time::Instant::now() + LATE_BIND_WITHIN;
        loop {
            let bound = self
                .inbound_manager
                .lock()
                .map_err(|_| Error::RuntimeManager)?
                .bind_late(inbound_reload);
            match bound {
                Ok(()) => break,
                Err(_) if tokio::time::Instant::now() < giving_up => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(failed) => {
                    return Err(self
                        .inbound_manager
                        .lock()
                        .map_err(|_| Error::RuntimeManager)?
                        .put_back(inbound_reload, failed)
                        .into());
                }
            }
        }
        Ok(())
    }

    /// Ends what the inbounds a reload stopped had accepted, and runs the
    /// new ones.
    async fn finish_inbounds(&self, reloaded: &mut app::inbound::manager::Reloaded) {
        // What the inbounds that went had accepted goes with them, as
        // when one is removed: those listed, then those in their handshake
        // or carrying streams. Nothing is accepted under their tags
        // meanwhile; the new ones run from here, on the new routing.
        for tag in &reloaded.gone {
            let closed = self.close_connections_of(tag).await;
            info!(
                "[{}] inbound: stopped by the reload; {} of its connections closed",
                tag, closed
            );
        }
        for accepted in std::mem::take(&mut reloaded.accepted) {
            accepted.disconnect();
        }
        if let Ok(mut inbounds) = self.inbound_manager.lock() {
            inbounds.start_reloaded(reloaded.take_starting());
        }
        for (tag, change) in &reloaded.changes {
            if *change != control::InboundChange::Untouched {
                info!("[{}] inbound: {} by the reload", tag, change.name());
            }
        }
    }

    /// Closes the connections listed under the inbound `tag`; how many.
    async fn close_connections_of(&self, tag: &str) -> usize {
        let mut closed = 0;
        for connection in self.connections().await {
            if connection.inbound_tag == tag && self.close_connection(connection.id).await {
                closed += 1;
            }
        }
        closed
    }

    /// How many reloads took since the instance started.
    #[doc(hidden)]
    pub fn reloads(&self) -> u64 {
        self.reloads.load(portable_atomic::Ordering::Relaxed)
    }

    /// Drops the traffic counts of the inbounds and outbounds `config` no
    /// longer has, once nothing counts to them.
    fn prune_stats(&self, config: &config::Config) {
        let inbounds = config
            .inbounds
            .iter()
            .map(|i| i.tag.clone())
            .chain(config.endpoints.iter().map(|e| e.tag.clone()))
            .collect();
        #[allow(unused_mut)]
        let mut outbounds: std::collections::HashSet<String> = self
            .outbound_manager
            .load()
            .handlers()
            .map(|h| h.tag().clone())
            .collect();
        #[cfg(feature = "outbound-pass")]
        outbounds.insert(app::outbound::manager::IMPLICIT_DIRECT.to_owned());
        self.stat_manager.configure(&inbounds, &outbounds);
    }

    /// Builds `outbound` and makes it available to routing. It may be built
    /// on the outbounds there are, but not take one's tag.
    pub async fn add_outbound(&self, mut outbound: config::Outbound) -> Result<(), Error> {
        let _update = self.update.lock().await;
        if outbound.tag.is_empty() {
            outbound.tag = outbound.protocol.clone();
        }
        let next = self
            .outbound_manager
            .load()
            .with_outbound(
                &outbound,
                &self.dial_defaults.load(),
                &self.env,
                self.dns_client.clone(),
            )
            .map_err(Error::Config)?;
        self.outbound_manager.store(Arc::new(next));
        let mut order = (**self.order.load()).clone();
        order.push(outbound.tag.clone());
        self.order.store(Arc::new(order));
        // What runs is no longer the configuration: the next reload
        // builds it all.
        *self.running.lock().unwrap_or_else(|e| e.into_inner()) = None;
        info!("added outbound [{}]", outbound.tag);
        Ok(())
    }

    /// Removes the outbound `tag`, which no rule may route to and no other
    /// outbound be built on. Connections through it go on.
    pub async fn remove_outbound(&self, tag: &str) -> Result<(), Error> {
        let _update = self.update.lock().await;
        if self.router.load().uses(tag) {
            return Err(Error::Config(anyhow!(
                "[{}] outbound: the routing uses it",
                tag
            )));
        }
        let (next, tasks) = self
            .outbound_manager
            .load()
            .without_outbound(tag)
            .map_err(Error::Config)?;
        self.outbound_manager.store(Arc::new(next));
        for task in tasks {
            task.abort();
        }
        let mut order = (**self.order.load()).clone();
        order.retain(|t| t != tag);
        self.order.store(Arc::new(order));
        *self.running.lock().unwrap_or_else(|e| e.into_inner()) = None;
        info!("removed outbound [{}]", tag);
        Ok(())
    }

    /// Builds `inbound` and starts listening on its port.
    pub async fn add_inbound(&self, mut inbound: config::Inbound) -> Result<(), Error> {
        let _update = self.update.lock().await;
        if inbound.tag.is_empty() {
            inbound.tag = inbound.protocol.clone();
        }
        #[cfg(feature = "auto-reload")]
        let files = app::inbound::follow::about_to_read(std::slice::from_ref(&inbound), &self.env);
        let mut inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        inbounds.add(&inbound).map_err(Error::Config)?;
        drop(inbounds);
        #[cfg(feature = "auto-reload")]
        self.follow_certificates_read(&files);
        info!("added inbound [{}]", inbound.tag);
        Ok(())
    }

    /// Replaces a supported inbound's users and TLS certificate without
    /// rebinding its socket. Pass the complete inbound configuration; all
    /// static fields must match. Existing authenticated sessions continue.
    /// Does not write the configuration file or disconnect removed users.
    pub async fn update_inbound_resources(
        &self,
        mut inbound: config::Inbound,
    ) -> Result<(), Error> {
        let _update = self.update.lock().await;
        if inbound.tag.is_empty() {
            inbound.tag = inbound.protocol.clone();
        }
        self.update_inbound_resources_locked(&inbound)
    }

    /// `update_inbound_resources`, the changes lock held: what reads an
    /// inbound's configuration and writes it back changes it under the
    /// same lock.
    pub(crate) fn update_inbound_resources_locked(
        &self,
        inbound: &config::Inbound,
    ) -> Result<(), Error> {
        let mut inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        let prepared = inbounds
            .prepare_update_resources(inbound)
            .map_err(Error::Config)?;
        inbounds.publish_resources(prepared);
        drop(inbounds);
        #[cfg(feature = "auto-reload")]
        self.follow_certificates();
        Ok(())
    }

    /// Stops listening for the inbound `tag`, removes it, and disconnects
    /// the connections it accepted (its UDP sessions and the streams of
    /// its multiplexed connections among them); those of other inbounds go
    /// on. Removing an outbound leaves its connections going on.
    pub async fn remove_inbound(&self, tag: &str) -> Result<(), Error> {
        self.remove_inbound_closing(tag).await.map(|_| ())
    }

    /// Stops listening for the inbound `tag` and removes it, leaving the
    /// connections it accepted going on: for tests that check a relayed
    /// connection does not depend on its inbound's tasks. `remove_inbound`
    /// is the real operation, which disconnects them too.
    #[doc(hidden)]
    pub async fn stop_listening(&self, tag: &str) -> Result<(), Error> {
        let _update = self.update.lock().await;
        self.inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .remove(tag)
            .map_err(Error::Config)
    }

    /// `remove_inbound`, and how many connections it disconnected.
    pub async fn remove_inbound_closing(&self, tag: &str) -> Result<usize, Error> {
        let _update = self.update.lock().await;
        // The lock goes before anything awaited.
        let accepted = {
            let mut inbounds = self
                .inbound_manager
                .lock()
                .map_err(|_| Error::RuntimeManager)?;
            if !inbounds.has(tag) {
                return Err(Error::NoInbound(tag.to_string()));
            }
            inbounds.remove_accepted(tag).map_err(Error::Config)?
        };
        #[cfg(feature = "auto-reload")]
        self.follow_certificates();
        // The listener has stopped. The connections the runtime lists are
        // closed and counted first; then whatever else the inbound accepted
        // over TCP ends, a connection still in its handshake or one that
        // carries streams, which are not among those listed.
        let closed = self.close_connections_of(tag).await;
        accepted.disconnect();
        info!(
            "removed inbound [{}]; {} of its connections closed",
            tag, closed
        );
        Ok(closed)
    }

    pub fn blocking_reload(&self) -> Result<(), Error> {
        let tx = self.reload_tx.clone();
        let (res_tx, res_rx) = sync_channel(0);
        if let Err(e) = tx.blocking_send(res_tx) {
            return Err(Error::AsyncChannelSend(e));
        }
        match res_rx.recv() {
            Ok(res) => res,
            Err(e) => Err(Error::SyncChannelRecv(e)),
        }
    }

    pub async fn shutdown(&self) -> bool {
        let tx = self.shutdown_tx.clone();
        if let Err(e) = tx.send(()).await {
            warn!("sending shutdown signal failed: {}", e);
            return false;
        }
        true
    }

    /// The host says its network changed: with `mtu`, the TUN inbound's
    /// stack takes the new interface MTU; then the instance drops what was
    /// of the network before, as for any change (`network_moved`).
    #[cfg(feature = "inbound-tun")]
    pub async fn network_changed(&self, mtu: Option<usize>) -> Result<(), Error> {
        let Some(mut control) = self.tun_control.clone() else {
            return Err(Error::Config(anyhow!("there is no tun inbound")));
        };
        if let Some(mtu) = mtu {
            let _update = self.update.lock().await;
            control.update_mtu(mtu).await?;
        }
        self.network()
            .announce(net::network::ChangeReason::HostPush);
        Ok(())
    }

    /// Stops serving the TUN inbound's flows of the network before.
    #[cfg(feature = "inbound-tun")]
    async fn reset_tun_flows(&self) -> Result<(), Error> {
        let Some(mut control) = self.tun_control.clone() else {
            return Ok(());
        };
        let generation = {
            let mut generation = self
                .network_generation
                .lock()
                .map_err(|_| Error::RuntimeManager)?;
            // Zero is the generation the stack starts in.
            *generation = generation.wrapping_add(1).max(1);
            *generation
        };
        control
            .reset_network(sail_netstack::NetworkGeneration::new(generation))
            .await?;
        Ok(())
    }

    #[cfg(feature = "inbound-tun")]
    pub fn blocking_network_changed(&self, mtu: Option<usize>) -> Result<(), Error> {
        let (res_tx, res_rx) = sync_channel(0);
        self.network_change_tx
            .blocking_send(NetworkChange {
                mtu,
                response: res_tx,
            })
            .map_err(|_| Error::RuntimeManager)?;
        res_rx.recv().map_err(Error::SyncChannelRecv)?
    }

    /// Asks the instance to stop, without waiting: a stop already asked
    /// for is this one too. It never blocks, so any thread may ask, one
    /// of the instance's runtime too. False when the instance has stopped.
    pub fn blocking_shutdown(&self) -> bool {
        match self.shutdown_tx.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => true,
            Err(mpsc::error::TrySendError::Closed(())) => false,
        }
    }

    /// Watches the configuration file, when the instance reloads as it
    /// changes. What the configuration names, certificates and local
    /// rule-sets, each follows its own files, without a reload.
    #[cfg(feature = "auto-reload")]
    fn prepare_watcher(&self) -> Result<Option<runtime::watch::FileWatcher>, Error> {
        if !self.auto_reload {
            return Ok(None);
        }
        let Some(config_path) = self.config_path.as_ref() else {
            return Ok(None);
        };
        let mut events = self.watch_events.lock().unwrap_or_else(|e| e.into_inner());
        let events =
            events.get_or_insert_with(|| runtime::watch::ReloadEvents::new(self.reload_tx.clone()));
        runtime::watch::FileWatcher::new(vec![config_path.into()], events).map(Some)
    }

    #[cfg(feature = "auto-reload")]
    pub(crate) fn new_watcher(&self) -> Result<(), Error> {
        let watcher = self.prepare_watcher()?;
        *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = watcher;
        Ok(())
    }

    /// Reloads, where the instance reloads as its configuration file
    /// changes, if the file was written since `read` was taken of it: just
    /// before the start read it, long before `new_watcher` watched it. No
    /// event told of that write.
    #[cfg(feature = "auto-reload")]
    pub(crate) fn reload_if_written_since(&self, read: Option<runtime::watch::Stamp>) {
        let Some(config_path) = self.config_path.as_ref().filter(|_| self.auto_reload) else {
            return;
        };
        if !runtime::watch::written_since(read, std::path::Path::new(config_path)) {
            return;
        }
        info!("the configuration file was written while the instance started: reloading");
        if let Some(events) = &*self.watch_events.lock().unwrap_or_else(|e| e.into_inner()) {
            events.changed();
        }
    }

    /// Stops watching files: what the instance followed goes with it.
    pub(crate) fn stop_watching(&self) {
        #[cfg(feature = "auto-reload")]
        {
            *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = None;
            self.stop_following_certificates();
        }
    }
}

pub type RuntimeId = u16;

/// A network change a host reports, and where its result goes.
#[cfg(feature = "inbound-tun")]
pub struct NetworkChange {
    mtu: Option<usize>,
    response: std::sync::mpsc::SyncSender<Result<(), Error>>,
}

lazy_static! {
    pub static ref RUNTIME_MANAGER: Mutex<HashMap<RuntimeId, Arc<RuntimeManager>>> =
        Mutex::new(HashMap::new());
}

/// The running runtimes. A panic while the registry was locked cannot leave
/// the map half-changed, so a poisoned lock is taken over rather than
/// failing every later call.
pub fn runtime_managers() -> std::sync::MutexGuard<'static, HashMap<RuntimeId, Arc<RuntimeManager>>>
{
    RUNTIME_MANAGER.lock().unwrap_or_else(|e| e.into_inner())
}

/// An instance being started, not running yet: a stop asked for now
/// ends the start at its next step, or its download.
#[derive(Default)]
struct Starting {
    stopped: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Starting {
    fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn stopped(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_stopped() {
            return;
        }
        notified.await
    }
}

lazy_static! {
    /// The instances starting. Locked after the running ones, never before.
    static ref STARTING: Mutex<HashMap<RuntimeId, Arc<Starting>>> = Mutex::new(HashMap::new());
}

fn starting() -> std::sync::MutexGuard<'static, HashMap<RuntimeId, Arc<Starting>>> {
    STARTING.lock().unwrap_or_else(|e| e.into_inner())
}

/// The instance `key`, if it runs. The registry is not held on to: calls
/// into the instance, which may block, leave every other free.
pub fn runtime_manager(key: RuntimeId) -> Option<Arc<RuntimeManager>> {
    runtime_managers().get(&key).cloned()
}

pub fn reload(key: RuntimeId) -> Result<(), Error> {
    runtime_manager(key)
        .ok_or(Error::RuntimeManager)?
        .blocking_reload()
}

/// Asks the instance `key` to stop, without waiting for it: one running
/// stops, one starting ends its start. False when there is none.
pub fn shutdown(key: RuntimeId) -> bool {
    let running = runtime_managers();
    if let Some(m) = running.get(&key).cloned() {
        drop(running);
        return m.blocking_shutdown();
    }
    match starting().get(&key) {
        Some(start) => {
            start.stop();
            true
        }
        None => false,
    }
}

/// Forgets the instance `key` as running or starting: after a run that
/// unwound, which left them registered.
#[doc(hidden)]
pub fn forget(key: RuntimeId) {
    runtime_managers().remove(&key);
    starting().remove(&key);
}

/// Tells runtime `key` what network the host is on (JSON, as
/// [`net::network::NetworkState`] reads it); sail's own detection is left
/// from then on.
pub fn set_network_state(key: RuntimeId, json: &str) -> Result<(), Error> {
    let manager = runtime_manager(key).ok_or(Error::RuntimeManager)?;
    let state = net::network::NetworkState::from_json(json).map_err(Error::Config)?;
    manager.network().push(state);
    Ok(())
}

/// Tells the TUN inbound of runtime `key` that the host's network changed,
/// with the new interface MTU when it changed too.
pub fn network_changed(key: RuntimeId, mtu: Option<usize>) -> Result<(), Error> {
    let manager = runtime_manager(key).ok_or(Error::RuntimeManager)?;
    #[cfg(feature = "inbound-tun")]
    return manager.blocking_network_changed(mtu);
    #[cfg(not(feature = "inbound-tun"))]
    {
        let _ = (manager, mtu);
        Err(Error::Config(anyhow!("there is no tun inbound")))
    }
}

/// The interfaces `config` has sail make on `host`: its TUNs'.
fn own_interfaces(config: &config::Config, host: &runtime::Host) -> Vec<String> {
    #[cfg(feature = "inbound-tun")]
    {
        config
            .inbounds
            .iter()
            .filter(|i| i.protocol == "tun")
            .filter_map(|i| protocol::tun::inbound::options(i, host).ok())
            .map(|settings| settings.name)
            .collect()
    }
    #[cfg(not(feature = "inbound-tun"))]
    {
        let _ = (config, host);
        Vec::new()
    }
}

/// Looks at the default interface and the network again when interfaces,
/// addresses or routes change, a second after the last change, as
/// sing-box does; when the interface moved, the TUN's flows, bound to the
/// old one, are reset. It never ends: the instance runs on without it.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn follow_default_interface(manager: Arc<RuntimeManager>) {
    let _ = manager
        .detect_network(net::network::ChangeReason::State)
        .await;
    follow_nat64(&manager).await;
    // Linux: netlink's notices of links, addresses and routes.
    #[cfg(target_os = "linux")]
    let monitor = match platform::addr_monitor::AddressMonitor::open_with_routes() {
        Ok(monitor) => monitor,
        Err(e) => {
            warn!("not following the network as it changes: {}", e);
            return std::future::pending().await;
        }
    };
    #[cfg(target_os = "linux")]
    let changed = || monitor.changed();
    // macOS: the routing socket's messages.
    #[cfg(target_os = "macos")]
    let monitor = match platform::route_socket::RouteMonitor::open() {
        Ok(monitor) => monitor,
        Err(e) => {
            warn!("not following the network as it changes: {}", e);
            return std::future::pending().await;
        }
    };
    #[cfg(target_os = "macos")]
    let changed = || monitor.changed();
    // Windows: IP Helper's of routes and interfaces.
    #[cfg(target_os = "windows")]
    let notify = Arc::new(tokio::sync::Notify::new());
    #[cfg(target_os = "windows")]
    let _notices = match platform::windows::ip_helper::ChangeNotices::start(notify.clone()) {
        Ok(notices) => notices,
        Err(e) => {
            warn!("not following the network as it changes: {}", e);
            return std::future::pending().await;
        }
    };
    #[cfg(target_os = "windows")]
    let changed = || {
        let notify = notify.clone();
        async move {
            notify.notified().await;
            std::io::Result::Ok(())
        }
    };
    loop {
        if let Err(e) = changed().await {
            warn!("not following the network as it changes: {}", e);
            return std::future::pending().await;
        }
        // Take the notices of the change before looking.
        settle(&changed, SETTLE_QUIET, SETTLE_MAX).await;
        // The instance's detector, whatever the configuration running says
        // of detection now: what a reload kept may still send by it.
        let moved = match manager.env.auto_interface.get().cloned() {
            Some(auto) => manager
                .env
                .scope
                .spawn_blocking("default interface", move || auto.refresh())
                .await
                .unwrap_or(false),
            None => false,
        };
        let reason = if moved {
            net::network::ChangeReason::DefaultInterface
        } else {
            net::network::ChangeReason::State
        };
        let told = manager.detect_network(reason).await.unwrap_or(false);
        follow_nat64(&manager).await;
        // The interface sail sends through moved though the state, pushed
        // or not detected, says nothing of it.
        if moved && !told {
            manager.network().announce(reason);
        }
    }
}

/// On a network with IPv6 addresses and no IPv4 one, finds its NAT64
/// prefix, which IPv4 is then reached through; elsewhere uses none. The
/// host's network only: a host that pushes the state (a phone) translates
/// IPv4 itself.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn follow_nat64(manager: &RuntimeManager) {
    let network = manager.network().clone();
    if network.pushed() {
        return;
    }
    let state = network.snapshot();
    let v6_only = !state.addresses.iter().any(|a| a.address().is_ipv4())
        && state.addresses.iter().any(|a| match a.address() {
            std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
            std::net::IpAddr::V4(_) => false,
        });
    let prefix = if v6_only {
        manager
            .env
            .scope
            .spawn_blocking("nat64 discovery", net::nat64::discover)
            .await
            .unwrap_or(None)
    } else {
        None
    };
    if net::nat64::set(prefix) {
        match prefix {
            Some(prefix) => info!("network: IPv6 only, IPv4 reached through NAT64 {}", prefix),
            None => info!("network: NAT64 no longer used"),
        }
    }
}

/// Drops what was of the network before whenever it changes so that
/// connections do not survive: the one place every source of change
/// (detection, the host, waking) comes to.
async fn follow_network_changes(manager: Arc<RuntimeManager>) {
    let mut changes = manager.network().changes();
    while changes.changed().await.is_ok() {
        let change = changes.borrow_and_update().clone();
        if let Some(change) = change {
            manager.network_moved(&change).await;
        }
    }
    std::future::pending().await
}

/// Writes out what the log holds, for a host about to exit: the last lines,
/// such as how a stop went, are otherwise lost with the thread that writes
/// them.
pub fn flush_log() {
    app::logger::flush();
}

/// The signals that stop the CLI: Ctrl-C, and SIGTERM on Unix.
#[cfg(feature = "ctrlc")]
struct StopSignals {
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
}

#[cfg(feature = "ctrlc")]
impl StopSignals {
    fn new() -> Self {
        StopSignals {
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| warn!("cannot watch SIGTERM: {}", e))
                .ok(),
        }
    }

    /// The next one to come, by name.
    async fn next(&mut self) -> &'static str {
        #[cfg(unix)]
        if let Some(terminate) = &mut self.terminate {
            return tokio::select! {
                _ = tokio::signal::ctrl_c() => "SIGINT",
                _ = terminate.recv() => "SIGTERM",
            };
        }
        let _ = tokio::signal::ctrl_c().await;
        "SIGINT"
    }
}

/// Stops the TUN inbound's stack, so that its flows are reset rather than
/// left open, before the instance goes.
#[cfg(feature = "inbound-tun")]
async fn stop_tun(control: Option<net::netstack::NativeRuntimeControl>) {
    let Some(mut control) = control else {
        return;
    };
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        control.shutdown(0).await?;
        control.wait_stopped().await
    })
    .await;
    match stopped {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("stopping the tun inbound failed: {}", e),
        Err(_) => warn!("the tun inbound did not stop in time"),
    }
}

pub fn is_running(key: RuntimeId) -> bool {
    runtime_managers().contains_key(&key)
}

/// The dial defaults of an instance: `route`'s, with the system's default
/// interface when `route.auto_detect_interface` asks for it.
/// The output mark of the TUN inbound's auto_redirect, if it has one. A
/// mark of the configuration's own on sail's sockets would undo it, so
/// `route.default_mark` and an outbound's `routing_mark` are errors then, as
/// in sing-box.
#[cfg(feature = "inbound-tun")]
fn auto_redirect_output_mark(
    config: &config::Config,
    host: &runtime::Host,
) -> anyhow::Result<Option<u32>> {
    let Some(tun) = config.inbounds.iter().find(|i| i.protocol == "tun") else {
        return Ok(None);
    };
    let Some(redirect) = protocol::tun::inbound::options(tun, host)?.auto_redirect else {
        return Ok(None);
    };
    if config.route.default_mark.is_some() {
        anyhow::bail!("route.default_mark: conflicts with the tun inbound's auto_redirect");
    }
    let marked = config
        .outbounds
        .iter()
        .map(|o| ("outbound", &o.tag, &o.options))
        .chain(
            config
                .endpoints
                .iter()
                .map(|e| ("endpoint", &e.tag, &e.options)),
        )
        .find(|(_, _, options)| options.contains_key("routing_mark"));
    if let Some((kind, tag, _)) = marked {
        anyhow::bail!(
            "[{}] {}: routing_mark conflicts with the tun inbound's auto_redirect",
            tag,
            kind
        );
    }
    Ok(Some(redirect.output_mark))
}

pub(crate) fn dial_defaults(
    config: &config::Config,
    env: &runtime::RuntimeEnv,
) -> anyhow::Result<Arc<net::DialDefaults>> {
    let route = &config.route;
    let mut defaults = net::DialDefaults::new(route)?;
    #[cfg(feature = "inbound-tun")]
    if let Some(mark) = auto_redirect_output_mark(config, &env.host)? {
        // auto_redirect's only guard against loops: its rules let sail's
        // own sockets, which carry this mark, go out as they are.
        defaults.route.routing_mark = Some(mark);
    }
    defaults.env.protect = match &env.host.platform {
        Some(platform) if platform.protects_sockets() => {
            Some(net::dial::SocketProtect::Platform(platform.clone()))
        }
        _ => env.host.socket_protect.clone(),
    };
    defaults.route.ipv6 = config.dns.strategy.ipv6();
    // What network_strategy chooses among, and never: sail's own TUNs.
    let own_interfaces: Vec<String> = config
        .inbounds
        .iter()
        .filter(|i| i.protocol == "tun")
        .filter_map(|i| i.options.get("interface_name")?.as_str().map(str::to_owned))
        .collect();
    defaults.env.network = Some(env.network.clone());
    defaults.env.own_interfaces = own_interfaces.clone();
    let host_routes = env
        .host
        .platform
        .as_ref()
        .is_some_and(|platform| platform.opens_tun());
    // A TUN that takes the default route takes sail's own traffic too,
    // unless it goes out bound to the physical interface: auto_route turns
    // detection on where nothing else says where to send.
    let implicit = route.default_interface.is_none() && config.tun_takes_own_traffic(host_routes);
    if !route.auto_detect_interface && !implicit {
        return Ok(Arc::new(defaults));
    }
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        defaults.route.auto_detect_interface = true;
        // The instance's, the same at every reload: sail's own TUNs, which
        // it skips, change only at a start.
        defaults.env.auto_interface = Some(
            env.auto_interface
                .get_or_init(|| {
                    net::interface::AutoInterface::new(
                        own_interfaces,
                        platform::detect_default_interface,
                    )
                })
                .clone(),
        );
        Ok(Arc::new(defaults))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        // Bound to the default interface's addresses, found once: the
        // default interface is not taken with them.
        let (inet4, inet6) = platform::default_interface()?;
        info!(
            "outbound traffic goes through the default interface: {}",
            inet4
                .map(|a| a.to_string())
                .or_else(|| inet6.map(|a| a.to_string()))
                .unwrap_or_default()
        );
        defaults.route.bind_interface = None;
        defaults.route.inet4_bind_address = inet4;
        defaults.route.inet6_bind_address = inet6;
        Ok(Arc::new(defaults))
    }
}

/// Checks a configuration file by building everything in it, short of
/// listening or connecting.
pub fn test_config(config_path: &str) -> Result<(), Error> {
    test_config_with(config_path, &runtime::RuntimeEnv::default())
}

/// `test_config`, with the tuning and host the instance would run with.
pub fn test_config_with(config_path: &str, env: &runtime::RuntimeEnv) -> Result<(), Error> {
    let config = config::from_file_for(config_path, &env.host).map_err(Error::Config)?;
    check_config(&config, env).map_err(Error::Config)
}

/// `test_config_with`, and the warnings a start would log: what reading
/// the file found, and what building it logged, as `sing-box check`
/// prints its warnings.
pub fn test_config_with_warnings(
    config_path: &str,
    env: &runtime::RuntimeEnv,
) -> Result<Vec<String>, Error> {
    let (read, logged) =
        app::logger::collect_warnings(|| config::from_file_for(config_path, &env.host));
    let config = read.map_err(Error::Config)?;
    let mut warnings = logged;
    warnings.extend(config.warnings.iter().cloned());
    warnings.extend(check_config_with_warnings(&config, env).map_err(Error::Config)?);
    Ok(warnings)
}

/// `check_config`, and what building logged at WARN or above.
pub fn check_config_with_warnings(
    config: &config::Config,
    env: &runtime::RuntimeEnv,
) -> anyhow::Result<Vec<String>> {
    let (built, warnings) = app::logger::collect_warnings(|| check_config(config, env));
    built.map(|()| warnings)
}

/// Builds the inbounds, outbounds, DNS and routing of `config` and throws
/// them away, so that every mistake building would find is found.
pub fn check_config(config: &config::Config, env: &runtime::RuntimeEnv) -> anyhow::Result<()> {
    // Some handlers start background tasks when built.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _g = rt.enter();
    // What they start is a throwaway scope's, ended with this runtime.
    let scope = runtime::scope::TaskScope::default();
    let _building = scope.building();
    // The interface auto_detect_interface would find is the start's to ask.
    let dial_defaults = Arc::new(net::DialDefaults::new(&config.route)?);
    app::instance::Instance::build(config, Arc::new(env.clone()), dial_defaults)?;
    Ok(())
}

/// Logs what the configuration sets that sail ignores.
fn log_warnings(config: &config::Config) {
    for warning in &config.warnings {
        tracing::warn!("{}", warning);
    }
}

/// The instance's runtime; what its threads log goes to `log`.
fn new_runtime(
    opt: &RuntimeOption,
    log: Arc<app::logger::InstanceLog>,
) -> Result<tokio::runtime::Runtime, Error> {
    let mut builder = match opt {
        RuntimeOption::SingleThread => tokio::runtime::Builder::new_current_thread(),
        RuntimeOption::MultiThreadAuto(stack_size) => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.thread_stack_size(*stack_size);
            builder
        }
        RuntimeOption::MultiThread(worker_threads, stack_size) => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder
                .worker_threads(*worker_threads)
                .thread_stack_size(*stack_size);
            builder
        }
    };
    builder
        .enable_all()
        // Each thread the runtime starts, its blocking ones too, logs to the
        // instance's log for as long as it lives.
        .on_thread_start(move || std::mem::forget(app::logger::enter(Some(log.clone()))))
        .build()
        .map_err(Error::Io)
}

#[derive(Debug)]
pub enum RuntimeOption {
    // Single-threaded runtime.
    SingleThread,
    // Multi-threaded runtime with thread stack size.
    MultiThreadAuto(usize),
    // Multi-threaded runtime with the number of worker threads and thread stack size.
    MultiThread(usize, usize),
}

#[derive(Debug)]
pub enum Config {
    File(String),
    Str(String),
    Internal(Box<config::Config>),
}

#[derive(Debug)]
pub struct StartOptions {
    // The path of the config.
    pub config: Config,
    // Enable auto reload, take effect only when "auto-reload" feature is enabled.
    #[cfg(feature = "auto-reload")]
    pub auto_reload: bool,
    // Tokio runtime options.
    pub runtime_opt: RuntimeOption,
    /// Tuning: a profile and settings on top of it.
    pub runtime: runtime::RuntimeOptions,
    /// What the host provides.
    pub host: runtime::Host,
}

/// Starts the instance `rt_id` and runs it on this thread until it is
/// stopped. `shutdown(rt_id)` stops it from the moment this is called, a
/// start not finished too. An id starting or running already is an error.
pub fn start(rt_id: RuntimeId, opts: StartOptions) -> Result<(), Error> {
    let start = {
        let running = runtime_managers();
        let mut starting = starting();
        if running.contains_key(&rt_id) || starting.contains_key(&rt_id) {
            return Err(Error::InUse(rt_id));
        }
        let start = Arc::new(Starting::default());
        starting.insert(rt_id, start.clone());
        start
    };
    let result = run(rt_id, opts, &start);
    // Gone once it runs; here when the start failed or was stopped.
    let mut starting = starting();
    if starting.get(&rt_id).is_some_and(|s| Arc::ptr_eq(s, &start)) {
        starting.remove(&rt_id);
    }
    result
}

fn run(rt_id: RuntimeId, opts: StartOptions, start: &Arc<Starting>) -> Result<(), Error> {
    let (reload_tx, mut reload_rx) = mpsc::channel(1);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    #[cfg(feature = "inbound-tun")]
    let (network_change_tx, mut network_change_rx) = mpsc::channel::<NetworkChange>(1);

    let config_path = match opts.config {
        Config::File(ref p) => Some(p.to_owned()),
        _ => None,
    };

    // The file as it is before it is read: where it is watched, a write
    // from here until its watch is set up is reloaded then.
    #[cfg(feature = "auto-reload")]
    let config_read = config_path
        .as_deref()
        .and_then(|path| runtime::watch::Stamp::of(std::path::Path::new(path)));
    let config = match opts.config {
        Config::File(p) => config::from_file_for(&p, &opts.host).map_err(Error::Config)?,
        Config::Str(s) => config::from_string_for(&s, &opts.host).map_err(Error::Config)?,
        Config::Internal(c) => *c,
    };

    let mut host = opts.host;
    let log = host
        .log
        .get_or_insert_with(|| app::logger::InstanceLogRef(app::logger::InstanceLog::new(0)))
        .0
        .clone();
    // What this thread logs while it starts and runs the instance is its.
    let _log = app::logger::enter(Some(log.clone()));
    // The TUNs' names, before anything reads them.
    #[cfg(feature = "inbound-tun")]
    let mut config = config;
    #[cfg(feature = "inbound-tun")]
    let tun_names =
        protocol::tun::inbound::resolve_names(&mut config.inbounds, &Default::default(), &host);
    #[cfg(feature = "inbound-tun")]
    let listen_mark = auto_redirect_output_mark(&config, &host).map_err(Error::Config)?;
    // What a killed instance left goes before this one changes anything;
    // this one's place among those running ends with the run, however it
    // ends.
    let (ledger, _running) = platform::sweep::begin(&host.run_dir);
    let events = control::events::EventHub::default();
    let scope = runtime::scope::TaskScope::new(events.clone());
    let stop_within = host.stop_within.unwrap_or(runtime::scope::STOP_WITHIN);
    let env = Arc::new(runtime::RuntimeEnv {
        options: opts.runtime,
        host,
        #[cfg(feature = "inbound-tun")]
        listen_mark,
        ledger,
        #[cfg(feature = "inbound-tun")]
        tun_names: Arc::new(std::sync::Mutex::new(tun_names)),
        events,
        scope: scope.clone(),
        ..Default::default()
    });

    app::logger::setup_logger(&config.log, &env.host)?;
    log.configure(&config.log);
    log_warnings(&config);
    tracing::debug!("runtime options: {:?}", env.options);
    #[cfg(unix)]
    log_file_limit();

    if start.is_stopped() {
        return Ok(());
    }
    // Every way out of the run from here, a failed start or an unwind as
    // well as a stop, goes through `exit` (E2 teardown).
    let exit = Exit {
        rt: Some(new_runtime(&opts.runtime_opt, log)?),
        env: env.clone(),
        scope: scope.clone(),
        stop_within,
        stopped: false,
    };
    let rt = exit.runtime();
    let _g = rt.enter();
    // The build below is synchronous, on no task: what it spawns (groups'
    // health checks, among others) finds the scope through this thread
    // until the root tasks run, which carry it themselves. A reload builds
    // on one of them, inside the scope already.
    let building = scope.building();

    let mut tasks: Vec<Runner> = Vec::new();

    // The network it starts on, settled before anything of the instance
    // is built: a host reading it from then has the interface, or an
    // explicit offline, at generation 1, before the first name the
    // instance asks for. Its own TUNs, not opened yet, are left out by
    // name all the same. Detection gets 1 s (a judgment value): past it,
    // offline, and the interface found later is told as a change. A
    // phone's host pushes the state instead.
    env.network
        .set_own_interfaces(own_interfaces(&config, &env.host));
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let detected = rt.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                scope.spawn_blocking("network settle", platform::network::detect),
            )
            .await
        });
        env.network
            .settle_first(detected.ok().and_then(|joined| joined.ok()));
    }
    if start.is_stopped() {
        return Ok(());
    }
    if let Some(platform) = &env.host.platform {
        platform.settled(&env);
    }

    let dial_defaults = dial_defaults(&config, &env).map_err(Error::Config)?;
    // The inbounds' certificate files as they are before they are read:
    // they are watched only once the instance is built and what its start
    // waits for is fetched, and one written until then is read again then.
    #[cfg(feature = "auto-reload")]
    let inbound_files = app::inbound::follow::about_to_read(&config.inbounds, &env);
    // What it runs, and the files it names as they are before they are
    // read: what tells a later reload that changes the inbounds alone.
    let running = runtime::running::Running::of(&config, &env);
    let mut instance = app::instance::Instance::build(&config, env.clone(), dial_defaults)
        .map_err(Error::Config)?;
    // On a failed start from here, what the system was changed by is
    // undone before what changed it drops (declared after it, so dropped
    // before it).
    let _undo_built = UndoFirst(env.teardown.clone());
    // Its outbounds are built: the host dials through them from here,
    // before the names the start itself asks for (rule-sets, providers)
    // and while those the groups' first checks ask for are answered.
    if let Some(platform) = &env.host.platform {
        platform.dialable(&control::Dialer::new(
            &instance.dispatcher,
            env.clone(),
            rt.handle().clone(),
        ));
    }
    // The LAN devices, when a rule or DNS server asks for them.
    env.neighbors.start_if_needed(&config);
    // The API server joins them, when it is compiled in.
    // Bound before anything starts: an address in use fails the start.
    #[cfg(feature = "clash-api")]
    let clash_api = app::clash_api::bind(config.clash_api.as_ref()).map_err(Error::Config)?;
    #[cfg(feature = "api")]
    let api_listeners = config
        .api
        .as_ref()
        .map(|api| app::api::api_server::bind(api, &env))
        .transpose()
        .map_err(Error::Config)?;
    // The rules cannot match a rule-set not downloaded yet: before any
    // connection comes in.
    let fetched = rt.block_on(async {
        tokio::select! {
            fetched = instance.rule_sets.fetch_missing(&instance.dispatcher) => Some(fetched),
            _ = start.stopped() => None,
        }
    });
    match fetched {
        Some(fetched) => fetched.map_err(Error::Config)?,
        None => return Ok(()),
    }
    // Groups have no members from a provider not downloaded yet; one that
    // fails is left to the updater.
    #[cfg(feature = "outbound-provider")]
    {
        let providers = instance.outbound_manager.load().providers();
        rt.block_on(async {
            tokio::select! {
                _ = providers.fetch_missing(&instance.dispatcher) => {}
                _ = start.stopped() => {}
            }
        });
    }
    if start.is_stopped() {
        return Ok(());
    }
    // Without the API nothing is added to them.
    #[cfg_attr(not(any(feature = "api", feature = "clash-api")), allow(unused_mut))]
    let mut runners = instance.start().map_err(Error::Config)?;
    let _undo_started = UndoFirst(env.teardown.clone());

    let runtime_manager = RuntimeManager::new(
        #[cfg(feature = "auto-reload")]
        rt_id,
        config_path,
        #[cfg(feature = "auto-reload")]
        opts.auto_reload,
        reload_tx,
        shutdown_tx,
        #[cfg(feature = "inbound-tun")]
        network_change_tx,
        &instance,
    );

    // The configuration file is watched when the host asked for it
    // (new_watcher checks); the inbounds' certificate files are followed
    // whatever the host asked, an FFI or embedded host's as well.
    #[cfg(feature = "auto-reload")]
    {
        if let Err(e) = runtime_manager.new_watcher() {
            warn!("start config file watcher failed: {}", e);
        }
        runtime_manager.reload_if_written_since(config_read);
        runtime_manager.follow_certificates_read(&inbound_files);
    }

    *runtime_manager
        .running
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(running);
    runtime_manager.set_assets(&config);
    #[cfg(feature = "api")]
    if let Some((listeners, secret)) = api_listeners {
        let api_server = ApiServer::new(runtime_manager.clone());
        runners.push(api_server.serve(listeners, secret));
    }
    runtime_manager.set_views(&config);
    #[cfg(feature = "clash-api")]
    {
        if let Some((listener, api)) = clash_api {
            runners.push(app::clash_api::serve(
                listener,
                &api,
                runtime_manager.clone(),
            )?);
        }
    }

    drop(config); // explicitly free the memory

    // Monitor reload signal.
    let rm = runtime_manager.clone();
    tasks.push(Box::pin(async move {
        loop {
            if let Some(res_tx) = reload_rx.recv().await {
                let res = rm.reload().await;
                if let Err(e) = res_tx.send(res) {
                    warn!("sending reload result failed: {}", e);
                }
            } else {
                warn!("receiving none reload signal");
            }
        }
    }));

    // auto_detect_interface follows the default interface as it moves, and
    // detection the network the host is on, on one monitor, whatever
    // needs them: a change of network is followed in any case.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    tasks.push(Box::pin(follow_default_interface(runtime_manager.clone())));
    // What was of the network before goes when it changes.
    tasks.push(Box::pin(follow_network_changes(runtime_manager.clone())));
    // A wake from sleep is one: the connections were most likely dropped
    // by their peers meanwhile.
    {
        let network = runtime_manager.network().clone();
        tasks.push(Box::pin(async move {
            platform::sleep::follow(|asleep| {
                info!("woke after {}s asleep", asleep.as_secs());
                network.announce(net::network::ChangeReason::Wake);
            })
            .await;
            std::future::pending().await
        }));
    }
    // Where there is no monitor, the network is detected at the start and
    // on each reload only.
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let rm = runtime_manager.clone();
        tasks.push(Box::pin(async move {
            if rm.needs_network() {
                tracing::debug!("network: not followed as it changes on this system");
            }
            let _ = rm.detect_network(net::network::ChangeReason::State).await;
            std::future::pending().await
        }));
    }

    // Monitor network changes the host reports.
    #[cfg(feature = "inbound-tun")]
    {
        let rm = runtime_manager.clone();
        tasks.push(Box::pin(async move {
            while let Some(change) = network_change_rx.recv().await {
                let res = rm.network_changed(change.mtu).await;
                if change.response.send(res).is_err() {
                    warn!("sending network change result failed");
                }
            }
        }));
    }

    // The main task joining all runners.
    tasks.push(Box::pin(async move {
        futures::future::join_all(runners).await;
    }));

    // Every way to stop stops the TUN inbound first, while its runners still
    // run.
    #[cfg(feature = "inbound-tun")]
    let tun_control = instance.tun_control.clone();

    // Monitor shutdown signal.
    #[cfg(feature = "inbound-tun")]
    let control = tun_control.clone();
    tasks.push(Box::pin(async move {
        let _ = shutdown_rx.recv().await;
        #[cfg(feature = "inbound-tun")]
        stop_tun(control).await;
    }));

    // Ctrl-C, and SIGTERM, as systemd, kill and container runtimes send
    // it: what the instance changed on the system is put back, and the
    // connections open may finish.
    #[cfg(feature = "ctrlc")]
    {
        #[cfg(feature = "inbound-tun")]
        let control = tun_control.clone();
        let rm = runtime_manager.clone();
        tasks.push(Box::pin(async move {
            let mut signals = StopSignals::new();
            let signal = signals.next().await;
            info!("{}: stopping", signal);
            #[cfg(feature = "inbound-tun")]
            stop_tun(control).await;
            rm.drain(signals.next()).await;
        }));
    }

    // SIGHUP reloads the configuration file, as ExecReload sends it; a
    // configuration that fails leaves the one before running.
    #[cfg(all(feature = "ctrlc", unix))]
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(mut hangup) => {
            let rm = runtime_manager.clone();
            tasks.push(Box::pin(async move {
                while hangup.recv().await.is_some() {
                    info!("SIGHUP: reloading");
                    match rm.reload().await {
                        Ok(()) => info!("{}", SIGHUP_RELOADED),
                        Err(e) => tracing::error!("{}: {}", SIGHUP_NOT_LOADED, e),
                    }
                }
                std::future::pending::<()>().await
            }))
        }
        Err(e) => warn!("cannot watch SIGHUP: {}", e),
    }

    // Running from here, unless a stop came while it started: checked and
    // done under the registry's lock, as `shutdown` looks, so that no stop
    // falls between.
    {
        let mut running = runtime_managers();
        let mut starting = starting();
        if start.is_stopped() {
            drop((running, starting));
            env.teardown.run_all();
            #[cfg(feature = "inbound-tun")]
            rt.block_on(stop_tun(tun_control));
            runtime_manager.stop_watching();
            instance.stop();
            drop(instance);
            return Ok(());
        }
        running.insert(rt_id, runtime_manager.clone());
        starting.remove(&rt_id);
    }

    trace!("added runtime {}", &rt_id);
    if let Some(platform) = &runtime_manager.env.host.platform {
        platform.running(&runtime_manager);
    }

    // An essential task's panic ends the run, as a stop does.
    tasks.push(Box::pin({
        let scope = scope.clone();
        async move { scope.failed().await }
    }));
    drop(building);
    // Each root task's panic fails the instance through the scope rather
    // than unwinding run(): the stop below runs as on any end.
    let tasks = tasks
        .into_iter()
        .map(|task| Box::pin(scope.root("root task", task)));
    let (_, _, rest) = rt.block_on(scope.enter(futures::future::select_all(tasks)));

    // In this order (design-notes, E2 teardown): what the instance changed
    // in the system (routes, rules, filters, DNS); then the root tasks
    // left, the TUN's among them, which closes the device; the instance;
    // its tasks, within the bound; the runtime, within it too.
    env.teardown.run_all();
    drop(rest);
    runtime_manager.stop_watching();
    instance.stop();
    drop(instance);
    // What went with them (the device) is gone, or is said to be left.
    env.teardown.check_all();
    let report = rt.block_on(scope.stop(stop_within));
    scope.note_left(env.teardown.left());
    if !report.tasks.is_empty() {
        warn!(
            "stopped with tasks still running after {:?}: {:?}",
            report.waited, report.tasks
        );
    }
    for left in env.teardown.left() {
        warn!("stopped, leaving {}", left);
    }

    let mut running = runtime_managers();
    if running
        .get(&rt_id)
        .is_some_and(|m| Arc::ptr_eq(m, &runtime_manager))
    {
        running.remove(&rt_id);
    }
    drop(running);

    drop(_g);
    exit.done();

    trace!("removed runtime {}", &rt_id);

    match scope.failure() {
        Some(why) => Err(Error::Panicked(with_left(why, &env.teardown.left()))),
        None => Ok(()),
    }
}

/// The way out of a run: whatever ends it, what the instance changed in
/// the system is undone, its tasks are stopped within the bound (unless
/// it unwinds), what is left is recorded, and the runtime is shut down
/// within the bound too, never dropped, which would wait on its blocking
/// threads however long (E2 teardown).
struct Exit {
    rt: Option<tokio::runtime::Runtime>,
    env: Arc<runtime::RuntimeEnv>,
    scope: runtime::scope::TaskScope,
    stop_within: std::time::Duration,
    /// The run's own end stopped the tasks already.
    stopped: bool,
}

impl Exit {
    fn runtime(&self) -> &tokio::runtime::Runtime {
        // Some until it drops.
        self.rt.as_ref().expect("the run's runtime")
    }

    /// The run ended, and stopped its tasks itself.
    fn done(mut self) {
        self.stopped = true;
    }
}

impl Drop for Exit {
    fn drop(&mut self) {
        self.env.teardown.run_all();
        // The runners and the instance dropped before this, declared after
        // it: what went with them (the device) is gone, or is said left.
        self.env.teardown.check_all();
        if let Some(rt) = self.rt.take() {
            if !self.stopped && !std::thread::panicking() {
                rt.block_on(self.scope.stop(self.stop_within));
            }
            self.scope.note_left(self.env.teardown.left());
            // What it still holds (a blocking thread with the device, a
            // task's last drop) goes before the run is said to end, as a
            // drop of the runtime would, but bounded: a thread stuck past
            // it is left behind rather than waited for.
            rt.shutdown_timeout(self.stop_within);
        }
    }
}

/// Undoes what the instance changed in the system when it drops: declared
/// after what made the changes, so that it drops, and undoes, first.
struct UndoFirst(runtime::teardown::Teardown);

impl Drop for UndoFirst {
    fn drop(&mut self) {
        self.0.run_all();
    }
}

/// How a message says what a teardown left.
pub(crate) const LEFT_SAID: &str = "left in the system: ";

/// `why`, and what the teardown left, if anything.
pub(crate) fn with_left(why: String, left: &[runtime::teardown::Left]) -> String {
    if left.is_empty() {
        return why;
    }
    let left: Vec<String> = left.iter().map(|l| l.to_string()).collect();
    format!("{}; {}{}", why, LEFT_SAID, left.join("; "))
}

/// How long the system is quiet after a change of network before sail
/// looks: the notices of a switch of default route, its old interface
/// going down and its routes and addresses going, came within 3 ms in five
/// runs on Linux (netns, measured); this leaves room for slower systems
/// (judgment). A real device's DHCP and router advertisements after a
/// switch are not measured: notices that come later make sail look again,
/// which closes nothing unless the network differs again.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
const SETTLE_QUIET: std::time::Duration = std::time::Duration::from_millis(100);

/// The longest sail waits for the system to be quiet: notices that have
/// nothing to do with the change, an address's duplicate detection ending
/// on another interface, kept a quiet window of 1 s from ending for 1.4 s
/// (measured). Judgment: the 1 s sail used to wait at the least.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
const SETTLE_MAX: std::time::Duration = std::time::Duration::from_secs(1);

/// Waits until `changed` gives no notice for `quiet`, or `max` has passed.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
async fn settle<F, Fut>(changed: &F, quiet: std::time::Duration, max: std::time::Duration)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    let deadline = tokio::time::Instant::now() + max;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(quiet.min(left), changed()).await {
            Ok(Ok(())) if !left.is_zero() => continue,
            _ => return,
        }
    }
}

/// The open-file limit the process runs with, which every connection
/// counts against. The embedding host's to set: the CLI raises it to the
/// hard limit.
#[cfg(unix)]
fn log_file_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct it is given, nothing else.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
        tracing::debug!(
            "open file limit: {} (hard {})",
            limit.rlim_cur,
            limit.rlim_max
        );
    }
}

#[cfg(test)]
mod tests {
    /// A reload keeps the interface detector the start made: what it keeps
    /// running (an endpoint, the outbounds under it) holds that one, and
    /// only the instance's is looked at again when the network changes.
    #[cfg(all(
        feature = "outbound-direct",
        any(target_os = "macos", target_os = "linux", target_os = "windows")
    ))]
    #[test]
    fn a_reload_keeps_the_interface_detector_of_the_start() {
        use std::sync::Arc;
        let config = super::config::Config::from_json(
            r#"{ "route": { "auto_detect_interface": true },
                 "outbounds": [{ "type": "direct" }] }"#,
        )
        .unwrap();
        let env = super::runtime::RuntimeEnv::default();
        let detector = |defaults: &Arc<super::net::DialDefaults>| {
            defaults
                .env
                .auto_interface
                .clone()
                .expect("detection is on")
        };
        let started = detector(&super::dial_defaults(&config, &env).unwrap());
        let reloaded = detector(&super::dial_defaults(&config, &env).unwrap());
        assert!(
            Arc::ptr_eq(&started, &reloaded),
            "a reload made a detector of its own"
        );
        // And it is the one the network's follower refreshes.
        assert!(Arc::ptr_eq(&started, env.auto_interface.get().unwrap()));
    }

    /// What a service manager's scripts read of the log stays as it is:
    /// sail-openwrt's init script restarts sail, or does not, by these.
    #[test]
    fn the_lines_a_service_manager_reads_are_not_reworded() {
        assert_eq!(super::SIGHUP_RELOADED, "SIGHUP: reloaded");
        assert_eq!(
            super::SIGHUP_NOT_LOADED,
            "SIGHUP: the configuration is not loaded, the one before runs on"
        );
        assert_eq!(super::RESTART_TO_APPLY, "restart to apply");
        let refused = super::Error::NeedsRestart(format!(
            "[tun-in] inbound: a tun inbound is changed only at a start; {}",
            super::RESTART_TO_APPLY
        ));
        assert!(format!("{}: {}", super::SIGHUP_NOT_LOADED, refused).contains("restart to apply"));
    }

    use super::*;

    /// The notices of a switch, 3 ms apart, are taken 100 ms after the
    /// last; notices that keep coming are taken at 1 s, not waited out.
    #[tokio::test(start_paused = true)]
    async fn a_change_is_looked_at_once_its_notices_stop_or_at_the_latest() {
        use std::time::Duration;
        let changed_at = |notices: Vec<Duration>| {
            let started = tokio::time::Instant::now();
            let notices = std::sync::Arc::new(std::sync::Mutex::new(notices.into_iter()));
            move || {
                let notices = notices.clone();
                async move {
                    let next = notices.lock().unwrap().next();
                    match next {
                        Some(at) => tokio::time::sleep_until(started + at).await,
                        None => std::future::pending::<()>().await,
                    }
                    std::io::Result::Ok(())
                }
            }
        };
        let start = tokio::time::Instant::now();
        let burst = changed_at(vec![Duration::from_millis(1), Duration::from_millis(3)]);
        settle(&burst, SETTLE_QUIET, SETTLE_MAX).await;
        assert_eq!(start.elapsed(), Duration::from_millis(103));

        let start = tokio::time::Instant::now();
        let endless = changed_at((1..100).map(|i| Duration::from_millis(50 * i)).collect());
        settle(&endless, SETTLE_QUIET, SETTLE_MAX).await;
        assert_eq!(start.elapsed(), SETTLE_MAX);
    }
    use std::thread;

    #[test]
    fn test_restart() {
        // A port of the system's choosing, so parallel test runs do not
        // clash.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        let conf = serde_json::json!({
            "log": { "level": "trace" },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }]
        })
        .to_string();

        for _i in 1..3 {
            let conf = conf.clone();
            thread::spawn(move || {
                let opts = StartOptions {
                    config: Config::Str(conf),
                    #[cfg(feature = "auto-reload")]
                    auto_reload: false,
                    runtime_opt: RuntimeOption::SingleThread,
                    runtime: Default::default(),
                    host: Default::default(),
                };
                start(0, opts).unwrap();
            });
            thread::sleep(std::time::Duration::from_secs(2));
            assert!(shutdown(0));
            loop {
                thread::sleep(std::time::Duration::from_secs(1));
                if !is_running(0) {
                    break;
                }
            }
        }
    }
}
