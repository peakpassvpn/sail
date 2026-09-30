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

pub mod adapter;
pub mod app;
pub mod assets;
pub mod common;
pub mod config;
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
}

pub type Runner = futures::future::BoxFuture<'static, ()>;

pub struct RuntimeManager {
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
    #[cfg(feature = "auto-reload")]
    rule_set_files: Mutex<Vec<std::path::PathBuf>>,
    /// Where a reload's rule-sets go for the TUN's routing.
    #[cfg(all(feature = "inbound-tun", any(target_os = "linux", target_os = "macos")))]
    tun_rule_sets: Option<app::instance::TunRuleSets>,
    /// What the Clash API tells of the configuration.
    #[cfg(feature = "clash-api")]
    clash_view: arc_swap::ArcSwap<app::clash_api::ConfigView>,
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
        Arc::new(Self {
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
            #[cfg(all(feature = "inbound-tun", any(target_os = "linux", target_os = "macos")))]
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
            rule_set_files: Mutex::new(instance.rule_sets.files()),
            #[cfg(feature = "clash-api")]
            clash_view: Default::default(),
            assets: Default::default(),
        })
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

    #[cfg(feature = "clash-api")]
    /// The outbounds, as they are now.
    pub(crate) fn outbound_manager(&self) -> Arc<app::outbound::manager::OutboundManager> {
        self.outbound_manager.load_full()
    }

    #[cfg(feature = "clash-api")]
    pub(crate) fn dns_client(&self) -> SyncDnsClient {
        self.dns_client.clone()
    }

    /// The dispatcher, while the instance runs.
    #[cfg(all(
        feature = "clash-api",
        any(feature = "outbound-provider", feature = "http-client")
    ))]
    pub(crate) fn dispatcher(&self) -> Option<Arc<app::dispatcher::Dispatcher>> {
        self.dispatcher.upgrade()
    }

    #[cfg(feature = "clash-api")]
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
    /// unless the host pushes it or nothing asks for it. Awaiting the
    /// handle waits for it.
    fn detect_network(&self) -> tokio::task::JoinHandle<()> {
        let network = self.network().clone();
        let wanted = !network.pushed() && self.needs_network();
        tokio::task::spawn_blocking(move || {
            if wanted {
                network.detected(platform::network::detect());
            }
        })
    }

    /// What the Clash API tells of the configuration.
    #[cfg(feature = "clash-api")]
    pub(crate) fn clash_view(&self) -> app::clash_api::ConfigView {
        (**self.clash_view.load()).clone()
    }

    #[cfg(feature = "clash-api")]
    fn set_clash_view(&self, config: &config::Config) {
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
        Ok(self
            .stat_manager
            .read()
            .await
            .get_last_peer_active(outbound))
    }

    /// Reloads DNS, outbounds and routing from the configuration file. They
    /// are all built before any is replaced: a configuration that fails to
    /// build changes nothing. Connections already routed keep what they
    /// were routed with.
    //
    // TODO Reload FakeDns.
    pub async fn reload(&self) -> Result<(), Error> {
        let config_path = if let Some(p) = self.config_path.as_ref() {
            p
        } else {
            return Err(Error::NoConfigFile);
        };
        let _update = self.update.lock().await;
        info!("reloading from config file: {}", config_path);
        let config = config::from_file_for(config_path, &self.env.host).map_err(Error::Config)?;
        let inbound_resources = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .prepare_resources(&config.inbounds)
            .map_err(Error::Config)?;
        let dial_defaults = dial_defaults(&config, &self.env).map_err(Error::Config)?;
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
        dns_client
            .check_loops(&config.outbounds, &config.route)
            .map_err(Error::Config)?;
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
        )
        .map_err(Error::Config)?;
        app::logger::setup_logger(&config.log, &self.env.host)?;
        log_warnings(&config);

        #[cfg(feature = "outbound-select")]
        outbound_manager
            .restore_selected(&self.outbound_manager.load())
            .await;
        #[cfg(all(feature = "inbound-tun", any(target_os = "linux", target_os = "macos")))]
        if let Some(feed) = &self.tun_rule_sets {
            feed.check(&rule_sets).map_err(Error::Config)?;
        }
        // Acquire the last fallible lock before publishing anything. No
        // listener is stopped or rebound by a resource update.
        let mut inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        #[cfg(feature = "auto-reload")]
        let watcher = self.prepare_watcher_with_rules(
            inbounds.prepared_resource_files(&inbound_resources),
            rule_sets.files(),
        )?;
        self.env.clash_mode.configure(
            config.clash_api.as_ref(),
            self.env.cache_file.get().as_deref(),
        );
        #[cfg(feature = "clash-api")]
        self.set_clash_view(&config);
        self.set_assets(&config);
        inbounds.publish_resources(inbound_resources);
        #[cfg(feature = "auto-reload")]
        {
            *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = watcher;
            *self
                .rule_set_files
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = rule_sets.files();
        }
        self.dns_client.store(dns_client.into_arc());
        let replaced = self.outbound_manager.swap(Arc::new(outbound_manager));
        self.router.store(Arc::new(router));
        #[cfg(all(feature = "inbound-tun", any(target_os = "linux", target_os = "macos")))]
        if let Some(feed) = &self.tun_rule_sets {
            feed.publish(rule_sets.clone());
        }
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
        info!("reloaded from config file: {}", config_path);
        // What it matches on may be new to this configuration.
        self.detect_network();
        Ok(())
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
        info!("removed outbound [{}]", tag);
        Ok(())
    }

    /// Builds `inbound` and starts listening on its port.
    pub async fn add_inbound(&self, mut inbound: config::Inbound) -> Result<(), Error> {
        let _update = self.update.lock().await;
        if inbound.tag.is_empty() {
            inbound.tag = inbound.protocol.clone();
        }
        let mut inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        #[cfg(feature = "auto-reload")]
        let watcher = self.prepare_watcher(inbounds.resource_files_after_add(&inbound))?;
        inbounds.add(&inbound).map_err(Error::Config)?;
        #[cfg(feature = "auto-reload")]
        {
            *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = watcher;
        }
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
        let mut inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        let prepared = inbounds
            .prepare_update_resources(&inbound)
            .map_err(Error::Config)?;
        #[cfg(feature = "auto-reload")]
        let watcher = self.prepare_watcher(inbounds.prepared_resource_files(&prepared))?;
        inbounds.publish_resources(prepared);
        #[cfg(feature = "auto-reload")]
        {
            *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = watcher;
        }
        Ok(())
    }

    /// Stops listening for the inbound `tag`, and removes it.
    pub async fn remove_inbound(&self, tag: &str) -> Result<(), Error> {
        let _update = self.update.lock().await;
        let mut inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        #[cfg(feature = "auto-reload")]
        let watcher = self.prepare_watcher(inbounds.resource_files_after_remove(tag))?;
        inbounds.remove(tag).map_err(Error::Config)?;
        #[cfg(feature = "auto-reload")]
        {
            *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = watcher;
        }
        info!("removed inbound [{}]", tag);
        Ok(())
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

    /// Tells the TUN inbound's stack that the host's network changed: flows
    /// of the previous network stop being served, and with `mtu`, the stack
    /// takes the new interface MTU. The DNS answers kept go too: those of
    /// the previous network may be wrong on this one.
    #[cfg(feature = "inbound-tun")]
    pub async fn network_changed(&self, mtu: Option<usize>) -> Result<(), Error> {
        let _update = self.update.lock().await;
        self.dns_client.load().clear_cache();
        let Some(mut control) = self.tun_control.clone() else {
            return Err(Error::Config(anyhow!("there is no tun inbound")));
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
        if let Some(mtu) = mtu {
            control.update_mtu(mtu).await?;
        }
        info!("network changed (generation {})", generation);
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

    pub fn blocking_shutdown(&self) -> bool {
        let tx = self.shutdown_tx.clone();
        if let Err(e) = tx.blocking_send(()) {
            warn!("sending shutdown signal failed: {}", e);
            return false;
        }
        true
    }

    #[cfg(feature = "auto-reload")]
    fn prepare_watcher(
        &self,
        files: Vec<std::path::PathBuf>,
    ) -> Result<Option<runtime::watch::FileWatcher>, Error> {
        self.prepare_watcher_with_rules(
            files,
            self.rule_set_files
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        )
    }

    #[cfg(feature = "auto-reload")]
    fn prepare_watcher_with_rules(
        &self,
        mut files: Vec<std::path::PathBuf>,
        rules: Vec<std::path::PathBuf>,
    ) -> Result<Option<runtime::watch::FileWatcher>, Error> {
        if !self.auto_reload {
            return Ok(None);
        }
        let Some(config_path) = self.config_path.as_ref() else {
            return Ok(None);
        };
        files.push(config_path.into());
        files.extend(rules);
        let mut events = self.watch_events.lock().unwrap_or_else(|e| e.into_inner());
        let events =
            events.get_or_insert_with(|| runtime::watch::ReloadEvents::new(self.reload_tx.clone()));
        runtime::watch::FileWatcher::new(files, events).map(Some)
    }

    #[cfg(feature = "auto-reload")]
    pub(crate) fn new_watcher(&self) -> Result<(), Error> {
        let files = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .resource_files();
        let watcher = self.prepare_watcher(files)?;
        *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = watcher;
        Ok(())
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

pub fn reload(key: RuntimeId) -> Result<(), Error> {
    if let Some(m) = runtime_managers().get(&key) {
        return m.blocking_reload();
    }
    Err(Error::RuntimeManager)
}

pub fn shutdown(key: RuntimeId) -> bool {
    if let Some(m) = runtime_managers().get(&key) {
        return m.blocking_shutdown();
    }
    false
}

/// Tells runtime `key` what network the host is on (JSON, as
/// [`net::network::NetworkState`] reads it); sail's own detection is left
/// from then on.
pub fn set_network_state(key: RuntimeId, json: &str) -> Result<(), Error> {
    let manager = runtime_managers()
        .get(&key)
        .cloned()
        .ok_or(Error::RuntimeManager)?;
    let state = net::network::NetworkState::from_json(json).map_err(Error::Config)?;
    manager.network().push(state);
    Ok(())
}

/// Tells the TUN inbound of runtime `key` that the host's network changed,
/// with the new interface MTU when it changed too.
pub fn network_changed(key: RuntimeId, mtu: Option<usize>) -> Result<(), Error> {
    let manager = runtime_managers()
        .get(&key)
        .cloned()
        .ok_or(Error::RuntimeManager)?;
    #[cfg(feature = "inbound-tun")]
    return manager.blocking_network_changed(mtu);
    #[cfg(not(feature = "inbound-tun"))]
    {
        let _ = (manager, mtu);
        Err(Error::Config(anyhow!("there is no tun inbound")))
    }
}

/// Looks at the default interface and the network again when interfaces,
/// addresses or routes change, a second after the last change, as
/// sing-box does; when the interface moved, the TUN's flows, bound to the
/// old one, are reset. It never ends: the instance runs on without it.
#[cfg(target_os = "linux")]
async fn follow_default_interface(manager: Arc<RuntimeManager>) {
    let _ = manager.detect_network().await;
    let monitor = match platform::addr_monitor::AddressMonitor::open_with_routes() {
        Ok(monitor) => monitor,
        Err(e) => {
            warn!("not following the network as it changes: {}", e);
            return std::future::pending().await;
        }
    };
    loop {
        if let Err(e) = monitor.changed().await {
            warn!("not following the network as it changes: {}", e);
            return std::future::pending().await;
        }
        // Take every notice of the change before looking.
        while let Ok(Ok(())) =
            tokio::time::timeout(std::time::Duration::from_secs(1), monitor.changed()).await
        {
        }
        if let Some(auto) = manager.dial_defaults.load().env.auto_interface.clone() {
            let moved = tokio::task::spawn_blocking(move || auto.refresh())
                .await
                .unwrap_or(false);
            // What was answered on the interface before may be wrong on this
            // one.
            if moved {
                manager.dns_client.load().clear_cache();
            }
            #[cfg(feature = "inbound-tun")]
            if moved && manager.tun_control.is_some() {
                if let Err(e) = manager.network_changed(None).await {
                    warn!("auto_detect_interface: resetting the tun's flows: {}", e);
                }
            }
            #[cfg(not(feature = "inbound-tun"))]
            let _ = moved;
        }
        let _ = manager.detect_network().await;
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
fn auto_redirect_output_mark(config: &config::Config) -> anyhow::Result<Option<u32>> {
    let Some(tun) = config.inbounds.iter().find(|i| i.protocol == "tun") else {
        return Ok(None);
    };
    let Some(redirect) = protocol::tun::inbound::options(tun)?.auto_redirect else {
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
    if let Some(mark) = auto_redirect_output_mark(config)? {
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
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let skip = config
            .inbounds
            .iter()
            .filter(|i| i.protocol == "tun")
            .filter_map(|i| i.options.get("interface_name")?.as_str().map(str::to_owned))
            .collect();
        defaults.route.auto_detect_interface = true;
        defaults.env.auto_interface = Some(net::interface::AutoInterface::new(
            skip,
            platform::detect_default_interface,
        ));
        Ok(Arc::new(defaults))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
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

/// Builds the inbounds, outbounds, DNS and routing of `config` and throws
/// them away, so that every mistake building would find is found.
pub fn check_config(config: &config::Config, env: &runtime::RuntimeEnv) -> anyhow::Result<()> {
    // Some handlers start background tasks when built.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _g = rt.enter();
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

fn new_runtime(opt: &RuntimeOption) -> Result<tokio::runtime::Runtime, Error> {
    match opt {
        RuntimeOption::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Io),
        RuntimeOption::MultiThreadAuto(stack_size) => tokio::runtime::Builder::new_multi_thread()
            .thread_stack_size(*stack_size)
            .enable_all()
            .build()
            .map_err(Error::Io),
        RuntimeOption::MultiThread(worker_threads, stack_size) => {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(*worker_threads)
                .thread_stack_size(*stack_size)
                .enable_all()
                .build()
                .map_err(Error::Io)
        }
    }
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

pub fn start(rt_id: RuntimeId, opts: StartOptions) -> Result<(), Error> {
    let (reload_tx, mut reload_rx) = mpsc::channel(1);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    #[cfg(feature = "inbound-tun")]
    let (network_change_tx, mut network_change_rx) = mpsc::channel::<NetworkChange>(1);

    let config_path = match opts.config {
        Config::File(ref p) => Some(p.to_owned()),
        _ => None,
    };

    let config = match opts.config {
        Config::File(p) => config::from_file_for(&p, &opts.host).map_err(Error::Config)?,
        Config::Str(s) => config::from_string(&s).map_err(Error::Config)?,
        Config::Internal(c) => *c,
    };

    let env = Arc::new(runtime::RuntimeEnv {
        options: opts.runtime,
        host: opts.host,
        #[cfg(feature = "inbound-tun")]
        listen_mark: auto_redirect_output_mark(&config).map_err(Error::Config)?,
        ..Default::default()
    });

    app::logger::setup_logger(&config.log, &env.host)?;
    log_warnings(&config);
    tracing::debug!("runtime options: {:?}", env.options);
    #[cfg(unix)]
    log_file_limit();

    let rt = new_runtime(&opts.runtime_opt)?;
    let _g = rt.enter();

    let mut tasks: Vec<Runner> = Vec::new();

    let dial_defaults = dial_defaults(&config, &env).map_err(Error::Config)?;
    #[cfg(target_os = "linux")]
    let follows_interface = dial_defaults.env.auto_interface.is_some();
    let mut instance = app::instance::Instance::build(&config, env.clone(), dial_defaults)
        .map_err(Error::Config)?;
    // The API server joins them, when it is compiled in.
    // Bound before anything starts: an address in use fails the start.
    #[cfg(feature = "clash-api")]
    let clash_api = app::clash_api::bind(config.clash_api.as_ref()).map_err(Error::Config)?;
    #[cfg(feature = "api")]
    let api_listener = config
        .api
        .listen
        .map(|addr| {
            std::net::TcpListener::bind(addr)
                .map_err(|e| Error::Config(anyhow!("api.listen: {}: {}", addr, e)))
        })
        .transpose()?;
    // The rules cannot match a rule-set not downloaded yet: before any
    // connection comes in.
    rt.block_on(instance.rule_sets.fetch_missing(&instance.dispatcher))
        .map_err(Error::Config)?;
    // Groups have no members from a provider not downloaded yet; one that
    // fails is left to the updater.
    #[cfg(feature = "outbound-provider")]
    rt.block_on(
        instance
            .outbound_manager
            .load()
            .providers()
            .fetch_missing(&instance.dispatcher),
    );
    // Without the API nothing is added to them.
    #[cfg_attr(not(any(feature = "api", feature = "clash-api")), allow(unused_mut))]
    let mut runners = instance.start().map_err(Error::Config)?;

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

    // Monitor config file changes.
    #[cfg(feature = "auto-reload")]
    {
        if let Err(e) = runtime_manager.new_watcher() {
            warn!("start config file watcher failed: {}", e);
        }
    }

    runtime_manager.set_assets(&config);
    #[cfg(feature = "api")]
    if let Some(listener) = api_listener {
        let api_server = ApiServer::new(runtime_manager.clone());
        runners.push(api_server.serve(listener)?);
    }
    #[cfg(feature = "clash-api")]
    {
        runtime_manager.set_clash_view(&config);
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
    // detection the network the host is on, on one monitor.
    #[cfg(target_os = "linux")]
    if follows_interface || runtime_manager.needs_network() {
        tasks.push(Box::pin(follow_default_interface(runtime_manager.clone())));
    }
    // Where there is no monitor, the network is detected at the start and
    // on each reload only.
    #[cfg(not(target_os = "linux"))]
    {
        let rm = runtime_manager.clone();
        tasks.push(Box::pin(async move {
            if rm.needs_network() {
                tracing::debug!("network: not followed as it changes on this system");
            }
            let _ = rm.detect_network().await;
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

    // Monitor ctrl-c exit signal.
    #[cfg(feature = "ctrlc")]
    {
        #[cfg(feature = "inbound-tun")]
        let control = tun_control.clone();
        tasks.push(Box::pin(async move {
            let _ = tokio::signal::ctrl_c().await;
            #[cfg(feature = "inbound-tun")]
            stop_tun(control).await;
        }));
    }

    // SIGTERM too, as systemd, kill and container runtimes send it, so that
    // what the instance changed on the system is put back.
    #[cfg(all(feature = "ctrlc", unix))]
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => {
            #[cfg(feature = "inbound-tun")]
            let control = tun_control.clone();
            tasks.push(Box::pin(async move {
                terminate.recv().await;
                #[cfg(feature = "inbound-tun")]
                stop_tun(control).await;
            }))
        }
        Err(e) => warn!("cannot watch SIGTERM: {}", e),
    }

    runtime_managers().insert(rt_id, runtime_manager);

    trace!("added runtime {}", &rt_id);

    rt.block_on(futures::future::select_all(tasks));

    instance.stop();
    drop(instance);

    runtime_managers().remove(&rt_id);

    rt.shutdown_background();

    trace!("removed runtime {}", &rt_id);

    Ok(())
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
    use super::*;
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
