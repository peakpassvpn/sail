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
use notify::{
    event, Error as NotifyError, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher,
};

use app::{outbound::manager::OutboundManager, router::Router};

use crate::app::{SyncDnsClient, SyncOutboundManager, SyncRouter, SyncStatManager};

#[cfg(feature = "api")]
use crate::app::api::api_server::ApiServer;

pub mod adapter;
pub mod app;
pub mod common;
pub mod config;
mod include;
pub mod net;
pub mod platform;
pub mod protocol;
pub mod runtime;
pub mod session;
pub mod sniff;
pub mod transport;
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
    #[cfg(feature = "auto-reload")]
    rt_id: RuntimeId,
    config_path: Option<String>,
    #[cfg(feature = "auto-reload")]
    auto_reload: bool,
    reload_tx: mpsc::Sender<std::sync::mpsc::SyncSender<Result<(), Error>>>,
    shutdown_tx: mpsc::Sender<()>,
    router: SyncRouter,
    dns_client: SyncDnsClient,
    outbound_manager: SyncOutboundManager,
    inbound_manager: Arc<Mutex<app::inbound::manager::InboundManager>>,
    stat_manager: SyncStatManager,
    env: runtime::SyncRuntimeEnv,
    /// What outbounds dial with where theirs leave off, as the current
    /// configuration has it.
    dial_defaults: arc_swap::ArcSwap<net::DialOptions>,
    /// Serializes the changes: reloads, and outbounds and inbounds added
    /// or removed.
    update: tokio::sync::Mutex<()>,
    #[cfg(feature = "auto-reload")]
    watcher: Mutex<Option<RecommendedWatcher>>,
}

impl RuntimeManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        #[cfg(feature = "auto-reload")] rt_id: RuntimeId,
        config_path: Option<String>,
        #[cfg(feature = "auto-reload")] auto_reload: bool,
        reload_tx: mpsc::Sender<std::sync::mpsc::SyncSender<Result<(), Error>>>,
        shutdown_tx: mpsc::Sender<()>,
        instance: &app::instance::Instance,
        dial_defaults: Arc<net::DialOptions>,
    ) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(feature = "auto-reload")]
            rt_id,
            config_path,
            #[cfg(feature = "auto-reload")]
            auto_reload,
            reload_tx,
            shutdown_tx,
            router: instance.router.clone(),
            dns_client: instance.dns_client.clone(),
            outbound_manager: instance.outbound_manager.clone(),
            inbound_manager: instance.inbound_manager.clone(),
            stat_manager: instance.stat_manager.clone(),
            env: instance.env.clone(),
            dial_defaults: arc_swap::ArcSwap::new(dial_defaults),
            update: tokio::sync::Mutex::new(()),
            #[cfg(feature = "auto-reload")]
            watcher: Mutex::new(None),
        })
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
    // TODO Reload FakeDns. And perhaps the inbounds as long as the listening
    // addresses haven't changed.
    pub async fn reload(&self) -> Result<(), Error> {
        let config_path = if let Some(p) = self.config_path.as_ref() {
            p
        } else {
            return Err(Error::NoConfigFile);
        };
        let _update = self.update.lock().await;
        info!("reloading from config file: {}", config_path);
        let config = config::from_file(config_path).map_err(Error::Config)?;
        let dial_defaults = dial_defaults(&config, &self.env).map_err(Error::Config)?;
        let dns_client = self
            .dns_client
            .load()
            .reloaded(&config.dns, dial_defaults.clone())
            .map_err(Error::Config)?;
        // Outbounds and routing reach the DNS client through the shared
        // cell, and so find the new one once it is stored.
        let outbound_manager = OutboundManager::new(
            &config.outbounds,
            &dial_defaults,
            &self.env,
            self.dns_client.clone(),
        )
        .map_err(Error::Config)?;
        let router = Router::new(&config.route, self.dns_client.clone(), &self.env)
            .map_err(Error::Config)?;
        app::logger::setup_logger(&config.log, &self.env.host)?;

        #[cfg(feature = "outbound-select")]
        outbound_manager
            .restore_selected(&self.outbound_manager.load())
            .await;
        self.dns_client.store(Arc::new(dns_client));
        let replaced = self.outbound_manager.swap(Arc::new(outbound_manager));
        self.router.store(Arc::new(router));
        self.dial_defaults.store(dial_defaults);
        replaced.abort_tasks();
        info!("reloaded from config file: {}", config_path);
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
        self.inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .add(&inbound)
            .map_err(Error::Config)?;
        info!("added inbound [{}]", inbound.tag);
        Ok(())
    }

    /// Stops listening for the inbound `tag`, and removes it.
    pub async fn remove_inbound(&self, tag: &str) -> Result<(), Error> {
        let _update = self.update.lock().await;
        self.inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?
            .remove(tag)
            .map_err(Error::Config)?;
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

    pub fn blocking_shutdown(&self) -> bool {
        let tx = self.shutdown_tx.clone();
        if let Err(e) = tx.blocking_send(()) {
            warn!("sending shutdown signal failed: {}", e);
            return false;
        }
        true
    }

    #[cfg(feature = "auto-reload")]
    pub(crate) fn new_watcher(&self) -> Result<(), Error> {
        let config_path = if let Some(p) = self.config_path.as_ref() {
            p
        } else {
            return Err(Error::NoConfigFile);
        };
        if self.auto_reload {
            trace!("starting new watcher for config file: {}", config_path);
            let rt_id = self.rt_id;
            let mut watcher: RecommendedWatcher =
                notify::recommended_watcher(move |res: NotifyResult<event::Event>| {
                    match res {
                        // FIXME Not sure what are the most appropriate events to
                        // filter on different platforms.
                        Ok(ev) => {
                            match ev.kind {
                                #[cfg(any(target_os = "macos", target_os = "ios"))]
                                event::EventKind::Modify(event::ModifyKind::Data(
                                    event::DataChange::Content,
                                )) => {
                                    info!("config file event matched: {:?}", ev);
                                    if let Err(e) = reload(rt_id) {
                                        warn!("reload config file failed: {}", e);
                                    }
                                }
                                #[cfg(any(target_os = "linux", target_os = "android"))]
                                event::EventKind::Access(event::AccessKind::Close(
                                    event::AccessMode::Write,
                                ))
                                | event::EventKind::Remove(event::RemoveKind::File) => {
                                    info!("config file event matched: {:?}", ev);
                                    if let Err(e) = reload(rt_id) {
                                        warn!("reload config file failed: {}", e);
                                    }
                                }
                                #[cfg(target_os = "windows")]
                                event::EventKind::Modify(event::ModifyKind::Data(
                                    event::DataChange::Any,
                                )) => {
                                    info!("config file event matched: {:?}", ev);
                                    if let Err(e) = reload(rt_id) {
                                        warn!("reload config file failed: {}", e);
                                    }
                                }
                                _ => {
                                    trace!("skip config file event: {:?}", ev);
                                }
                            }
                            // The config file could somehow be removed and re-created
                            // by an editor, in that case create a new watcher to watch
                            // the new file.
                            if let event::EventKind::Remove(event::RemoveKind::File) = ev.kind {
                                if let Some(m) = RUNTIME_MANAGER.lock().unwrap().get(&rt_id) {
                                    let _ = m.new_watcher();
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("config file watch error: {:?}", e);
                        }
                    }
                })
                .map_err(Error::Watcher)?;
            watcher
                .watch(
                    std::path::Path::new(&config_path),
                    RecursiveMode::NonRecursive,
                )
                .map_err(Error::Watcher)?;
            info!("watching changes of file: {}", config_path);
            self.watcher.lock().unwrap().replace(watcher);
        }
        Ok(())
    }
}

pub type RuntimeId = u16;

lazy_static! {
    pub static ref RUNTIME_MANAGER: Mutex<HashMap<RuntimeId, Arc<RuntimeManager>>> =
        Mutex::new(HashMap::new());
}

pub fn reload(key: RuntimeId) -> Result<(), Error> {
    if let Some(m) = RUNTIME_MANAGER
        .lock()
        .map_err(|_| Error::RuntimeManager)?
        .get(&key)
    {
        return m.blocking_reload();
    }
    Err(Error::RuntimeManager)
}

pub fn shutdown(key: RuntimeId) -> bool {
    if let Some(m) = RUNTIME_MANAGER.lock().unwrap().get(&key) {
        return m.blocking_shutdown();
    }
    false
}

pub fn is_running(key: RuntimeId) -> bool {
    RUNTIME_MANAGER.lock().unwrap().contains_key(&key)
}

/// The dial defaults of an instance: `route`'s, with the system's default
/// interface when `route.auto_detect_interface` asks for it.
pub(crate) fn dial_defaults(
    config: &config::Config,
    env: &runtime::RuntimeEnv,
) -> anyhow::Result<Arc<net::DialOptions>> {
    let route = &config.route;
    let mut defaults = net::DialOptions::defaults(route)?;
    defaults.protect = match &env.host.platform {
        Some(platform) if platform.protects_sockets() => {
            Some(net::dial::SocketProtect::Platform(platform.clone()))
        }
        _ => env.host.socket_protect.clone(),
    };
    defaults.ipv6 = config.dns.strategy.ipv6();
    if !route.auto_detect_interface {
        return Ok(Arc::new(defaults));
    }
    let detected = platform::default_interface()?;
    info!(
        "outbound traffic goes through the default interface: {}",
        detected
            .bind_interface
            .clone()
            .or_else(|| detected.inet4_bind_address.map(|a| a.to_string()))
            .or_else(|| detected.inet6_bind_address.map(|a| a.to_string()))
            .unwrap_or_default()
    );
    Ok(Arc::new(detected.or(&defaults)))
}

/// Checks a configuration file by building everything in it, short of
/// listening or connecting.
pub fn test_config(config_path: &str) -> Result<(), Error> {
    test_config_with(config_path, &runtime::RuntimeEnv::default())
}

/// `test_config`, with the tuning and host the instance would run with.
pub fn test_config_with(config_path: &str, env: &runtime::RuntimeEnv) -> Result<(), Error> {
    let config = config::from_file(config_path).map_err(Error::Config)?;
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
    let dial_defaults = Arc::new(net::DialOptions::defaults(&config.route)?);
    app::instance::Instance::build(config, Arc::new(env.clone()), dial_defaults)?;
    Ok(())
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
    Internal(config::Config),
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

    let config_path = match opts.config {
        Config::File(ref p) => Some(p.to_owned()),
        _ => None,
    };

    let config = match opts.config {
        Config::File(p) => config::from_file(&p).map_err(Error::Config)?,
        Config::Str(s) => config::from_string(&s).map_err(Error::Config)?,
        Config::Internal(c) => c,
    };

    let env = Arc::new(runtime::RuntimeEnv {
        options: opts.runtime,
        host: opts.host,
    });

    app::logger::setup_logger(&config.log, &env.host)?;
    tracing::debug!("runtime options: {:?}", env.options);

    let rt = new_runtime(&opts.runtime_opt)?;
    let _g = rt.enter();

    let mut tasks: Vec<Runner> = Vec::new();

    let dial_defaults = dial_defaults(&config, &env).map_err(Error::Config)?;
    let mut instance = app::instance::Instance::build(&config, env.clone(), dial_defaults.clone())
        .map_err(Error::Config)?;
    // The API server joins them, when it is compiled in.
    #[allow(unused_mut)]
    // Bound before anything starts: an address in use fails the start.
    #[cfg(feature = "api")]
    let api_listener = config
        .api
        .listen
        .map(|addr| {
            std::net::TcpListener::bind(addr)
                .map_err(|e| Error::Config(anyhow!("api.listen: {}: {}", addr, e)))
        })
        .transpose()?;
    let mut runners = instance.start().map_err(Error::Config)?;

    let runtime_manager = RuntimeManager::new(
        #[cfg(feature = "auto-reload")]
        rt_id,
        config_path,
        #[cfg(feature = "auto-reload")]
        opts.auto_reload,
        reload_tx,
        shutdown_tx,
        &instance,
        dial_defaults,
    );

    // Monitor config file changes.
    #[cfg(feature = "auto-reload")]
    {
        if let Err(e) = runtime_manager.new_watcher() {
            warn!("start config file watcher failed: {}", e);
        }
    }

    #[cfg(feature = "api")]
    if let Some(listener) = api_listener {
        let api_server = ApiServer::new(runtime_manager.clone());
        runners.push(api_server.serve(listener)?);
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

    // The main task joining all runners.
    tasks.push(Box::pin(async move {
        futures::future::join_all(runners).await;
    }));

    // Monitor shutdown signal.
    tasks.push(Box::pin(async move {
        let _ = shutdown_rx.recv().await;
    }));

    // Monitor ctrl-c exit signal.
    #[cfg(feature = "ctrlc")]
    tasks.push(Box::pin(async move {
        let _ = tokio::signal::ctrl_c().await;
    }));

    // SIGTERM too, as systemd, kill and container runtimes send it, so that
    // what the instance changed on the system is put back.
    #[cfg(all(feature = "ctrlc", unix))]
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => tasks.push(Box::pin(async move {
            terminate.recv().await;
        })),
        Err(e) => warn!("cannot watch SIGTERM: {}", e),
    }

    RUNTIME_MANAGER
        .lock()
        .map_err(|_| Error::RuntimeManager)?
        .insert(rt_id, runtime_manager);

    trace!("added runtime {}", &rt_id);

    rt.block_on(futures::future::select_all(tasks));

    instance.stop();
    drop(instance);

    RUNTIME_MANAGER
        .lock()
        .map_err(|_| Error::RuntimeManager)?
        .remove(&rt_id);

    rt.shutdown_background();

    trace!("removed runtime {}", &rt_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_restart() {
        let conf = r#"
[General]
loglevel = trace
dns-server = 1.1.1.1
socks-interface = 127.0.0.1
socks-port = 1080
# tun = auto

[Proxy]
Direct = direct
"#;

        for _i in 1..3 {
            thread::spawn(move || {
                let opts = StartOptions {
                    config: Config::Str(conf.to_string()),
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
