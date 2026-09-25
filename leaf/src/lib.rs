use std::collections::HashMap;
use std::io;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::anyhow;
use lazy_static::lazy_static;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tracing::{info, trace, warn};

#[cfg(feature = "auto-reload")]
use notify::{
    event, Error as NotifyError, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher,
};

use app::{
    dispatcher::Dispatcher, dns::DnsClient, inbound::manager::InboundManager,
    nat_manager::NatManager, outbound::manager::OutboundManager, router::Router,
};

use crate::app::{stat_manager::StatManager, SyncStatManager};

#[cfg(feature = "api")]
use crate::app::api::api_server::ApiServer;

pub mod adapter;
pub mod app;
pub mod common;
pub mod config;
mod include;
pub mod net;
pub mod option;
pub mod platform;
pub mod protocol;
pub mod runtime;
pub mod session;
pub mod sniff;
pub mod transport;
pub mod util;

#[cfg(any(target_os = "ios", target_os = "macos", target_os = "android"))]
pub mod mobile;

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
    router: Arc<RwLock<Router>>,
    dns_client: Arc<RwLock<DnsClient>>,
    outbound_manager: Arc<RwLock<OutboundManager>>,
    stat_manager: SyncStatManager,
    env: runtime::SyncRuntimeEnv,
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
        router: Arc<RwLock<Router>>,
        dns_client: Arc<RwLock<DnsClient>>,
        outbound_manager: Arc<RwLock<OutboundManager>>,
        stat_manager: SyncStatManager,
        env: runtime::SyncRuntimeEnv,
    ) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(feature = "auto-reload")]
            rt_id,
            config_path,
            #[cfg(feature = "auto-reload")]
            auto_reload,
            reload_tx,
            shutdown_tx,
            router,
            dns_client,
            outbound_manager,
            stat_manager,
            env,
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
        let handler = {
            let om = self.outbound_manager.read().await;
            om.get(tag)
                .ok_or_else(|| Error::Config(anyhow!("outbound {} not found", tag)))?
        };

        async fn test_tcp(
            dns_client: Arc<RwLock<DnsClient>>,
            handler: crate::adapter::AnyOutboundHandler,
        ) -> anyhow::Result<Duration> {
            crate::app::healthcheck::tcp(dns_client, handler).await
        }

        async fn test_udp(
            dns_client: Arc<RwLock<DnsClient>>,
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
        if let Some(selector) = self.outbound_manager.read().await.get_selector(outbound) {
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
        if let Some(selector) = self.outbound_manager.read().await.get_selector(outbound) {
            return Ok(selector.read().await.get_selected_tag());
        }
        Err(Error::Config(anyhow!("selector {} not found", outbound)))
    }

    #[cfg(feature = "outbound-select")]
    pub async fn get_outbound_selects(&self, outbound: &str) -> Result<Vec<String>, Error> {
        if let Some(selector) = self.outbound_manager.read().await.get_selector(outbound) {
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

    // This function could block by an in-progress connection dialing.
    //
    // TODO Reload FakeDns. And perhaps the inbounds as long as the listening
    // addresses haven't changed.
    pub async fn reload(&self) -> Result<(), Error> {
        let config_path = if let Some(p) = self.config_path.as_ref() {
            p
        } else {
            return Err(Error::NoConfigFile);
        };
        info!("reloading from config file: {}", config_path);
        let config = config::from_file(config_path).map_err(Error::Config)?;
        app::logger::setup_logger(&config.log, self.env.host.log_to_system)?;
        let dial_defaults = dial_defaults(&config, &self.env).map_err(Error::Config)?;
        self.router.write().await.reload(&config.route, &self.env)?;
        self.dns_client
            .write()
            .await
            .reload(&config.dns, dial_defaults.clone())?;
        self.outbound_manager
            .write()
            .await
            .reload(
                &config.outbounds,
                &dial_defaults,
                &self.env,
                self.dns_client.clone(),
            )
            .await?;
        info!("reloaded from config file: {}", config_path);
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
    defaults.protect = env.host.socket_protect.clone();
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
    let dns_client = Arc::new(RwLock::new(DnsClient::new(
        &config.dns,
        dial_defaults.clone(),
        env.options.dns.clone(),
    )?));
    OutboundManager::new(&config.outbounds, &dial_defaults, env, dns_client.clone())?;
    let mut inbounds = HashMap::new();
    adapter::registry::build_inbounds(
        &include::INBOUNDS,
        &config.inbounds,
        include::LISTENER_INBOUNDS,
        env,
        &mut inbounds,
    )?;
    app::inbound::manager::plan_listeners(&config.inbounds, &inbounds)?;
    #[cfg(feature = "inbound-tun")]
    for inbound in config.inbounds.iter().filter(|i| i.protocol == "tun") {
        protocol::tun::inbound::options(inbound)?;
    }
    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    platform::tun_setup::TunRoute::from_config(config)?;
    Router::new(&config.route, dns_client, env)?;
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
    #[cfg(debug_assertions)]
    println!("start with options:\n{:#?}", opts);

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

    app::logger::setup_logger(&config.log, env.host.log_to_system)?;

    let rt = new_runtime(&opts.runtime_opt)?;
    let _g = rt.enter();

    let mut tasks: Vec<Runner> = Vec::new();
    let mut runners = Vec::new();

    let dial_defaults = dial_defaults(&config, &env).map_err(Error::Config)?;
    let dns_client = Arc::new(RwLock::new(
        DnsClient::new(&config.dns, dial_defaults.clone(), env.options.dns.clone())
            .map_err(Error::Config)?,
    ));
    let outbound_manager = Arc::new(RwLock::new(
        OutboundManager::new(&config.outbounds, &dial_defaults, &env, dns_client.clone())
            .map_err(Error::Config)?,
    ));
    let router = Arc::new(RwLock::new(
        Router::new(&config.route, dns_client.clone(), &env).map_err(Error::Config)?,
    ));
    let stat_manager = Arc::new(RwLock::new(
        StatManager::new().with_max_recent_connections(env.options.stats.max_recent_connections),
    ));
    runners.push(StatManager::cleanup_task(stat_manager.clone()));
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_client.clone(),
        stat_manager.clone(),
        env.clone(),
    ));

    let dispatcher_weak = Arc::downgrade(&dispatcher);
    let dns_client_cloned = dns_client.clone();
    rt.block_on(async move {
        dns_client_cloned
            .write()
            .await
            .replace_dispatcher(dispatcher_weak);
    });

    let nat_manager = Arc::new(NatManager::new(dispatcher.clone(), &config.inbounds));
    let inbound_manager = InboundManager::new(&config.inbounds, &env, dispatcher, nat_manager)
        .map_err(Error::Config)?;
    let mut inbound_net_runners = inbound_manager
        .get_network_runners()
        .map_err(Error::Config)?;
    runners.append(&mut inbound_net_runners);

    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    let net_info =
        match platform::tun_setup::TunRoute::from_config(&config).map_err(Error::Config)? {
            Some(route) => platform::tun_setup::get_net_info(route),
            None => platform::tun_setup::NetInfo::default(),
        };

    #[cfg(feature = "inbound-tun")]
    if let Some(r) = inbound_manager.get_tun_runner() {
        runners.push(r.map_err(Error::Config)?);
    }

    #[cfg(feature = "inbound-cat")]
    if let Some(r) = inbound_manager.get_cat_runner() {
        runners.push(r.map_err(Error::Config)?);
    }

    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    platform::tun_setup::post_tun_creation_setup(&net_info);

    let runtime_manager = RuntimeManager::new(
        #[cfg(feature = "auto-reload")]
        rt_id,
        config_path,
        #[cfg(feature = "auto-reload")]
        opts.auto_reload,
        reload_tx,
        shutdown_tx,
        router,
        dns_client,
        outbound_manager,
        stat_manager,
        env.clone(),
    );

    // Monitor config file changes.
    #[cfg(feature = "auto-reload")]
    {
        if let Err(e) = runtime_manager.new_watcher() {
            warn!("start config file watcher failed: {}", e);
        }
    }

    #[cfg(feature = "api")]
    if let Some(listen_addr) = config.api.listen {
        let api_server = ApiServer::new(runtime_manager.clone());
        runners.push(api_server.serve(listen_addr));
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

    RUNTIME_MANAGER
        .lock()
        .map_err(|_| Error::RuntimeManager)?
        .insert(rt_id, runtime_manager);

    trace!("added runtime {}", &rt_id);

    rt.block_on(futures::future::select_all(tasks));

    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    platform::tun_setup::post_tun_completion_setup(&net_info);

    drop(inbound_manager);

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
