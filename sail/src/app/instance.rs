//! An instance: the components a configuration describes, built in
//! dependency order, started in stages, and stopped in reverse.

use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use tokio::sync::RwLock;

use super::dispatcher::Dispatcher;
use super::dns::DnsClient;
use super::inbound::manager::InboundManager;
use super::nat_manager::NatManager;
use super::outbound::manager::OutboundManager;
use super::router::Router;
use super::stat_manager::StatManager;
use super::{SyncDnsClient, SyncOutboundManager, SyncRouter, SyncStatManager};
use crate::config::Config;
use crate::net::DialOptions;
use crate::runtime::SyncRuntimeEnv;
use crate::Runner;

#[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
use crate::platform::tun_setup;

pub struct Instance {
    pub env: SyncRuntimeEnv,
    pub dns_client: SyncDnsClient,
    pub outbound_manager: SyncOutboundManager,
    pub router: SyncRouter,
    pub stat_manager: SyncStatManager,
    pub dispatcher: Arc<Dispatcher>,
    pub inbound_manager: Arc<std::sync::Mutex<InboundManager>>,
    /// The routes a TUN with `auto` takes, and once started, what they
    /// replaced.
    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    tun_route: Option<tun_setup::TunRoute>,
    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    net_info: Option<tun_setup::NetInfo>,
}

impl Instance {
    /// Builds what `config` describes, each component after those it uses:
    /// DNS, outbounds, routing, statistics, the dispatcher, NAT, inbounds.
    /// Nothing listens, connects or changes on the system yet, so a
    /// configuration that cannot run fails here and leaves no trace.
    ///
    /// Handlers may start background tasks: this runs within a runtime.
    pub fn build(
        config: &Config,
        env: SyncRuntimeEnv,
        dial_defaults: Arc<DialOptions>,
    ) -> Result<Self> {
        let dns_client =
            DnsClient::new(&config.dns, dial_defaults.clone(), env.options.dns.clone())?
                .into_shared();
        let outbound_manager: SyncOutboundManager = Arc::new(ArcSwap::from_pointee(
            OutboundManager::new(&config.outbounds, &dial_defaults, &env, dns_client.clone())?,
        ));
        let router: SyncRouter = Arc::new(ArcSwap::from_pointee(Router::new(
            &config.route,
            dns_client.clone(),
            &env,
        )?));
        let stat_manager = Arc::new(RwLock::new(
            StatManager::new()
                .with_max_recent_connections(env.options.stats.max_recent_connections),
        ));
        let dispatcher = Arc::new(Dispatcher::new(
            outbound_manager.clone(),
            router.clone(),
            dns_client.clone(),
            stat_manager.clone(),
            env.clone(),
        ));
        dns_client
            .load()
            .set_dispatcher(Arc::downgrade(&dispatcher));
        for inbound in &config.inbounds {
            dispatcher.set_inbound_type(&inbound.tag, Some(&inbound.protocol));
        }
        let nat_manager = Arc::new(NatManager::new(dispatcher.clone(), &config.inbounds));
        let inbound_manager = Arc::new(std::sync::Mutex::new(InboundManager::new(
            &config.inbounds,
            &env,
            dispatcher.clone(),
            nat_manager,
        )?));
        #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
        let tun_route = tun_setup::TunRoute::from_config(config)?;
        Ok(Instance {
            env,
            dns_client,
            outbound_manager,
            router,
            stat_manager,
            dispatcher,
            inbound_manager,
            #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
            tun_route,
            #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
            net_info: None,
        })
    }

    /// Starts serving: the listeners first, so that a port in use fails the
    /// start before the system is touched; then the TUN device, and the
    /// routes into it. Returns what runs the instance.
    pub fn start(&mut self) -> Result<Vec<Runner>> {
        let mut runners = vec![StatManager::cleanup_task(self.stat_manager.clone())];
        let inbound_manager = self.inbound_manager.clone();
        let mut inbounds = inbound_manager.lock().unwrap();
        inbounds.start_network_listeners()?;

        // What the routes replace is read before the device takes them.
        #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
        let net_info = self.tun_route.clone().map(tun_setup::get_net_info);
        #[cfg(feature = "inbound-tun")]
        if let Some(runner) = inbounds.get_tun_runner() {
            runners.push(runner?);
        }
        #[cfg(feature = "inbound-cat")]
        if let Some(runner) = inbounds.get_cat_runner() {
            runners.push(runner?);
        }
        #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
        if let Some(net_info) = net_info {
            tun_setup::post_tun_creation_setup(&net_info);
            // Only what was done is undone.
            self.net_info = Some(net_info);
        }
        Ok(runners)
    }

    /// Undoes what `start` did to the system.
    pub fn stop(&mut self) {
        #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
        if let Some(net_info) = self.net_info.take() {
            tun_setup::post_tun_completion_setup(&net_info);
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.stop();
    }
}
