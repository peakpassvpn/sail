//! An instance: the components a configuration describes, built in
//! dependency order, started in stages, and stopped in reverse.

use crate::app::router::rule_set::RuleSets;
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
    /// Serves the UDP of the inbounds, and of the endpoints once started.
    nat_manager: Arc<NatManager>,
    /// The routes a TUN with `auto` takes, and once started, what they
    /// replaced.
    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    tun_route: Option<tun_setup::TunRoute>,
    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    net_info: Option<tun_setup::NetInfo>,
    /// Controls the TUN inbound's stack once it is started.
    #[cfg(feature = "inbound-tun")]
    pub(crate) tun_control: Option<crate::net::netstack::NativeRuntimeControl>,
}

impl Instance {
    /// Builds what `config` describes, each component after those it uses:
    /// DNS, outbounds and endpoints, routing, statistics, the dispatcher, NAT, inbounds.
    /// Nothing listens, connects or changes on the system yet, so a
    /// configuration that cannot run fails here and leaves no trace.
    ///
    /// Handlers may start background tasks: this runs within a runtime.
    pub fn build(
        config: &Config,
        env: SyncRuntimeEnv,
        dial_defaults: Arc<DialOptions>,
    ) -> Result<Self> {
        // Only a host that opens the TUN routes it; another platform (a
        // desktop app through the FFI, say) leaves the routes to the instance.
        let host_routes = env
            .host
            .platform
            .as_ref()
            .is_some_and(|platform| platform.opens_tun());
        config.check_tun_route(host_routes)?;
        let rule_sets = RuleSets::load(&config.route.rule_set, &env)?;
        let dns_client =
            DnsClient::with_rule_sets(&config.dns, dial_defaults.clone(), &env, &rule_sets)?;
        dns_client.check_loops(
            &config.outbounds,
            config.route.default_domain_resolver.as_ref(),
        )?;
        let dns_client = dns_client.into_shared();
        let outbound_manager: SyncOutboundManager =
            Arc::new(ArcSwap::from_pointee(OutboundManager::with_endpoints(
                &config.outbounds,
                &config.endpoints,
                &dial_defaults,
                &env,
                dns_client.clone(),
            )?));
        let router: SyncRouter = Arc::new(ArcSwap::from_pointee(Router::with_rule_sets(
            &config.route,
            dns_client.clone(),
            &env,
            &rule_sets,
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
        // An endpoint is an inbound too.
        let inbounds: Vec<crate::config::Inbound> = config
            .inbounds
            .iter()
            .cloned()
            .chain(config.endpoints.iter().map(|e| e.as_inbound()))
            .collect();
        for inbound in &inbounds {
            dispatcher.set_inbound_type(&inbound.tag, Some(&inbound.protocol));
        }
        let nat_manager = Arc::new(NatManager::new(dispatcher.clone(), &inbounds));
        let inbound_manager = Arc::new(std::sync::Mutex::new(InboundManager::new(
            &config.inbounds,
            &env,
            dispatcher.clone(),
            nat_manager.clone(),
        )?));
        #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
        let tun_route = tun_setup::TunRoute::from_config(config, &env.host)?;
        Ok(Instance {
            env,
            dns_client,
            outbound_manager,
            router,
            stat_manager,
            dispatcher,
            inbound_manager,
            nat_manager,
            #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
            tun_route,
            #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
            net_info: None,
            #[cfg(feature = "inbound-tun")]
            tun_control: None,
        })
    }

    /// Starts serving: the listeners first, so that a port in use fails the
    /// start before the system is touched; then the TUN device, and the
    /// routes into it. Returns what runs the instance.
    pub fn start(&mut self) -> Result<Vec<Runner>> {
        let mut runners = vec![StatManager::cleanup_task(self.stat_manager.clone())];
        let inbound_manager = self.inbound_manager.clone();
        let mut inbounds = inbound_manager.lock().unwrap_or_else(|e| e.into_inner());
        inbounds.start_network_listeners()?;
        for (tag, server) in self.outbound_manager.load().endpoint_servers() {
            let runner = server
                .start(self.dispatcher.clone(), self.nat_manager.clone())
                .map_err(|e| anyhow::anyhow!("[{}] endpoint: {}", tag, e))?;
            runners.push(runner);
        }

        // What the routes replace is read before the device takes them.
        #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
        let net_info = self
            .tun_route
            .clone()
            .map(tun_setup::get_net_info)
            .transpose()?;
        #[cfg(feature = "inbound-tun")]
        if let Some(tun) = inbounds.get_tun_runner() {
            let tun = tun?;
            runners.push(tun.runner);
            self.tun_control = Some(tun.control);
        }
        #[cfg(feature = "inbound-cat")]
        if let Some(runner) = inbounds.get_cat_runner() {
            runners.push(runner?);
        }
        #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
        if let Some(net_info) = net_info {
            if let Err(e) = tun_setup::post_tun_creation_setup(&net_info) {
                // The routes are restored already. The TUN runner has not
                // been polled, so its stack never ran: dropping the runners
                // drops it and closes the device, and the instance keeps
                // no control of it.
                self.tun_control = None;
                drop(runners);
                return Err(e);
            }
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
