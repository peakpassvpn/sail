//! An instance: the components a configuration describes, built in
//! dependency order, started in stages, and stopped in reverse.

use crate::app::router::rule_set::{HttpClients, RuleSets};
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

#[cfg(all(feature = "inbound-tun", target_os = "macos"))]
use crate::platform::tun_setup;

pub struct Instance {
    pub env: SyncRuntimeEnv,
    pub dns_client: SyncDnsClient,
    pub outbound_manager: SyncOutboundManager,
    pub router: SyncRouter,
    pub stat_manager: SyncStatManager,
    pub dispatcher: Arc<Dispatcher>,
    /// The rule-sets the rules name.
    pub(crate) rule_sets: RuleSets,
    pub inbound_manager: Arc<std::sync::Mutex<InboundManager>>,
    /// Serves the UDP of the inbounds, and of the endpoints once started.
    nat_manager: Arc<NatManager>,
    /// The routes a TUN with `auto` takes, and once started, what they
    /// replaced.
    #[cfg(all(feature = "inbound-tun", target_os = "macos"))]
    tun_route: Option<tun_setup::TunRoute>,
    #[cfg(all(feature = "inbound-tun", target_os = "macos"))]
    net_info: Option<tun_setup::NetInfo>,
    /// Controls the TUN inbound's stack once it is started.
    #[cfg(feature = "inbound-tun")]
    pub(crate) tun_control: Option<crate::net::netstack::NativeRuntimeControl>,
    /// A TUN inbound's tag and settings, when the instance routes into it
    /// (Linux: auto_redirect, or auto_route alone); once started, what
    /// that set up.
    #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
    routed_tun: Option<(String, crate::protocol::tun::inbound::TunSettings)>,
    #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
    tun_routing: Option<TunRouting>,
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
        // Closed again if the build fails.
        let cache_file = env
            .cache_file
            .replace(config.experimental.cache_file.as_ref(), &env)?;
        env.clash_mode.configure(
            config.experimental.clash_api.as_ref(),
            env.cache_file.get().as_deref(),
        );
        #[cfg(feature = "tls")]
        env.tls_roots.set(crate::transport::tls::roots::configured(
            config.certificate.as_ref(),
            &env,
        )?);
        let http_clients = HttpClients::new(config, dial_defaults.clone());
        let rule_sets = RuleSets::load(&config.route.rule_set, &http_clients, &env)?;
        #[cfg(feature = "outbound-provider")]
        let providers = crate::app::provider::Providers::load(
            &config.outbound_providers,
            &http_clients,
            dial_defaults.clone(),
            &env,
            None,
        )?;
        let dns_client =
            DnsClient::with_rule_sets(&config.dns, dial_defaults.clone(), &env, &rule_sets)?;
        dns_client.check_loops(&config.outbounds, &config.route)?;
        let dns_client = dns_client.into_shared();
        let outbound_manager: SyncOutboundManager =
            Arc::new(ArcSwap::from_pointee(OutboundManager::with_endpoints(
                &config.outbounds,
                &config.endpoints,
                #[cfg(feature = "outbound-provider")]
                providers,
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
        #[cfg(all(feature = "inbound-tun", target_os = "macos"))]
        let tun_route = tun_setup::TunRoute::from_config(config, &env.host)?;
        #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
        let routed_tun = config
            .inbounds
            .iter()
            .find(|i| i.protocol == "tun")
            .map(|i| {
                crate::protocol::tun::inbound::options(i).map(|settings| (i.tag.clone(), settings))
            })
            .transpose()?
            .filter(|(_, settings)| {
                settings.auto_redirect.is_some() || (settings.auto_route && !host_opens_tun(&env))
            });
        cache_file.keep();
        Ok(Instance {
            env,
            dns_client,
            outbound_manager,
            router,
            stat_manager,
            dispatcher,
            rule_sets,
            inbound_manager,
            nat_manager,
            #[cfg(all(feature = "inbound-tun", target_os = "macos"))]
            tun_route,
            #[cfg(all(feature = "inbound-tun", target_os = "macos"))]
            net_info: None,
            #[cfg(feature = "inbound-tun")]
            tun_control: None,
            #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
            routed_tun,
            #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
            tun_routing: None,
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
        #[cfg(all(feature = "inbound-tun", target_os = "macos"))]
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
        #[cfg(all(feature = "inbound-tun", target_os = "macos"))]
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
        // After the device, whose routes it adds; what fails is undone.
        #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
        if let Some((tag, settings)) = &self.routed_tun {
            let started = match &settings.auto_redirect {
                Some(options) => crate::protocol::tun::auto_redirect::AutoRedirect::start(
                    tag,
                    settings,
                    options,
                    self.dispatcher.clone(),
                    &self.rule_sets,
                )
                .map(|(routing, runner)| (TunRouting::Redirect(routing), runner)),
                None => crate::protocol::tun::auto_route::AutoRoute::start(
                    tag,
                    settings,
                    &self.rule_sets,
                )
                .map(|(routing, runner)| (TunRouting::Route(routing), runner)),
            };
            match started {
                Ok((routing, runner)) => {
                    runners.push(runner);
                    self.tun_routing = Some(routing);
                }
                Err(e) => {
                    self.tun_control = None;
                    drop(runners);
                    return Err(e);
                }
            }
        }
        Ok(runners)
    }

    /// What a reload hands its rule-sets to, when the instance routes
    /// into the TUN.
    #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
    pub(crate) fn tun_rule_sets(&self) -> Option<TunRuleSets> {
        self.tun_routing.as_ref().map(|routing| match routing {
            TunRouting::Redirect(r) => TunRuleSets::Redirect(r.rule_set_feed()),
            TunRouting::Route(r) => TunRuleSets::Route(r.rule_set_feed()),
        })
    }

    /// Undoes what `start` did to the system.
    pub fn stop(&mut self) {
        // What it kept is written, and the file freed for the next start.
        self.env.cache_file.close();
        // Before the device goes, as sing-box closes it.
        #[cfg(all(feature = "inbound-tun", target_os = "linux"))]
        drop(self.tun_routing.take());
        #[cfg(all(feature = "inbound-tun", target_os = "macos"))]
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

/// Whether a host that runs the VPN opens the TUN, and routes it.
#[cfg(all(feature = "inbound-tun", target_os = "linux"))]
fn host_opens_tun(env: &crate::runtime::RuntimeEnv) -> bool {
    env.host
        .platform
        .as_ref()
        .is_some_and(|platform| platform.opens_tun())
}

/// How the instance routes into the TUN (Linux).
#[cfg(all(feature = "inbound-tun", target_os = "linux"))]
enum TunRouting {
    Redirect(crate::protocol::tun::auto_redirect::AutoRedirect),
    Route(crate::protocol::tun::auto_route::AutoRoute),
}

/// Where a reload's rule-sets go for the TUN's routing.
#[cfg(all(feature = "inbound-tun", target_os = "linux"))]
#[derive(Clone)]
pub(crate) enum TunRuleSets {
    Redirect(crate::protocol::tun::auto_redirect::RuleSetFeed),
    Route(crate::protocol::tun::auto_route::RouteSetFeed),
}

#[cfg(all(feature = "inbound-tun", target_os = "linux"))]
impl TunRuleSets {
    /// Whether `rule_sets` has every rule-set the TUN names.
    pub(crate) fn check(&self, rule_sets: &RuleSets) -> Result<()> {
        match self {
            TunRuleSets::Redirect(feed) => feed.check(rule_sets),
            TunRuleSets::Route(feed) => feed.check(rule_sets),
        }
    }

    pub(crate) fn publish(&self, rule_sets: RuleSets) {
        match self {
            TunRuleSets::Redirect(feed) => feed.publish(rule_sets),
            TunRuleSets::Route(feed) => feed.publish(rule_sets),
        }
    }
}
