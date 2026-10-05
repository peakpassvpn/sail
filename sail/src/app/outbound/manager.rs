use std::collections::{hash_map, HashMap};
use std::sync::Arc;

#[cfg(feature = "outbound-select")]
use tokio::sync::RwLock;

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;

use crate::{
    adapter::registry::{self, AnyEndpointServer, EndpointEntry, OutboundBuildState},
    adapter::*,
    app::SyncDnsClient,
    config::{model::Endpoint, Outbound},
    include,
    net::DialDefaults,
    runtime::RuntimeEnv,
};

#[cfg(feature = "outbound-select")]
use super::selector::OutboundSelector;
#[cfg(any(
    feature = "outbound-urltest",
    feature = "outbound-load-balance",
    feature = "outbound-fallback"
))]
use crate::protocol::group::members::Snapshot;
#[cfg(feature = "outbound-provider")]
use crate::{
    app::provider::Providers,
    protocol::group::merge::{Merge, Sources},
};

/// The outbounds of an instance. It is not changed in place: a change
/// makes a new manager, which replaces this one in the instance's
/// snapshot.
#[derive(Clone)]
pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
    /// Keeps the plugin libraries the handlers come from loaded.
    #[cfg(feature = "plugin")]
    external_handlers: Vec<Arc<super::plugin::ExternalHandlers>>,
    #[cfg(feature = "outbound-select")]
    selectors: Arc<super::Selectors>,
    default_handler: Option<String>,
    /// Where a connection goes when every rule, and `final`, passes it on
    /// (Mihomo's DIRECT), and behind a captive portal.
    #[cfg(feature = "outbound-direct")]
    direct: Option<AnyOutboundHandler>,
    /// The tasks each outbound's handler spawned.
    abort_handles: HashMap<String, Vec<AbortHandle>>,
    /// The outbounds each outbound is built on.
    dependencies: HashMap<String, Vec<String>>,
    /// The endpoints, whose outbounds are among `handlers`.
    endpoints: HashMap<String, EndpointEntry>,
    /// How each outbound was configured, to tell whether a reload changed
    /// one that must not change.
    configs: HashMap<String, Outbound>,
    /// The outbound providers, whose members groups take.
    #[cfg(feature = "outbound-provider")]
    providers: Arc<Providers>,
    /// What merges the members of each group that takes some from
    /// providers.
    #[cfg(feature = "outbound-provider")]
    merges: HashMap<String, Arc<Merge>>,
    /// The checkers of the groups that test their members, which a
    /// reload carries over.
    #[cfg(any(
        feature = "outbound-urltest",
        feature = "outbound-load-balance",
        feature = "outbound-fallback"
    ))]
    checkers: super::Checkers,
}

impl OutboundManager {
    /// Builds `outbounds`; their sockets are opened with `dial_defaults`
    /// where their own dial fields leave off.
    pub fn new(
        outbounds: &[Outbound],
        dial_defaults: &DialDefaults,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        Self::with_endpoints(
            outbounds,
            &[],
            #[cfg(feature = "outbound-provider")]
            Default::default(),
            dial_defaults,
            env,
            dns_client,
        )
    }

    /// Builds `outbounds` and `endpoints`, as `new` does outbounds, and
    /// the members of `providers`.
    pub(crate) fn with_endpoints(
        outbounds: &[Outbound],
        endpoints: &[Endpoint],
        #[cfg(feature = "outbound-provider")] providers: Providers,
        dial_defaults: &DialDefaults,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        #[cfg_attr(not(feature = "outbound-provider"), allow(unused_mut))]
        let mut empty = Self::empty(outbounds, endpoints);
        #[cfg(feature = "outbound-provider")]
        {
            empty.providers = Arc::new(providers);
        }
        let next = empty.with(outbounds, endpoints, dial_defaults, env, dns_client.clone())?;
        #[cfg(feature = "outbound-provider")]
        next.build_providers(env, &dns_client)?;
        Ok(next)
    }

    /// Builds `outbounds` anew for a reload, keeping the endpoints of
    /// `previous`, which run, and the outbounds they are built on: those
    /// are only configured at start, and must be configured as they were.
    pub(crate) fn reloaded(
        previous: &OutboundManager,
        outbounds: &[Outbound],
        endpoints: &[Endpoint],
        #[cfg(feature = "outbound-provider")] providers: Providers,
        dial_defaults: &DialDefaults,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        let running: Vec<&Endpoint> = previous.endpoints.values().map(|e| &e.config).collect();
        let unchanged =
            running.len() == endpoints.len() && endpoints.iter().all(|e| running.contains(&e));
        if !unchanged {
            return Err(anyhow!(
                "endpoints: changed; endpoints are only configured at start"
            ));
        }
        // The members of the groups that test theirs, as they were: a
        // group's merge follows the members of a provider configured as it
        // was, which the providers built below publish into.
        #[cfg(any(
            feature = "outbound-urltest",
            feature = "outbound-load-balance",
            feature = "outbound-fallback"
        ))]
        let before: HashMap<String, Arc<Snapshot>> = previous
            .checkers
            .iter()
            .map(|(tag, checker)| (tag.clone(), checker.checker().members()))
            .collect();
        // The endpoints and what they are built on, all the way down.
        let mut kept: Vec<String> = previous.endpoints.keys().cloned().collect();
        let mut i = 0;
        while i < kept.len() {
            for dep in previous.dependencies.get(&kept[i]).into_iter().flatten() {
                if !kept.contains(dep) {
                    kept.push(dep.clone());
                }
            }
            i += 1;
        }
        let mut next = Self::empty(outbounds, endpoints);
        #[cfg(feature = "outbound-provider")]
        {
            next.providers = Arc::new(providers);
        }
        #[cfg(feature = "outbound-select")]
        let mut selectors = HashMap::new();
        for tag in &kept {
            if !previous.endpoints.contains_key(tag) {
                let now = outbounds.iter().find(|o| &o.tag == tag);
                if now != previous.configs.get(tag) {
                    return Err(anyhow!(
                        "[{}] outbound: changed, but an endpoint is built on it, and it is \
                         only configured at start",
                        tag
                    ));
                }
                next.configs
                    .insert(tag.clone(), previous.configs[tag].clone());
            }
            next.handlers
                .insert(tag.clone(), previous.handlers[tag].clone());
            if let Some(deps) = previous.dependencies.get(tag) {
                next.dependencies.insert(tag.clone(), deps.clone());
            }
            if let Some(tasks) = previous.abort_handles.get(tag) {
                next.abort_handles.insert(tag.clone(), tasks.clone());
            }
            #[cfg(feature = "outbound-select")]
            if let Some(selector) = previous.selectors.get(tag) {
                selectors.insert(tag.clone(), selector.clone());
            }
            #[cfg(any(
                feature = "outbound-urltest",
                feature = "outbound-load-balance",
                feature = "outbound-fallback"
            ))]
            if let Some(checker) = previous.checkers.get(tag) {
                next.checkers.insert(tag.clone(), checker.clone());
            }
            // A group kept follows the members of the providers it was
            // built on, which must be the ones there are.
            #[cfg(feature = "outbound-provider")]
            if let Some(merge) = previous.merges.get(tag) {
                let now = next.providers.members();
                let unchanged = merge.providers().iter().all(|(provider, members)| {
                    now.get(provider).is_some_and(|m| Arc::ptr_eq(m, members))
                });
                if !unchanged {
                    return Err(anyhow!(
                        "[{}] outbound: its providers changed, but an endpoint is built on it, \
                         and it is only configured at start",
                        tag
                    ));
                }
                next.merges.insert(tag.clone(), merge.clone());
            }
        }
        #[cfg(feature = "outbound-select")]
        {
            next.selectors = Arc::new(selectors);
        }
        next.endpoints = previous.endpoints.clone();
        let rest: Vec<Outbound> = outbounds
            .iter()
            .filter(|o| !kept.contains(&o.tag))
            .cloned()
            .collect();
        let next = next.with(&rest, &[], dial_defaults, env, dns_client.clone())?;
        #[cfg(feature = "outbound-provider")]
        next.build_providers(env, &dns_client)?;
        #[cfg(any(
            feature = "outbound-urltest",
            feature = "outbound-load-balance",
            feature = "outbound-fallback"
        ))]
        next.carry_checks(previous, &before);
        Ok(next)
    }

    /// Starts each group rebuilt that tests its members from what the
    /// group of its tag and type in `previous` found, see `Checker::carry`,
    /// for the members that are as they were: those with the same handler,
    /// an endpoint kept or a provider's member unchanged, and outbounds of
    /// the configuration configured as they were. `before` are the
    /// previous groups' members, taken before the reload built anything.
    #[cfg(any(
        feature = "outbound-urltest",
        feature = "outbound-load-balance",
        feature = "outbound-fallback"
    ))]
    fn carry_checks(&self, previous: &OutboundManager, before: &HashMap<String, Arc<Snapshot>>) {
        let configured_as_it_was = |tag: &str| {
            previous
                .configs
                .get(tag)
                .is_some_and(|was| self.configs.get(tag) == Some(was))
        };
        for (tag, checker) in &self.checkers {
            let (Some(old), Some(before)) = (previous.checkers.get(tag), before.get(tag)) else {
                continue;
            };
            if Arc::ptr_eq(old, checker) || previous.protocol(tag) != self.protocol(tag) {
                continue;
            }
            checker.checker().carry(old.checker(), before, |was, now| {
                Arc::ptr_eq(&was.handler, &now.handler)
                    || (now.key.source.is_none() && configured_as_it_was(&now.key.name))
            });
        }
    }

    fn empty(outbounds: &[Outbound], endpoints: &[Endpoint]) -> Self {
        let empty = OutboundManager {
            handlers: HashMap::new(),
            #[cfg(feature = "plugin")]
            external_handlers: Vec::new(),
            #[cfg(feature = "outbound-select")]
            selectors: Arc::new(HashMap::new()),
            // The first outbound in the configuration is the default one,
            // or without outbounds, the first endpoint.
            default_handler: outbounds
                .first()
                .map(|o| o.tag.clone())
                .or_else(|| endpoints.first().map(|e| e.tag.clone())),
            #[cfg(feature = "outbound-direct")]
            direct: None,
            abort_handles: HashMap::new(),
            dependencies: HashMap::new(),
            endpoints: HashMap::new(),
            configs: HashMap::new(),
            #[cfg(feature = "outbound-provider")]
            providers: Default::default(),
            #[cfg(feature = "outbound-provider")]
            merges: HashMap::new(),
            #[cfg(any(
                feature = "outbound-urltest",
                feature = "outbound-load-balance",
                feature = "outbound-fallback"
            ))]
            checkers: HashMap::new(),
        };
        if let Some(tag) = &empty.default_handler {
            tracing::debug!("default handler [{}]", tag);
        }
        empty
    }

    /// This manager with `outbounds` built onto it: they may be built on
    /// the outbounds here, but not take their tags.
    fn with(
        &self,
        outbounds: &[Outbound],
        endpoints: &[Endpoint],
        dial_defaults: &DialDefaults,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        let mut next = self.clone();
        #[cfg(feature = "plugin")]
        let mut external_handlers = super::plugin::ExternalHandlers::new();
        #[cfg(feature = "outbound-select")]
        let mut selectors = (*self.selectors).clone();
        #[cfg(feature = "outbound-provider")]
        let mut sources = Sources {
            providers: self.providers.members(),
            protocols: self
                .configs
                .values()
                .chain(outbounds)
                .map(|o| (o.tag.clone(), o.protocol.clone()))
                .chain(
                    self.endpoints
                        .values()
                        .map(|e| &e.config)
                        .chain(endpoints)
                        .map(|e| (e.tag.clone(), e.protocol.clone())),
                )
                .collect(),
            merges: Vec::new(),
        };
        registry::build_outbounds(
            &include::OUTBOUNDS,
            &include::ENDPOINTS,
            outbounds,
            endpoints,
            OutboundBuildState {
                dns_client: &dns_client,
                dial_defaults,
                env,
                handlers: &mut next.handlers,
                abort_handles: &mut next.abort_handles,
                dependencies: &mut next.dependencies,
                endpoints: &mut next.endpoints,
                #[cfg(feature = "outbound-select")]
                selectors: &mut selectors,
                #[cfg(feature = "plugin")]
                external_handlers: &mut external_handlers,
                #[cfg(feature = "outbound-provider")]
                providers: &mut sources,
                #[cfg(any(
                    feature = "outbound-urltest",
                    feature = "outbound-load-balance",
                    feature = "outbound-fallback"
                ))]
                checkers: &mut next.checkers,
            },
        )?;
        for outbound in outbounds {
            next.configs.insert(outbound.tag.clone(), outbound.clone());
        }
        #[cfg(feature = "outbound-provider")]
        for merge in sources.merges {
            next.merges.insert(merge.tag().to_string(), merge);
        }
        #[cfg(feature = "plugin")]
        next.external_handlers.push(Arc::new(external_handlers));
        #[cfg(feature = "outbound-select")]
        {
            next.selectors = Arc::new(selectors);
        }
        // Built anew with the defaults of each build.
        #[cfg(feature = "outbound-direct")]
        {
            next.direct = Some(implicit_direct(dial_defaults)?);
        }
        Ok(next)
    }

    /// This manager with `outbound` added.
    pub fn with_outbound(
        &self,
        outbound: &Outbound,
        dial_defaults: &DialDefaults,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        self.with(
            std::slice::from_ref(outbound),
            &[],
            dial_defaults,
            env,
            dns_client,
        )
    }

    /// This manager without the outbound `tag`, which nothing else may be
    /// built on, and the tasks to stop once it is replaced.
    pub fn without_outbound(&self, tag: &str) -> Result<(Self, Vec<AbortHandle>)> {
        let Some(removed) = self.handlers.get(tag) else {
            return Err(anyhow!("[{}] outbound: does not exist", tag));
        };
        if self.endpoints.contains_key(tag) {
            return Err(anyhow!(
                "[{}] outbound: it is an endpoint, which is only configured at start",
                tag
            ));
        }
        if let Some((user, _)) = self
            .dependencies
            .iter()
            .find(|(user, deps)| user.as_str() != tag && deps.iter().any(|d| d == tag))
        {
            return Err(anyhow!("[{}] outbound: [{}] is built on it", tag, user));
        }
        if self.default_handler.as_deref() == Some(tag) {
            return Err(anyhow!(
                "[{}] outbound: it is the default outbound, the first configured",
                tag
            ));
        }
        let mut next = self.clone();
        next.handlers.remove(tag);
        next.dependencies.remove(tag);
        next.configs.remove(tag);
        let mut tasks = next.abort_handles.remove(tag).unwrap_or_default();
        // An outbound identical to another shares its handler, and the
        // tasks go on for the one left.
        if let Some((twin, _)) = next.handlers.iter().find(|(_, h)| Arc::ptr_eq(h, removed)) {
            next.abort_handles
                .entry(twin.clone())
                .or_default()
                .append(&mut tasks);
        }
        #[cfg(feature = "outbound-select")]
        if next.selectors.contains_key(tag) {
            let mut selectors = (*next.selectors).clone();
            selectors.remove(tag);
            next.selectors = Arc::new(selectors);
        }
        #[cfg(feature = "outbound-provider")]
        next.merges.remove(tag);
        #[cfg(any(
            feature = "outbound-urltest",
            feature = "outbound-load-balance",
            feature = "outbound-fallback"
        ))]
        next.checkers.remove(tag);
        Ok((next, tasks))
    }

    /// Builds the members of the providers onto the outbounds, and merges
    /// the groups that take them.
    #[cfg(feature = "outbound-provider")]
    fn build_providers(&self, env: &RuntimeEnv, dns_client: &SyncDnsClient) -> Result<()> {
        self.providers.build(&self.handlers, dns_client, env)?;
        self.merge_groups();
        Ok(())
    }

    /// Merges the members of the groups that take some from providers
    /// again, where a provider changed.
    #[cfg(feature = "outbound-provider")]
    pub(crate) fn merge_groups(&self) {
        for merge in self.merges.values() {
            merge.run();
        }
    }

    /// The outbound providers.
    #[cfg(feature = "outbound-provider")]
    pub(crate) fn providers(&self) -> Arc<Providers> {
        self.providers.clone()
    }

    /// The handlers, by tag.
    #[cfg(feature = "outbound-provider")]
    pub(crate) fn handler_map(&self) -> &HashMap<String, AnyOutboundHandler> {
        &self.handlers
    }

    /// Selects what `previous`, the manager this one replaces, had
    /// selected by hand, see `OutboundSelector::restore`.
    #[cfg(feature = "outbound-select")]
    pub async fn restore_selected(&self, previous: &OutboundManager) {
        for (tag, selector) in self.selectors.iter() {
            if let Some(old) = previous.selectors.get(tag) {
                selector.read().await.restore(&*old.read().await);
            }
        }
    }

    /// Stops the tasks the handlers started, once they are replaced.
    pub fn abort_tasks(&self) {
        for abort_handle in self.abort_handles.values().flatten() {
            abort_handle.abort();
        }
    }

    /// Stops the tasks of the handlers `next`, which replaces this
    /// manager, does not keep: a reload keeps the endpoints and what they
    /// are built on running.
    pub fn abort_tasks_replaced_by(&self, next: &OutboundManager) {
        for (tag, tasks) in &self.abort_handles {
            let kept = match (self.handlers.get(tag), next.handlers.get(tag)) {
                (Some(old), Some(new)) => Arc::ptr_eq(old, new),
                _ => false,
            };
            if !kept {
                for task in tasks {
                    task.abort();
                }
            }
        }
    }

    /// The endpoints' running sides, to start with the instance.
    pub fn endpoint_servers(&self) -> Vec<(String, AnyEndpointServer)> {
        self.endpoints
            .iter()
            .map(|(tag, e)| (tag.clone(), e.server.clone()))
            .collect()
    }

    /// The type an outbound or endpoint was configured with: `direct`,
    /// `selector`, `vless`.
    pub fn protocol(&self, tag: &str) -> Option<&str> {
        self.configs
            .get(tag)
            .map(|o| o.protocol.as_str())
            .or_else(|| self.endpoints.get(tag).map(|e| e.config.protocol.as_str()))
    }

    /// Whether an outbound picks its way by the network the host is on:
    /// a `network` group, whose branches always have conditions on it.
    pub fn needs_network(&self) -> bool {
        self.configs.values().any(|o| o.protocol == "network")
    }

    pub fn get(&self, tag: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(tag).map(Clone::clone)
    }

    pub fn default_handler(&self) -> Option<String> {
        self.default_handler.clone()
    }

    /// The handler of the outbound `tag`, or with `None`, the implicit
    /// direct connections go to when every rule and `final` pass them on.
    pub fn handler(&self, tag: Option<&str>) -> Option<AnyOutboundHandler> {
        match tag {
            Some(tag) => self.get(tag),
            #[cfg(feature = "outbound-direct")]
            None => self.direct.clone(),
            #[cfg(not(feature = "outbound-direct"))]
            None => None,
        }
    }

    pub fn handlers(&self) -> Handlers<'_> {
        Handlers {
            inner: self.handlers.values(),
        }
    }

    #[cfg(feature = "outbound-select")]
    pub fn get_selector(&self, tag: &str) -> Option<Arc<RwLock<OutboundSelector>>> {
        self.selectors.get(tag).map(Clone::clone)
    }
}

/// The tag the implicit direct goes by in logs and connection lists, as
/// Mihomo's.
#[cfg(feature = "outbound-direct")]
pub const IMPLICIT_DIRECT: &str = "DIRECT";

/// The implicit direct, which dials with the instance's defaults.
#[cfg(feature = "outbound-direct")]
fn implicit_direct(dial_defaults: &DialDefaults) -> Result<AnyOutboundHandler> {
    use crate::protocol::direct::outbound::{DatagramHandler, StreamHandler};
    let dialer = dial_defaults.dialer(&Default::default(), None)?;
    Ok(crate::adapter::outbound::HandlerBuilder::default()
        .tag(IMPLICIT_DIRECT.to_owned())
        .stream_handler(Arc::new(StreamHandler(dialer.clone())))
        .datagram_handler(Arc::new(DatagramHandler(dialer)))
        .is_direct(true)
        .build())
}

/// Tells the router which outbounds pass a connection on: a `pass`
/// outbound, or a group of those that pick one member at a time
/// (`selector`, `urltest`, `fallback`, `network`) whose pick, followed
/// down, is one. Every other outbound is looked up once and does not.
impl crate::app::router::Passes for OutboundManager {
    async fn passes(&self, tag: &str) -> bool {
        let Some(handler) = self.handlers.get(tag) else {
            return false;
        };
        if handler.is_pass() {
            return true;
        }
        #[cfg(feature = "outbound-select")]
        {
            let mut group = match self.selectors.get(tag) {
                Some(selector) => selector.clone(),
                None => return false,
            };
            // Groups are built on the members they pick, so they cannot
            // pick in a circle; one pick per group is the most there are.
            for _ in 0..self.selectors.len() {
                let Some(member) = group.read().await.selected_member() else {
                    return false;
                };
                if member.handler.is_pass() {
                    return true;
                }
                // A provider's member is no group.
                if member.key.source.is_some() {
                    return false;
                }
                group = match self.selectors.get(&*member.key.name) {
                    Some(selector) => selector.clone(),
                    None => return false,
                };
            }
        }
        false
    }
}

pub struct Handlers<'a> {
    inner: hash_map::Values<'a, String, AnyOutboundHandler>,
}

impl<'a> Iterator for Handlers<'a> {
    type Item = &'a AnyOutboundHandler;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[cfg(all(test, feature = "wireguard", feature = "outbound-direct"))]
mod tests {
    use super::*;
    use crate::config::Config;

    fn build(json: &str, previous: Option<&OutboundManager>) -> Result<OutboundManager> {
        let config = Config::from_json(json)?;
        let dial = DialDefaults::default();
        let dns = crate::app::dns::DnsClient::new(
            &config.dns,
            Arc::new(dial.clone()),
            &Default::default(),
        )?
        .into_shared();
        let env = RuntimeEnv::default();
        match previous {
            None => OutboundManager::with_endpoints(
                &config.outbounds,
                &config.endpoints,
                #[cfg(feature = "outbound-provider")]
                Default::default(),
                &dial,
                &env,
                dns,
            ),
            Some(previous) => OutboundManager::reloaded(
                previous,
                &config.outbounds,
                &config.endpoints,
                #[cfg(feature = "outbound-provider")]
                Default::default(),
                &dial,
                &env,
                dns,
            ),
        }
    }

    fn config(outbound: &str, detour: &str) -> String {
        format!(
            r#"{{
                "outbounds": [
                    {{ "type": "direct", "tag": "a", "connect_timeout": "5s" }},
                    {{ "type": "direct", "tag": "relay", "connect_timeout": "5s"{} }}
                ],
                "endpoints": [{{
                    "type": "wireguard", "tag": "wg", "detour": "{}",
                    "address": ["10.0.0.2/32"],
                    "private_key": "YFf6vyGG0nAu8ZlKIYO7nZbcfdd2dbmodt1XRkcCdU4=",
                    "peers": [{{
                        "address": "192.0.2.1", "port": 51820,
                        "public_key": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=",
                        "allowed_ips": ["0.0.0.0/0"]
                    }}]
                }}]
            }}"#,
            outbound, detour
        )
    }

    #[test]
    fn a_reload_keeps_the_endpoints_and_what_they_are_built_on() {
        let first = build(&config("", "relay"), None).unwrap();
        assert_eq!(first.endpoint_servers().len(), 1);
        assert!(first.get("wg").is_some());

        // Other outbounds are built again; the endpoint and its detour are
        // the ones running.
        let next = build(&config("", "relay"), Some(&first)).unwrap();
        assert!(Arc::ptr_eq(
            &first.get("wg").unwrap(),
            &next.get("wg").unwrap()
        ));
        assert!(Arc::ptr_eq(
            &first.get("relay").unwrap(),
            &next.get("relay").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            &first.get("a").unwrap(),
            &next.get("a").unwrap()
        ));

        let err = build(&config("", "a"), Some(&first)).err().unwrap();
        assert!(err.to_string().contains("endpoints: changed"), "{}", err);
        let err = build(
            &config(r#", "bind_interface": "lo0""#, "relay"),
            Some(&first),
        )
        .err()
        .unwrap();
        assert!(
            err.to_string().contains("[relay] outbound: changed"),
            "{}",
            err
        );
        let err = first.without_outbound("wg").err().unwrap();
        assert!(err.to_string().contains("endpoint"), "{}", err);
    }
}

#[cfg(all(
    test,
    feature = "outbound-pass",
    feature = "outbound-urltest",
    feature = "outbound-fallback"
))]
mod pass_tests {
    use super::*;
    use crate::app::router::Passes;
    use crate::config::Config;

    fn build(outbounds: &str) -> OutboundManager {
        let config = Config::from_json(&format!(
            r#"{{ "outbounds": [{{ "type": "direct", "tag": "a" }},
                                 {{ "type": "pass", "tag": "PASS" }}, {}] }}"#,
            outbounds
        ))
        .unwrap();
        let dial = DialDefaults::default();
        let dns = crate::app::dns::DnsClient::new(
            &config.dns,
            Arc::new(dial.clone()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        OutboundManager::new(&config.outbounds, &dial, &RuntimeEnv::default(), dns).unwrap()
    }

    #[tokio::test]
    async fn a_group_passes_while_its_pick_followed_down_is_pass() {
        let om = build(
            r#"{ "type": "selector", "tag": "s", "outbounds": ["PASS", "a"] },
               { "type": "selector", "tag": "outer", "outbounds": ["s", "a"] },
               { "type": "urltest", "tag": "u", "outbounds": ["PASS", "a"] },
               { "type": "fallback", "tag": "f", "outbounds": ["PASS", "a"] },
               { "type": "urltest", "tag": "only", "outbounds": ["PASS"] }"#,
        );
        assert!(om.passes("PASS").await);
        assert!(!om.passes("a").await);
        assert!(!om.passes("nothing").await);
        assert!(om.passes("s").await);
        assert!(om.passes("outer").await);
        // Tested groups never take PASS while another member may be up.
        assert!(!om.passes("u").await);
        assert!(!om.passes("f").await);
        assert!(om.passes("only").await);

        om.get_selector("s")
            .unwrap()
            .write()
            .await
            .set_selected("a")
            .unwrap();
        assert!(!om.passes("s").await);
        assert!(!om.passes("outer").await);
    }

    #[tokio::test]
    async fn pass_fails_what_is_dialled_and_the_implicit_direct_is_built() {
        let om = build(r#"{ "type": "selector", "tag": "s", "outbounds": ["PASS", "a"] }"#);
        let pass = om.get("PASS").unwrap();
        assert!(pass.is_pass());
        let sess = crate::session::Session::default();
        let err = pass
            .stream()
            .unwrap()
            .handle(&sess, None, None)
            .await
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "routed to PASS");
        let err = pass
            .datagram()
            .unwrap()
            .handle(&sess, None)
            .await
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "routed to PASS");

        let direct = om.handler(None).unwrap();
        assert_eq!(direct.tag(), IMPLICIT_DIRECT);
        assert!(direct.is_direct());
        assert!(om.get(IMPLICIT_DIRECT).is_none());
    }
}

#[cfg(all(
    test,
    feature = "outbound-direct",
    any(
        feature = "outbound-urltest",
        feature = "outbound-load-balance",
        feature = "outbound-fallback"
    )
))]
mod carry_tests {
    use std::time::Duration;

    use super::*;
    use crate::config::Config;

    /// A URL whose host never answers: no round of tests ends by itself,
    /// nor does one begin, without a runtime.
    const SILENT: &str = "http://192.0.2.1/";

    /// Two members, configured apart, so that they share no handler.
    const MEMBERS: &str = r#"{ "type": "direct", "tag": "a", "connect_timeout": "1s" },
                             { "type": "direct", "tag": "b", "connect_timeout": "2s" }"#;

    fn ms(v: u64) -> Option<Duration> {
        Some(Duration::from_millis(v))
    }

    /// The outbounds of `json`, built, or reloaded over `previous`, in
    /// `env`, whose network every build shares, as an instance's does.
    fn build(json: &str, previous: Option<&OutboundManager>, env: &RuntimeEnv) -> OutboundManager {
        let config = Config::from_json(json).unwrap();
        let dial = DialDefaults::default();
        let dns = crate::app::dns::DnsClient::new(
            &config.dns,
            Arc::new(dial.clone()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        #[cfg(feature = "outbound-provider")]
        let providers = Providers::load(
            &config.outbound_providers,
            &crate::app::http::HttpClients::new(&config, Arc::new(dial.clone())),
            Arc::new(dial.clone()),
            env,
            previous.map(|p| &*p.providers),
        )
        .unwrap();
        match previous {
            None => OutboundManager::with_endpoints(
                &config.outbounds,
                &config.endpoints,
                #[cfg(feature = "outbound-provider")]
                providers,
                &dial,
                env,
                dns,
            ),
            Some(previous) => OutboundManager::reloaded(
                previous,
                &config.outbounds,
                &config.endpoints,
                #[cfg(feature = "outbound-provider")]
                providers,
                &dial,
                env,
                dns,
            ),
        }
        .unwrap()
    }

    /// The configuration of the outbounds `members` and `group`.
    fn config(members: &str, group: &str) -> String {
        format!(r#"{{ "outbounds": [{}, {}] }}"#, members, group)
    }

    /// The group `g` of `kind`, of members [a] and [b], testing `url`,
    /// with the fields `more`.
    fn group(kind: &str, url: &str, more: &str) -> String {
        format!(
            r#"{{ "type": "{}", "tag": "g", "outbounds": ["a", "b"], "url": "{}"{} }}"#,
            kind, url, more
        )
    }

    #[cfg(any(feature = "outbound-urltest", feature = "outbound-fallback"))]
    fn selected(om: &OutboundManager) -> String {
        om.get_selector("g")
            .unwrap()
            .try_read()
            .unwrap()
            .get_selected_tag()
    }

    /// Each member of `g` with its last check's latency, as the API shows
    /// them: `None` for one not checked.
    #[cfg(any(feature = "outbound-urltest", feature = "outbound-fallback"))]
    fn tested(om: &OutboundManager) -> Vec<(String, Option<Option<Duration>>)> {
        om.get_selector("g")
            .unwrap()
            .try_read()
            .unwrap()
            .get_tested()
            .unwrap()
            .into_iter()
            .map(|(name, t)| (name, t.map(|t| t.latency)))
            .collect()
    }

    #[cfg(any(feature = "outbound-urltest", feature = "outbound-fallback"))]
    fn named(name: &str, latency: Option<Option<Duration>>) -> (String, Option<Option<Duration>>) {
        (name.to_string(), latency)
    }

    #[cfg(feature = "outbound-urltest")]
    #[test]
    fn after_a_reload_urltest_takes_the_member_found_fastest_at_once() {
        let env = RuntimeEnv::default();
        let json = config(MEMBERS, &group("urltest", SILENT, ""));
        let first = build(&json, None, &env);
        assert_eq!(selected(&first), "a");
        first.checkers["g"].checker().round(&[ms(300), ms(20)]);
        assert_eq!(selected(&first), "b");

        // Before any round of its own.
        let next = build(&json, Some(&first), &env);
        assert!(!Arc::ptr_eq(&first.checkers["g"], &next.checkers["g"]));
        assert_eq!(selected(&next), "b");
        assert_eq!(
            tested(&next),
            [named("a", Some(ms(300))), named("b", Some(ms(20)))]
        );
        // A round of its own replaces them.
        next.checkers["g"].checker().round(&[ms(10), ms(200)]);
        assert_eq!(selected(&next), "a");
    }

    #[cfg(feature = "outbound-urltest")]
    #[test]
    fn a_member_configured_otherwise_starts_untested() {
        let env = RuntimeEnv::default();
        let first = build(&config(MEMBERS, &group("urltest", SILENT, "")), None, &env);
        first.checkers["g"].checker().round(&[ms(300), ms(20)]);
        let changed = MEMBERS.replace("2s", "3s");
        let next = build(
            &config(&changed, &group("urltest", SILENT, "")),
            Some(&first),
            &env,
        );
        assert_eq!(tested(&next), [named("a", Some(ms(300))), named("b", None)]);
        // The one member found up is taken.
        assert_eq!(selected(&next), "a");
    }

    #[cfg(feature = "outbound-urltest")]
    #[test]
    fn a_group_that_tests_otherwise_carries_nothing() {
        let env = RuntimeEnv::default();
        let json = config(MEMBERS, &group("urltest", SILENT, ""));
        let first = build(&json, None, &env);
        first.checkers["g"].checker().round(&[ms(300), ms(20)]);
        let next = build(&json, Some(&first), &env);
        assert_eq!(
            tested(&next),
            [named("a", Some(ms(300))), named("b", Some(ms(20)))]
        );

        // Another URL.
        let elsewhere = build(
            &config(MEMBERS, &group("urltest", "http://192.0.2.2/", "")),
            Some(&next),
            &env,
        );
        assert_eq!(tested(&elsewhere), [named("a", None), named("b", None)]);
        assert_eq!(selected(&elsewhere), "a");
        // Other statuses expected.
        let expecting = build(
            &config(
                MEMBERS,
                &group("urltest", SILENT, r#", "expected_status": "204""#),
            ),
            Some(&next),
            &env,
        );
        assert_eq!(tested(&expecting), [named("a", None), named("b", None)]);
        // A group of another type, of the same tag.
        #[cfg(feature = "outbound-fallback")]
        {
            let fallback = build(
                &config(MEMBERS, &group("fallback", SILENT, "")),
                Some(&next),
                &env,
            );
            assert_eq!(tested(&fallback), [named("a", None), named("b", None)]);
        }
    }

    #[cfg(feature = "outbound-fallback")]
    #[test]
    fn after_a_reload_fallback_skips_a_member_found_down_and_keeps_its_standing() {
        let env = RuntimeEnv::default();
        let json = config(
            MEMBERS,
            &group(
                "fallback",
                SILENT,
                r#", "debounce": { "recover_after": 2 }"#,
            ),
        );
        let first = build(&json, None, &env);
        assert_eq!(selected(&first), "a");
        first.checkers["g"].checker().round(&[None, ms(10)]);
        assert_eq!(selected(&first), "b");

        let next = build(&json, Some(&first), &env);
        assert_eq!(selected(&next), "b");
        assert_eq!(
            tested(&next),
            [named("a", Some(None)), named("b", Some(ms(10)))]
        );
        // [a] is down as it stood: two rounds passed in a row take it back,
        // as they would have before the reload.
        let checker = next.checkers["g"].checker();
        checker.round(&[ms(10), ms(10)]);
        assert_eq!(selected(&next), "b");
        checker.round(&[ms(10), ms(10)]);
        assert_eq!(selected(&next), "a");
    }

    #[cfg(feature = "outbound-load-balance")]
    #[test]
    fn after_a_reload_load_balance_leaves_out_a_member_found_down() {
        let env = RuntimeEnv::default();
        let json = config(MEMBERS, &group("load-balance", SILENT, ""));
        let first = build(&json, None, &env);
        first.checkers["g"].checker().round(&[None, ms(10)]);
        let next = build(&json, Some(&first), &env);
        let checker = next.checkers["g"].checker();
        let key = crate::protocol::group::members::MemberKey::outbound;
        assert!(!checker.is_up(&key("a")));
        assert!(checker.is_up(&key("b")));
    }

    /// A provider's member carries while the provider keeps its handler;
    /// a provider configured otherwise builds its members anew, and they
    /// carry nothing.
    #[cfg(all(feature = "outbound-provider", feature = "outbound-urltest"))]
    #[test]
    fn a_provider_member_carries_while_its_handler_is_kept() {
        let provider = |timeout: &str| {
            format!(
                r#"{{ "outbounds": [
                        {{ "type": "direct", "tag": "d" }},
                        {{ "type": "urltest", "tag": "g", "providers": "p", "url": "{}" }}
                      ],
                      "outbound_providers": [{{ "type": "inline", "tag": "p", "outbounds": [
                        {{ "type": "direct", "tag": "x", "connect_timeout": "1s" }},
                        {{ "type": "direct", "tag": "y", "connect_timeout": "{}" }}
                      ] }}] }}"#,
                SILENT, timeout
            )
        };
        let env = RuntimeEnv::default();
        let first = build(&provider("2s"), None, &env);
        first.checkers["g"].checker().round(&[ms(300), ms(20)]);
        assert_eq!(selected(&first), "y");

        let next = build(&provider("2s"), Some(&first), &env);
        assert_eq!(selected(&next), "y");
        assert_eq!(
            tested(&next),
            [named("x", Some(ms(300))), named("y", Some(ms(20)))]
        );

        let otherwise = build(&provider("3s"), Some(&next), &env);
        assert_eq!(tested(&otherwise), [named("x", None), named("y", None)]);
    }
}
