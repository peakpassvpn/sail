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
    net::DialOptions,
    runtime::RuntimeEnv,
};

#[cfg(feature = "outbound-select")]
use super::selector::OutboundSelector;

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
    /// The tasks each outbound's handler spawned.
    abort_handles: HashMap<String, Vec<AbortHandle>>,
    /// The outbounds each outbound is built on.
    dependencies: HashMap<String, Vec<String>>,
    /// The endpoints, whose outbounds are among `handlers`.
    endpoints: HashMap<String, EndpointEntry>,
    /// How each outbound was configured, to tell whether a reload changed
    /// one that must not change.
    configs: HashMap<String, Outbound>,
}

impl OutboundManager {
    /// Builds `outbounds`; their sockets are opened with `dial_defaults`
    /// where their own dial fields leave off.
    pub fn new(
        outbounds: &[Outbound],
        dial_defaults: &DialOptions,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        Self::with_endpoints(outbounds, &[], dial_defaults, env, dns_client)
    }

    /// Builds `outbounds` and `endpoints`, as `new` does outbounds.
    pub fn with_endpoints(
        outbounds: &[Outbound],
        endpoints: &[Endpoint],
        dial_defaults: &DialOptions,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        let empty = Self::empty(outbounds, endpoints);
        empty.with(outbounds, endpoints, dial_defaults, env, dns_client)
    }

    /// Builds `outbounds` anew for a reload, keeping the endpoints of
    /// `previous`, which run, and the outbounds they are built on: those
    /// are only configured at start, and must be configured as they were.
    pub fn reloaded(
        previous: &OutboundManager,
        outbounds: &[Outbound],
        endpoints: &[Endpoint],
        dial_defaults: &DialOptions,
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
        next.with(&rest, &[], dial_defaults, env, dns_client)
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
            abort_handles: HashMap::new(),
            dependencies: HashMap::new(),
            endpoints: HashMap::new(),
            configs: HashMap::new(),
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
        dial_defaults: &DialOptions,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        let mut next = self.clone();
        #[cfg(feature = "plugin")]
        let mut external_handlers = super::plugin::ExternalHandlers::new();
        #[cfg(feature = "outbound-select")]
        let mut selectors = (*self.selectors).clone();
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
            },
        )?;
        for outbound in outbounds {
            next.configs.insert(outbound.tag.clone(), outbound.clone());
        }
        #[cfg(feature = "plugin")]
        next.external_handlers.push(Arc::new(external_handlers));
        #[cfg(feature = "outbound-select")]
        {
            next.selectors = Arc::new(selectors);
        }
        Ok(next)
    }

    /// This manager with `outbound` added.
    pub fn with_outbound(
        &self,
        outbound: &Outbound,
        dial_defaults: &DialOptions,
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
        Ok((next, tasks))
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

    pub fn get(&self, tag: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(tag).map(Clone::clone)
    }

    pub fn default_handler(&self) -> Option<String> {
        self.default_handler.clone()
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
        let dial = DialOptions::default();
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
                &dial,
                &env,
                dns,
            ),
            Some(previous) => OutboundManager::reloaded(
                previous,
                &config.outbounds,
                &config.endpoints,
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
                    {{ "type": "direct", "tag": "a" }},
                    {{ "type": "direct", "tag": "relay"{} }}
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
