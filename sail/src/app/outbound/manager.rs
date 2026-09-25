use std::collections::{hash_map, HashMap};
use std::sync::Arc;

#[cfg(feature = "outbound-select")]
use tokio::sync::RwLock;

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;

use crate::{
    adapter::registry::{self, OutboundBuildState},
    adapter::*,
    app::SyncDnsClient,
    config::Outbound,
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
        let empty = OutboundManager {
            handlers: HashMap::new(),
            #[cfg(feature = "plugin")]
            external_handlers: Vec::new(),
            #[cfg(feature = "outbound-select")]
            selectors: Arc::new(HashMap::new()),
            // The first outbound in the configuration is the default one.
            default_handler: outbounds.first().map(|o| o.tag.clone()),
            abort_handles: HashMap::new(),
            dependencies: HashMap::new(),
        };
        if let Some(tag) = &empty.default_handler {
            tracing::debug!("default handler [{}]", tag);
        }
        empty.with(outbounds, dial_defaults, env, dns_client)
    }

    /// This manager with `outbounds` built onto it: they may be built on
    /// the outbounds here, but not take their tags.
    fn with(
        &self,
        outbounds: &[Outbound],
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
            outbounds,
            OutboundBuildState {
                dns_client: &dns_client,
                dial_defaults,
                env,
                handlers: &mut next.handlers,
                abort_handles: &mut next.abort_handles,
                dependencies: &mut next.dependencies,
                #[cfg(feature = "outbound-select")]
                selectors: &mut selectors,
                #[cfg(feature = "plugin")]
                external_handlers: &mut external_handlers,
            },
        )?;
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
    /// selected, where the same selector still offers it.
    #[cfg(feature = "outbound-select")]
    pub async fn restore_selected(&self, previous: &OutboundManager) {
        for (tag, selector) in self.selectors.iter() {
            if let Some(old) = previous.selectors.get(tag) {
                let selected = old.read().await.get_selected_tag();
                let _ = selector.write().await.set_selected(&selected);
            }
        }
    }

    /// Stops the tasks the handlers started, once they are replaced.
    pub fn abort_tasks(&self) {
        for abort_handle in self.abort_handles.values().flatten() {
            abort_handle.abort();
        }
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
