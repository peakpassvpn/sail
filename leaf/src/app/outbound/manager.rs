use std::collections::{hash_map, HashMap};
#[cfg(feature = "outbound-select")]
use std::sync::Arc;

#[cfg(feature = "outbound-select")]
use tokio::sync::RwLock;

use anyhow::Result;
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

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
    #[cfg(feature = "plugin")]
    external_handlers: super::plugin::ExternalHandlers,
    #[cfg(feature = "outbound-select")]
    selectors: Arc<super::Selectors>,
    default_handler: Option<String>,
    abort_handles: Vec<AbortHandle>,
}

/// Everything building a set of outbounds produces.
struct Loaded {
    handlers: HashMap<String, AnyOutboundHandler>,
    #[cfg(feature = "plugin")]
    external_handlers: super::plugin::ExternalHandlers,
    #[cfg(feature = "outbound-select")]
    selectors: super::Selectors,
    default_handler: Option<String>,
    abort_handles: Vec<AbortHandle>,
}

impl OutboundManager {
    fn load(
        outbounds: &[Outbound],
        dial_defaults: &DialOptions,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Loaded> {
        let mut handlers = HashMap::new();
        #[cfg(feature = "plugin")]
        let mut external_handlers = super::plugin::ExternalHandlers::new();
        #[cfg(feature = "outbound-select")]
        let mut selectors = HashMap::new();
        let mut abort_handles = Vec::new();

        registry::build_outbounds(
            &include::OUTBOUNDS,
            outbounds,
            OutboundBuildState {
                dns_client: &dns_client,
                dial_defaults,
                env,
                handlers: &mut handlers,
                abort_handles: &mut abort_handles,
                #[cfg(feature = "outbound-select")]
                selectors: &mut selectors,
                #[cfg(feature = "plugin")]
                external_handlers: &mut external_handlers,
            },
        )?;

        // The first outbound in the configuration is the default one.
        let default_handler = outbounds.first().map(|o| o.tag.clone());
        if let Some(tag) = &default_handler {
            tracing::debug!("default handler [{}]", tag);
        }

        Ok(Loaded {
            handlers,
            #[cfg(feature = "plugin")]
            external_handlers,
            #[cfg(feature = "outbound-select")]
            selectors,
            default_handler,
            abort_handles,
        })
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
        for abort_handle in self.abort_handles.iter() {
            abort_handle.abort();
        }
    }

    /// Builds `outbounds`; their sockets are opened with `dial_defaults`
    /// where their own dial fields leave off.
    pub fn new(
        outbounds: &[Outbound],
        dial_defaults: &DialOptions,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        let Loaded {
            handlers,
            #[cfg(feature = "plugin")]
            external_handlers,
            #[cfg(feature = "outbound-select")]
            selectors,
            default_handler,
            abort_handles,
        } = Self::load(outbounds, dial_defaults, env, dns_client)?;

        Ok(OutboundManager {
            handlers,
            #[cfg(feature = "plugin")]
            external_handlers,

            #[cfg(feature = "outbound-select")]
            selectors: Arc::new(selectors),
            default_handler,
            abort_handles,
        })
    }

    pub fn add(&mut self, tag: String, handler: AnyOutboundHandler) {
        self.handlers.insert(tag, handler);
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
