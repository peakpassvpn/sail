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

    // TODO make this non-async?
    pub async fn reload(
        &mut self,
        outbounds: &[Outbound],
        dial_defaults: &DialOptions,
        env: &RuntimeEnv,
        dns_client: SyncDnsClient,
    ) -> Result<()> {
        // Save outound select states.
        #[cfg(feature = "outbound-select")]
        let selected_outbounds: HashMap<String, String> = {
            let mut m = HashMap::new();
            for (k, v) in self.selectors.iter() {
                m.insert(k.to_owned(), v.read().await.get_selected_tag());
            }
            m
        };

        // Load new outbounds.
        #[allow(unused_mut)]
        let Loaded {
            handlers,
            #[cfg(feature = "plugin")]
            external_handlers,
            #[cfg(feature = "outbound-select")]
            mut selectors,
            default_handler,
            abort_handles,
        } = Self::load(outbounds, dial_defaults, env, dns_client)?;

        // Restore outbound select states.
        #[cfg(feature = "outbound-select")]
        {
            for (k, v) in selected_outbounds.iter() {
                for (k2, v2) in selectors.iter_mut() {
                    if k == k2 {
                        let _ = v2.write().await.set_selected(v);
                    }
                }
            }
        }

        // Abort spawned tasks inside handlers.
        for abort_handle in self.abort_handles.iter() {
            abort_handle.abort();
        }

        self.handlers = handlers;

        #[cfg(feature = "plugin")]
        {
            self.external_handlers = external_handlers;
        }
        #[cfg(feature = "outbound-select")]
        {
            self.selectors = Arc::new(selectors);
        }

        self.default_handler = default_handler;
        self.abort_handles = abort_handles;
        Ok(())
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
