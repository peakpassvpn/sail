use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::registry;
use crate::adapter::AnyInboundHandler;
use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::config;
use crate::include;
use crate::Runner;

use super::network_listener::NetworkInboundListener;

#[cfg(feature = "inbound-cat")]
use super::cat_listener::CatInboundListener;

#[cfg(feature = "inbound-tun")]
use super::tun_listener::TunInboundListener;

pub struct InboundManager {
    network_listeners: HashMap<String, NetworkInboundListener>,
    #[cfg(feature = "inbound-tun")]
    tun_listener: Option<TunInboundListener>,
    #[cfg(feature = "inbound-cat")]
    cat_listener: Option<CatInboundListener>,
    tun_auto: bool,
}

impl InboundManager {
    pub fn new(
        inbounds: &[config::Inbound],
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
    ) -> Result<Self> {
        let mut handlers: HashMap<String, AnyInboundHandler> = HashMap::new();
        registry::build_inbounds(
            &include::INBOUNDS,
            inbounds,
            include::LISTENER_INBOUNDS,
            &mut handlers,
        )?;

        let mut network_listeners: HashMap<String, NetworkInboundListener> = HashMap::new();

        #[cfg(feature = "inbound-tun")]
        let mut tun_listener: Option<TunInboundListener> = None;

        #[cfg(feature = "inbound-cat")]
        let mut cat_listener: Option<CatInboundListener> = None;

        let mut tun_auto = false;

        for inbound in inbounds.iter() {
            let tag = inbound.tag.clone();
            if include::LISTENER_INBOUNDS.contains(&inbound.protocol.as_str())
                && (inbound.listen.is_some() || inbound.listen_port.is_some())
            {
                return Err(anyhow!(
                    "[{}] inbound: a {} inbound does not listen on a port",
                    tag,
                    inbound.protocol
                ));
            }
            match inbound.protocol.as_str() {
                #[cfg(feature = "inbound-tun")]
                "tun" => {
                    tun_auto = crate::protocol::tun::inbound::options(inbound)?.auto;
                    let listener = TunInboundListener {
                        inbound: inbound.clone(),
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                    };
                    tun_listener.replace(listener);
                }
                #[cfg(feature = "inbound-cat")]
                "cat" => {
                    let listener = CatInboundListener {
                        inbound: inbound.clone(),
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                    };
                    cat_listener.replace(listener);
                }
                _ => {
                    // Without a port an inbound is only a part of another.
                    let Some(port) = inbound.listen_port else {
                        continue;
                    };
                    let listener = NetworkInboundListener {
                        address: inbound
                            .listen
                            .clone()
                            .unwrap_or_else(|| "127.0.0.1".to_string()),
                        port,
                        handler: handlers[&tag].clone(),
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                    };
                    network_listeners.insert(tag, listener);
                }
            }
        }

        Ok(InboundManager {
            network_listeners,
            #[cfg(feature = "inbound-tun")]
            tun_listener,
            #[cfg(feature = "inbound-cat")]
            cat_listener,
            tun_auto,
        })
    }

    pub fn get_network_runners(&self) -> Result<Vec<Runner>> {
        let mut runners: Vec<Runner> = Vec::new();
        for (_, listener) in self.network_listeners.iter() {
            runners.append(&mut listener.listen()?);
        }
        Ok(runners)
    }

    #[cfg(feature = "inbound-tun")]
    pub fn get_tun_runner(&self) -> Option<Result<Runner>> {
        self.tun_listener.as_ref().map(TunInboundListener::listen)
    }

    #[cfg(feature = "inbound-cat")]
    pub fn get_cat_runner(&self) -> Option<Result<Runner>> {
        self.cat_listener.as_ref().map(CatInboundListener::listen)
    }

    #[cfg(feature = "inbound-tun")]
    pub fn has_tun_listener(&self) -> bool {
        self.tun_listener.is_some()
    }

    pub fn tun_auto(&self) -> bool {
        self.tun_auto
    }
}
