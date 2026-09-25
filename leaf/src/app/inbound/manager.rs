use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
}

impl InboundManager {
    pub fn new(
        inbounds: &[config::Inbound],
        env: &crate::runtime::RuntimeEnv,
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
    ) -> Result<Self> {
        let mut handlers: HashMap<String, AnyInboundHandler> = HashMap::new();
        registry::build_inbounds(
            &include::INBOUNDS,
            inbounds,
            include::LISTENER_INBOUNDS,
            env,
            &mut handlers,
        )?;

        let mut network_listeners: HashMap<String, NetworkInboundListener> = HashMap::new();
        for (inbound, address) in plan_listeners(inbounds, &handlers)? {
            let listener = NetworkInboundListener {
                address,
                handler: handlers[&inbound.tag].clone(),
                dispatcher: dispatcher.clone(),
                nat_manager: nat_manager.clone(),
            };
            network_listeners.insert(inbound.tag.clone(), listener);
        }

        #[cfg(feature = "inbound-tun")]
        let mut tun_listener: Option<TunInboundListener> = None;

        #[cfg(feature = "inbound-cat")]
        let mut cat_listener: Option<CatInboundListener> = None;

        for inbound in inbounds.iter() {
            match inbound.protocol.as_str() {
                #[cfg(feature = "inbound-tun")]
                "tun" => {
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
                _ => {}
            }
        }

        Ok(InboundManager {
            network_listeners,
            #[cfg(feature = "inbound-tun")]
            tun_listener,
            #[cfg(feature = "inbound-cat")]
            cat_listener,
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
}

/// The inbounds that listen on a port, with the address each listens on.
///
/// Fails when two of them would bind the same port on the same network --
/// the second bind would fail, and only at startup -- and when an inbound
/// served by a listener of its own (tun, cat) is misconfigured: given an
/// address, or given twice.
pub(crate) fn plan_listeners<'a>(
    inbounds: &'a [config::Inbound],
    handlers: &HashMap<String, AnyInboundHandler>,
) -> Result<Vec<(&'a config::Inbound, SocketAddr)>> {
    let mut planned: Vec<(&config::Inbound, SocketAddr, bool, bool)> = Vec::new();
    let mut own_listeners: Vec<&config::Inbound> = Vec::new();
    for inbound in inbounds {
        let tag = &inbound.tag;
        if include::LISTENER_INBOUNDS.contains(&inbound.protocol.as_str()) {
            if inbound.listen.is_some() || inbound.listen_port.is_some() {
                return Err(anyhow!(
                    "[{}] inbound: a {} inbound does not listen on a port",
                    tag,
                    inbound.protocol
                ));
            }
            if let Some(other) = own_listeners
                .iter()
                .find(|o| o.protocol == inbound.protocol)
            {
                return Err(anyhow!(
                    "[{}] inbound: there can be only one {} inbound, and [{}] is one",
                    tag,
                    inbound.protocol,
                    other.tag
                ));
            }
            own_listeners.push(inbound);
            continue;
        }
        // Without a port an inbound does not listen.
        let Some(port) = inbound.listen_port else {
            continue;
        };
        let listen = inbound.listen.as_deref().unwrap_or("127.0.0.1");
        let ip: IpAddr = listen
            .parse()
            .map_err(|_| anyhow!("[{}] inbound: listen: invalid address \"{}\"", tag, listen))?;
        let address = SocketAddr::new(ip, port);
        let handler = &handlers[tag];
        let (tcp, udp) = (handler.stream().is_ok(), handler.datagram().is_ok());
        for (other, other_address, other_tcp, other_udp) in &planned {
            // Port 0 is a different free port every time.
            if port == 0 || other_address.port() != port {
                continue;
            }
            // An unspecified address takes the port on every address.
            let ips_overlap = other_address.ip() == ip
                || other_address.ip().is_unspecified()
                || ip.is_unspecified();
            let network = if tcp && *other_tcp {
                "tcp"
            } else if udp && *other_udp {
                "udp"
            } else {
                continue;
            };
            if ips_overlap {
                return Err(anyhow!(
                    "[{}] inbound: listen_port: {} {} is taken by [{}]",
                    tag,
                    network,
                    other_address,
                    other.tag
                ));
            }
        }
        planned.push((inbound, address, tcp, udp));
    }
    Ok(planned
        .into_iter()
        .map(|(inbound, address, _, _)| (inbound, address))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(json: &str) -> Result<Vec<(String, SocketAddr)>> {
        let config = config::Config::from_json(json)?;
        let mut handlers = HashMap::new();
        registry::build_inbounds(
            &include::INBOUNDS,
            &config.inbounds,
            include::LISTENER_INBOUNDS,
            &crate::runtime::RuntimeEnv::default(),
            &mut handlers,
        )?;
        Ok(plan_listeners(&config.inbounds, &handlers)?
            .into_iter()
            .map(|(inbound, address)| (inbound.tag.clone(), address))
            .collect())
    }

    #[test]
    fn inbounds_listen_on_ports_of_their_own() {
        let planned = plan(
            r#"{ "inbounds": [
                { "type": "socks", "tag": "a", "listen_port": 1080 },
                { "type": "http", "tag": "b", "listen_port": 8080 },
                { "type": "http", "tag": "c", "listen": "127.0.0.2", "listen_port": 1080 },
                { "type": "http", "tag": "d" }
            ] }"#,
        )
        .unwrap();
        let tags: Vec<_> = planned.iter().map(|(t, _)| t.as_str()).collect();
        // d has no port and does not listen.
        assert_eq!(tags, ["a", "b", "c"]);
        assert_eq!(planned[0].1, "127.0.0.1:1080".parse().unwrap());
    }

    #[test]
    fn a_port_taken_twice_is_an_error() {
        let err = plan(
            r#"{ "inbounds": [
                { "type": "socks", "tag": "a", "listen_port": 1080 },
                { "type": "http", "tag": "b", "listen_port": 1080 }
            ] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "[b] inbound: listen_port: tcp 127.0.0.1:1080 is taken by [a]"
        );
    }

    #[test]
    fn an_unspecified_address_takes_the_port_on_every_address() {
        let err = plan(
            r#"{ "inbounds": [
                { "type": "socks", "tag": "a", "listen": "0.0.0.0", "listen_port": 1080 },
                { "type": "socks", "tag": "b", "listen": "127.0.0.1", "listen_port": 1080 }
            ] }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("is taken by [a]"), "{}", err);
    }

    #[test]
    fn an_invalid_listen_address_is_an_error() {
        let err = plan(
            r#"{ "inbounds": [ { "type": "http", "listen": "localhost", "listen_port": 1 } ] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "[http] inbound: listen: invalid address \"localhost\""
        );
    }

    #[cfg(feature = "inbound-tun")]
    #[test]
    fn there_is_only_one_tun() {
        let err = plan(
            r#"{ "inbounds": [ { "type": "tun", "tag": "t1" }, { "type": "tun", "tag": "t2" } ] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "[t2] inbound: there can be only one tun inbound, and [t1] is one"
        );
    }
}
