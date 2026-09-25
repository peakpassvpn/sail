use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::future::{abortable, AbortHandle};

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
    /// Every inbound's handler, for inbounds built on others.
    handlers: HashMap<String, AnyInboundHandler>,
    /// The inbounds each inbound is built on.
    dependencies: HashMap<String, Vec<String>>,
    network_listeners: HashMap<String, NetworkInboundListener>,
    /// The tasks of each started listener.
    running: HashMap<String, Vec<AbortHandle>>,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
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
        let mut dependencies = HashMap::new();
        registry::build_inbounds(
            &include::INBOUNDS,
            inbounds,
            include::LISTENER_INBOUNDS,
            env,
            &mut handlers,
            &mut dependencies,
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
                    crate::protocol::tun::inbound::options(inbound)?;
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
            handlers,
            dependencies,
            network_listeners,
            running: HashMap::new(),
            dispatcher,
            nat_manager,
            #[cfg(feature = "inbound-tun")]
            tun_listener,
            #[cfg(feature = "inbound-cat")]
            cat_listener,
        })
    }

    /// Binds every listener, and runs each as a task of its own, to be
    /// stopped alone. Fails, with none running, when one cannot bind.
    pub fn start_network_listeners(&mut self) -> Result<()> {
        let mut bound = Vec::new();
        for (tag, listener) in self.network_listeners.iter() {
            bound.push((tag.clone(), listener.listen()?));
        }
        for (tag, runners) in bound {
            self.run(tag, runners);
        }
        Ok(())
    }

    fn run(&mut self, tag: String, runners: Vec<Runner>) {
        let handles = runners
            .into_iter()
            .map(|runner| {
                let (task, handle) = abortable(runner);
                tokio::spawn(task);
                handle
            })
            .collect();
        self.running.insert(tag, handles);
    }

    /// Builds `inbound` and starts listening on its port. A TUN or cat
    /// inbound is only configured at start.
    pub fn add(&mut self, inbound: &config::Inbound) -> Result<()> {
        if include::LISTENER_INBOUNDS.contains(&inbound.protocol.as_str()) {
            return Err(anyhow!(
                "[{}] inbound: a {} inbound is only configured at start",
                inbound.tag,
                inbound.protocol
            ));
        }
        let mut handlers = self.handlers.clone();
        let mut dependencies = self.dependencies.clone();
        registry::build_inbounds(
            &include::INBOUNDS,
            std::slice::from_ref(inbound),
            include::LISTENER_INBOUNDS,
            self.dispatcher.env(),
            &mut handlers,
            &mut dependencies,
        )?;
        let planned = plan_listeners(std::slice::from_ref(inbound), &handlers)?;
        if let Some((_, address)) = planned.first() {
            let listener = NetworkInboundListener {
                address: *address,
                handler: handlers[&inbound.tag].clone(),
                dispatcher: self.dispatcher.clone(),
                nat_manager: self.nat_manager.clone(),
            };
            let runners = listener.listen()?;
            self.network_listeners.insert(inbound.tag.clone(), listener);
            self.run(inbound.tag.clone(), runners);
        }
        self.handlers = handlers;
        self.dependencies = dependencies;
        Ok(())
    }

    /// Stops listening for the inbound `tag` and removes it. Connections it
    /// accepted go on.
    pub fn remove(&mut self, tag: &str) -> Result<()> {
        if !self.handlers.contains_key(tag) {
            return Err(anyhow!("[{}] inbound: does not exist", tag));
        }
        if let Some((user, _)) = self
            .dependencies
            .iter()
            .find(|(user, deps)| user.as_str() != tag && deps.iter().any(|d| d == tag))
        {
            return Err(anyhow!("[{}] inbound: [{}] is built on it", tag, user));
        }
        for handle in self.running.remove(tag).unwrap_or_default() {
            handle.abort();
        }
        self.network_listeners.remove(tag);
        self.handlers.remove(tag);
        self.dependencies.remove(tag);
        Ok(())
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
            &mut HashMap::new(),
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
