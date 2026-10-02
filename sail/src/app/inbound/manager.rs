use std::collections::{HashMap, HashSet};
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
use crate::net::InstanceDial;
use crate::Runner;

use super::network_listener::NetworkInboundListener;
use super::resource::{self, StreamGeneration, StreamResource};

/// Nothing is published until every candidate (and the other reloadable
/// components) has been built successfully. Commit itself cannot fail.
pub(crate) struct PreparedResources {
    protocol_updates: Vec<crate::runtime::resource::ResourceUpdate>,
    configs: HashMap<String, config::Inbound>,
    updates: Vec<(StreamResource, Arc<StreamGeneration>)>,
}

#[cfg(feature = "inbound-cat")]
use super::cat_listener::CatInboundListener;

#[cfg(feature = "inbound-tun")]
use super::tun_listener::TunInboundListener;

pub struct InboundManager {
    stateful_resources: HashSet<String>,
    states: HashMap<String, Arc<registry::InboundState>>,
    configs: HashMap<String, config::Inbound>,
    resources: HashMap<String, StreamResource>,
    /// Every inbound's handler, for inbounds built on others.
    handlers: HashMap<String, AnyInboundHandler>,
    /// The inbounds each inbound is built on.
    dependencies: HashMap<String, Vec<String>>,
    network_listeners: HashMap<String, NetworkInboundListener>,
    /// The tasks of each started listener.
    running: HashMap<String, Vec<AbortHandle>>,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    /// What the inbounds dial with when they connect somewhere themselves.
    dial: InstanceDial,
    #[cfg(feature = "inbound-tun")]
    tun_listener: Option<TunInboundListener>,
    #[cfg(feature = "inbound-cat")]
    cat_listener: Option<CatInboundListener>,
}

impl InboundManager {
    /// Whether the users and certificate of the inbound `tag` change while
    /// it runs, without its socket rebound.
    pub(crate) fn reloadable(&self, tag: &str) -> bool {
        self.resources.contains_key(tag) || self.stateful_resources.contains(tag)
    }

    /// The configurations of the inbounds, by tag.
    pub(crate) fn configs(&self) -> Vec<config::Inbound> {
        let mut configs: Vec<_> = self.configs.values().cloned().collect();
        configs.sort_by(|a, b| a.tag.cmp(&b.tag));
        configs
    }
    /// The files the resources of each reloadable inbound are read from,
    /// its certificate and key, by tag; those that read none left out.
    #[cfg(feature = "auto-reload")]
    pub(crate) fn resource_files(&self) -> Vec<(String, Vec<std::path::PathBuf>)> {
        let mut files: Vec<_> = self
            .configs
            .values()
            .filter(|i| self.reloadable(&i.tag))
            .map(|i| (i.tag.clone(), resource::files(i, self.dispatcher.env())))
            .filter(|(_, files)| !files.is_empty())
            .collect();
        files.sort();
        files
    }

    pub fn new(
        inbounds: &[config::Inbound],
        env: &crate::runtime::RuntimeEnv,
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
        dial: InstanceDial,
    ) -> Result<Self> {
        let mut handlers: HashMap<String, AnyInboundHandler> = HashMap::new();
        let mut dependencies = HashMap::new();
        let mut states = HashMap::new();
        registry::build_inbounds(
            &include::INBOUNDS,
            inbounds,
            include::LISTENER_INBOUNDS,
            env,
            &dial,
            &mut handlers,
            &mut dependencies,
            &mut states,
        )?;

        let mut resources = HashMap::new();
        let mut stateful_resources = HashSet::new();
        for inbound in inbounds {
            // An initially built dependent holds the original handler.
            // Such graphs need resource-aware factories before reloading.
            if resource::supported(inbound)
                && !dependencies
                    .values()
                    .any(|deps| deps.contains(&inbound.tag))
            {
                if resource::stateful(inbound) {
                    stateful_resources.insert(inbound.tag.clone());
                } else {
                    resources.insert(
                        inbound.tag.clone(),
                        resource::wrap(handlers.get_mut(&inbound.tag).unwrap())?,
                    );
                }
            }
        }

        let mut network_listeners: HashMap<String, NetworkInboundListener> = HashMap::new();
        for (inbound, address) in plan_listeners(inbounds, &handlers, &dependencies)? {
            let listener = NetworkInboundListener {
                address,
                keepalive: inbound.tcp_keep_alive(),
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
                    crate::protocol::tun::inbound::options(inbound, &dispatcher.env().host)?;
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
            stateful_resources,
            states,
            configs: inbounds
                .iter()
                .map(|i| (i.tag.clone(), i.clone()))
                .collect(),
            resources,
            handlers,
            dependencies,
            network_listeners,
            running: HashMap::new(),
            dispatcher,
            nat_manager,
            dial,
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

    /// Stops accepting on every listener; the connections they accepted
    /// run on. Returns how many listeners there were.
    pub fn stop_listening(&mut self) -> usize {
        let mut stopped = 0;
        for (_, handles) in self.running.drain() {
            for handle in handles {
                handle.abort();
                stopped += 1;
            }
        }
        stopped
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

    /// Builds replacement users/certificates without binding any sockets or
    /// mutating live resources. Re-read certificate files even if the JSON
    /// did not change. Unsupported inbounds are retained, never rebuilt.
    pub(crate) fn prepare_resources(
        &self,
        inbounds: &[config::Inbound],
    ) -> Result<PreparedResources> {
        self.prepare_selected_resources(inbounds, None)
    }

    fn prepare_selected_resources(
        &self,
        inbounds: &[config::Inbound],
        selected: Option<&str>,
    ) -> Result<PreparedResources> {
        let mut configs = HashMap::new();
        for inbound in inbounds {
            if configs
                .insert(inbound.tag.clone(), inbound.clone())
                .is_some()
            {
                return Err(anyhow!("[{}] inbound: duplicate tag", inbound.tag));
            }
            let old = self.configs.get(&inbound.tag).ok_or_else(|| {
                anyhow!(
                    "[{}] inbound: reload cannot add listeners; use add_inbound",
                    inbound.tag
                )
            })?;
            resource::check_change(old, inbound)?;
            if !self.reloadable(&inbound.tag) && old != inbound {
                return Err(anyhow!(
                    "[{}] inbound: resource reload is not supported for this pipeline",
                    inbound.tag
                ));
            }
        }
        if configs.len() != self.configs.len() {
            return Err(anyhow!(
                "inbound: reload cannot remove listeners; use remove_inbound"
            ));
        }
        let mut updates = Vec::new();
        let mut protocol_updates = Vec::new();
        let mut states = self.states.clone();
        for inbound in inbounds {
            if selected.is_some_and(|tag| tag != inbound.tag) {
                continue;
            }
            if !self.reloadable(&inbound.tag) {
                continue;
            }
            let mut handlers = HashMap::new();
            let mut dependencies = HashMap::new();
            protocol_updates.extend(registry::build_inbounds(
                &include::INBOUNDS,
                std::slice::from_ref(inbound),
                include::LISTENER_INBOUNDS,
                self.dispatcher.env(),
                &self.dial,
                &mut handlers,
                &mut dependencies,
                &mut states,
            )?);
            if let Some(resource) = self.resources.get(&inbound.tag) {
                updates.push((
                    resource.clone(),
                    resource::generation(&handlers[&inbound.tag])?,
                ));
            }
        }
        Ok(PreparedResources {
            configs,
            updates,
            protocol_updates,
        })
    }

    /// The configuration of the inbound `tag`.
    pub(crate) fn config(&self, tag: &str) -> Option<config::Inbound> {
        self.configs.get(tag).cloned()
    }

    /// The inbounds whose configuration has the user `name`, by tag.
    pub(crate) fn inbounds_of(&self, name: &str) -> Vec<String> {
        let mut tags: Vec<_> = self
            .configs
            .values()
            .filter(|i| i.user_names().contains(name))
            .map(|i| i.tag.clone())
            .collect();
        tags.sort();
        tags
    }

    pub(crate) fn publish_resources(&mut self, prepared: PreparedResources) {
        for update in prepared.protocol_updates {
            update();
        }
        for (resource, generation) in prepared.updates {
            resource.publish(generation);
        }
        // A user taken out of an inbound loses what it has through it at
        // once: its credential no longer lets it in, and what it opened
        // with it goes too, carriers included.
        let users = &self.dispatcher.env().users;
        for (tag, old) in &self.configs {
            let Some(new) = prepared.configs.get(tag) else {
                continue;
            };
            let kept = new.user_names();
            for name in &kept {
                users.restore_to(name, tag);
            }
            for name in old.user_names().difference(&kept) {
                let closed = users.remove_from(name, tag);
                tracing::info!(
                    "[{}] inbound: user [{}] removed; {} connections closed",
                    tag,
                    name,
                    closed
                );
            }
        }
        self.configs = prepared.configs;
    }

    /// The same validation/publication path for an embedding host changing
    /// one inbound's users or certificate without a configuration file.
    pub(crate) fn prepare_update_resources(
        &self,
        inbound: &config::Inbound,
    ) -> Result<PreparedResources> {
        if !self.configs.contains_key(&inbound.tag) {
            return Err(anyhow!("[{}] inbound: does not exist", inbound.tag));
        }
        if !self.reloadable(&inbound.tag) {
            return Err(anyhow!(
                "[{}] inbound: resource reload is not supported for this pipeline",
                inbound.tag
            ));
        }
        let configs: Vec<_> = self
            .configs
            .values()
            .map(|old| {
                if old.tag == inbound.tag {
                    inbound.clone()
                } else {
                    old.clone()
                }
            })
            .collect();
        self.prepare_selected_resources(&configs, Some(&inbound.tag))
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
        let mut states = self.states.clone();
        registry::build_inbounds(
            &include::INBOUNDS,
            std::slice::from_ref(inbound),
            include::LISTENER_INBOUNDS,
            self.dispatcher.env(),
            &self.dial,
            &mut handlers,
            &mut dependencies,
            &mut states,
        )?;
        let resource = if resource::supported(inbound) && !resource::stateful(inbound) {
            Some(resource::wrap(handlers.get_mut(&inbound.tag).unwrap())?)
        } else {
            None
        };
        let planned = plan_listeners(std::slice::from_ref(inbound), &handlers, &dependencies)?;
        if let Some((_, address)) = planned.first() {
            let listener = NetworkInboundListener {
                address: *address,
                keepalive: inbound.tcp_keep_alive(),
                handler: handlers[&inbound.tag].clone(),
                dispatcher: self.dispatcher.clone(),
                nat_manager: self.nat_manager.clone(),
            };
            let runners = listener.listen()?;
            self.network_listeners.insert(inbound.tag.clone(), listener);
            self.run(inbound.tag.clone(), runners);
        }
        self.handlers = handlers;
        self.states = states;
        self.dependencies = dependencies;
        self.configs.insert(inbound.tag.clone(), inbound.clone());
        if resource::stateful(inbound) {
            self.stateful_resources.insert(inbound.tag.clone());
        }
        if let Some(resource) = resource {
            self.resources.insert(inbound.tag.clone(), resource);
        }
        self.dispatcher
            .set_inbound_type(&inbound.tag, Some(&inbound.protocol));
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
        self.configs.remove(tag);
        self.resources.remove(tag);
        self.stateful_resources.remove(tag);
        self.states.remove(tag);
        self.dispatcher.set_inbound_type(tag, None);
        Ok(())
    }

    #[cfg(feature = "inbound-tun")]
    pub(crate) fn get_tun_runner(
        &self,
    ) -> Option<Result<crate::protocol::tun::inbound::TunRunner>> {
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
/// the second bind would fail, and only at startup -- when an inbound
/// served by a listener of its own (tun, cat) is misconfigured: given an
/// address, or given twice; and when an inbound has no port and no other
/// inbound in `dependencies` leads to it, which nothing would ever reach.
pub(crate) fn plan_listeners<'a>(
    inbounds: &'a [config::Inbound],
    handlers: &HashMap<String, AnyInboundHandler>,
    dependencies: &HashMap<String, Vec<String>>,
) -> Result<Vec<(&'a config::Inbound, SocketAddr)>> {
    let mut planned: Vec<(&config::Inbound, SocketAddr, bool, bool)> = Vec::new();
    let mut own_listeners: Vec<&config::Inbound> = Vec::new();
    for inbound in inbounds {
        let tag = &inbound.tag;
        if include::LISTENER_INBOUNDS.contains(&inbound.protocol.as_str()) {
            // The shared fields of a listening inbound mean nothing to one
            // that does not listen, as sing-box's tun has none of them: a
            // TUN keeps only udp_timeout, which its UDP flows use.
            let given = [
                ("listen", inbound.listen.is_some()),
                ("listen_port", inbound.listen_port.is_some()),
                ("tcp_keep_alive", inbound.tcp_keep_alive.is_some()),
                (
                    "tcp_keep_alive_interval",
                    inbound.tcp_keep_alive_interval.is_some(),
                ),
                ("disable_tcp_keep_alive", inbound.disable_tcp_keep_alive),
                (
                    "udp_timeout",
                    inbound.udp_timeout.is_some() && inbound.protocol != "tun",
                ),
            ];
            if let Some((field, _)) = given.iter().find(|(_, set)| *set) {
                return Err(anyhow!(
                    "[{}] inbound: a {} inbound does not listen on a port, so it takes no {}",
                    tag,
                    inbound.protocol,
                    field
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
        // Without a port an inbound does not listen: only one that another
        // leads to (a detour's) is reached at all.
        let Some(port) = inbound.listen_port else {
            if dependencies.values().any(|deps| deps.contains(tag)) {
                continue;
            }
            return Err(anyhow!(
                "[{}] inbound: listen_port: missing; without it the inbound listens on nothing \
                 (only one another inbound leads to may leave it out)",
                tag
            ));
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

    /// A user taken out of an inbound loses what it has through it, the
    /// connections it carries others on too; not what it has through
    /// another inbound, nor what other users have.
    #[cfg(all(feature = "inbound-trojan", feature = "outbound-direct"))]
    #[tokio::test]
    async fn a_user_taken_out_of_an_inbound_is_disconnected_from_it() {
        use crate::session::Session;
        use serde_json::json;
        use std::sync::atomic::{AtomicBool, Ordering};

        let trojan = |tag: &str, users: serde_json::Value| json!({"type": "trojan", "tag": tag, "listen_port": 0, "users": users});
        let config = config::Config::from_json(
            &json!({
                "inbounds": [
                    trojan("t", json!([{"name": "alice", "password": "a"},
                                       {"name": "bob", "password": "b"}])),
                    trojan("t2", json!([{"name": "alice", "password": "a2"}])),
                ],
                "outbounds": [{"type": "direct"}]
            })
            .to_string(),
        )
        .unwrap();
        let instance =
            crate::app::instance::Instance::build(&config, Arc::default(), Arc::default()).unwrap();
        let users = &instance.env.users;
        let (alice, bob) = (users.bind("alice"), users.bind("bob"));
        let connect = |user: &crate::user::UserRef, inbound: &str| {
            let (a, b) = tokio::io::duplex(64);
            std::mem::forget(b);
            let sess = Session {
                user: Some(user.clone()),
                inbound_tag: inbound.into(),
                ..Default::default()
            };
            instance.stat_manager.stat_stream(Box::new(a), sess)
        };
        let _conns = [
            connect(&alice, "t"),
            connect(&alice, "t2"),
            connect(&bob, "t"),
        ];
        let carried = Arc::new(AtomicBool::new(false));
        let _carrier = {
            let carried = carried.clone();
            alice.carry("t", move || carried.store(true, Ordering::SeqCst))
        };

        let mut without_alice = config.inbounds[0].clone();
        without_alice
            .options
            .insert("users".into(), json!([{"name": "bob", "password": "b"}]));
        {
            let mut manager = instance.inbound_manager.lock().unwrap();
            let prepared = manager.prepare_update_resources(&without_alice).unwrap();
            manager.publish_resources(prepared);
        }
        let closed: Vec<_> = instance
            .stat_manager
            .connections()
            .iter()
            .map(|c| {
                (
                    c.sess.inbound_tag.clone(),
                    crate::user::name(&c.sess.user).unwrap().to_owned(),
                    c.closer.is_closed(),
                )
            })
            .collect();
        assert_eq!(
            closed,
            [
                ("t".to_owned(), "alice".to_owned(), true),
                ("t2".to_owned(), "alice".to_owned(), false),
                ("t".to_owned(), "bob".to_owned(), false),
            ]
        );
        assert!(carried.load(Ordering::SeqCst));
        // Still a user, through the other inbound; not through this one,
        // even on a session a transport kept with the old credentials.
        assert!(alice.active());
        assert!(!alice.admits("t"));
        assert!(alice.admits("t2"));
        let refused = connect(&alice, "t");
        assert!(instance
            .stat_manager
            .connections()
            .last()
            .unwrap()
            .closer
            .is_closed());
        drop(refused);
        // Put back, and let in again.
        {
            let mut manager = instance.inbound_manager.lock().unwrap();
            let prepared = manager
                .prepare_update_resources(&config.inbounds[0])
                .unwrap();
            manager.publish_resources(prepared);
        }
        assert!(alice.admits("t"));
    }

    #[cfg(all(feature = "inbound-vmess", feature = "outbound-direct"))]
    #[tokio::test]
    async fn vmess_manager_preserves_replay_state_until_inbound_removal() {
        use crate::adapter::InboundTransport;
        use crate::protocol::vmess::header::*;
        use crate::session::{Session, SocksAddr};
        use serde_json::json;
        use tokio::io::AsyncWriteExt;

        async fn accepted(handler: &AnyInboundHandler, wire: &[u8]) -> bool {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(wire).await.unwrap();
            client.shutdown().await.unwrap();
            matches!(
                handler
                    .stream()
                    .unwrap()
                    .handle(Session::default(), Box::new(server))
                    .await,
                Ok(InboundTransport::Stream(_, _))
            )
        }
        let uuid = uuid::Uuid::from_bytes([42; 16]);
        let config = config::Config::from_json(
            &json!({
                "inbounds":[{"type":"vmess", "tag":"v", "listen_port":0, "users":[{"uuid":uuid.to_string()}]}],
                "outbounds":[{"type":"direct"}]
            })
            .to_string(),
        )
        .unwrap();
        let instance =
            crate::app::instance::Instance::build(&config, Arc::default(), Arc::default()).unwrap();
        let live = instance.inbound_manager.lock().unwrap().handlers["v"].clone();
        let request = RequestHeader::new(
            OPTION_CHUNK_STREAM,
            SECURITY_AES128_GCM,
            COMMAND_TCP,
            Some(SocksAddr::try_from(("example.com", 443)).unwrap()),
        );
        let wire = request.seal(&cmd_key(uuid.as_bytes())).unwrap();
        assert!(accepted(&live, &wire).await);
        {
            let mut manager = instance.inbound_manager.lock().unwrap();
            let prepared = manager.prepare_resources(&config.inbounds).unwrap();
            manager.publish_resources(prepared);
        }
        assert!(!accepted(&live, &wire).await);
        {
            let mut manager = instance.inbound_manager.lock().unwrap();
            let mut empty = config.inbounds[0].clone();
            empty.options.insert("users".into(), json!([]));
            let prepared = manager.prepare_update_resources(&empty).unwrap();
            manager.publish_resources(prepared);
            let prepared = manager
                .prepare_update_resources(&config.inbounds[0])
                .unwrap();
            manager.publish_resources(prepared);
            let mut invalid = empty;
            invalid
                .options
                .insert("users".into(), json!([{"uuid":"invalid"}]));
            assert!(manager.prepare_update_resources(&invalid).is_err());
        }
        assert!(!accepted(&live, &wire).await);
        assert!(accepted(&live, &request.seal(&cmd_key(uuid.as_bytes())).unwrap()).await);
        let recreated = {
            let mut manager = instance.inbound_manager.lock().unwrap();
            manager.remove("v").unwrap();
            manager.add(&config.inbounds[0]).unwrap();
            manager.handlers["v"].clone()
        };
        assert!(accepted(&recreated, &wire).await);
        assert!(!accepted(&live, &wire).await); // Old lifetime is still held by this connection.
    }

    fn plan(json: &str) -> Result<Vec<(String, SocketAddr)>> {
        let config = config::Config::from_json(json)?;
        let mut handlers = HashMap::new();
        let mut dependencies = HashMap::new();
        registry::build_inbounds(
            &include::INBOUNDS,
            &config.inbounds,
            include::LISTENER_INBOUNDS,
            &crate::runtime::RuntimeEnv::default(),
            &Default::default(),
            &mut handlers,
            &mut dependencies,
            &mut HashMap::new(),
        )?;
        Ok(plan_listeners(&config.inbounds, &handlers, &dependencies)?
            .into_iter()
            .map(|(inbound, address)| (inbound.tag.clone(), address))
            .collect())
    }

    /// One inbound of `protocol` with one more `field`, planned on its own.
    #[cfg(any(feature = "inbound-tun", feature = "inbound-cat"))]
    fn plan_one(protocol: &str, field: &str) -> Result<Vec<(String, SocketAddr)>> {
        plan(&format!(
            r#"{{ "inbounds": [ {{ "type": "{protocol}", "tag": "x", {field} }} ] }}"#
        ))
    }

    /// A test that `$protocol` refuses `$field`: each used to pass in
    /// silence, as sing-box's tun takes none of the listening inbounds'
    /// fields.
    macro_rules! refuses_field {
        ($feature:literal, $test:ident, $protocol:literal, $name:literal, $field:literal) => {
            #[cfg(feature = $feature)]
            #[test]
            fn $test() {
                let err = plan_one($protocol, $field).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    concat!(
                        "[x] inbound: a ",
                        $protocol,
                        " inbound does not listen on a port, so it takes no ",
                        $name
                    ),
                );
            }
        };
    }

    refuses_field!(
        "inbound-tun",
        a_tun_takes_no_listen,
        "tun",
        "listen",
        r#""listen": "127.0.0.1""#
    );
    refuses_field!(
        "inbound-tun",
        a_tun_takes_no_listen_port,
        "tun",
        "listen_port",
        r#""listen_port": 1080"#
    );
    refuses_field!(
        "inbound-tun",
        a_tun_takes_no_tcp_keep_alive,
        "tun",
        "tcp_keep_alive",
        r#""tcp_keep_alive": "5m""#
    );
    refuses_field!(
        "inbound-tun",
        a_tun_takes_no_tcp_keep_alive_interval,
        "tun",
        "tcp_keep_alive_interval",
        r#""tcp_keep_alive_interval": "75s""#
    );
    refuses_field!(
        "inbound-tun",
        a_tun_takes_no_disable_tcp_keep_alive,
        "tun",
        "disable_tcp_keep_alive",
        r#""disable_tcp_keep_alive": true"#
    );
    refuses_field!(
        "inbound-cat",
        a_cat_takes_no_listen,
        "cat",
        "listen",
        r#""listen": "127.0.0.1""#
    );
    refuses_field!(
        "inbound-cat",
        a_cat_takes_no_listen_port,
        "cat",
        "listen_port",
        r#""listen_port": 1080"#
    );
    refuses_field!(
        "inbound-cat",
        a_cat_takes_no_tcp_keep_alive,
        "cat",
        "tcp_keep_alive",
        r#""tcp_keep_alive": "5m""#
    );
    refuses_field!(
        "inbound-cat",
        a_cat_takes_no_tcp_keep_alive_interval,
        "cat",
        "tcp_keep_alive_interval",
        r#""tcp_keep_alive_interval": "75s""#
    );
    refuses_field!(
        "inbound-cat",
        a_cat_takes_no_disable_tcp_keep_alive,
        "cat",
        "disable_tcp_keep_alive",
        r#""disable_tcp_keep_alive": true"#
    );
    // cat reads stdin, so even udp_timeout means nothing to it.
    refuses_field!(
        "inbound-cat",
        a_cat_takes_no_udp_timeout,
        "cat",
        "udp_timeout",
        r#""udp_timeout": "5m""#
    );

    /// A TUN's UDP flows use udp_timeout, which it keeps.
    #[cfg(feature = "inbound-tun")]
    #[test]
    fn a_tun_takes_udp_timeout() {
        assert!(plan_one("tun", r#""udp_timeout": "5m""#)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn inbounds_listen_on_ports_of_their_own() {
        let planned = plan(
            r#"{ "inbounds": [
                { "type": "socks", "tag": "a", "listen_port": 1080 },
                { "type": "http", "tag": "b", "listen_port": 8080 },
                { "type": "http", "tag": "c", "listen": "127.0.0.2", "listen_port": 1080 }
            ] }"#,
        )
        .unwrap();
        let tags: Vec<_> = planned.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(tags, ["a", "b", "c"]);
        assert_eq!(planned[0].1, "127.0.0.1:1080".parse().unwrap());
        // One with no port would listen on nothing, and nothing leads to it.
        let err = plan(
            r#"{ "inbounds": [
                { "type": "socks", "tag": "a", "listen_port": 1080 },
                { "type": "http", "tag": "d" }
            ] }"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("[d] inbound: listen_port: missing"),
            "{}",
            err
        );
    }

    #[cfg(all(feature = "inbound-shadowtls", feature = "inbound-shadowsocks"))]
    #[test]
    fn an_inbound_another_leads_to_takes_no_port() {
        let planned = plan(
            r#"{ "inbounds": [
                { "type": "shadowtls", "tag": "stls", "listen_port": 443, "version": 3,
                  "users": [{ "password": "p" }],
                  "handshake": { "server": "example.com", "server_port": 443 },
                  "detour": "ss" },
                { "type": "shadowsocks", "tag": "ss", "method": "aes-128-gcm", "password": "p" }
            ] }"#,
        )
        .unwrap();
        let tags: Vec<_> = planned.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(tags, ["stls"]);
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
