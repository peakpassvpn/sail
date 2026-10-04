//! A reload's inbounds: those the new configuration has are those that run
//! once it is taken. Compared by tag with those running, each is left as
//! it is, given new users and certificates, added, removed, or replaced
//! where anything else of it changed; one served by a listener of its own
//! (a TUN) changes only at a start.
//!
//! Nothing is half applied. `prepare_reload` builds what is new and binds
//! its sockets, and fails with nothing changed. An address that an inbound
//! going away still holds cannot be bound until that one has stopped:
//! `stop_for` stops those, `bind_late` binds what waited for them and,
//! failing for good, `put_back` puts back what was stopped. Only then does `commit_reload`,
//! which cannot fail, take the rest, with the routing and the outbounds.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use anyhow::anyhow;

use super::{
    plan_listeners, resource, InboundManager, ListenerTask, NetworkInboundListener,
    PreparedResources,
};
use crate::adapter::registry;
use crate::adapter::AnyInboundHandler;
use crate::app::inbound::network_listener::Accepted;
use crate::config;
use crate::include;
use crate::Runner;

/// What a reload did to an inbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundChange {
    /// As it was: its listener, its connections.
    Untouched,
    /// Its users or its certificate replaced; its listener and its
    /// connections as they were.
    Reloaded,
    /// New: built, and listening.
    Added,
    /// Gone: its listener stopped, its connections closed.
    Removed,
    /// Something else of it changed: the one before removed, its
    /// connections closed, and this one built in its place.
    Replaced,
    /// It was to be replaced on the address it had; the new one could not
    /// take the address, and the one before could not take it back: it
    /// listens no more. The reload failed.
    Lost,
}

impl InboundChange {
    /// As the API and the log tell it.
    pub fn name(self) -> &'static str {
        match self {
            InboundChange::Untouched => "untouched",
            InboundChange::Reloaded => "reloaded",
            InboundChange::Added => "added",
            InboundChange::Removed => "removed",
            InboundChange::Replaced => "replaced",
            InboundChange::Lost => "lost",
        }
    }
}

/// Why a reload's inbounds are not taken.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The configuration, or a socket that does not bind.
    Config(anyhow::Error),
    /// An inbound served by a listener of its own was added, removed or
    /// changed: only a start does that.
    NeedsRestart(String),
    /// An inbound that was stopped for another to take its address could
    /// not be put back: `tag` listens no more.
    Lost { tag: String, reason: String },
}

impl From<anyhow::Error> for Refused {
    fn from(e: anyhow::Error) -> Self {
        Refused::Config(e)
    }
}

/// An inbound built for a reload, added or put in another's place.
struct New {
    config: config::Inbound,
    resource: Option<resource::StreamResource>,
    /// None for one that listens on no port of its own.
    listener: Option<NetworkInboundListener>,
    /// Its sockets, bound: none yet for one that waits for the inbound
    /// holding its address to stop.
    runners: Option<Vec<Runner>>,
}

/// The inbounds as a reload makes them: built and, but for those waiting
/// for an address, bound; nothing running is touched yet.
pub(crate) struct PreparedReload {
    kept: PreparedResources,
    /// Those that go: removed, and those another takes the place of.
    gone: Vec<String>,
    new: Vec<New>,
    handlers: HashMap<String, AnyInboundHandler>,
    dependencies: HashMap<String, Vec<String>>,
    states: HashMap<String, std::sync::Arc<registry::InboundState>>,
    /// Those stopped by `stop_for`, which a failure puts back.
    stopped: Vec<String>,
    changes: Vec<(String, InboundChange)>,
}

/// What `commit_reload` leaves to do, and what it did.
pub(crate) struct Reloaded {
    /// What each inbound came to, in the configuration's order, those
    /// removed last.
    pub(crate) changes: Vec<(String, InboundChange)>,
    /// The inbounds that went, whose connections are to be closed.
    pub(crate) gone: Vec<String>,
    /// The TCP connections they accepted that are not listed.
    pub(crate) accepted: Vec<Accepted>,
    /// The new listeners, bound, to run once the routing is in place.
    starting: Vec<(String, Vec<Runner>)>,
}

/// Whether a socket bound to `a` keeps one from being bound to `b`.
fn clash(a: &SocketAddr, b: &SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

impl InboundManager {
    /// What `inbounds`, a new configuration's, make of the inbounds:
    /// built, and bound where no inbound that goes holds the address.
    /// Nothing running is touched.
    pub(crate) fn prepare_reload(
        &self,
        inbounds: &[config::Inbound],
    ) -> std::result::Result<PreparedReload, Refused> {
        let own_listener =
            |i: &config::Inbound| include::LISTENER_INBOUNDS.contains(&i.protocol.as_str());
        let needs_restart = |i: &config::Inbound, what: &str| {
            Refused::NeedsRestart(format!(
                "[{}] inbound: a {} inbound is {} only at a start; {}",
                i.tag,
                i.protocol,
                what,
                crate::RESTART_TO_APPLY
            ))
        };
        let mut seen = HashSet::new();
        let mut kept = Vec::new();
        let mut fresh = Vec::new();
        let mut replaced = Vec::new();
        let mut changes = Vec::new();
        for inbound in inbounds {
            if !seen.insert(inbound.tag.as_str()) {
                return Err(anyhow!("[{}] inbound: duplicate tag", inbound.tag).into());
            }
            let change = match self.configs.get(&inbound.tag) {
                None if own_listener(inbound) => return Err(needs_restart(inbound, "added")),
                None => InboundChange::Added,
                Some(old) if old == inbound => InboundChange::Untouched,
                Some(old)
                    if self.reloadable(&inbound.tag)
                        && resource::check_change(old, inbound).is_ok() =>
                {
                    InboundChange::Reloaded
                }
                Some(old) if own_listener(old) || own_listener(inbound) => {
                    return Err(needs_restart(old, "changed"));
                }
                Some(_) => InboundChange::Replaced,
            };
            match change {
                InboundChange::Added => fresh.push(inbound.clone()),
                InboundChange::Replaced => {
                    replaced.push(inbound.tag.clone());
                    fresh.push(inbound.clone());
                }
                _ => kept.push(inbound.clone()),
            }
            changes.push((inbound.tag.clone(), change));
        }
        let mut removed: Vec<&config::Inbound> = self
            .configs
            .values()
            .filter(|old| !seen.contains(old.tag.as_str()))
            .collect();
        removed.sort_by(|a, b| a.tag.cmp(&b.tag));
        for old in &removed {
            if own_listener(old) {
                return Err(needs_restart(old, "removed"));
            }
            changes.push((old.tag.clone(), InboundChange::Removed));
        }
        let gone: Vec<String> = removed
            .iter()
            .map(|old| old.tag.clone())
            .chain(replaced)
            .collect();
        // One that stays cannot be built on one that goes: it holds the
        // handler it was built with.
        for tag in &gone {
            if let Some((user, _)) = self
                .dependencies
                .iter()
                .find(|(user, deps)| !gone.contains(*user) && deps.iter().any(|dep| dep == tag))
            {
                return Err(anyhow!(
                    "[{}] inbound: [{}] is built on it, and stays as it is; change both, or neither",
                    tag,
                    user
                )
                .into());
            }
        }

        let kept_configs = kept.iter().map(|i| (i.tag.clone(), i.clone())).collect();
        let kept = self.prepare_kept(&kept, kept_configs, None)?;

        let mut handlers = self.handlers.clone();
        let mut dependencies = self.dependencies.clone();
        let mut states = self.states.clone();
        for tag in &gone {
            handlers.remove(tag);
            dependencies.remove(tag);
            states.remove(tag);
        }
        registry::build_inbounds(
            &include::INBOUNDS,
            &fresh,
            include::LISTENER_INBOUNDS,
            self.dispatcher.env(),
            &self.dial,
            &mut handlers,
            &mut dependencies,
            &mut states,
        )?;
        // The addresses held until those that go have stopped.
        let held: Vec<SocketAddr> = gone
            .iter()
            .filter_map(|tag| self.network_listeners.get(tag))
            .map(|listener| listener.address)
            .collect();
        let addresses: HashMap<String, SocketAddr> =
            plan_listeners(&fresh, &handlers, &dependencies)?
                .into_iter()
                .map(|(inbound, address)| (inbound.tag.clone(), address))
                .collect();
        let mut new = Vec::new();
        for inbound in fresh {
            let resource = if resource::supported(&inbound) && !resource::stateful(&inbound) {
                let handler = handlers
                    .get_mut(&inbound.tag)
                    .ok_or_else(|| anyhow!("[{}] inbound: was not built", inbound.tag))?;
                Some(resource::wrap(handler)?)
            } else {
                None
            };
            let listener = addresses.get(&inbound.tag).map(|address| {
                NetworkInboundListener::new(
                    *address,
                    inbound.tcp_keep_alive(),
                    handlers[&inbound.tag].clone(),
                    self.dispatcher.clone(),
                    self.nat_manager.clone(),
                )
            });
            let runners = match &listener {
                Some(listener) if !held.iter().any(|held| clash(held, &listener.address)) => {
                    Some(listener.listen()?)
                }
                _ => None,
            };
            new.push(New {
                config: inbound,
                resource,
                listener,
                runners,
            });
        }
        Ok(PreparedReload {
            kept,
            gone,
            new,
            handlers,
            dependencies,
            states,
            stopped: Vec::new(),
            changes,
        })
    }

    /// Stops the inbounds that go and hold an address a new one waits
    /// for, and gives their listeners' tasks: once those have ended, the
    /// addresses are free. Their connections go on for now.
    pub(crate) fn stop_for(&mut self, prepared: &mut PreparedReload) -> Vec<ListenerTask> {
        let waiting: Vec<SocketAddr> = prepared
            .new
            .iter()
            .filter(|new| new.runners.is_none())
            .filter_map(|new| new.listener.as_ref().map(|listener| listener.address))
            .collect();
        let mut tasks = Vec::new();
        for tag in &prepared.gone {
            let holds = self
                .network_listeners
                .get(tag)
                .is_some_and(|old| waiting.iter().any(|new| clash(&old.address, new)));
            if !holds {
                continue;
            }
            for handle in self.running.remove(tag).unwrap_or_default() {
                handle.abort();
            }
            tasks.extend(self.ended.remove(tag).unwrap_or_default());
            prepared.stopped.push(tag.clone());
        }
        tasks
    }

    /// Binds the new inbounds that waited for an address, those holding
    /// it having stopped. When one does not bind, the sockets bound here
    /// are closed again and nothing else is done: the caller tries again,
    /// an address being freed a moment after its listener has ended (a
    /// QUIC endpoint closes its socket once its connections are gone), or
    /// gives up with `put_back`.
    pub(crate) fn bind_late(&mut self, prepared: &mut PreparedReload) -> anyhow::Result<()> {
        let mut bound = Vec::new();
        for (i, new) in prepared.new.iter().enumerate() {
            let (None, Some(listener)) = (&new.runners, &new.listener) else {
                continue;
            };
            // What was bound before this one failed closes with `bound`.
            bound.push((i, listener.listen()?));
        }
        for (i, runners) in bound {
            prepared.new[i].runners = Some(runners);
        }
        Ok(())
    }

    /// Puts back the inbounds `stop_for` stopped, listening as they were,
    /// their connections never touched, after `failed`, why a new one did
    /// not bind: what the reload is refused for. One that cannot be put
    /// back is lost.
    pub(crate) fn put_back(
        &mut self,
        prepared: &mut PreparedReload,
        failed: anyhow::Error,
    ) -> Refused {
        for tag in std::mem::take(&mut prepared.stopped) {
            let Some(old) = self.network_listeners.get(&tag) else {
                continue;
            };
            match old.listen() {
                Ok(runners) => self.run(tag, runners),
                Err(e) => {
                    tracing::error!(
                        "[{}] inbound: could not be replaced nor put back: {:#}; it no longer listens",
                        tag,
                        e
                    );
                    return Refused::Lost {
                        tag,
                        reason: format!(
                            "{:#}; the one before could not listen again: {:#}",
                            failed, e
                        ),
                    };
                }
            }
        }
        Refused::Config(failed)
    }

    /// Takes the reload: the users and certificates of those that stay,
    /// the inbounds that go stopped and forgotten, the new ones in their
    /// place, bound and not yet running. It cannot fail.
    pub(crate) fn commit_reload(&mut self, prepared: PreparedReload) -> Reloaded {
        // The inbounds that stay, with their new users: `configs` is theirs
        // alone from here.
        self.publish_resources(prepared.kept);
        let mut accepted = Vec::new();
        for tag in &prepared.gone {
            accepted.push(Accepted::of(self.network_listeners.get(tag)));
            for handle in self.running.remove(tag).unwrap_or_default() {
                handle.abort();
            }
            self.ended.remove(tag);
            self.network_listeners.remove(tag);
            self.resources.remove(tag);
            self.stateful_resources.remove(tag);
            self.dispatcher.set_inbound_type(tag, None);
        }
        self.handlers = prepared.handlers;
        self.dependencies = prepared.dependencies;
        self.states = prepared.states;
        let mut starting = Vec::new();
        for new in prepared.new {
            let tag = new.config.tag.clone();
            if resource::stateful(&new.config) {
                self.stateful_resources.insert(tag.clone());
            }
            if let Some(resource) = new.resource {
                self.resources.insert(tag.clone(), resource);
            }
            self.dispatcher
                .set_inbound_type(&tag, Some(&new.config.protocol));
            self.configs.insert(tag.clone(), new.config);
            if let Some(listener) = new.listener {
                self.network_listeners.insert(tag.clone(), listener);
            }
            if let Some(runners) = new.runners {
                starting.push((tag, runners));
            }
        }
        Reloaded {
            changes: prepared.changes,
            gone: prepared.gone,
            accepted,
            starting,
        }
    }

    /// Runs the listeners a reload bound: they accept from here.
    pub(crate) fn start_reloaded(&mut self, starting: Vec<(String, Vec<Runner>)>) {
        for (tag, runners) in starting {
            self.run(tag, runners);
        }
    }
}

impl PreparedReload {
    /// What becomes of each inbound, for the test that reads it.
    #[cfg(all(
        test,
        feature = "inbound-socks",
        feature = "inbound-tun",
        feature = "outbound-direct"
    ))]
    pub(crate) fn changes(&self) -> &[(String, InboundChange)] {
        &self.changes
    }
}

impl Reloaded {
    /// The new listeners, to run with `InboundManager::start_reloaded`.
    pub(crate) fn take_starting(&mut self) -> Vec<(String, Vec<Runner>)> {
        std::mem::take(&mut self.starting)
    }
}
