//! What turns a configured inbound or outbound into a handler.
//!
//! Every protocol registers a factory under its protocol name, and the
//! managers look the name up instead of knowing each protocol themselves.
//! Which factories exist is decided in one place, `crate::include`, so that
//! adding a protocol touches that list and the protocol's own directory and
//! nothing else.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use tracing::warn;

use crate::app::SyncDnsClient;

use super::{AnyInboundHandler, AnyOutboundHandler};

/// Factories by protocol name.
pub struct Registry<F> {
    kind: &'static str,
    factories: HashMap<&'static str, F>,
}

impl<F> Registry<F> {
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            factories: HashMap::new(),
        }
    }

    /// Registers `factory` under `protocol`.
    ///
    /// Panics if the name is taken: two protocols answering to one name is a
    /// mistake in the build, not in anyone's configuration.
    pub fn register(&mut self, protocol: &'static str, factory: F) {
        if self.factories.insert(protocol, factory).is_some() {
            panic!("{} protocol \"{}\" registered twice", self.kind, protocol);
        }
    }

    pub fn get(&self, protocol: &str) -> Option<&F> {
        self.factories.get(protocol)
    }

    /// Looks up `protocol`, failing with an error that names the offending
    /// inbound or outbound.
    pub fn require(&self, tag: &str, protocol: &str) -> Result<&F> {
        self.get(protocol).ok_or_else(|| {
            anyhow!(
                "[{}] {}: unknown protocol \"{}\" (not a {} protocol, or not compiled into this build)",
                tag,
                self.kind,
                protocol,
                self.kind,
            )
        })
    }
}

/// Parses the protobuf settings of the inbound or outbound `tag`.
pub fn parse_settings<T: protobuf::Message>(kind: &str, tag: &str, settings: &[u8]) -> Result<T> {
    T::parse_from_bytes(settings).map_err(|e| anyhow!("invalid [{}] {} settings: {}", tag, kind, e))
}

/// Every handler a factory is being built into, keyed by tag.
pub type Handlers<H> = HashMap<String, H>;

/// A dependency-free factory needs no settings parsing to say so.
pub fn no_dependencies(_tag: &str, _settings: &[u8]) -> Result<Vec<String>> {
    Ok(Vec::new())
}

// ---------------------------------------------------------------------------
// Outbounds
// ---------------------------------------------------------------------------

pub type OutboundRegistry = Registry<OutboundFactory>;

/// Builds one outbound protocol.
pub struct OutboundFactory {
    /// Tags of the outbounds this one is built on. They are built first;
    /// what to do when one of them is missing is up to `build`.
    pub dependencies: fn(&str, &[u8]) -> Result<Vec<String>>,
    /// Builds the handler, or returns `None` when there is nothing to build
    /// (a group none of whose members exist, for example).
    pub build: fn(&mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>>,
    /// Whether outbounds with this protocol and byte-identical settings may
    /// share one handler instead of each building their own.
    pub shareable: bool,
}

impl OutboundFactory {
    /// A protocol that stands on its own.
    pub fn standalone(
        build: fn(&mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>>,
    ) -> Self {
        Self {
            dependencies: no_dependencies,
            build,
            shareable: true,
        }
    }

    /// A protocol built out of other outbounds.
    pub fn composite(
        dependencies: fn(&str, &[u8]) -> Result<Vec<String>>,
        build: fn(&mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>>,
    ) -> Self {
        Self {
            dependencies,
            build,
            shareable: false,
        }
    }
}

/// What an outbound factory is given to build with.
pub struct OutboundContext<'a> {
    pub tag: &'a str,
    pub settings: &'a [u8],
    pub dns_client: &'a SyncDnsClient,
    /// Tasks the handler spawned, aborted when the outbounds are replaced.
    pub abort_handles: &'a mut Vec<AbortHandle>,
    #[cfg(feature = "outbound-select")]
    pub selectors: &'a mut crate::app::outbound::Selectors,
    #[cfg(feature = "plugin")]
    pub external_handlers: &'a mut crate::app::outbound::plugin::ExternalHandlers,
    handlers: &'a Handlers<AnyOutboundHandler>,
}

impl OutboundContext<'_> {
    pub fn settings<T: protobuf::Message>(&self) -> Result<T> {
        parse_settings("outbound", self.tag, self.settings)
    }

    /// The already built outbound `tag`, if there is one.
    pub fn handler(&self, tag: &str) -> Option<AnyOutboundHandler> {
        self.handlers.get(tag).cloned()
    }

    /// The outbounds `tags`, or `None` if any of them does not exist.
    pub fn actors(&self, tags: &[String]) -> Option<Vec<AnyOutboundHandler>> {
        let actors = tags
            .iter()
            .map(|tag| self.handler(tag))
            .collect::<Option<Vec<_>>>();
        if actors.is_none() {
            warn!(
                "outbound [{}] skipped: not all of its actors [{}] exist",
                self.tag,
                tags.join(",")
            );
        }
        actors
    }
}

/// The state outbound factories build into, kept by the outbound manager.
pub struct OutboundBuildState<'a> {
    pub dns_client: &'a SyncDnsClient,
    pub handlers: &'a mut Handlers<AnyOutboundHandler>,
    pub abort_handles: &'a mut Vec<AbortHandle>,
    #[cfg(feature = "outbound-select")]
    pub selectors: &'a mut crate::app::outbound::Selectors,
    #[cfg(feature = "plugin")]
    pub external_handlers: &'a mut crate::app::outbound::plugin::ExternalHandlers,
}

/// Builds every outbound in `outbounds`, each after the ones it is built on.
pub fn build_outbounds(
    registry: &OutboundRegistry,
    outbounds: &[crate::config::Outbound],
    state: OutboundBuildState<'_>,
) -> Result<()> {
    let nodes = outbounds
        .iter()
        .map(|o| {
            let factory = registry.require(&o.tag, &o.protocol)?;
            let dependencies = (factory.dependencies)(&o.tag, &o.settings)?;
            Ok(Node {
                tag: &o.tag,
                dependencies,
                item: (o, factory),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Outbounds with identical settings share a handler, see
    // `OutboundFactory::shareable`.
    let mut shared: Vec<(&str, &str, &[u8])> = Vec::new();

    in_dependency_order("outbound", nodes, |(outbound, factory)| {
        if factory.shareable {
            if let Some((tag, _, _)) = shared.iter().find(|(_, protocol, settings)| {
                *protocol == outbound.protocol && *settings == &outbound.settings[..]
            }) {
                let handler = state.handlers[*tag].clone();
                state.handlers.insert(outbound.tag.clone(), handler);
                return Ok(true);
            }
        }
        let mut ctx = OutboundContext {
            tag: &outbound.tag,
            settings: &outbound.settings,
            dns_client: state.dns_client,
            abort_handles: state.abort_handles,
            #[cfg(feature = "outbound-select")]
            selectors: state.selectors,
            #[cfg(feature = "plugin")]
            external_handlers: state.external_handlers,
            handlers: state.handlers,
        };
        let Some(handler) = (factory.build)(&mut ctx)? else {
            return Ok(false);
        };
        state.handlers.insert(outbound.tag.clone(), handler);
        if factory.shareable {
            shared.push((&outbound.tag, &outbound.protocol, &outbound.settings));
        }
        Ok(true)
    })
}

// ---------------------------------------------------------------------------
// Inbounds
// ---------------------------------------------------------------------------

pub type InboundRegistry = Registry<InboundFactory>;

/// Builds one inbound protocol.
pub struct InboundFactory {
    /// Tags of the inbounds this one is built on. They are built first;
    /// what to do when one of them is missing is up to `build`.
    pub dependencies: fn(&str, &[u8]) -> Result<Vec<String>>,
    /// Builds the handler, or returns `None` when there is nothing to build.
    pub build: fn(&InboundContext<'_>) -> Result<Option<AnyInboundHandler>>,
}

impl InboundFactory {
    /// A protocol that stands on its own.
    pub fn standalone(build: fn(&InboundContext<'_>) -> Result<Option<AnyInboundHandler>>) -> Self {
        Self {
            dependencies: no_dependencies,
            build,
        }
    }

    /// A protocol built out of other inbounds.
    pub fn composite(
        dependencies: fn(&str, &[u8]) -> Result<Vec<String>>,
        build: fn(&InboundContext<'_>) -> Result<Option<AnyInboundHandler>>,
    ) -> Self {
        Self {
            dependencies,
            build,
        }
    }
}

/// What an inbound factory is given to build with.
pub struct InboundContext<'a> {
    pub tag: &'a str,
    pub settings: &'a [u8],
    handlers: &'a Handlers<AnyInboundHandler>,
}

impl InboundContext<'_> {
    pub fn settings<T: protobuf::Message>(&self) -> Result<T> {
        parse_settings("inbound", self.tag, self.settings)
    }

    /// The already built inbound `tag`, if there is one.
    pub fn handler(&self, tag: &str) -> Option<AnyInboundHandler> {
        self.handlers.get(tag).cloned()
    }

    /// Those of the inbounds `tags` that exist, in order.
    pub fn existing_actors(&self, tags: &[String]) -> Vec<AnyInboundHandler> {
        tags.iter()
            .filter_map(|tag| {
                let actor = self.handler(tag);
                if actor.is_none() {
                    warn!("inbound [{}]: actor [{}] does not exist", self.tag, tag);
                }
                actor
            })
            .collect()
    }
}

/// Builds every inbound in `inbounds` whose protocol makes a handler, each
/// after the ones it is built on. Protocols in `listeners` are served by a
/// listener of their own rather than a handler, and are skipped.
pub fn build_inbounds(
    registry: &InboundRegistry,
    inbounds: &[crate::config::Inbound],
    listeners: &[&str],
    handlers: &mut Handlers<AnyInboundHandler>,
) -> Result<()> {
    let nodes = inbounds
        .iter()
        .filter(|i| !listeners.contains(&i.protocol.as_str()))
        .map(|i| {
            let factory = registry.require(&i.tag, &i.protocol)?;
            let dependencies = (factory.dependencies)(&i.tag, &i.settings)?;
            Ok(Node {
                tag: &i.tag,
                dependencies,
                item: (i, factory),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    in_dependency_order("inbound", nodes, |(inbound, factory)| {
        let ctx = InboundContext {
            tag: &inbound.tag,
            settings: &inbound.settings,
            handlers,
        };
        let Some(handler) = (factory.build)(&ctx)? else {
            return Ok(false);
        };
        handlers.insert(inbound.tag.clone(), handler);
        Ok(true)
    })
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

struct Node<'a, T> {
    tag: &'a str,
    dependencies: Vec<String>,
    item: T,
}

/// Runs `build` over `nodes` so that every node comes after the nodes it
/// depends on, keeping configuration order otherwise.
///
/// A dependency on a tag that no node has does not hold anything back; the
/// builder sees it missing and decides. Nodes caught in a cycle are never
/// built, and are reported. `build` returns whether it produced something,
/// which is only used for logging: a node that produced nothing still counts
/// as settled, so that its dependents get their turn to see it missing.
fn in_dependency_order<T>(
    kind: &str,
    nodes: Vec<Node<'_, T>>,
    mut build: impl FnMut(T) -> Result<bool>,
) -> Result<()> {
    let known: HashSet<&str> = nodes.iter().map(|n| n.tag).collect();
    let mut settled: HashSet<String> = HashSet::new();
    let mut pending = nodes;

    loop {
        let before = pending.len();
        let mut waiting = Vec::new();
        for node in pending {
            let ready = node
                .dependencies
                .iter()
                .all(|d| !known.contains(d.as_str()) || settled.contains(d));
            if !ready {
                waiting.push(node);
                continue;
            }
            let tag = node.tag.to_owned();
            if !build(node.item)? {
                tracing::debug!("{} [{}] built nothing", kind, tag);
            }
            settled.insert(tag);
        }
        pending = waiting;
        if pending.is_empty() {
            return Ok(());
        }
        if pending.len() == before {
            let tags: Vec<&str> = pending.iter().map(|n| n.tag).collect();
            warn!(
                "{}s skipped: [{}] depend on each other in a cycle, or on one that does",
                kind,
                tags.join(",")
            );
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node<'a>(tag: &'a str, deps: &[&str]) -> Node<'a, &'a str> {
        Node {
            tag,
            dependencies: deps.iter().map(|d| d.to_string()).collect(),
            item: tag,
        }
    }

    fn order(nodes: Vec<Node<'_, &str>>) -> Vec<String> {
        let mut built = Vec::new();
        in_dependency_order("test", nodes, |tag| {
            built.push(tag.to_owned());
            Ok(true)
        })
        .unwrap();
        built
    }

    #[test]
    fn dependencies_come_first_and_config_order_is_kept_otherwise() {
        let built = order(vec![
            node("group", &["b", "a"]),
            node("a", &[]),
            node("outer", &["group"]),
            node("b", &[]),
        ]);
        assert_eq!(built, ["a", "b", "group", "outer"]);
    }

    #[test]
    fn a_missing_dependency_does_not_hold_a_node_back() {
        let built = order(vec![node("group", &["nowhere"]), node("a", &[])]);
        assert_eq!(built, ["group", "a"]);
    }

    #[test]
    fn a_cycle_is_left_unbuilt_and_the_rest_is_built() {
        let built = order(vec![
            node("x", &["y"]),
            node("y", &["x"]),
            node("a", &[]),
            node("after_x", &["x"]),
        ]);
        assert_eq!(built, ["a"]);
    }

    #[test]
    fn an_unknown_protocol_names_the_tag() {
        let registry: OutboundRegistry = Registry::new("outbound");
        let err = registry.require("proxy-1", "nope").err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("[proxy-1]"), "{}", msg);
        assert!(msg.contains("\"nope\""), "{}", msg);
    }

    #[test]
    fn an_unknown_inbound_protocol_is_an_error_but_a_listener_is_not() {
        let mut unknown = crate::config::Inbound::new();
        unknown.tag = "in-1".to_string();
        unknown.protocol = "no-such-protocol".to_string();
        let mut listener = crate::config::Inbound::new();
        listener.tag = "tun-1".to_string();
        listener.protocol = "tun".to_string();

        let mut handlers = Handlers::new();
        let registry: InboundRegistry = Registry::new("inbound");
        build_inbounds(&registry, &[listener.clone()], &["tun"], &mut handlers).unwrap();
        let err = build_inbounds(&registry, &[listener, unknown], &["tun"], &mut handlers)
            .err()
            .unwrap();
        assert!(err.to_string().contains("[in-1]"), "{}", err);
    }

    #[test]
    #[should_panic(expected = "registered twice")]
    fn a_protocol_cannot_be_registered_twice() {
        let mut registry: InboundRegistry = Registry::new("inbound");
        registry.register("x", InboundFactory::standalone(|_| Ok(None)));
        registry.register("x", InboundFactory::standalone(|_| Ok(None)));
    }
}
