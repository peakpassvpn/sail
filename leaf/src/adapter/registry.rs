//! What turns a configured inbound or outbound into a handler.
//!
//! Every protocol registers a factory under its protocol name, and the
//! managers look the name up instead of knowing each protocol themselves.
//! Which factories exist is decided in one place, `crate::include`, so that
//! adding a protocol touches that list and the protocol's own directory and
//! nothing else.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::app::SyncDnsClient;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::{self, Blocks, InboundBlocks, OutboundBlocks, OutboundLayering};
use anyhow::{anyhow, Result};
use futures::future::AbortHandle;

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
                "[{}] {}: unknown protocol \"{}\" (not supported, or not compiled into this build)",
                tag,
                self.kind,
                protocol,
            )
        })
    }
}

pub use crate::config::model::{parse_options, Options};

/// Every handler a factory is being built into, keyed by tag.
pub type Handlers<H> = HashMap<String, H>;

/// For a factory that depends on nothing.
pub fn no_dependencies(_tag: &str, _options: &Options) -> Result<Vec<String>> {
    Ok(Vec::new())
}

// ---------------------------------------------------------------------------
// Outbounds
// ---------------------------------------------------------------------------

pub type OutboundRegistry = Registry<OutboundFactory>;

/// Builds one outbound protocol.
pub struct OutboundFactory {
    /// Tags of the outbounds this one is built on. Each must exist, and is
    /// built first.
    pub dependencies: fn(&str, &Options) -> Result<Vec<String>>,
    pub build: fn(&mut OutboundContext<'_>) -> Result<AnyOutboundHandler>,
    /// Whether outbounds with this protocol and identical options may
    /// share one handler instead of each building their own.
    pub shareable: bool,
    /// The shared blocks it can be configured with. They are taken out of
    /// its options before `dependencies` and `build` see them, and applied
    /// around what `build` returns.
    pub blocks: Blocks,
}

impl OutboundFactory {
    /// A protocol that stands on its own.
    pub fn standalone(build: fn(&mut OutboundContext<'_>) -> Result<AnyOutboundHandler>) -> Self {
        Self {
            dependencies: no_dependencies,
            build,
            shareable: true,
            blocks: Blocks::NONE,
        }
    }

    /// A protocol built out of other outbounds.
    pub fn composite(
        dependencies: fn(&str, &Options) -> Result<Vec<String>>,
        build: fn(&mut OutboundContext<'_>) -> Result<AnyOutboundHandler>,
    ) -> Self {
        Self {
            dependencies,
            build,
            shareable: false,
            blocks: Blocks::NONE,
        }
    }

    pub fn with_blocks(mut self, blocks: Blocks) -> Self {
        self.blocks = blocks;
        self
    }
}

/// What an outbound factory is given to build with.
pub struct OutboundContext<'a> {
    pub tag: &'a str,
    pub options: &'a Options,
    pub dns_client: &'a SyncDnsClient,
    /// How this outbound opens its sockets, for a handler that dials by
    /// itself rather than asking through `connect_addr`.
    pub dial: Arc<crate::net::DialOptions>,
    /// The instance's tuning and host.
    pub env: &'a RuntimeEnv,
    /// Tasks the handler spawned, aborted when the outbounds are replaced.
    pub abort_handles: &'a mut Vec<AbortHandle>,
    #[cfg(feature = "outbound-select")]
    pub selectors: &'a mut crate::app::outbound::Selectors,
    #[cfg(feature = "plugin")]
    pub external_handlers: &'a mut crate::app::outbound::plugin::ExternalHandlers,
    handlers: &'a Handlers<AnyOutboundHandler>,
}

impl OutboundContext<'_> {
    /// This outbound's options, read into its protocol's options type.
    pub fn options<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        parse_options("outbound", self.tag, self.options)
    }

    /// The outbound `tag`, which must be one of this outbound's
    /// dependencies.
    pub fn handler(&self, tag: &str) -> Result<AnyOutboundHandler> {
        dependency(&self.handlers, "outbound", self.tag, tag)
    }

    /// The outbounds `tags`, which must be among this outbound's
    /// dependencies. There may be none.
    pub fn actors(&self, tags: &[String]) -> Result<Vec<AnyOutboundHandler>> {
        tags.iter().map(|tag| self.handler(tag)).collect()
    }

    /// Like `actors`, for a group that needs at least one member.
    pub fn members(&self, tags: &[String]) -> Result<Vec<AnyOutboundHandler>> {
        non_empty("outbound", self.tag, self.actors(tags)?)
    }
}

/// The state outbound factories build into, kept by the outbound manager.
pub struct OutboundBuildState<'a> {
    pub dns_client: &'a SyncDnsClient,
    /// What outbounds dial with where their dial fields leave off.
    pub dial_defaults: &'a crate::net::DialOptions,
    pub env: &'a RuntimeEnv,
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
    outbounds: &[crate::config::model::Outbound],
    state: OutboundBuildState<'_>,
) -> Result<()> {
    let nodes = outbounds
        .iter()
        .map(|o| {
            let factory = registry.require(&o.tag, &o.protocol)?;
            let (options, blocks) = factory.blocks.split(&o.options);
            let blocks = OutboundBlocks::parse(&o.tag, &blocks)?;
            let mut dependencies = (factory.dependencies)(&o.tag, &options)?;
            dependencies.extend(blocks.detour.clone());
            Ok(Node {
                tag: &o.tag,
                dependencies,
                item: (o, factory, options, blocks),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Outbounds with identical options share a handler, see
    // `OutboundFactory::shareable`.
    let mut shared: Vec<(&str, &str, &Options)> = Vec::new();

    in_dependency_order("outbound", nodes, |(outbound, factory, options, blocks)| {
        if factory.shareable {
            if let Some((tag, _, _)) = shared.iter().find(|(_, protocol, options)| {
                *protocol == outbound.protocol && *options == &outbound.options
            }) {
                let handler = state.handlers[*tag].clone();
                state.handlers.insert(outbound.tag.clone(), handler);
                return Ok(());
            }
        }
        let dial = Arc::new(blocks.dial(&outbound.tag)?.or(state.dial_defaults));
        let mut ctx = OutboundContext {
            tag: &outbound.tag,
            options: &options,
            dns_client: state.dns_client,
            dial: dial.clone(),
            env: state.env,
            abort_handles: state.abort_handles,
            #[cfg(feature = "outbound-select")]
            selectors: state.selectors,
            #[cfg(feature = "plugin")]
            external_handlers: state.external_handlers,
            handlers: state.handlers,
        };
        let core = (factory.build)(&mut ctx)?;
        let detour = match &blocks.detour {
            Some(detour) => Some(dependency(
                state.handlers,
                "outbound",
                &outbound.tag,
                detour,
            )?),
            None => None,
        };
        let handler = layers::outbound(
            core,
            &blocks,
            OutboundLayering {
                tag: &outbound.tag,
                options: &options,
                dns_client: state.dns_client,
                abort_handles: state.abort_handles,
                detour,
                dial,
                env: state.env,
            },
        )?;
        state.handlers.insert(outbound.tag.clone(), handler);
        if factory.shareable {
            shared.push((&outbound.tag, &outbound.protocol, &outbound.options));
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Inbounds
// ---------------------------------------------------------------------------

pub type InboundRegistry = Registry<InboundFactory>;

/// Builds one inbound protocol.
pub struct InboundFactory {
    /// Tags of the inbounds this one is built on. Each must exist, and is
    /// built first.
    pub dependencies: fn(&str, &Options) -> Result<Vec<String>>,
    pub build: fn(&InboundContext<'_>) -> Result<AnyInboundHandler>,
    /// The shared blocks it can be configured with; see
    /// `OutboundFactory::blocks`. `detour` means nothing to an inbound.
    pub blocks: Blocks,
}

impl InboundFactory {
    /// A protocol that stands on its own.
    pub fn standalone(build: fn(&InboundContext<'_>) -> Result<AnyInboundHandler>) -> Self {
        Self {
            dependencies: no_dependencies,
            build,
            blocks: Blocks::NONE,
        }
    }

    /// A protocol built out of other inbounds.
    pub fn composite(
        dependencies: fn(&str, &Options) -> Result<Vec<String>>,
        build: fn(&InboundContext<'_>) -> Result<AnyInboundHandler>,
    ) -> Self {
        Self {
            dependencies,
            build,
            blocks: Blocks::NONE,
        }
    }

    pub fn with_blocks(mut self, blocks: Blocks) -> Self {
        debug_assert!(!blocks.detour, "an inbound cannot detour");
        self.blocks = blocks;
        self
    }
}

/// What an inbound factory is given to build with.
pub struct InboundContext<'a> {
    pub tag: &'a str,
    pub options: &'a Options,
    /// The instance's tuning and host.
    pub env: &'a RuntimeEnv,
    handlers: &'a Handlers<AnyInboundHandler>,
}

impl InboundContext<'_> {
    /// This inbound's options, read into its protocol's options type.
    pub fn options<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        parse_options("inbound", self.tag, self.options)
    }

    /// The inbound `tag`, which must be one of this inbound's dependencies.
    pub fn handler(&self, tag: &str) -> Result<AnyInboundHandler> {
        dependency(self.handlers, "inbound", self.tag, tag)
    }

    /// The inbounds `tags`, which must be among this inbound's
    /// dependencies. There may be none.
    pub fn actors(&self, tags: &[String]) -> Result<Vec<AnyInboundHandler>> {
        tags.iter().map(|tag| self.handler(tag)).collect()
    }

    /// Like `actors`, for a composite that needs at least one member.
    pub fn members(&self, tags: &[String]) -> Result<Vec<AnyInboundHandler>> {
        non_empty("inbound", self.tag, self.actors(tags)?)
    }
}

/// Builds every inbound in `inbounds` whose protocol makes a handler, each
/// after the ones it is built on. Protocols in `listeners` are served by a
/// listener of their own rather than a handler, and are skipped.
pub fn build_inbounds(
    registry: &InboundRegistry,
    inbounds: &[crate::config::model::Inbound],
    listeners: &[&str],
    env: &RuntimeEnv,
    handlers: &mut Handlers<AnyInboundHandler>,
) -> Result<()> {
    let nodes = inbounds
        .iter()
        .filter(|i| !listeners.contains(&i.protocol.as_str()))
        .map(|i| {
            let factory = registry.require(&i.tag, &i.protocol)?;
            let (options, blocks) = factory.blocks.split(&i.options);
            let blocks = InboundBlocks::parse(&i.tag, &blocks)?;
            let dependencies = (factory.dependencies)(&i.tag, &options)?;
            Ok(Node {
                tag: &i.tag,
                dependencies,
                item: (i, factory, options, blocks),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    in_dependency_order("inbound", nodes, |(inbound, factory, options, blocks)| {
        let ctx = InboundContext {
            tag: &inbound.tag,
            options: &options,
            env,
            handlers,
        };
        let core = (factory.build)(&ctx)?;
        let handler = layers::inbound(&inbound.tag, core, &blocks, env)?;
        handlers.insert(inbound.tag.clone(), handler);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

fn dependency<H: Clone>(handlers: &Handlers<H>, kind: &str, tag: &str, dep: &str) -> Result<H> {
    handlers.get(dep).cloned().ok_or_else(|| {
        anyhow!(
            "[{}] {}: [{}] is used but not declared as a dependency",
            tag,
            kind,
            dep
        )
    })
}

fn non_empty<H>(kind: &str, tag: &str, members: Vec<H>) -> Result<Vec<H>> {
    if members.is_empty() {
        return Err(anyhow!("[{}] {}: needs at least one actor", tag, kind));
    }
    Ok(members)
}

struct Node<'a, T> {
    tag: &'a str,
    dependencies: Vec<String>,
    item: T,
}

/// Runs `build` over `nodes` so that every node comes after the nodes it
/// depends on, keeping configuration order otherwise.
///
/// The graph is checked first: two nodes sharing a tag, a dependency on a
/// tag no node has, and a cycle are each an error, and nothing is built.
fn in_dependency_order<T>(
    kind: &str,
    nodes: Vec<Node<'_, T>>,
    mut build: impl FnMut(T) -> Result<()>,
) -> Result<()> {
    let mut known: HashSet<&str> = HashSet::new();
    for node in &nodes {
        if !known.insert(node.tag) {
            return Err(anyhow!("[{}] {}: tag used more than once", node.tag, kind));
        }
    }
    for node in &nodes {
        if let Some(missing) = node
            .dependencies
            .iter()
            .find(|d| !known.contains(d.as_str()))
        {
            return Err(anyhow!(
                "[{}] {}: depends on [{}], which does not exist",
                node.tag,
                kind,
                missing
            ));
        }
    }
    if let Some(cycle) = find_cycle(&nodes) {
        return Err(anyhow!(
            "{}s depend on each other in a cycle: {}",
            kind,
            cycle.join(" -> ")
        ));
    }

    // Acyclic with every dependency present, so each pass settles at least
    // one node.
    let mut settled: HashSet<String> = HashSet::new();
    let mut pending = nodes;
    while !pending.is_empty() {
        let mut waiting = Vec::new();
        for node in pending {
            if node.dependencies.iter().all(|d| settled.contains(d)) {
                let tag = node.tag.to_owned();
                build(node.item)?;
                settled.insert(tag);
            } else {
                waiting.push(node);
            }
        }
        pending = waiting;
    }
    Ok(())
}

/// A cycle among `nodes`, as the tags along it with the first repeated at
/// the end, if there is one.
fn find_cycle<T>(nodes: &[Node<'_, T>]) -> Option<Vec<String>> {
    let deps: HashMap<&str, &[String]> = nodes
        .iter()
        .map(|n| (n.tag, n.dependencies.as_slice()))
        .collect();

    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Visiting,
        Done,
    }
    let mut marks: HashMap<&str, Mark> = HashMap::new();

    fn visit<'a>(
        tag: &'a str,
        deps: &HashMap<&'a str, &'a [String]>,
        marks: &mut HashMap<&'a str, Mark>,
        path: &mut Vec<&'a str>,
    ) -> Option<Vec<String>> {
        match marks.get(tag) {
            Some(Mark::Done) => return None,
            Some(Mark::Visiting) => {
                let start = path.iter().position(|t| *t == tag).unwrap();
                let mut cycle: Vec<String> = path[start..].iter().map(|t| t.to_string()).collect();
                cycle.push(tag.to_owned());
                return Some(cycle);
            }
            None => {}
        }
        marks.insert(tag, Mark::Visiting);
        path.push(tag);
        for dep in deps.get(tag).copied().unwrap_or_default() {
            if let Some(cycle) = visit(dep.as_str(), deps, marks, path) {
                return Some(cycle);
            }
        }
        path.pop();
        marks.insert(tag, Mark::Done);
        None
    }

    for node in nodes {
        let mut path = Vec::new();
        if let Some(cycle) = visit(node.tag, &deps, &mut marks, &mut path) {
            return Some(cycle);
        }
    }
    None
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

    fn order(nodes: Vec<Node<'_, &str>>) -> Result<Vec<String>> {
        let mut built = Vec::new();
        in_dependency_order("test", nodes, |tag| {
            built.push(tag.to_owned());
            Ok(())
        })?;
        Ok(built)
    }

    #[test]
    fn dependencies_come_first_and_config_order_is_kept_otherwise() {
        let built = order(vec![
            node("group", &["b", "a"]),
            node("a", &[]),
            node("outer", &["group"]),
            node("b", &[]),
        ])
        .unwrap();
        assert_eq!(built, ["a", "b", "group", "outer"]);
    }

    #[test]
    fn a_missing_dependency_is_an_error() {
        let err = order(vec![node("a", &[]), node("group", &["a", "nowhere"])]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[group] test: depends on [nowhere], which does not exist"
        );
    }

    #[test]
    fn a_cycle_is_an_error_that_spells_out_the_cycle() {
        let err = order(vec![
            node("a", &[]),
            node("entry", &["x"]),
            node("x", &["y"]),
            node("y", &["z"]),
            node("z", &["x"]),
        ])
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "tests depend on each other in a cycle: x -> y -> z -> x"
        );
    }

    #[test]
    fn depending_on_itself_is_a_cycle() {
        let err = order(vec![node("a", &["a"])]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "tests depend on each other in a cycle: a -> a"
        );
    }

    #[test]
    fn a_tag_used_twice_is_an_error() {
        let err = order(vec![node("a", &[]), node("a", &[])]).unwrap_err();
        assert_eq!(err.to_string(), "[a] test: tag used more than once");
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
        let inbound = |tag: &str, protocol: &str| crate::config::model::Inbound {
            protocol: protocol.to_string(),
            tag: tag.to_string(),
            listen: None,
            listen_port: None,
            options: Options::new(),
        };
        let unknown = inbound("in-1", "no-such-protocol");
        let listener = inbound("tun-1", "tun");

        let mut handlers = Handlers::new();
        let registry: InboundRegistry = Registry::new("inbound");
        let env = RuntimeEnv::default();
        build_inbounds(
            &registry,
            &[listener.clone()],
            &["tun"],
            &env,
            &mut handlers,
        )
        .unwrap();
        let err = build_inbounds(
            &registry,
            &[listener, unknown],
            &["tun"],
            &env,
            &mut handlers,
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("[in-1]"), "{}", err);
    }

    #[test]
    #[should_panic(expected = "registered twice")]
    fn a_protocol_cannot_be_registered_twice() {
        fn build(_: &InboundContext<'_>) -> Result<AnyInboundHandler> {
            unreachable!()
        }
        let mut registry: InboundRegistry = Registry::new("inbound");
        registry.register("x", InboundFactory::standalone(build));
        registry.register("x", InboundFactory::standalone(build));
    }
}
