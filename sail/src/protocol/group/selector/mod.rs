//! `selector`: sends every connection to the one member selected by hand
//! through the API, as sing-box's selector does. The choice is kept
//! across restarts.

use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use crate::app::outbound::selector::{OutboundSelector, SelectedBy, Selection};
use crate::config::model::GroupProviders;
use crate::protocol::group::members::{Member, MemberKey, Snapshot};
use crate::protocol::group::merge;
use serde_derive::Deserialize;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("selector", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorOutboundOptions {
    /// Its members; none may be when its providers give others.
    #[serde(default)]
    outbounds: Vec<String>,
    /// Members from outbound providers too, a sail extension.
    #[serde(flatten)]
    providers: GroupProviders,
    /// Selected when nothing was selected before, or what was is no
    /// longer a member; defaults to the first. It may be a member a
    /// provider gives, the first so named.
    #[serde(default)]
    default: Option<String>,
    /// Ends the connections through the member selected before once
    /// another is selected, rather than leaving them on it.
    #[serde(default)]
    interrupt_exist_connections: bool,
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: SelectorOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.providers.dependencies(options.outbounds))
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: SelectorOutboundOptions = ctx.options()?;
    let merged = merge::members(ctx, &options.outbounds, &options.providers)?;
    let members = merged.members.clone();
    let snapshot = members.load();
    // A provider's members may be there only later.
    let default: Arc<str> = match &options.default {
        Some(default) if snapshot.find(default).is_none() && !merged.has_providers() => {
            return Err(anyhow!(
                "[{}] outbound: default: [{}] is not one of its outbounds",
                ctx.tag,
                default
            ));
        }
        Some(default) => default.as_str().into(),
        None => snapshot
            .members
            .first()
            .map(|m| m.key.name.clone())
            .unwrap_or_default(),
    };
    let default_key = snapshot
        .find(&default)
        .map(|m| m.key.clone())
        .unwrap_or_else(|| MemberKey::outbound(&default));
    let mut wanted = None;

    // What was selected before the restart, if it is still a member: the
    // configuration may have changed since.
    let cache_file = ctx.env.cache_file.get();
    let cached = match cache_file.as_ref().map(|c| c.load_selected(ctx.tag)) {
        None => None,
        Some(Ok(cached)) => cached,
        Some(Err(e)) => {
            tracing::warn!(
                "[{}] outbound: selection kept in the cache file not read: {}",
                ctx.tag,
                e
            );
            None
        }
    };
    let initial = match cached {
        Some(cached) => match snapshot.find(&cached) {
            Some(member) => member.key.clone(),
            // Until its providers give it, if they do.
            None if merged.has_providers() => {
                wanted = Some(cached);
                default_key
            }
            None => {
                tracing::warn!(
                    "[{}] outbound: [{}] was selected but is no longer one of its outbounds",
                    ctx.tag,
                    cached
                );
                default_key
            }
        },
        None => default_key,
    };

    let selected = Arc::new(Selection::new(&default, initial));
    if let Some(wanted) = wanted {
        selected.want(&wanted);
    }
    merged.on_merged({
        let selected = selected.clone();
        Box::new(move |snapshot, _| selected.settle(snapshot))
    });
    let outbound_selector = OutboundSelector::new(
        ctx.tag.to_owned(),
        members.clone(),
        selected.clone(),
        SelectedBy::Hand { cache_file },
        None,
    );
    ctx.selectors
        .insert(ctx.tag.to_owned(), Arc::new(RwLock::new(outbound_selector)));

    let interrupt = options
        .interrupt_exist_connections
        .then(|| selected.subscribe());
    let stream = Arc::new(StreamHandler {
        members: members.clone(),
        selected: selected.clone(),
        interrupt: interrupt.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        members,
        selected,
        interrupt,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}

/// The member of `snapshot` a connection goes to, and, for
/// `interrupt_exist_connections`, the selection it went by.
fn pick<'s>(
    snapshot: &'s Snapshot,
    selected: &Selection,
    interrupt: bool,
) -> io::Result<(&'s Member, Option<MemberKey>)> {
    let (i, by) = selected
        .pick(snapshot)
        .ok_or_else(|| io::Error::other("no outbound to select"))?;
    let by = interrupt.then(|| MemberKey::clone(&by));
    Ok((&snapshot.members[i], by))
}
