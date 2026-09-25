//! `selector`: sends every connection to the one member selected by hand
//! through the API, as sing-box's selector does. The choice is kept
//! across restarts.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use crate::app::outbound::selector::{self, OutboundSelector, SelectedBy, Selection};
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
    outbounds: Vec<String>,
    /// Selected when nothing was selected before, or what was is no
    /// longer a member; defaults to the first.
    #[serde(default)]
    default: Option<String>,
    /// Ends the connections through the member selected before once
    /// another is selected, rather than leaving them on it.
    #[serde(default)]
    interrupt_exist_connections: bool,
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: SelectorOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.outbounds)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: SelectorOutboundOptions = ctx.options()?;
    let actors = ctx.members(&options.outbounds)?;
    let position = |tag: &str| options.outbounds.iter().position(|x| x == tag);
    let default = match &options.default {
        Some(default) => position(default).ok_or_else(|| {
            anyhow!(
                "[{}] outbound: default: [{}] is not one of its outbounds",
                ctx.tag,
                default
            )
        })?,
        None => 0,
    };

    // What was selected before the restart, if it is still a member: the
    // configuration may have changed since.
    let cache_file = selector::cache_file(ctx.env);
    let cached = match selector::get_selected_from_cache(&cache_file, ctx.tag) {
        Ok(cached) => cached,
        Err(e) => {
            tracing::warn!(
                "[{}] outbound: selection kept in {} not read: {}",
                ctx.tag,
                cache_file.display(),
                e
            );
            None
        }
    };
    let initial = match cached {
        Some(cached) => position(&cached).unwrap_or_else(|| {
            tracing::warn!(
                "[{}] outbound: [{}] was selected but is no longer one of its outbounds",
                ctx.tag,
                cached
            );
            default
        }),
        None => default,
    };

    let selected = Arc::new(Selection::new(initial));
    let outbound_selector = OutboundSelector::new(
        ctx.tag.to_owned(),
        options.outbounds.clone(),
        selected.clone(),
        SelectedBy::Hand {
            cache_file: Some(cache_file),
        },
        None,
    );
    ctx.selectors
        .insert(ctx.tag.to_owned(), Arc::new(RwLock::new(outbound_selector)));

    let interrupt = options
        .interrupt_exist_connections
        .then(|| selected.subscribe());
    let stream = Arc::new(StreamHandler {
        actors: actors.clone(),
        selected: selected.clone(),
        interrupt: interrupt.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        actors,
        selected,
        interrupt,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
