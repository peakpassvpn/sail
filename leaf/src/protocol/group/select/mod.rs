use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use crate::app::outbound::selector::{self, OutboundSelector};
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
    /// Selected when nothing was selected before; defaults to the first.
    #[serde(default)]
    default: Option<String>,
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: SelectorOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.outbounds)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: SelectorOutboundOptions = ctx.options()?;
    let actors = ctx.members(&options.outbounds)?;
    let default = match options.default {
        Some(default) if !options.outbounds.contains(&default) => {
            return Err(anyhow!(
                "[{}] outbound: default: [{}] is not one of its outbounds",
                ctx.tag,
                default
            ))
        }
        Some(default) => default,
        None => options.outbounds[0].clone(),
    };

    let actors_tags: Vec<String> = actors.iter().map(|x| x.tag().to_owned()).collect();
    let selected = Arc::new(AtomicUsize::new(0));
    let mut outbound_selector =
        OutboundSelector::new(ctx.tag.to_owned(), actors_tags, selected.clone());
    if let Ok(Some(selected)) = selector::get_selected_from_cache(ctx.tag) {
        // FIXME handle error
        let _ = outbound_selector.set_selected(&selected);
    } else {
        let _ = outbound_selector.set_selected(&default);
    }
    ctx.selectors
        .insert(ctx.tag.to_owned(), Arc::new(RwLock::new(outbound_selector)));

    let stream = Arc::new(StreamHandler {
        actors: actors.clone(),
        selected: selected.clone(),
    });
    let datagram = Arc::new(DatagramHandler { actors, selected });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
