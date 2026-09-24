use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_settings, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use crate::app::outbound::selector::{self, OutboundSelector};
use crate::config;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("select", OutboundFactory::composite(dependencies, build));
}

fn dependencies(tag: &str, settings: &[u8]) -> Result<Vec<String>> {
    let settings: config::SelectOutboundSettings = parse_settings("outbound", tag, settings)?;
    Ok(settings.actors.to_vec())
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::SelectOutboundSettings = ctx.settings()?;
    let Some(actors) = ctx.actors(&settings.actors) else {
        return Ok(None);
    };
    if actors.is_empty() {
        return Ok(None);
    }

    let actors_tags: Vec<String> = actors.iter().map(|x| x.tag().to_owned()).collect();
    let selected = Arc::new(AtomicUsize::new(0));
    let mut outbound_selector =
        OutboundSelector::new(ctx.tag.to_owned(), actors_tags, selected.clone());
    if let Ok(Some(selected)) = selector::get_selected_from_cache(ctx.tag) {
        // FIXME handle error
        let _ = outbound_selector.set_selected(&selected);
    } else {
        let _ = outbound_selector.set_selected(&settings.actors[0]);
    }
    ctx.selectors
        .insert(ctx.tag.to_owned(), Arc::new(RwLock::new(outbound_selector)));

    let stream = Arc::new(StreamHandler {
        actors: actors.clone(),
        selected: selected.clone(),
    });
    let datagram = Arc::new(DatagramHandler { actors, selected });
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .datagram_handler(datagram)
            .build(),
    ))
}
