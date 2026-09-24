use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_settings, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use crate::config;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("tryall", OutboundFactory::composite(dependencies, build));
}

fn dependencies(tag: &str, settings: &[u8]) -> Result<Vec<String>> {
    let settings: config::TryAllOutboundSettings = parse_settings("outbound", tag, settings)?;
    Ok(settings.actors.to_vec())
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::TryAllOutboundSettings = ctx.settings()?;
    let Some(actors) = ctx.actors(&settings.actors) else {
        return Ok(None);
    };
    if actors.is_empty() {
        return Ok(None);
    }
    let stream = Arc::new(StreamHandler {
        actors: actors.clone(),
        delay_base: settings.delay_base,
        dns_client: ctx.dns_client.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        actors,
        delay_base: settings.delay_base,
        dns_client: ctx.dns_client.clone(),
    });
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .datagram_handler(datagram)
            .build(),
    ))
}
