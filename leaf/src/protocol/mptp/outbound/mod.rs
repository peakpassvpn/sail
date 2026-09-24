use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_settings, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use crate::config;

pub mod stream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("mptp", OutboundFactory::composite(dependencies, build));
}

fn dependencies(tag: &str, settings: &[u8]) -> Result<Vec<String>> {
    let settings: config::MptpOutboundSettings = parse_settings("outbound", tag, settings)?;
    Ok(settings.actors.to_vec())
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::MptpOutboundSettings = ctx.settings()?;
    let Some(actors) = ctx.actors(&settings.actors) else {
        return Ok(None);
    };
    if actors.is_empty() {
        return Ok(None);
    }
    let stream = Arc::new(stream::Handler {
        actors,
        address: settings.address.clone(),
        port: settings.port as u16,
        dns_client: ctx.dns_client.clone(),
    });
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream.clone())
            .datagram_handler(stream)
            .build(),
    ))
}
