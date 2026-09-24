use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_settings, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use crate::config;

mod stream;

pub use stream::Handler as StreamHandler;

use super::MuxConnector;
use super::MuxSession;
use super::MuxStream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("amux", OutboundFactory::composite(dependencies, build));
}

fn dependencies(tag: &str, settings: &[u8]) -> Result<Vec<String>> {
    let settings: config::AMuxOutboundSettings = parse_settings("outbound", tag, settings)?;
    Ok(settings.actors.to_vec())
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::AMuxOutboundSettings = ctx.settings()?;
    let Some(actors) = ctx.actors(&settings.actors) else {
        return Ok(None);
    };
    let (stream, mut abort_handles) = StreamHandler::new(
        settings.address.clone(),
        settings.port as u16,
        actors,
        settings.max_accepts as usize,
        settings.concurrency as usize,
        settings.max_recv_bytes as usize,
        settings.max_lifetime,
        ctx.dns_client.clone(),
    );
    ctx.abort_handles.append(&mut abort_handles);
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(Arc::new(stream))
            .build(),
    ))
}
