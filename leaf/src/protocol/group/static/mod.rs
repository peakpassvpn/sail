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

enum Method {
    Random,
    RandomOnce,
    RoundRobin,
}

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("static", OutboundFactory::composite(dependencies, build));
}

fn dependencies(tag: &str, settings: &[u8]) -> Result<Vec<String>> {
    let settings: config::StaticOutboundSettings = parse_settings("outbound", tag, settings)?;
    Ok(settings.actors.to_vec())
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let settings: config::StaticOutboundSettings = ctx.settings()?;
    let actors = ctx.members(&settings.actors)?;
    let stream = Arc::new(StreamHandler::new(actors.clone(), &settings.method)?);
    let datagram = Arc::new(DatagramHandler::new(actors, &settings.method)?);
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
