use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("vless", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let settings: config::VlessOutboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler {
        address: settings.address.clone(),
        port: settings.port as u16,
        uuid: settings.uuid.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: settings.address.clone(),
        port: settings.port as u16,
        uuid: settings.uuid.clone(),
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
