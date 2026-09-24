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

use super::crypto;
use super::protocol;
use super::stream as vmess_stream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("vmess", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::VMessOutboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler {
        address: settings.address.clone(),
        port: settings.port as u16,
        uuid: settings.uuid.clone(),
        security: settings.security.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: settings.address.clone(),
        port: settings.port as u16,
        uuid: settings.uuid.clone(),
        security: settings.security.clone(),
    });
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .datagram_handler(datagram)
            .build(),
    ))
}
