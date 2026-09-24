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
    registry.register("redirect", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::RedirectOutboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler {
        address: settings.address.clone(),
        port: settings.port as u16,
    });
    let datagram = Arc::new(DatagramHandler {
        address: settings.address,
        port: settings.port as u16,
    });
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .datagram_handler(datagram)
            .build(),
    ))
}
