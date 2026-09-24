use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("drop", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(Arc::new(StreamHandler))
        .datagram_handler(Arc::new(DatagramHandler))
        .build())
}
