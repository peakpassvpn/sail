use std::sync::Arc;

use anyhow::Result;
use serde_derive::Deserialize;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("block", OutboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockOptions {}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let BlockOptions {} = ctx.options()?;
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(Arc::new(StreamHandler))
        .datagram_handler(Arc::new(DatagramHandler))
        .build())
}
