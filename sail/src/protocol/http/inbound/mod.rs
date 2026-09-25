use std::sync::Arc;

use anyhow::Result;
use serde_derive::Deserialize;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;

mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register(
        "http",
        InboundFactory::standalone(build).with_blocks(Blocks {
            tls: true,
            ..Blocks::NONE
        }),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpInboundOptions {}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let HttpInboundOptions {} = ctx.options()?;
    let stream = Arc::new(StreamHandler);
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
