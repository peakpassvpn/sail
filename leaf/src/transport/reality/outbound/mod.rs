use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use serde_derive::Deserialize;

pub mod stream;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("reality", OutboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealityOutboundOptions {
    server_name: String,
    public_key: String,
    #[serde(default)]
    short_id: String,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: RealityOutboundOptions = ctx.options()?;
    let stream = Arc::new(StreamHandler {
        server_name: options.server_name,
        public_key: options.public_key,
        short_id: options.short_id,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}
