use std::sync::Arc;

use anyhow::Result;
use serde_derive::Deserialize;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;

pub mod stream;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("mptp", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MptpInboundOptions {}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let MptpInboundOptions {} = ctx.options()?;
    let stream = Arc::new(stream::Handler::new());
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
