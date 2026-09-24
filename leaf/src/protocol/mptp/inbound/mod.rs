use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;

pub mod stream;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("mptp", InboundFactory::standalone(build));
}

fn build(ctx: &InboundContext<'_>) -> Result<Option<AnyInboundHandler>> {
    let stream = Arc::new(stream::Handler::new());
    Ok(Some(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    ))))
}
