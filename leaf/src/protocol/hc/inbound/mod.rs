use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler as InboundHandler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config;

mod stream;

pub use stream::Handler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("hc", InboundFactory::standalone(build));
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let settings: config::HcInboundSettings = ctx.settings()?;
    let stream = Arc::new(Handler::new(
        settings.path,
        settings.request,
        settings.response,
    ));
    Ok(Arc::new(InboundHandler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
