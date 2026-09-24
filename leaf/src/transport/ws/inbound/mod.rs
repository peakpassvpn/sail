use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config;

mod stream;

pub use stream::Handler as StreamHandler;

use super::stream as ws_stream;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("ws", InboundFactory::standalone(build));
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let settings: config::WebSocketInboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler::new(settings.path.clone()));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
