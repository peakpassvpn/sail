use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config;

pub mod stream;

pub use stream::Handler as StreamHandler;

use super::stream as ws_stream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("ws", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::WebSocketOutboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler {
        path: settings.path.clone(),
        headers: settings.headers.clone(),
    });
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .build(),
    ))
}
