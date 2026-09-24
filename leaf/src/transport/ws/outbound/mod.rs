use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use serde_derive::Deserialize;

pub mod stream;

pub use stream::Handler as StreamHandler;

use super::stream as ws_stream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("ws", OutboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebSocketOutboundOptions {
    #[serde(default = "default_path")]
    path: String,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
}

fn default_path() -> String {
    "/".to_string()
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: WebSocketOutboundOptions = ctx.options()?;
    let stream = Arc::new(StreamHandler {
        path: options.path,
        headers: options.headers,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}
