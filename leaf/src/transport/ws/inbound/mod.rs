use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use serde_derive::Deserialize;

mod stream;

pub use stream::Handler as StreamHandler;

use super::stream as ws_stream;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("ws", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebSocketInboundOptions {
    #[serde(default = "default_path")]
    path: String,
}

fn default_path() -> String {
    "/".to_string()
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: WebSocketInboundOptions = ctx.options()?;
    let stream = Arc::new(StreamHandler::new(options.path));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
