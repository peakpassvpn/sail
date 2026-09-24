use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler as InboundHandler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use serde_derive::Deserialize;

mod stream;

pub use stream::Handler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("hc", InboundFactory::standalone(build));
}

/// Answers health checks: `request` on `path` gets `response`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HcInboundOptions {
    path: String,
    #[serde(default)]
    request: String,
    response: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: HcInboundOptions = ctx.options()?;
    let stream = Arc::new(Handler::new(
        options.path,
        options.request,
        options.response,
    ));
    Ok(Arc::new(InboundHandler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
