use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config;

mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("trojan", InboundFactory::standalone(build));
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let settings: config::TrojanInboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler::new(settings.passwords.to_vec()));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
