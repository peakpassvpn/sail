use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{parse_settings, InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config;

mod stream;

pub use stream::Handler as StreamHandler;

use super::MuxAcceptor;
use super::MuxSession;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("amux", InboundFactory::composite(dependencies, build));
}

fn dependencies(tag: &str, settings: &[u8]) -> Result<Vec<String>> {
    let settings: config::AMuxInboundSettings = parse_settings("inbound", tag, settings)?;
    Ok(settings.actors.to_vec())
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let settings: config::AMuxInboundSettings = ctx.settings()?;
    let actors = ctx.actors(&settings.actors)?;
    let stream = Arc::new(StreamHandler { actors });
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
