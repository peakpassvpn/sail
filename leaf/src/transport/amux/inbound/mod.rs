use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{
    parse_options, InboundContext, InboundFactory, InboundRegistry, Options,
};
use crate::adapter::AnyInboundHandler;
use serde_derive::Deserialize;

mod stream;

pub use stream::Handler as StreamHandler;

use super::MuxAcceptor;
use super::MuxSession;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("amux", InboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AMuxInboundOptions {
    /// The layers each underlying connection comes in over.
    #[serde(default)]
    inbounds: Vec<String>,
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: AMuxInboundOptions = parse_options("inbound", tag, options)?;
    Ok(options.inbounds)
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: AMuxInboundOptions = ctx.options()?;
    let actors = ctx.actors(&options.inbounds)?;
    let stream = Arc::new(StreamHandler { actors });
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
