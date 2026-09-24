use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use serde_derive::Deserialize;

pub mod datagram;
mod plan;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("chain", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainOutboundOptions {
    outbounds: Vec<String>,
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: ChainOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.outbounds)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: ChainOutboundOptions = ctx.options()?;
    let actors = ctx.members(&options.outbounds)?;
    let stream = Arc::new(StreamHandler {
        actors: actors.clone(),
    });
    let datagram = Arc::new(DatagramHandler { actors });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
