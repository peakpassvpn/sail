use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use serde_derive::Deserialize;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

enum Method {
    Random,
    RandomOnce,
    RoundRobin,
}

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("static", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticOutboundOptions {
    outbounds: Vec<String>,
    /// `random`, `random-once` or `rr`.
    #[serde(default = "default_method")]
    method: String,
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: StaticOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.outbounds)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: StaticOutboundOptions = ctx.options()?;
    let actors = ctx.members(&options.outbounds)?;
    let stream = Arc::new(StreamHandler::new(actors.clone(), &options.method)?);
    let datagram = Arc::new(DatagramHandler::new(actors, &options.method)?);
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}

fn default_method() -> String {
    "random".to_string()
}
