use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use serde_derive::Deserialize;

pub mod stream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("mptp", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MptpOutboundOptions {
    outbounds: Vec<String>,
    server: String,
    server_port: u16,
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: MptpOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.outbounds)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: MptpOutboundOptions = ctx.options()?;
    let actors = ctx.members(&options.outbounds)?;
    let stream = Arc::new(stream::Handler {
        actors,
        address: options.server,
        port: options.server_port,
        dns_client: ctx.dns_client.clone(),
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream.clone())
        .datagram_handler(stream)
        .build())
}
