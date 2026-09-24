use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use serde_derive::Deserialize;

mod stream;

pub use stream::Handler as StreamHandler;

use super::MuxConnector;
use super::MuxSession;
use super::MuxStream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("amux", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AMuxOutboundOptions {
    server: String,
    server_port: u16,
    /// The layers each underlying connection is carried over.
    #[serde(default)]
    outbounds: Vec<String>,
    #[serde(default = "default_max_accepts")]
    max_accepts: usize,
    #[serde(default = "default_concurrency")]
    concurrency: usize,
    #[serde(default)]
    max_recv_bytes: usize,
    #[serde(default)]
    max_lifetime: u64,
}

fn default_max_accepts() -> usize {
    8
}

fn default_concurrency() -> usize {
    2
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: AMuxOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.outbounds)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: AMuxOutboundOptions = ctx.options()?;
    let actors = ctx.actors(&options.outbounds)?;
    let (stream, mut abort_handles) = StreamHandler::new(
        options.server,
        options.server_port,
        actors,
        options.max_accepts,
        options.concurrency,
        options.max_recv_bytes,
        options.max_lifetime,
        ctx.dns_client.clone(),
    );
    ctx.abort_handles.append(&mut abort_handles);
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(Arc::new(stream))
        .build())
}
