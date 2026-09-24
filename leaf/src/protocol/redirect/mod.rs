use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::transport::layers::Blocks;
use serde_derive::Deserialize;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "redirect",
        OutboundFactory::standalone(build).with_blocks(Blocks::DETOUR),
    );
}

/// Sends every connection to one fixed address.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectOptions {
    server: String,
    server_port: u16,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: RedirectOptions = ctx.options()?;
    let stream = Arc::new(StreamHandler {
        address: options.server.clone(),
        port: options.server_port,
    });
    let datagram = Arc::new(DatagramHandler {
        address: options.server,
        port: options.server_port,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
