use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use serde_derive::Deserialize;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

use super::crypto;
use super::protocol;
use super::stream as vmess_stream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("vmess", OutboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VMessOutboundOptions {
    // Only the server of the first actor in a chain is dialled; the others
    // may leave it out until chains are built from shared blocks.
    #[serde(default)]
    server: String,
    #[serde(default)]
    server_port: u16,
    uuid: String,
    security: String,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: VMessOutboundOptions = ctx.options()?;
    let stream = Arc::new(StreamHandler {
        address: options.server.clone(),
        port: options.server_port,
        uuid: options.uuid.clone(),
        security: options.security.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: options.server,
        port: options.server_port,
        uuid: options.uuid,
        security: options.security,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
