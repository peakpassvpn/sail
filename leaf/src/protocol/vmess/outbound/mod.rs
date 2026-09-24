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

use super::crypto;
use super::protocol;
use super::stream as vmess_stream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "vmess",
        OutboundFactory::standalone(build).with_blocks(Blocks::ALL),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VMessOutboundOptions {
    server: String,
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
