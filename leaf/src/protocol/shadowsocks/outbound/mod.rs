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

use super::shadow;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("shadowsocks", OutboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksOutboundOptions {
    // Only the server of the first actor in a chain is dialled; the others
    // may leave it out until chains are built from shared blocks.
    #[serde(default)]
    server: String,
    #[serde(default)]
    server_port: u16,
    method: String,
    password: String,
    /// Bytes sent before the first payload, percent-encoded.
    #[serde(default)]
    prefix: Option<String>,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: ShadowsocksOutboundOptions = ctx.options()?;
    let stream = Arc::new(StreamHandler::new(
        options.server.clone(),
        options.server_port,
        options.method.clone(),
        options.password.clone(),
        options.prefix,
    )?);
    let datagram = Arc::new(DatagramHandler {
        address: options.server,
        port: options.server_port,
        cipher: options.method,
        password: options.password,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
