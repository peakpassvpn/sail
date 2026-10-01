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
        "trojan",
        OutboundFactory::standalone(build).with_blocks(Blocks::ALL),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrojanOutboundOptions {
    /// May be left out, with `server_port`, by an outbound with a
    /// `detour`: one over ShadowTLS, which dials its own server.
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    password: String,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: TrojanOutboundOptions = ctx.options()?;
    let (server, server_port) = ctx.server(options.server.clone(), options.server_port)?;
    let stream = Arc::new(StreamHandler {
        address: server.clone(),
        port: server_port,
        dialer: ctx.dialer.clone(),
        password: options.password.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: server,
        port: server_port,
        dialer: ctx.dialer.clone(),
        password: options.password,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
