use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::transport::layers::Blocks;
use crate::transport::uot;
use serde_derive::Deserialize;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "socks",
        OutboundFactory::standalone(build).with_blocks(Blocks::DIALER),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksOutboundOptions {
    server: String,
    server_port: u16,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    /// UDP over its TCP, to `sp.v2.udp-over-tcp.arpa`, instead of UDP
    /// ASSOCIATE.
    #[serde(default)]
    udp_over_tcp: Option<uot::UdpOverTcpOptions>,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: SocksOutboundOptions = ctx.options()?;
    let udp_over_tcp = match &options.udp_over_tcp {
        Some(uot) => uot.enabled(ctx.tag)?,
        None => false,
    };
    let stream = Arc::new(StreamHandler {
        address: options.server.clone(),
        port: options.server_port,
        username: options.username.clone(),
        password: options.password.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: options.server,
        port: options.server_port,
        username: options.username,
        password: options.password,
        dns_client: ctx.dns_client.clone(),
        dial: ctx.dial.clone(),
    });
    let socks = HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build();
    if udp_over_tcp {
        return Ok(uot::over_stream(socks)?);
    }
    Ok(socks)
}
