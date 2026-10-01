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
    /// May be left out, with `server_port`, by an outbound with a
    /// `detour`: one over ShadowTLS, which dials its own server.
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
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
    let (server, server_port) = ctx.server(options.server.clone(), options.server_port)?;
    let udp_over_tcp = match &options.udp_over_tcp {
        Some(uot) => uot.enabled(ctx.tag)?,
        None => false,
    };
    let stream = Arc::new(StreamHandler {
        address: server.clone(),
        port: server_port,
        username: options.username.clone(),
        password: options.password.clone(),
        dialer: ctx.dialer.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: server,
        port: server_port,
        username: options.username,
        password: options.password,
        dns_client: ctx.dns_client.clone(),
        dialer: ctx.dialer.clone(),
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
