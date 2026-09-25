use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::transport::layers::Blocks;
use serde_derive::Deserialize;

use super::request::Flow;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "vless",
        OutboundFactory::standalone(build).with_blocks(Blocks::ALL),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessOutboundOptions {
    server: String,
    server_port: u16,
    uuid: String,
    /// `""` or `xtls-rprx-vision`.
    #[serde(default)]
    flow: String,
    /// How UDP travels: unset means `xudp`, as in sing-box; `""` is
    /// VLESS's own UDP, one destination per connection.
    #[serde(default)]
    packet_encoding: Option<String>,
}

/// How an outbound carries UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEncoding {
    /// The protocol's own UDP command: one destination per connection.
    Plain,
    /// XUDP over Mux.Cool: each packet names its destination.
    Xudp,
}

impl PacketEncoding {
    /// `packet_encoding` as VLESS and VMess outbounds take it, `default`
    /// when unset.
    pub fn parse(tag: &str, value: Option<&str>, default: PacketEncoding) -> Result<Self> {
        match value {
            None => Ok(default),
            Some("") => Ok(PacketEncoding::Plain),
            Some("xudp") => Ok(PacketEncoding::Xudp),
            Some(other) => Err(anyhow!(
                "[{}] outbound: packet_encoding: unsupported \"{}\", expected \"\" or \"xudp\"",
                tag,
                other
            )),
        }
    }
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: VlessOutboundOptions = ctx.options()?;
    let uuid = *uuid::Uuid::parse_str(&options.uuid)
        .map_err(|e| anyhow!("[{}] outbound: uuid: {}", ctx.tag, e))?
        .as_bytes();
    let flow =
        Flow::parse(&options.flow).map_err(|e| anyhow!("[{}] outbound: flow: {}", ctx.tag, e))?;
    let packet_encoding = PacketEncoding::parse(
        ctx.tag,
        options.packet_encoding.as_deref(),
        PacketEncoding::Xudp,
    )?;
    if flow == Flow::Vision && packet_encoding == PacketEncoding::Plain {
        // Vision cannot carry VLESS's own UDP; only XUDP.
        return Err(anyhow!(
            "[{}] outbound: packet_encoding: xtls-rprx-vision carries UDP only as xudp",
            ctx.tag
        ));
    }
    let stream = Arc::new(StreamHandler {
        address: options.server.clone(),
        port: options.server_port,
        uuid,
        flow,
    });
    let datagram = Arc::new(DatagramHandler {
        address: options.server,
        port: options.server_port,
        uuid,
        flow,
        packet_encoding,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}
