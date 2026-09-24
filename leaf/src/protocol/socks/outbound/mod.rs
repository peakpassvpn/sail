use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("socks", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::SocksOutboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler {
        address: settings.address.clone(),
        port: settings.port as u16,
        username: settings.username.clone(),
        password: settings.password.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: settings.address.clone(),
        port: settings.port as u16,
        username: settings.username.clone(),
        password: settings.password.clone(),
        dns_client: ctx.dns_client.clone(),
    });
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .datagram_handler(datagram)
            .build(),
    ))
}
