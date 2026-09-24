use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

use super::shadow;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("shadowsocks", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::ShadowsocksOutboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler::new(
        settings.address.clone(),
        settings.port as u16,
        settings.method.clone(),
        settings.password.clone(),
        settings.prefix.as_ref().cloned(),
    )?);
    let datagram = Arc::new(DatagramHandler {
        address: settings.address,
        port: settings.port as u16,
        cipher: settings.method,
        password: settings.password,
    });
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .datagram_handler(datagram)
            .build(),
    ))
}
