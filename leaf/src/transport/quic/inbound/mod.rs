use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config;

mod datagram;

pub use datagram::Handler as DatagramHandler;

use super::QuicProxyStream;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("quic", InboundFactory::standalone(build));
}

fn build(ctx: &InboundContext<'_>) -> Result<Option<AnyInboundHandler>> {
    let settings: config::QuicInboundSettings = ctx.settings()?;
    let datagram = Arc::new(DatagramHandler::new(
        settings.certificate.clone(),
        settings.certificate_key.clone(),
        settings.alpn.clone(),
    )?);
    Ok(Some(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        None,
        Some(datagram),
    ))))
}
