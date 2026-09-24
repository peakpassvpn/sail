use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config;

mod stream;

pub use stream::Handler as StreamHandler;

use super::QuicProxyStream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("quic", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let settings: config::QuicOutboundSettings = ctx.settings()?;
    let server_name = if settings.server_name.is_empty() {
        None
    } else {
        Some(settings.server_name.clone())
    };
    let certificate = if settings.certificate.is_empty() {
        None
    } else {
        Some(settings.certificate.clone())
    };
    let certificate_key = if settings.certificate_key.is_empty() {
        None
    } else {
        Some(settings.certificate_key.clone())
    };
    let stream = Arc::new(StreamHandler::new(
        settings.address.clone(),
        settings.port as u16,
        server_name,
        settings.alpn.clone(),
        certificate,
        certificate_key,
        ctx.dns_client.clone(),
    ));
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}
