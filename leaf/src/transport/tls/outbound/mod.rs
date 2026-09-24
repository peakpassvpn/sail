use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config;

pub mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("tls", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let settings: config::TlsOutboundSettings = ctx.settings()?;
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
    let ech_config_list = if settings.ech_config_list.is_empty() {
        None
    } else {
        Some(settings.ech_config_list.clone())
    };
    let stream = Arc::new(StreamHandler::new(
        settings.server_name.clone(),
        settings.alpn.clone(),
        certificate,
        certificate_key,
        settings.insecure,
        settings.ech,
        settings.ech_disable_dns_lookup,
        ech_config_list,
        ctx.dns_client.clone(),
    )?);
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}
