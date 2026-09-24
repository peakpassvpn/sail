use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config::model::resolve_certificate;
use serde_derive::Deserialize;

mod stream;

pub use stream::Handler as StreamHandler;

use super::QuicProxyStream;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("quic", OutboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuicOutboundOptions {
    server: String,
    server_port: u16,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    alpn: Vec<String>,
    /// A certificate to trust, inline or as a path.
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    certificate_key: Option<String>,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: QuicOutboundOptions = ctx.options()?;
    let stream = Arc::new(StreamHandler::new(
        options.server,
        options.server_port,
        options.server_name,
        options.alpn,
        options.certificate.as_deref().map(resolve_certificate),
        options.certificate_key.as_deref().map(resolve_certificate),
        ctx.dns_client.clone(),
    ));
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}
