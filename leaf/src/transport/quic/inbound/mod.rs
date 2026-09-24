use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config::model::resolve_certificate;
use serde_derive::Deserialize;

mod datagram;

pub use datagram::Handler as DatagramHandler;

use super::QuicProxyStream;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("quic", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuicInboundOptions {
    /// Inline or as a path.
    certificate: String,
    /// Inline or as a path.
    certificate_key: String,
    #[serde(default)]
    alpn: Vec<String>,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: QuicInboundOptions = ctx.options()?;
    let datagram = Arc::new(DatagramHandler::new(
        resolve_certificate(&options.certificate),
        resolve_certificate(&options.certificate_key),
        options.alpn,
    )?);
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        None,
        Some(datagram),
    )))
}
