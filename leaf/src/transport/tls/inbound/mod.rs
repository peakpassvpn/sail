use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config;

pub mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("tls", InboundFactory::standalone(build));
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let settings: config::TlsInboundSettings = ctx.settings()?;
    let ech_config = if settings.ech_config.is_empty() {
        None
    } else {
        Some(settings.ech_config.clone())
    };
    let ech_key = if settings.ech_key.is_empty() {
        None
    } else {
        Some(settings.ech_key.clone())
    };
    let stream = Arc::new(
        StreamHandler::new(
            settings.certificate.clone(),
            settings.certificate_key.clone(),
            ech_config,
            ech_key,
        )
        .map_err(|e| anyhow!("invalid [{}] inbound tls capability: {}", ctx.tag, e))?,
    );
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
