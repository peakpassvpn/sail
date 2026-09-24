use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config::model::resolve_certificate;
use serde_derive::Deserialize;

pub mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("tls", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsInboundOptions {
    /// Inline or as a path.
    certificate: String,
    /// Inline or as a path.
    certificate_key: String,
    #[serde(default)]
    ech_config: Option<String>,
    #[serde(default)]
    ech_key: Option<String>,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: TlsInboundOptions = ctx.options()?;
    match (&options.ech_config, &options.ech_key) {
        (None, None) => {}
        (Some(_), Some(_)) => {
            return Err(anyhow!(
                "[{}] inbound: ech_config: inbound ECH is not supported yet",
                ctx.tag
            ))
        }
        _ => {
            return Err(anyhow!(
                "[{}] inbound: ech_config and ech_key must be set together",
                ctx.tag
            ))
        }
    }
    let stream = Arc::new(
        StreamHandler::new(
            resolve_certificate(&options.certificate),
            resolve_certificate(&options.certificate_key),
            options.ech_config,
            options.ech_key,
        )
        .map_err(|e| anyhow!("[{}] inbound: {}", ctx.tag, e))?,
    );
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
