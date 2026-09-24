use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config;

pub mod http;
pub mod tls;

pub use self::http::Handler as HttpObfsStreamHandler;
pub use self::tls::Handler as TlsObfsStreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("obfs", OutboundFactory::standalone(build));
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<Option<AnyOutboundHandler>> {
    let settings: config::ObfsOutboundSettings = ctx.settings()?;
    let stream = match &*settings.method {
        "http" => Arc::new(HttpObfsStreamHandler::new(
            settings.path.as_bytes(),
            settings.host.as_bytes(),
        )) as _,
        "tls" => Arc::new(TlsObfsStreamHandler::new(settings.host.as_bytes())) as _,
        method => {
            return Err(anyhow!(
                "invalid [{}] outbound settings: unknown obfs method {}",
                ctx.tag,
                method
            ))
        }
    };
    Ok(Some(
        HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(stream)
            .build(),
    ))
}
