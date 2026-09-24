use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use serde_derive::Deserialize;

pub mod http;
pub mod tls;

pub use self::http::Handler as HttpObfsStreamHandler;
pub use self::tls::Handler as TlsObfsStreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("obfs", OutboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObfsOutboundOptions {
    /// `http` or `tls`.
    method: String,
    #[serde(default)]
    host: String,
    #[serde(default = "default_path")]
    path: String,
}

fn default_path() -> String {
    "/".to_string()
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: ObfsOutboundOptions = ctx.options()?;
    let stream = match &*options.method {
        "http" => Arc::new(HttpObfsStreamHandler::new(
            options.path.as_bytes(),
            options.host.as_bytes(),
        )) as _,
        "tls" => Arc::new(TlsObfsStreamHandler::new(options.host.as_bytes())) as _,
        method => {
            return Err(anyhow!(
                "[{}] outbound: method: unknown obfs method \"{}\"",
                ctx.tag,
                method
            ))
        }
    };
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}
