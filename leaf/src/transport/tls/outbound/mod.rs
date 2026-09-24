use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config::model::resolve_certificate;
use serde_derive::Deserialize;

pub mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("tls", OutboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsOutboundOptions {
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    alpn: Vec<String>,
    /// A certificate to trust, inline or as a path.
    #[serde(default)]
    certificate: Option<String>,
    /// A client certificate's key, inline or as a path.
    #[serde(default)]
    certificate_key: Option<String>,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    ech: bool,
    #[serde(default)]
    ech_disable_dns_lookup: bool,
    #[serde(default)]
    ech_config_list: Option<String>,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: TlsOutboundOptions = ctx.options()?;
    if options
        .ech_config_list
        .as_deref()
        .is_some_and(|l| l.trim().is_empty())
    {
        return Err(anyhow!(
            "[{}] outbound: ech_config_list: cannot be empty",
            ctx.tag
        ));
    }
    let stream = Arc::new(StreamHandler::new(
        options.server_name,
        options.alpn,
        options.certificate.as_deref().map(resolve_certificate),
        options.certificate_key.as_deref().map(resolve_certificate),
        options.insecure,
        options.ech,
        options.ech_disable_dns_lookup,
        options.ech_config_list,
        ctx.dns_client.clone(),
    )?);
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}
