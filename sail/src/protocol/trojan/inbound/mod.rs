use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;
use serde_derive::Deserialize;

// The VLESS inbound compiles it too.
mod stream;

use crate::protocol::fallback::{self, FallbackServer};

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register(
        "trojan",
        InboundFactory::standalone(build).with_blocks(Blocks {
            tls: true,
            transport: true,
            multiplex: true,
            ..Blocks::NONE
        }),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrojanInboundOptions {
    users: Vec<TrojanUser>,
    /// Where a connection that fails to authenticate is relayed.
    #[serde(default)]
    fallback: Option<FallbackServer>,
    /// The same, by the ALPN the connection's TLS negotiated; the ones it
    /// does not name go to `fallback`.
    #[serde(default)]
    fallback_for_alpn: HashMap<String, FallbackServer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrojanUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: TrojanInboundOptions = ctx.options()?;
    let fallback = fallback::Fallback::new(ctx.tag, options.fallback, options.fallback_for_alpn)?;
    let users = options
        .users
        .into_iter()
        .map(|u| (u.password, u.name))
        .collect();
    let stream = Arc::new(StreamHandler::new(users, fallback));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
