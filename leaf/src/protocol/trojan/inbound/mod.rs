use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;
use serde_derive::Deserialize;

mod stream;

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
    let users = options
        .users
        .into_iter()
        .map(|u| (u.password, u.name))
        .collect();
    let stream = Arc::new(StreamHandler::new(users));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
