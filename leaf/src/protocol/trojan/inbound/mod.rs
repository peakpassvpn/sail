use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use serde_derive::Deserialize;

mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("trojan", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrojanInboundOptions {
    users: Vec<TrojanUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrojanUser {
    /// Not used yet; users are told apart by password alone.
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: TrojanInboundOptions = ctx.options()?;
    let passwords = options.users.into_iter().map(|u| u.password).collect();
    let stream = Arc::new(StreamHandler::new(passwords));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
