use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;
use serde_derive::Deserialize;

use super::request::Flow;

mod stream;

pub use stream::{Handler as StreamHandler, User};

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register(
        "vless",
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
struct VlessInboundOptions {
    users: Vec<VlessUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    uuid: String,
    /// `""` or `xtls-rprx-vision`.
    #[serde(default)]
    flow: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: VlessInboundOptions = ctx.options()?;
    if options.users.is_empty() {
        return Err(anyhow!("[{}] inbound: users: cannot be empty", ctx.tag));
    }
    let mut users = HashMap::new();
    for (i, user) in options.users.into_iter().enumerate() {
        let uuid = *uuid::Uuid::parse_str(&user.uuid)
            .map_err(|e| anyhow!("[{}] inbound: users[{}].uuid: {}", ctx.tag, i, e))?
            .as_bytes();
        let flow = Flow::parse(&user.flow)
            .map_err(|e| anyhow!("[{}] inbound: users[{}].flow: {}", ctx.tag, i, e))?;
        let user = User {
            name: user.name.map(Into::into),
            flow,
        };
        if users.insert(uuid, user).is_some() {
            return Err(anyhow!(
                "[{}] inbound: users[{}].uuid: used by another user",
                ctx.tag,
                i
            ));
        }
    }
    let stream = Arc::new(StreamHandler::new(users));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
