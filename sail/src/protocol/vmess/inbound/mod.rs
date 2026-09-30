use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;
use serde_derive::Deserialize;

pub(crate) use super::header::ReplayFilter;
use super::header::User;

mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register(
        "vmess",
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
struct VMessInboundOptions {
    users: Vec<VMessUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VMessUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    uuid: String,
    /// Only 0: AEAD headers. Legacy VMess is not served.
    #[serde(default, rename = "alterId")]
    alter_id: u32,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: VMessInboundOptions = ctx.options()?;
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (i, user) in options.users.into_iter().enumerate() {
        let uuid = *uuid::Uuid::parse_str(&user.uuid)
            .map_err(|e| anyhow!("[{}] inbound: users[{}].uuid: {}", ctx.tag, i, e))?
            .as_bytes();
        if user.alter_id != 0 {
            return Err(anyhow!(
                "[{}] inbound: users[{}].alterId: only 0 is supported, legacy VMess is not",
                ctx.tag,
                i
            ));
        }
        if !seen.insert(uuid) {
            return Err(anyhow!(
                "[{}] inbound: users[{}].uuid: used by another user",
                ctx.tag,
                i
            ));
        }
        users.push(User::new(
            &uuid,
            ctx.env.users.bind_named(user.name.as_deref()),
        ));
    }
    let replay = ctx.state.vmess_replay.get_or_init(Arc::default).clone();
    let stream = Arc::new(StreamHandler::with_replay(users, replay));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
