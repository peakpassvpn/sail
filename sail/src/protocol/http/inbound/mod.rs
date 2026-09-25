use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;

mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register(
        "http",
        InboundFactory::standalone(build).with_blocks(Blocks {
            tls: true,
            ..Blocks::NONE
        }),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpInboundOptions {
    /// Clients must authenticate as one of these with `Proxy-Authorization:
    /// Basic`; anyone may connect when there are none.
    #[serde(default)]
    users: Vec<HttpUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpUser {
    pub username: String,
    pub password: String,
}

/// The users by username, with their passwords.
///
/// A username may appear only once: which of two passwords would name the
/// user is otherwise ambiguous. Basic credentials split at the first colon,
/// so a username cannot hold one.
pub(crate) fn users_by_name(tag: &str, users: Vec<HttpUser>) -> Result<HashMap<String, String>> {
    let mut map = HashMap::with_capacity(users.len());
    for user in users {
        if user.username.contains(':') {
            return Err(anyhow!(
                "[{}] inbound: users: username \"{}\" contains a colon",
                tag,
                user.username
            ));
        }
        if map.contains_key(&user.username) {
            return Err(anyhow!(
                "[{}] inbound: users: username \"{}\" appears more than once",
                tag,
                user.username
            ));
        }
        map.insert(user.username, user.password);
    }
    Ok(map)
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: HttpInboundOptions = ctx.options()?;
    let users = users_by_name(ctx.tag, options.users)?;
    let stream = Arc::new(StreamHandler::new(users));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}
