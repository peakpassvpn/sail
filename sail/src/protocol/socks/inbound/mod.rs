use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use serde_derive::Deserialize;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("socks", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksInboundOptions {
    /// Clients must authenticate as one of these; anyone may connect when
    /// there are none.
    #[serde(default)]
    users: Vec<SocksUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SocksUser {
    pub username: String,
    pub password: String,
}

/// The users by username, with their passwords.
///
/// A username may appear only once: which of two passwords would name the
/// user is otherwise ambiguous. RFC 1929 carries each in at most 255 bytes,
/// so a longer one could never authenticate.
pub(crate) fn users_by_name(tag: &str, users: Vec<SocksUser>) -> Result<HashMap<String, String>> {
    let mut map = HashMap::with_capacity(users.len());
    for user in users {
        if user.username.is_empty() || user.username.len() > 255 {
            return Err(anyhow!(
                "[{}] inbound: users: username \"{}\" must be 1 to 255 bytes",
                tag,
                user.username
            ));
        }
        if user.password.is_empty() || user.password.len() > 255 {
            return Err(anyhow!(
                "[{}] inbound: users: {}: password must be 1 to 255 bytes",
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
    let options: SocksInboundOptions = ctx.options()?;
    let users = users_by_name(ctx.tag, options.users)?;
    let stream = Arc::new(StreamHandler::new(users));
    let datagram = Arc::new(DatagramHandler);
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        Some(datagram),
    )))
}
